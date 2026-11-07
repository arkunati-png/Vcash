//! The sharded in-memory UTXO and nullifier store.

use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::Arc,
};

use dashmap::DashMap;
use thiserror::Error;
use volt_core::{
    calculate_tx_fee, BatchableTx, NoVerification, Nullifier, TxVerifier, TxVerifyItem, VerifyError,
};
use zebra_chain::{
    block::Height,
    transaction,
    transparent::{OutPoint, Output, Utxo},
};

/// Errors from validating or applying transactions against the store.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum StateError {
    /// An input refers to an output that does not exist or was already spent.
    #[error("missing input {0:?}")]
    MissingInput(OutPoint),

    /// Two inputs in the same batch spend the same output.
    #[error("double spend of {0:?}")]
    DoubleSpend(OutPoint),

    /// A nullifier was already revealed on chain or earlier in the same batch.
    #[error("nullifier reused: {}", hex_32(.0))]
    NullifierReused(Nullifier),

    /// A transaction creates an output that already exists.
    #[error("output {0:?} already exists")]
    OutputExists(OutPoint),

    /// A transaction's value does not balance to inputs = outputs + fee.
    #[error("transaction {txid} value imbalance: in {inputs}, out {outputs}, fee {fee}")]
    ValueImbalance {
        /// The offending transaction.
        txid: volt_core::VoltHash,
        /// Transparent input value plus value leaving the shielded pools.
        inputs: i128,
        /// Transparent output value.
        outputs: i128,
        /// The required fee.
        fee: i128,
    },

    /// A coinbase output was spent before it matured.
    #[error("coinbase output {outpoint:?} is {age} steps old, {required} are required")]
    ImmatureCoinbase {
        /// The output being spent.
        outpoint: OutPoint,
        /// How many steps old it is.
        age: u32,
        /// How many it needs.
        required: u32,
    },

    /// A transaction's proofs or signatures are invalid.
    #[error(transparent)]
    Verification(#[from] VerifyError),
}

/// The consensus rules a batch is applied under, beyond value balance.
#[derive(Clone, Copy, Debug)]
pub struct ApplyRules<'a> {
    /// Verifies proofs and signatures.
    pub verifier: &'a dyn TxVerifier,
    /// How many chain steps a coinbase output must age before it can be spent.
    pub coinbase_maturity: u32,
}

static NO_VERIFICATION: NoVerification = NoVerification;

impl ApplyRules<'static> {
    /// No proof checks and no coinbase maturity. For tests and proof-less devnets only.
    pub fn unchecked() -> Self {
        Self {
            verifier: &NO_VERIFICATION,
            coinbase_maturity: 0,
        }
    }
}

fn hex_32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What one successful step changed, so it can be reverted.
#[derive(Clone, Debug, Default)]
struct StepUndo {
    spent: Vec<(OutPoint, Utxo)>,
    created: Vec<OutPoint>,
    nullifiers: Vec<Nullifier>,
}

/// The undo data for a block applied with [`RamUtxoStore::apply_block`].
#[derive(Clone, Debug, Default)]
pub struct BlockUndo {
    steps: Vec<StepUndo>,
}

/// The planned effect of a batch, computed without touching the store.
#[derive(Default)]
struct Plan {
    /// Outputs spent from the store, with their original value.
    spent: HashMap<OutPoint, Utxo>,
    /// Outputs created and still unspent at the end of the batch.
    created: HashMap<OutPoint, Utxo>,
    nullifiers: HashSet<Nullifier>,
}

/// A sharded in-memory UTXO set and nullifier set.
///
/// Reads and writes lock a single shard, so independent lookups run in parallel and nothing
/// reaches the disk. State is rebuilt from the DAG at startup; it is not persisted.
///
/// Block application is meant to have a single writer (the validator), while mempool and RPC
/// code may read concurrently.
#[derive(Debug)]
pub struct RamUtxoStore {
    utxos: DashMap<OutPoint, Utxo>,
    nullifiers: DashMap<Nullifier, ()>,
}

impl BlockUndo {
    /// Appends later's steps, so reverting the result reverts later first.
    pub fn merge(&mut self, later: BlockUndo) {
        self.steps.extend(later.steps);
    }
}

impl Default for RamUtxoStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RamUtxoStore {
    /// Creates an empty store with dashmap's default shard count (4x the CPU count).
    pub fn new() -> Self {
        Self {
            utxos: DashMap::new(),
            nullifiers: DashMap::new(),
        }
    }

    /// Creates an empty store with `shards` shards.
    ///
    /// # Panics
    ///
    /// If `shards` is not a power of two greater than one.
    pub fn with_shard_amount(shards: usize) -> Self {
        Self {
            utxos: DashMap::with_shard_amount(shards),
            nullifiers: DashMap::with_shard_amount(shards),
        }
    }

    /// The number of unspent outputs.
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// Whether there are no unspent outputs.
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// The number of revealed nullifiers.
    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.len()
    }

    /// Returns a copy of the unspent output at `outpoint`.
    pub fn get(&self, outpoint: &OutPoint) -> Option<Utxo> {
        self.utxos.get(outpoint).map(|entry| entry.value().clone())
    }

    /// Whether `outpoint` is unspent.
    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.utxos.contains_key(outpoint)
    }

    /// Whether `nullifier` has been revealed.
    pub fn has_nullifier(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.contains_key(nullifier)
    }

    /// Checks a batch against the current state without changing it, with no proof checks and no
    /// coinbase maturity.
    ///
    /// Transactions are processed in order, so a later transaction may spend an output created
    /// by an earlier one in the same batch.
    pub fn validate_batch(&self, txs: &[Arc<dyn BatchableTx>]) -> Result<(), StateError> {
        self.plan(txs, Height(0), &ApplyRules::unchecked())
            .map(|_| ())
    }

    /// Checks a batch against the current state without changing it, under the given rules.
    ///
    /// Unlike [`RamUtxoStore::validate_batch`] this checks coinbase maturity against `height` and
    /// runs the rules' proof verifier. The mempool uses it to admit transactions.
    pub fn validate_batch_with(
        &self,
        txs: &[Arc<dyn BatchableTx>],
        height: Height,
        rules: &ApplyRules<'_>,
    ) -> Result<(), StateError> {
        self.plan(txs, height, rules).map(|_| ())
    }

    /// Validates `txs` and applies them, returning their undo step.
    fn apply_checked(
        &self,
        txs: &[Arc<dyn BatchableTx>],
        height: Height,
        rules: &ApplyRules<'_>,
    ) -> Result<StepUndo, StateError> {
        let plan = self.plan(txs, height, rules)?;
        Ok(self.commit(plan))
    }

    /// Validates and applies one batch with no proof checks and no coinbase maturity, returning
    /// its undo data. Consensus uses [`RamUtxoStore::apply_block`] instead.
    pub fn apply_batch(
        &self,
        txs: &[Arc<dyn BatchableTx>],
        height: Height,
    ) -> Result<BlockUndo, StateError> {
        Ok(BlockUndo {
            steps: vec![self.apply_checked(txs, height, &ApplyRules::unchecked())?],
        })
    }

    /// Applies a whole block atomically: the coinbase outputs, then each batch in order.
    ///
    /// If any batch fails, everything already applied for this block is reverted and the
    /// store is left unchanged.
    pub fn apply_block(
        &self,
        coinbase_outputs: Vec<(OutPoint, Output)>,
        batches: &[Vec<Arc<dyn BatchableTx>>],
        height: Height,
        rules: &ApplyRules<'_>,
    ) -> Result<BlockUndo, StateError> {
        let mut undo = BlockUndo::default();

        let mut coinbase_step = StepUndo::default();
        for (outpoint, output) in coinbase_outputs {
            if self.utxos.contains_key(&outpoint) {
                self.revert_block(undo);
                return Err(StateError::OutputExists(outpoint));
            }
            self.utxos.insert(outpoint, Utxo::new(output, height, true));
            coinbase_step.created.push(outpoint);
        }
        undo.steps.push(coinbase_step);

        for batch in batches {
            match self.apply_checked(batch, height, rules) {
                Ok(step) => undo.steps.push(step),
                Err(e) => {
                    self.revert_block(undo);
                    return Err(e);
                }
            }
        }
        Ok(undo)
    }

    /// Reverts a block (or batch) applied earlier, newest step first.
    ///
    /// Only the most recently applied, not yet reverted block may be reverted.
    pub fn revert_block(&self, undo: BlockUndo) {
        for step in undo.steps.into_iter().rev() {
            for nullifier in &step.nullifiers {
                self.nullifiers.remove(nullifier);
            }
            for outpoint in &step.created {
                self.utxos.remove(outpoint);
            }
            for (outpoint, utxo) in step.spent {
                self.utxos.insert(outpoint, utxo);
            }
        }
    }

    /// Computes the effect of `txs` without changing the store.
    fn plan(
        &self,
        txs: &[Arc<dyn BatchableTx>],
        height: Height,
        rules: &ApplyRules<'_>,
    ) -> Result<Plan, StateError> {
        let mut plan = Plan::default();
        // The outputs each transaction spends, kept for proof verification.
        let mut spent_outputs: Vec<Vec<Output>> = Vec::with_capacity(txs.len());

        for tx in txs {
            let txid = transaction::Hash(tx.txid().0);
            let mut inputs: i128 = 0;
            let mut tx_spent = Vec::new();

            for outpoint in tx.spent_outpoints() {
                let utxo = if let Some(utxo) = plan.created.remove(&outpoint) {
                    // Spending an output created earlier in this batch: net effect is nothing.
                    utxo
                } else {
                    match plan.spent.entry(outpoint) {
                        Entry::Occupied(_) => return Err(StateError::DoubleSpend(outpoint)),
                        Entry::Vacant(slot) => {
                            let utxo = self
                                .get(&outpoint)
                                .ok_or(StateError::MissingInput(outpoint))?;
                            let age = height.0.saturating_sub(utxo.height.0);
                            if utxo.from_coinbase && age < rules.coinbase_maturity {
                                return Err(StateError::ImmatureCoinbase {
                                    outpoint,
                                    age,
                                    required: rules.coinbase_maturity,
                                });
                            }
                            slot.insert(utxo.clone());
                            utxo
                        }
                    }
                };
                inputs += i128::from(utxo.output.value().zatoshis());
                tx_spent.push(utxo.output);
            }
            spent_outputs.push(tx_spent);
            inputs += i128::from(tx.shielded_value_out().zatoshis());

            let mut outputs: i128 = 0;
            for (index, output) in tx.outputs().into_iter().enumerate() {
                outputs += i128::from(output.value().zatoshis());
                let outpoint = OutPoint::from_usize(txid, index);
                if self.utxos.contains_key(&outpoint) || plan.created.contains_key(&outpoint) {
                    return Err(StateError::OutputExists(outpoint));
                }
                plan.created
                    .insert(outpoint, Utxo::new(output, height, false));
            }

            // Value must balance exactly: nothing is burned and nothing is created.
            let fee = i128::from(calculate_tx_fee(tx.as_ref()).zatoshis());
            if inputs != outputs + fee {
                return Err(StateError::ValueImbalance {
                    txid: tx.txid(),
                    inputs,
                    outputs,
                    fee,
                });
            }

            for nullifier in tx.nullifiers() {
                if self.nullifiers.contains_key(&nullifier) || !plan.nullifiers.insert(nullifier) {
                    return Err(StateError::NullifierReused(nullifier));
                }
            }
        }

        // Proofs and signatures are checked last: they are the expensive part, so a batch that
        // fails a cheap state check never pays for them.
        let items: Vec<TxVerifyItem<'_>> = txs
            .iter()
            .zip(spent_outputs)
            .map(|(tx, spent_outputs)| TxVerifyItem {
                tx: tx.as_ref(),
                spent_outputs,
            })
            .collect();
        rules.verifier.verify_batch(&items)?;

        Ok(plan)
    }

    /// Writes a validated plan into the store.
    fn commit(&self, plan: Plan) -> StepUndo {
        let mut undo = StepUndo::default();

        for (outpoint, utxo) in plan.spent {
            self.utxos.remove(&outpoint);
            undo.spent.push((outpoint, utxo));
        }
        for (outpoint, utxo) in plan.created {
            self.utxos.insert(outpoint, utxo);
            undo.created.push(outpoint);
        }
        for nullifier in plan.nullifiers {
            self.nullifiers.insert(nullifier, ());
            undo.nullifiers.push(nullifier);
        }
        undo
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volt_core::{DevTx, TxKind};
    use zebra_chain::{amount::Amount, transparent::Script};

    const H: Height = Height(1);

    fn out(value: i64) -> Output {
        Output::new(Amount::new(value), Script::new(&[0x51]))
    }

    fn fund(store: &RamUtxoStore, n: u8, value: i64) -> OutPoint {
        let outpoint = OutPoint {
            hash: transaction::Hash([n; 32]),
            index: 0,
        };
        store.utxos.insert(outpoint, Utxo::new(out(value), H, true));
        outpoint
    }

    fn arc(tx: DevTx) -> Arc<dyn BatchableTx> {
        Arc::new(tx)
    }

    #[test]
    fn spends_and_creates_outputs() {
        let store = RamUtxoStore::with_shard_amount(8);
        let funded = fund(&store, 1, 100_000);

        // 100_000 in = 60_000 + 30_000 out + 10_000 transparent fee
        let tx = DevTx::new(
            vec![funded],
            vec![out(60_000), out(30_000)],
            vec![],
            false,
            1,
        );
        let txid = transaction::Hash(tx.txid().0);
        store.apply_batch(&[arc(tx)], H).unwrap();

        assert!(!store.contains(&funded));
        assert!(store.contains(&OutPoint::from_usize(txid, 0)));
        assert!(store.contains(&OutPoint::from_usize(txid, 1)));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn rejects_double_spend_and_missing_inputs() {
        let store = RamUtxoStore::new();
        let funded = fund(&store, 1, 100_000);

        let a = DevTx::new(vec![funded], vec![out(90_000)], vec![], false, 1);
        let b = DevTx::new(vec![funded], vec![out(90_000)], vec![], false, 2);
        assert_eq!(
            store.validate_batch(&[arc(a), arc(b)]),
            Err(StateError::DoubleSpend(funded))
        );

        let ghost = OutPoint {
            hash: transaction::Hash([9; 32]),
            index: 0,
        };
        let c = DevTx::new(vec![ghost], vec![], vec![], false, 3);
        assert_eq!(
            store.validate_batch(&[arc(c)]),
            Err(StateError::MissingInput(ghost))
        );
        assert_eq!(store.len(), 1, "validation never mutates");
    }

    #[test]
    fn later_tx_can_spend_earlier_output_in_same_batch() {
        let store = RamUtxoStore::new();
        let funded = fund(&store, 1, 100_000);

        let first = DevTx::new(vec![funded], vec![out(90_000)], vec![], false, 1);
        let first_out = OutPoint::from_usize(transaction::Hash(first.txid().0), 0);
        let second = DevTx::new(vec![first_out], vec![out(80_000)], vec![], false, 2);

        store.apply_batch(&[arc(first), arc(second)], H).unwrap();
        assert_eq!(store.len(), 1, "only the final output remains");
    }

    #[test]
    fn enforces_exact_value_and_tiered_fee() {
        let store = RamUtxoStore::new();
        let funded = fund(&store, 1, 100_000);

        // Overpaying the fee burns value: rejected.
        let burn = DevTx::new(vec![funded], vec![out(50_000)], vec![], false, 1);
        assert!(matches!(
            store.validate_batch(&[arc(burn)]),
            Err(StateError::ValueImbalance { fee: 10_000, .. })
        ));

        // A shielded tx owes 20_000.
        let shielded = DevTx::new(vec![funded], vec![out(80_000)], vec![[5; 32]], true, 2);
        assert_eq!(shielded.kind(), TxKind::Shielded);
        store.validate_batch(&[arc(shielded)]).unwrap();

        // A pure shielded tx moves exactly its fee out of the shielded pool.
        let pure =
            DevTx::new(vec![], vec![], vec![[6; 32]], true, 3).with_shielded_value_out(20_000);
        store.validate_batch(&[arc(pure)]).unwrap();
    }

    #[test]
    fn nullifiers_cannot_repeat() {
        let store = RamUtxoStore::new();
        let tx = |nonce, nf| {
            arc(DevTx::new(vec![], vec![], vec![nf], true, nonce).with_shielded_value_out(20_000))
        };

        store.apply_batch(&[tx(1, [7; 32])], H).unwrap();
        assert!(store.has_nullifier(&[7; 32]));
        assert_eq!(
            store.validate_batch(&[tx(2, [7; 32])]),
            Err(StateError::NullifierReused([7; 32]))
        );
        assert_eq!(
            store.validate_batch(&[tx(3, [8; 32]), tx(4, [8; 32])]),
            Err(StateError::NullifierReused([8; 32]))
        );
    }

    #[test]
    fn revert_restores_state_exactly() {
        let store = RamUtxoStore::new();
        let funded = fund(&store, 1, 100_000);

        let first = DevTx::new(vec![funded], vec![out(90_000)], vec![], false, 1);
        let first_out = OutPoint::from_usize(transaction::Hash(first.txid().0), 0);
        let second = DevTx::new(vec![first_out], vec![out(80_000)], vec![], false, 2);
        let shielded =
            DevTx::new(vec![], vec![], vec![[3; 32]], true, 3).with_shielded_value_out(20_000);

        let undo = store
            .apply_block(
                vec![(
                    OutPoint {
                        hash: transaction::Hash([0xcb; 32]),
                        index: 0,
                    },
                    out(500),
                )],
                &[vec![arc(first)], vec![arc(second), arc(shielded)]],
                Height(2),
                &ApplyRules::unchecked(),
            )
            .unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store.nullifier_count(), 1);

        store.revert_block(undo);
        assert_eq!(store.len(), 1);
        assert!(store.contains(&funded));
        assert_eq!(store.nullifier_count(), 0);
    }

    #[test]
    fn failed_block_leaves_store_unchanged() {
        let store = RamUtxoStore::new();
        let funded = fund(&store, 1, 100_000);

        let good = DevTx::new(vec![funded], vec![out(90_000)], vec![], false, 1);
        let bad = DevTx::new(vec![funded], vec![out(90_000)], vec![], false, 2); // double spend across batches

        let result = store.apply_block(
            vec![],
            &[vec![arc(good)], vec![arc(bad)]],
            Height(2),
            &ApplyRules::unchecked(),
        );
        assert!(matches!(result, Err(StateError::MissingInput(_))));
        assert_eq!(store.len(), 1);
        assert!(store.contains(&funded));
    }

    #[test]
    fn coinbase_outputs_must_mature() {
        let store = RamUtxoStore::new();
        // `fund` creates a coinbase output at height 1.
        let funded = fund(&store, 1, 100_000);
        let spend = || {
            arc(DevTx::new(
                vec![funded],
                vec![out(90_000)],
                vec![],
                false,
                1,
            ))
        };
        let rules = ApplyRules {
            coinbase_maturity: 100,
            ..ApplyRules::unchecked()
        };

        // 50 steps old: still immature.
        let early = store.apply_block(vec![], &[vec![spend()]], Height(51), &rules);
        assert_eq!(
            early.err(),
            Some(StateError::ImmatureCoinbase {
                outpoint: funded,
                age: 50,
                required: 100
            })
        );
        assert!(store.contains(&funded), "a rejected block changes nothing");

        // Exactly 100 steps old: mature.
        store
            .apply_block(vec![], &[vec![spend()]], Height(101), &rules)
            .unwrap();
        assert!(!store.contains(&funded));
    }

    #[derive(Debug)]
    struct RejectNonce(u64);

    impl TxVerifier for RejectNonce {
        fn verify_batch(&self, items: &[TxVerifyItem<'_>]) -> Result<(), VerifyError> {
            for item in items {
                if item
                    .tx
                    .to_bytes()
                    .windows(8)
                    .any(|w| w == self.0.to_le_bytes())
                {
                    return Err(VerifyError {
                        txid: item.tx.txid(),
                        reason: "bad proof".into(),
                    });
                }
            }
            Ok(())
        }
    }

    #[test]
    fn the_verifier_sees_spent_outputs_and_can_reject_a_block() {
        let store = RamUtxoStore::new();
        let funded = fund(&store, 1, 100_000);
        let tx = arc(DevTx::new(
            vec![funded],
            vec![out(90_000)],
            vec![],
            false,
            0xdead_beef,
        ));

        let bad = RejectNonce(0xdead_beef);
        let rules = ApplyRules {
            verifier: &bad,
            coinbase_maturity: 0,
        };
        let result = store.apply_block(vec![], &[vec![tx.clone()]], Height(2), &rules);
        assert!(matches!(result, Err(StateError::Verification(_))));
        assert!(
            store.contains(&funded),
            "verification failure leaves state unchanged"
        );

        // The same transaction passes a verifier that accepts it.
        let ok = RejectNonce(1);
        let rules = ApplyRules {
            verifier: &ok,
            coinbase_maturity: 0,
        };
        store
            .apply_block(vec![], &[vec![tx]], Height(2), &rules)
            .unwrap();
    }

    #[test]
    fn proofs_are_not_checked_when_a_cheap_state_check_fails() {
        // A missing input must be reported without ever invoking the (expensive) verifier.
        #[derive(Debug)]
        struct Panics;
        impl TxVerifier for Panics {
            fn verify_batch(&self, _: &[TxVerifyItem<'_>]) -> Result<(), VerifyError> {
                panic!("the verifier must not run for a batch that fails state checks");
            }
        }

        let store = RamUtxoStore::new();
        let ghost = OutPoint {
            hash: transaction::Hash([9; 32]),
            index: 0,
        };
        let tx = arc(DevTx::new(vec![ghost], vec![], vec![], false, 1));
        let rules = ApplyRules {
            verifier: &Panics,
            coinbase_maturity: 0,
        };
        let result = store.apply_block(vec![], &[vec![tx]], Height(2), &rules);
        assert_eq!(result.err(), Some(StateError::MissingInput(ghost)));
    }
}
