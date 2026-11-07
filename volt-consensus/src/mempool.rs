//! A bounded, fee-aware transaction pool.
//!
//! - **Admission** runs the same rules a block would: the inputs must exist and be mature, the
//!   value must balance against the exact fee, nullifiers must be fresh, and proofs and
//!   signatures must verify. A transaction that conflicts with one already in the pool is
//!   refused, so everything in the pool can be mined together.
//! - **Selection** is by fee per unit of *weight* (the larger of its size and its actions), so a
//!   transaction that is cheap to verify beats an equally priced one that is expensive.
//! - The pool is **bounded** by count and bytes. When full, a new transaction replaces the
//!   lowest-priority one only if it pays a higher rate; otherwise it is refused.

use std::{
    cmp::Reverse,
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use thiserror::Error;
use volt_core::{
    calculate_tx_fee,
    constants::{MAX_BLOCK_ACTIONS, MAX_TX_BYTES},
    BatchableTx, Nullifier, VoltHash,
};
use volt_state::{ApplyRules, RamUtxoStore, StateError};
use zebra_chain::{block::Height, transparent::OutPoint};

/// One action is weighed as this many bytes when ranking by fee rate, so verification-heavy
/// transactions are not mistaken for small ones.
const BYTES_PER_ACTION: u64 = 150;

/// Why a transaction was not admitted.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum MempoolError {
    /// The transaction is already in the pool.
    #[error("transaction {0} is already in the pool")]
    Duplicate(VoltHash),

    /// Coinbase transactions are never relayed.
    #[error("coinbase transactions cannot enter the pool")]
    Coinbase,

    /// The transaction is larger than a block may carry.
    #[error("transaction is {0} bytes, the maximum is {MAX_TX_BYTES}")]
    TooLarge(usize),

    /// The transaction has more actions than a whole block may carry.
    #[error("transaction has {0} actions, a block may carry at most {MAX_BLOCK_ACTIONS}")]
    TooManyActions(u64),

    /// The transaction spends an output or reveals a nullifier that another pooled transaction
    /// already uses.
    #[error("transaction conflicts with pooled transaction {0}")]
    Conflict(VoltHash),

    /// The pool is full and this transaction does not pay enough to displace anything.
    #[error("the pool is full and this transaction's fee rate is too low")]
    PoolFull,

    /// The transaction fails the state rules or proof verification.
    #[error(transparent)]
    Invalid(#[from] StateError),
}

#[derive(Debug)]
struct Entry {
    tx: Arc<dyn BatchableTx>,
    bytes: usize,
    /// Fee per million weight units, so integer ordering is precise enough.
    rate: u64,
    seq: u64,
    outpoints: Vec<OutPoint>,
    nullifiers: Vec<Nullifier>,
}

/// The transaction pool.
#[derive(Debug)]
pub struct Mempool {
    entries: HashMap<VoltHash, Entry>,
    /// Highest fee rate first, then oldest first.
    ranking: BTreeSet<(Reverse<u64>, u64, VoltHash)>,
    spent: HashMap<OutPoint, VoltHash>,
    revealed: HashMap<Nullifier, VoltHash>,
    max_txs: usize,
    max_bytes: usize,
    bytes: usize,
    next_seq: u64,
}

impl Mempool {
    /// Creates a pool holding at most `max_txs` transactions and `max_bytes` serialized bytes.
    pub fn new(max_txs: usize, max_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            ranking: BTreeSet::new(),
            spent: HashMap::new(),
            revealed: HashMap::new(),
            max_txs,
            max_bytes,
            bytes: 0,
            next_seq: 0,
        }
    }

    /// The number of pooled transactions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The pooled serialized bytes.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether `txid` is pooled.
    pub fn contains(&self, txid: &VoltHash) -> bool {
        self.entries.contains_key(txid)
    }

    /// Admits `tx` if it is valid against `state` and fits in the pool.
    ///
    /// `height` is the chain height transactions would be mined at, used for coinbase maturity.
    pub fn admit(
        &mut self,
        tx: Arc<dyn BatchableTx>,
        state: &RamUtxoStore,
        height: Height,
        rules: &ApplyRules<'_>,
    ) -> Result<(), MempoolError> {
        let txid = tx.txid();
        if self.entries.contains_key(&txid) {
            return Err(MempoolError::Duplicate(txid));
        }
        if tx.is_coinbase() {
            return Err(MempoolError::Coinbase);
        }

        let bytes = tx.size_bytes();
        if bytes > MAX_TX_BYTES {
            return Err(MempoolError::TooLarge(bytes));
        }
        let actions = tx.logical_actions();
        if actions > MAX_BLOCK_ACTIONS {
            return Err(MempoolError::TooManyActions(actions));
        }

        let outpoints = tx.spent_outpoints();
        let nullifiers = tx.nullifiers();
        for outpoint in &outpoints {
            if let Some(other) = self.spent.get(outpoint) {
                return Err(MempoolError::Conflict(*other));
            }
        }
        for nullifier in &nullifiers {
            if let Some(other) = self.revealed.get(nullifier) {
                return Err(MempoolError::Conflict(*other));
            }
        }

        // The full rules, including proofs: the expensive check comes after the cheap ones.
        state.validate_batch_with(std::slice::from_ref(&tx), height, rules)?;

        let fee = u64::try_from(calculate_tx_fee(tx.as_ref()).zatoshis()).unwrap_or(0);
        let weight = (bytes as u64)
            .max(actions.saturating_mul(BYTES_PER_ACTION))
            .max(1); // lossless: usize fits in u64
        let rate = fee.saturating_mul(1_000_000) / weight;

        let seq = self.next_seq;
        self.next_seq += 1;
        let entry = Entry {
            tx,
            bytes,
            rate,
            seq,
            outpoints,
            nullifiers,
        };

        // Make room, or refuse if the newcomer is not better than what it would displace.
        while self.entries.len() >= self.max_txs || self.bytes + entry.bytes > self.max_bytes {
            let Some(&(Reverse(worst_rate), _, worst)) = self.ranking.iter().next_back() else {
                return Err(MempoolError::PoolFull);
            };
            if entry.rate <= worst_rate {
                return Err(MempoolError::PoolFull);
            }
            self.remove(&worst);
        }

        self.ranking.insert((Reverse(entry.rate), entry.seq, txid));
        self.bytes += entry.bytes;
        for outpoint in &entry.outpoints {
            self.spent.insert(*outpoint, txid);
        }
        for nullifier in &entry.nullifiers {
            self.revealed.insert(*nullifier, txid);
        }
        self.entries.insert(txid, entry);
        Ok(())
    }

    /// Removes `txid`, returning it if it was pooled.
    pub fn remove(&mut self, txid: &VoltHash) -> Option<Arc<dyn BatchableTx>> {
        let entry = self.entries.remove(txid)?;
        self.ranking
            .remove(&(Reverse(entry.rate), entry.seq, *txid));
        self.bytes -= entry.bytes;
        for outpoint in &entry.outpoints {
            self.spent.remove(outpoint);
        }
        for nullifier in &entry.nullifiers {
            self.revealed.remove(nullifier);
        }
        Some(entry.tx)
    }

    /// Removes every transaction in `mined`, and every pooled transaction that conflicts with one.
    ///
    /// Call this when a block is accepted into state.
    pub fn remove_confirmed(&mut self, mined: &[Arc<dyn BatchableTx>]) {
        for tx in mined {
            self.remove(&tx.txid());
            let conflicts: Vec<VoltHash> = tx
                .spent_outpoints()
                .iter()
                .filter_map(|o| self.spent.get(o).copied())
                .chain(
                    tx.nullifiers()
                        .iter()
                        .filter_map(|n| self.revealed.get(n).copied()),
                )
                .collect();
            for txid in conflicts {
                self.remove(&txid);
            }
        }
    }

    /// Removes and returns the best `batches * 10` transactions, highest fee rate first, or
    /// fewer if the pool holds fewer. The count is always a multiple of the batch size.
    pub fn take_batches(&mut self, batches: usize) -> Vec<Arc<dyn BatchableTx>> {
        let size = volt_core::constants::BATCH_SIZE;
        let available = (self.entries.len() / size).min(batches) * size;
        let best: Vec<VoltHash> = self
            .ranking
            .iter()
            .take(available)
            .map(|(_, _, txid)| *txid)
            .collect();
        best.iter().filter_map(|txid| self.remove(txid)).collect()
    }

    /// The fee rate of a pooled transaction, in zatoshis per million weight units.
    pub fn fee_rate(&self, txid: &VoltHash) -> Option<u64> {
        self.entries.get(txid).map(|e| e.rate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volt_core::DevTx;
    use zebra_chain::{
        amount::Amount,
        transaction,
        transparent::{Output, Script},
    };

    fn out(value: i64, script_len: usize) -> Output {
        Output::new(Amount::new(value), Script::new(&vec![0x51; script_len]))
    }

    fn fund(state: &RamUtxoStore, n: u32, value: i64) -> OutPoint {
        let outpoint = OutPoint {
            hash: transaction::Hash([(n % 251) as u8; 32]),
            index: n,
        };
        // Fund through the real block path. Maturity is 0 under `unchecked` rules.
        state
            .apply_block(
                vec![(outpoint, out(value, 1))],
                &[],
                Height(1),
                &ApplyRules::unchecked(),
            )
            .expect("a fresh outpoint can be funded");
        outpoint
    }

    fn pool(max: usize) -> (Mempool, RamUtxoStore) {
        (Mempool::new(max, 10_000_000), RamUtxoStore::new())
    }

    fn admit(
        pool: &mut Mempool,
        state: &RamUtxoStore,
        tx: DevTx,
    ) -> Result<VoltHash, MempoolError> {
        let id = tx.txid();
        pool.admit(Arc::new(tx), state, Height(10), &ApplyRules::unchecked())?;
        Ok(id)
    }

    /// A transaction paying exactly its required fee, whatever its size.
    fn spend(state: &RamUtxoStore, n: u32, script_len: usize) -> DevTx {
        let input = fund(state, n, 10_000_000);
        // Build the output first with a placeholder value to learn the fee, then balance it.
        let probe = DevTx::new(
            vec![input],
            vec![out(1, script_len)],
            vec![],
            false,
            u64::from(n),
        );
        let fee = calculate_tx_fee(&probe).zatoshis();
        DevTx::new(
            vec![input],
            vec![out(10_000_000 - fee, script_len)],
            vec![],
            false,
            u64::from(n),
        )
    }

    #[test]
    fn admits_valid_transactions_and_refuses_duplicates() {
        let (mut pool, state) = pool(100);
        let tx = spend(&state, 1, 1);
        let id = admit(&mut pool, &state, tx.clone()).unwrap();
        assert!(pool.contains(&id));
        assert_eq!(pool.len(), 1);
        assert_eq!(
            admit(&mut pool, &state, tx),
            Err(MempoolError::Duplicate(id))
        );
    }

    #[test]
    fn refuses_transactions_that_fail_the_state_rules() {
        let (mut pool, state) = pool(100);

        // Spends an output that does not exist.
        let ghost = OutPoint {
            hash: transaction::Hash([9; 32]),
            index: 0,
        };
        let missing = DevTx::new(vec![ghost], vec![out(1, 1)], vec![], false, 1);
        assert!(matches!(
            admit(&mut pool, &state, missing),
            Err(MempoolError::Invalid(StateError::MissingInput(_)))
        ));

        // Pays the wrong fee.
        let input = fund(&state, 5, 1_000_000);
        let burn = DevTx::new(vec![input], vec![out(1, 1)], vec![], false, 2);
        assert!(matches!(
            admit(&mut pool, &state, burn),
            Err(MempoolError::Invalid(StateError::ValueImbalance { .. }))
        ));
        assert!(pool.is_empty());
    }

    #[test]
    fn conflicting_transactions_are_refused_so_the_pool_is_always_minable() {
        let (mut pool, state) = pool(100);
        let input = fund(&state, 1, 10_000_000);
        let make = |nonce: u64| {
            let probe = DevTx::new(vec![input], vec![out(1, 1)], vec![], false, nonce);
            let fee = calculate_tx_fee(&probe).zatoshis();
            DevTx::new(
                vec![input],
                vec![out(10_000_000 - fee, 1)],
                vec![],
                false,
                nonce,
            )
        };

        let first = admit(&mut pool, &state, make(1)).unwrap();
        // The same input again: a double spend.
        assert_eq!(
            admit(&mut pool, &state, make(2)),
            Err(MempoolError::Conflict(first))
        );

        // A repeated nullifier conflicts too.
        let a = DevTx::new(vec![], vec![], vec![[7; 32]], true, 10).with_shielded_value_out(20_000);
        let b = DevTx::new(vec![], vec![], vec![[7; 32]], true, 11).with_shielded_value_out(20_000);
        let a_id = admit(&mut pool, &state, a).unwrap();
        assert_eq!(
            admit(&mut pool, &state, b),
            Err(MempoolError::Conflict(a_id))
        );
    }

    #[test]
    fn smaller_transactions_rank_above_heavier_ones_at_the_same_fee_tier() {
        let (mut pool, state) = pool(100);
        // A big script costs more in fees, but also weighs more: compare rates, not fees.
        let small = admit(&mut pool, &state, spend(&state, 1, 1)).unwrap();
        let heavy = admit(&mut pool, &state, spend(&state, 2, 4_000)).unwrap();
        assert!(
            pool.fee_rate(&small).unwrap() > pool.fee_rate(&heavy).unwrap(),
            "small {} vs heavy {}",
            pool.fee_rate(&small).unwrap(),
            pool.fee_rate(&heavy).unwrap()
        );
    }

    #[test]
    fn take_batches_returns_the_best_in_multiples_of_ten() {
        let (mut pool, state) = pool(100);
        // 23 transactions: 3 are heavy and rank last.
        let mut heavy = Vec::new();
        for n in 0..23u32 {
            let script_len = if n % 8 == 7 { 4_000 } else { 1 };
            let id = admit(&mut pool, &state, spend(&state, n, script_len)).unwrap();
            if script_len > 1 {
                heavy.push(id);
            }
        }
        assert_eq!(heavy.len(), 2);

        let taken = pool.take_batches(5);
        assert_eq!(taken.len(), 20, "only whole batches are returned");
        assert_eq!(pool.len(), 3);
        for tx in &taken {
            assert!(!heavy.contains(&tx.txid()), "heavy transactions rank last");
        }
        // Fewer than ten left: no batch can be formed.
        assert!(pool.take_batches(5).is_empty());
    }

    #[test]
    fn a_full_pool_evicts_the_worst_only_for_a_better_rate() {
        let (mut pool, state) = pool(3);
        let heavy = admit(&mut pool, &state, spend(&state, 1, 4_000)).unwrap();
        admit(&mut pool, &state, spend(&state, 2, 1)).unwrap();
        admit(&mut pool, &state, spend(&state, 3, 1)).unwrap();
        assert_eq!(pool.len(), 3);

        // Another heavy transaction is no better than the worst: refused.
        assert_eq!(
            admit(&mut pool, &state, spend(&state, 4, 4_000)),
            Err(MempoolError::PoolFull)
        );
        // A small one has a better rate: it displaces the heavy transaction.
        let small = admit(&mut pool, &state, spend(&state, 5, 1)).unwrap();
        assert!(pool.contains(&small));
        assert!(!pool.contains(&heavy));
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn the_byte_budget_is_enforced() {
        let state = RamUtxoStore::new();
        // Measure a transaction against a throwaway state so no outpoint is funded twice.
        let one = spend(&RamUtxoStore::new(), 1, 1).size_bytes();
        let mut pool = Mempool::new(1_000, one * 2 + one / 2);

        admit(&mut pool, &state, spend(&state, 1, 1)).unwrap();
        admit(&mut pool, &state, spend(&state, 2, 1)).unwrap();
        // The third does not fit and is not better than what is there.
        assert_eq!(
            admit(&mut pool, &state, spend(&state, 3, 1)),
            Err(MempoolError::PoolFull)
        );
        assert!(pool.bytes() <= one * 2 + one / 2);
    }

    #[test]
    fn mined_transactions_and_their_conflicts_leave_the_pool() {
        let (mut pool, state) = pool(100);
        let input = fund(&state, 1, 10_000_000);
        let pooled = {
            let probe = DevTx::new(vec![input], vec![out(1, 1)], vec![], false, 1);
            let fee = calculate_tx_fee(&probe).zatoshis();
            DevTx::new(
                vec![input],
                vec![out(10_000_000 - fee, 1)],
                vec![],
                false,
                1,
            )
        };
        let id = admit(&mut pool, &state, pooled).unwrap();
        let other = admit(&mut pool, &state, spend(&state, 2, 1)).unwrap();

        // A different transaction spending the same input is mined elsewhere.
        let rival: Arc<dyn BatchableTx> =
            Arc::new(DevTx::new(vec![input], vec![out(5, 1)], vec![], false, 99));
        pool.remove_confirmed(&[rival]);

        assert!(
            !pool.contains(&id),
            "the conflicting pooled transaction is dropped"
        );
        assert!(pool.contains(&other), "unrelated transactions stay");
    }
}
