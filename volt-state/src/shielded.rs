//! Shielded state: note commitment trees, anchors and the pool balances.
//!
//! Verifying a shielded proof is not enough on its own. The proof is checked against whatever
//! *anchor* (a note commitment tree root) the transaction claims, so without more it could be
//! made against a tree the spender invented, containing notes that never existed. Three more
//! rules, taken from Zcash, close that:
//!
//! 1. **Anchors.** A spend's anchor must be the root of the real tree at the end of an *earlier*
//!    chain step. Roots are recorded when a step is sealed ([`ShieldedState::seal_step`]), so a
//!    transaction can never anchor to its own step, and the empty-tree roots are valid from
//!    genesis.
//! 2. **Commitments.** Every note commitment a transaction creates is appended to its pool's tree,
//!    in consensus order, so the trees every node builds are identical.
//! 3. **The turnstile.** The value in each pool may never go negative. Even if a flaw in a proof
//!    system let someone mint shielded value, they could not take more out than was put in.
//!
//! Sprout and Ironwood are not supported: nothing here tracks their pools, so value could be
//! created in them without limit, and such transactions are refused outright.

use std::{collections::HashSet, sync::Arc};

use halo2::pasta::{group::ff::PrimeField, pallas};
use sapling_crypto::note::ExtractedNoteCommitment as SaplingCommitment;
use thiserror::Error;
use volt_core::{BatchableTx, VoltHash};
use zebra_chain::{orchard, sapling};

/// The capacity of each note commitment tree: `2^32` leaves.
const TREE_CAPACITY: u64 = 1 << 32;

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Why a block's shielded content was refused.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ShieldedError {
    /// A Sapling spend uses an anchor that is not the root of any earlier chain step.
    #[error("transaction {txid} spends against an unknown Sapling anchor {}", hex(.anchor))]
    UnknownSaplingAnchor {
        /// The offending transaction.
        txid: VoltHash,
        /// The anchor it claims.
        anchor: [u8; 32],
    },

    /// The Orchard bundle uses an anchor that is not the root of any earlier chain step.
    #[error("transaction {txid} spends against an unknown Orchard anchor {}", hex(.anchor))]
    UnknownOrchardAnchor {
        /// The offending transaction.
        txid: VoltHash,
        /// The anchor it claims.
        anchor: [u8; 32],
    },

    /// A note commitment is not a valid field element.
    #[error("transaction {txid} has an invalid {pool} note commitment")]
    InvalidCommitment {
        /// The offending transaction.
        txid: VoltHash,
        /// The pool the commitment belongs to.
        pool: &'static str,
    },

    /// The block would add more notes than a tree can hold.
    #[error("the {0} note commitment tree is full")]
    TreeFull(&'static str),

    /// The block would take more value out of a pool than it holds.
    #[error("the {pool} pool would go negative: balance {balance}, change {change}")]
    PoolOverdrawn {
        /// The pool.
        pool: &'static str,
        /// The pool's balance before the block.
        balance: i128,
        /// The net change the block would make.
        change: i128,
    },

    /// The transaction uses a shielded pool this node does not track.
    #[error("transaction {0} uses a shielded pool that is not supported (Sprout or Ironwood)")]
    UnsupportedPool(VoltHash),
}

/// Everything a chain step can change, small enough to copy for every step.
#[derive(Clone, Debug)]
pub struct ShieldedSnapshot {
    sapling: sapling::tree::NoteCommitmentTree,
    orchard: orchard::tree::NoteCommitmentTree,
    sapling_pool: i128,
    orchard_pool: i128,
}

/// The anchors a sealed step added, so sealing can be undone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StepSeal {
    sapling_root: Option<[u8; 32]>,
    orchard_root: Option<[u8; 32]>,
}

/// The note commitment trees, valid anchors and pool balances.
#[derive(Debug)]
pub struct ShieldedState {
    sapling: sapling::tree::NoteCommitmentTree,
    orchard: orchard::tree::NoteCommitmentTree,
    sapling_anchors: HashSet<[u8; 32]>,
    orchard_anchors: HashSet<[u8; 32]>,
    sapling_pool: i128,
    orchard_pool: i128,
}

impl Default for ShieldedState {
    fn default() -> Self {
        Self::new()
    }
}

impl ShieldedState {
    /// The state at genesis: empty trees, whose roots are the only valid anchors, and empty pools.
    pub fn new() -> Self {
        let sapling = sapling::tree::NoteCommitmentTree::default();
        let orchard = orchard::tree::NoteCommitmentTree::default();
        Self {
            sapling_anchors: HashSet::from([<[u8; 32]>::from(sapling.root())]),
            orchard_anchors: HashSet::from([<[u8; 32]>::from(orchard.root())]),
            sapling,
            orchard,
            sapling_pool: 0,
            orchard_pool: 0,
        }
    }

    /// The Sapling tree root as of now, including notes added in the step in progress.
    pub fn sapling_root(&self) -> [u8; 32] {
        self.sapling.root().into()
    }

    /// The Orchard tree root as of now.
    pub fn orchard_root(&self) -> [u8; 32] {
        self.orchard.root().into()
    }

    /// The number of Sapling notes ever created.
    pub fn sapling_notes(&self) -> u64 {
        self.sapling.count()
    }

    /// The number of Orchard notes ever created.
    pub fn orchard_notes(&self) -> u64 {
        self.orchard.count()
    }

    /// The value in the Sapling pool, in zatoshis.
    pub fn sapling_pool(&self) -> i128 {
        self.sapling_pool
    }

    /// The value in the Orchard pool, in zatoshis.
    pub fn orchard_pool(&self) -> i128 {
        self.orchard_pool
    }

    /// Whether `anchor` is currently a valid Sapling anchor.
    pub fn is_sapling_anchor(&self, anchor: &[u8; 32]) -> bool {
        self.sapling_anchors.contains(anchor)
    }

    /// Whether `anchor` is currently a valid Orchard anchor.
    pub fn is_orchard_anchor(&self, anchor: &[u8; 32]) -> bool {
        self.orchard_anchors.contains(anchor)
    }

    /// Checks everything about `tx` that depends only on the current anchors: that it uses no
    /// unsupported pool, and that every anchor it spends against is valid.
    ///
    /// The mempool uses this to refuse transactions a block could not include.
    pub fn check_anchors(&self, tx: &dyn BatchableTx) -> Result<(), ShieldedError> {
        if tx.has_unsupported_shielded_data() {
            return Err(ShieldedError::UnsupportedPool(tx.txid()));
        }
        for anchor in tx.sapling_anchor_roots() {
            if !self.sapling_anchors.contains(&anchor) {
                return Err(ShieldedError::UnknownSaplingAnchor {
                    txid: tx.txid(),
                    anchor,
                });
            }
        }
        if let Some(anchor) = tx.orchard_anchor_root() {
            if !self.orchard_anchors.contains(&anchor) {
                return Err(ShieldedError::UnknownOrchardAnchor {
                    txid: tx.txid(),
                    anchor,
                });
            }
        }
        Ok(())
    }

    /// Applies the shielded content of one block: checks every anchor, appends every note
    /// commitment in order, and updates the pools, refusing a block that overdraws one.
    ///
    /// All checks happen before anything changes, so on error the state is untouched.
    pub fn apply_block(
        &mut self,
        batches: &[Vec<Arc<dyn BatchableTx>>],
    ) -> Result<(), ShieldedError> {
        let mut sapling_notes: Vec<SaplingCommitment> = Vec::new();
        let mut orchard_notes: Vec<pallas::Base> = Vec::new();
        let mut sapling_change: i128 = 0;
        let mut orchard_change: i128 = 0;

        for tx in batches.iter().flatten() {
            self.check_anchors(tx.as_ref())?;

            for bytes in tx.sapling_commitment_bytes() {
                let commitment = Option::from(SaplingCommitment::from_bytes(&bytes)).ok_or(
                    ShieldedError::InvalidCommitment {
                        txid: tx.txid(),
                        pool: "Sapling",
                    },
                )?;
                sapling_notes.push(commitment);
            }
            for bytes in tx.orchard_commitment_bytes() {
                let commitment = Option::from(pallas::Base::from_repr(bytes)).ok_or(
                    ShieldedError::InvalidCommitment {
                        txid: tx.txid(),
                        pool: "Orchard",
                    },
                )?;
                orchard_notes.push(commitment);
            }

            // Value leaving a pool lowers it; value shielded into it raises it.
            sapling_change -= i128::from(tx.sapling_value_out());
            orchard_change -= i128::from(tx.orchard_value_out());
        }

        // The turnstile, checked per block as Zcash does: a pool may not end a block negative.
        for (pool, balance, change) in [
            ("Sapling", self.sapling_pool, sapling_change),
            ("Orchard", self.orchard_pool, orchard_change),
        ] {
            if balance + change < 0 {
                return Err(ShieldedError::PoolOverdrawn {
                    pool,
                    balance,
                    change,
                });
            }
        }
        if self.sapling.count() + sapling_notes.len() as u64 > TREE_CAPACITY {
            return Err(ShieldedError::TreeFull("Sapling"));
        }
        if self.orchard.count() + orchard_notes.len() as u64 > TREE_CAPACITY {
            return Err(ShieldedError::TreeFull("Orchard"));
        }

        // Everything is valid: commit. Capacity was checked, so the appends cannot fail.
        for commitment in sapling_notes {
            self.sapling
                .append(commitment)
                .map_err(|_| ShieldedError::TreeFull("Sapling"))?;
        }
        for commitment in orchard_notes {
            self.orchard
                .append(commitment)
                .map_err(|_| ShieldedError::TreeFull("Orchard"))?;
        }
        self.sapling_pool += sapling_change;
        self.orchard_pool += orchard_change;
        Ok(())
    }

    /// Ends a chain step: the trees' current roots become valid anchors for later steps.
    ///
    /// Returns what was newly added, to undo with [`ShieldedState::unseal_step`] if the step is
    /// reverted. Calling it for a step that changed nothing adds nothing.
    pub fn seal_step(&mut self) -> StepSeal {
        let sapling_root = self.sapling_root();
        let orchard_root = self.orchard_root();
        StepSeal {
            sapling_root: self
                .sapling_anchors
                .insert(sapling_root)
                .then_some(sapling_root),
            orchard_root: self
                .orchard_anchors
                .insert(orchard_root)
                .then_some(orchard_root),
        }
    }

    /// Removes the anchors a step added when it was sealed.
    pub fn unseal_step(&mut self, seal: StepSeal) {
        if let Some(root) = seal.sapling_root {
            self.sapling_anchors.remove(&root);
        }
        if let Some(root) = seal.orchard_root {
            self.orchard_anchors.remove(&root);
        }
    }

    /// Copies the trees and pool balances. The anchor sets are not copied; they change only by
    /// sealing and unsealing steps.
    pub fn snapshot(&self) -> ShieldedSnapshot {
        ShieldedSnapshot {
            sapling: self.sapling.clone(),
            orchard: self.orchard.clone(),
            sapling_pool: self.sapling_pool,
            orchard_pool: self.orchard_pool,
        }
    }

    /// Restores the trees and pool balances from a snapshot.
    pub fn restore(&mut self, snapshot: ShieldedSnapshot) {
        self.sapling = snapshot.sapling;
        self.orchard = snapshot.orchard;
        self.sapling_pool = snapshot.sapling_pool;
        self.orchard_pool = snapshot.orchard_pool;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volt_core::DevTx;

    fn arc(tx: DevTx) -> Arc<dyn BatchableTx> {
        Arc::new(tx)
    }

    fn block(txs: Vec<DevTx>) -> Vec<Vec<Arc<dyn BatchableTx>>> {
        vec![txs.into_iter().map(arc).collect()]
    }

    /// A transaction creating the given Sapling notes, shielding `value` into the pool.
    fn shield(nonce: u64, value: i64, notes: &[u64]) -> DevTx {
        DevTx::new(vec![], vec![], vec![], true, nonce).with_sapling(
            -value,
            vec![],
            notes.iter().map(|n| DevTx::commitment(*n)).collect(),
        )
    }

    /// A transaction spending a Sapling note against `anchor`, taking `value` out of the pool.
    fn unshield(nonce: u64, value: i64, anchor: [u8; 32]) -> DevTx {
        DevTx::new(vec![], vec![], vec![[nonce as u8; 32]], true, nonce).with_sapling(
            value,
            vec![anchor],
            vec![],
        )
    }

    #[test]
    fn the_empty_tree_roots_are_valid_anchors_from_genesis() {
        let state = ShieldedState::new();
        assert!(state.is_sapling_anchor(&state.sapling_root()));
        assert!(state.is_orchard_anchor(&state.orchard_root()));
        assert_eq!((state.sapling_notes(), state.orchard_notes()), (0, 0));
        assert_eq!((state.sapling_pool(), state.orchard_pool()), (0, 0));

        // A transaction that spends nothing needs no anchor and is fine.
        let mut state = state;
        state
            .apply_block(&block(vec![DevTx::new(vec![], vec![], vec![], false, 1)]))
            .unwrap();
    }

    #[test]
    fn a_new_root_is_not_an_anchor_until_its_step_is_sealed() {
        let mut state = ShieldedState::new();
        let empty = state.sapling_root();

        state
            .apply_block(&block(vec![shield(1, 1_000, &[1, 2])]))
            .unwrap();
        let after = state.sapling_root();
        assert_ne!(after, empty, "note commitments change the root");
        assert_eq!(state.sapling_notes(), 2);
        assert!(
            !state.is_sapling_anchor(&after),
            "a root is not an anchor until its step is sealed"
        );
        assert!(state.is_sapling_anchor(&empty), "earlier roots stay valid");

        let seal = state.seal_step();
        assert!(state.is_sapling_anchor(&after));

        // Undoing the seal removes exactly what it added.
        state.unseal_step(seal);
        assert!(!state.is_sapling_anchor(&after));
        assert!(state.is_sapling_anchor(&empty));
    }

    #[test]
    fn a_transaction_cannot_anchor_to_its_own_step() {
        let mut state = ShieldedState::new();
        state
            .apply_block(&block(vec![shield(1, 1_000, &[1])]))
            .unwrap();
        let same_step_root = state.sapling_root();

        // Same step (no seal yet): the new root is not valid, so this spend is refused.
        let result = state.apply_block(&block(vec![unshield(2, 500, same_step_root)]));
        assert!(
            matches!(result, Err(ShieldedError::UnknownSaplingAnchor { .. })),
            "got {result:?}"
        );

        // After sealing, the same spend is accepted.
        state.seal_step();
        state
            .apply_block(&block(vec![unshield(2, 500, same_step_root)]))
            .unwrap();
        assert_eq!(state.sapling_pool(), 500);
    }

    #[test]
    fn made_up_anchors_are_rejected_in_both_pools() {
        let mut state = ShieldedState::new();
        let fake = [0x42; 32];

        let result = state.apply_block(&block(vec![unshield(1, 0, fake)]));
        assert!(matches!(
            result,
            Err(ShieldedError::UnknownSaplingAnchor { anchor, .. }) if anchor == fake
        ));

        let orchard =
            DevTx::new(vec![], vec![], vec![], true, 2).with_orchard(0, Some(fake), vec![]);
        assert!(matches!(
            state.apply_block(&block(vec![orchard])),
            Err(ShieldedError::UnknownOrchardAnchor { .. })
        ));
    }

    #[test]
    fn the_turnstile_stops_more_value_leaving_a_pool_than_entered() {
        let mut state = ShieldedState::new();
        let empty = state.sapling_root();

        // Nothing has been shielded, so nothing can come out.
        let result = state.apply_block(&block(vec![unshield(1, 1, empty)]));
        assert!(matches!(
            result,
            Err(ShieldedError::PoolOverdrawn {
                pool: "Sapling",
                ..
            })
        ));

        // Shield 1_000, seal the step, then draw out more than that.
        state
            .apply_block(&block(vec![shield(2, 1_000, &[1])]))
            .unwrap();
        state.seal_step();
        let anchor = state.sapling_root();
        assert_eq!(state.sapling_pool(), 1_000);
        assert!(matches!(
            state.apply_block(&block(vec![unshield(3, 1_001, anchor)])),
            Err(ShieldedError::PoolOverdrawn { .. })
        ));
        // Exactly everything is fine, and leaves the pool empty.
        state
            .apply_block(&block(vec![unshield(4, 1_000, anchor)]))
            .unwrap();
        assert_eq!(state.sapling_pool(), 0);
    }

    #[test]
    fn the_turnstile_is_per_pool_so_one_pool_cannot_borrow_from_the_other() {
        let mut state = ShieldedState::new();
        // Shield 1_000 into Sapling, then try to take 1_000 out of Orchard.
        state
            .apply_block(&block(vec![shield(1, 1_000, &[])]))
            .unwrap();
        state.seal_step();
        let orchard_empty = state.orchard_root();
        let steal = DevTx::new(vec![], vec![], vec![], true, 2).with_orchard(
            1_000,
            Some(orchard_empty),
            vec![],
        );
        assert!(matches!(
            state.apply_block(&block(vec![steal])),
            Err(ShieldedError::PoolOverdrawn {
                pool: "Orchard",
                ..
            })
        ));
        assert_eq!(state.sapling_pool(), 1_000);
        assert_eq!(state.orchard_pool(), 0);
    }

    #[test]
    fn the_turnstile_is_checked_per_block_not_per_transaction() {
        let mut state = ShieldedState::new();
        let empty = state.sapling_root();
        // Within one block, a spend before the shield that funds it nets to zero. Zcash judges the
        // pool at the end of the block, and so does this.
        state
            .apply_block(&block(vec![unshield(1, 500, empty), shield(2, 500, &[7])]))
            .unwrap();
        assert_eq!(state.sapling_pool(), 0);
    }

    #[test]
    fn a_refused_block_changes_nothing() {
        let mut state = ShieldedState::new();
        state
            .apply_block(&block(vec![shield(1, 100, &[1])]))
            .unwrap();
        state.seal_step();
        let (sapling, orchard, pool, notes) = (
            state.sapling_root(),
            state.orchard_root(),
            state.sapling_pool(),
            state.sapling_notes(),
        );

        // The first transaction is fine and appends notes; the second has a bad anchor.
        let result = state.apply_block(&block(vec![
            shield(2, 50, &[10, 11, 12]),
            unshield(3, 1, [9; 32]),
        ]));
        assert!(result.is_err());

        assert_eq!(state.sapling_root(), sapling);
        assert_eq!(state.orchard_root(), orchard);
        assert_eq!(state.sapling_pool(), pool);
        assert_eq!(state.sapling_notes(), notes, "no note was appended");
    }

    #[test]
    fn an_invalid_note_commitment_is_refused() {
        let mut state = ShieldedState::new();
        // 0xff..ff is larger than either field's modulus, so it is not a valid commitment.
        let bad_sapling =
            DevTx::new(vec![], vec![], vec![], true, 1).with_sapling(0, vec![], vec![[0xff; 32]]);
        assert!(matches!(
            state.apply_block(&block(vec![bad_sapling])),
            Err(ShieldedError::InvalidCommitment {
                pool: "Sapling",
                ..
            })
        ));
        let bad_orchard =
            DevTx::new(vec![], vec![], vec![], true, 2).with_orchard(0, None, vec![[0xff; 32]]);
        assert!(matches!(
            state.apply_block(&block(vec![bad_orchard])),
            Err(ShieldedError::InvalidCommitment {
                pool: "Orchard",
                ..
            })
        ));
        assert_eq!(state.sapling_notes() + state.orchard_notes(), 0);
    }

    #[test]
    fn snapshots_restore_the_trees_and_pools_exactly() {
        let mut state = ShieldedState::new();
        state
            .apply_block(&block(vec![shield(1, 70, &[1, 2, 3])]))
            .unwrap();
        let snapshot = state.snapshot();
        let (root, notes, pool) = (
            state.sapling_root(),
            state.sapling_notes(),
            state.sapling_pool(),
        );

        state
            .apply_block(&block(vec![shield(2, 30, &[4, 5])]))
            .unwrap();
        assert_ne!(state.sapling_root(), root);

        state.restore(snapshot);
        assert_eq!(state.sapling_root(), root);
        assert_eq!(state.sapling_notes(), notes);
        assert_eq!(state.sapling_pool(), pool);

        // Appending the same notes again reproduces the same root: the trees are deterministic.
        state
            .apply_block(&block(vec![shield(2, 30, &[4, 5])]))
            .unwrap();
        let mut fresh = ShieldedState::new();
        fresh
            .apply_block(&block(vec![shield(1, 70, &[1, 2, 3])]))
            .unwrap();
        fresh
            .apply_block(&block(vec![shield(2, 30, &[4, 5])]))
            .unwrap();
        assert_eq!(state.sapling_root(), fresh.sapling_root());
    }

    #[test]
    fn note_order_matters_so_consensus_order_fixes_the_root() {
        let mut a = ShieldedState::new();
        a.apply_block(&block(vec![shield(1, 1, &[1, 2])])).unwrap();
        let mut b = ShieldedState::new();
        b.apply_block(&block(vec![shield(1, 1, &[2, 1])])).unwrap();
        assert_ne!(a.sapling_root(), b.sapling_root());
    }
}
