//! The shielded rules against genuine mainnet transactions.
//!
//! These check that the anchors, note commitments and pool values the node reads out of real
//! Zcash transactions are encoded the way the note commitment trees expect.

use std::sync::Arc;

use volt_core::BatchableTx;
use volt_state::{ShieldedError, ShieldedState};
use zebra_chain::{
    block::Block,
    serialization::{ZcashDeserializeInto, ZcashSerialize},
    transaction::Transaction,
};
use zebra_test::vectors::MAINNET_BLOCKS;

fn transactions(heights: &[u32]) -> Vec<Transaction> {
    heights
        .iter()
        .filter_map(|h| MAINNET_BLOCKS.get(h))
        .flat_map(|bytes| {
            let block: Block = bytes.zcash_deserialize_into().expect("vectors are valid");
            block
                .transactions
                .iter()
                .map(|tx| {
                    tx.zcash_serialize_to_vec()
                        .expect("serializes")
                        .zcash_deserialize_into::<Transaction>()
                        .expect("round-trips")
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn the_first_real_orchard_transactions_anchor_to_the_empty_tree_root() {
    // Block 1687107 holds the first Sapling-to-Orchard transaction on mainnet. The Orchard tree
    // was empty until that block, so every Orchard bundle in it can only anchor to the empty
    // tree's root. If the node read anchors out in a different byte encoding than its tree uses,
    // this would not match.
    let state = ShieldedState::new();
    let orchard: Vec<Transaction> = transactions(&[1_687_107])
        .into_iter()
        .filter(|tx| tx.has_orchard_shielded_data())
        .collect();
    assert!(!orchard.is_empty(), "the vector has an Orchard transaction");

    for tx in &orchard {
        let anchor = tx
            .orchard_anchor_root()
            .expect("an Orchard bundle has an anchor");
        assert_eq!(
            anchor,
            state.orchard_root(),
            "a real Orchard anchor must equal the empty tree root"
        );
        assert!(state.is_orchard_anchor(&anchor));
    }
}

#[test]
fn real_sapling_spends_against_an_unknown_tree_are_refused() {
    // A real Sapling spend names the mainnet tree's root at some height. A node that has not built
    // that tree must not accept it: this is exactly the forged-anchor attack, using a real anchor.
    let state = ShieldedState::new();
    let spend = transactions(&[1_687_106, 1_687_107, 1_687_108, 1_687_113])
        .into_iter()
        .find(|tx| !tx.sapling_anchor_roots().is_empty())
        .expect("the vectors contain a Sapling spend");

    assert!(matches!(
        state.check_anchors(&spend),
        Err(ShieldedError::UnknownSaplingAnchor { .. })
    ));

    // And the block-level rule agrees.
    let mut state = ShieldedState::new();
    let tx: Arc<dyn BatchableTx> = Arc::new(spend);
    assert!(state.apply_block(&[vec![tx]]).is_err());
}

#[test]
fn sprout_transactions_are_refused_as_an_untracked_pool() {
    // Block 396 holds the first JoinSplit. Nothing here tracks the Sprout pool, so value could be
    // created in it without limit: such a transaction must be refused outright.
    let sprout = transactions(&[396])
        .into_iter()
        .find(|tx| tx.has_sprout_joinsplit_data())
        .expect("block 396 has a JoinSplit transaction");
    assert!(sprout.has_unsupported_shielded_data());
    assert!(matches!(
        ShieldedState::new().check_anchors(&sprout),
        Err(ShieldedError::UnsupportedPool(_))
    ));
}

#[test]
fn what_the_node_reads_from_a_real_transaction_matches_zebras_own_accessors() {
    let heights = [
        1_687_106, 1_687_107, 1_687_108, 1_687_113, 1_687_118, 1_687_121,
    ];
    let txs = transactions(&heights);
    let mut sapling_seen = 0;
    let mut orchard_seen = 0;

    for tx in &txs {
        // Commitments: one per Sapling output and one per Orchard action.
        assert_eq!(
            tx.sapling_commitment_bytes().len(),
            tx.sapling_outputs().count()
        );
        assert_eq!(
            tx.orchard_commitment_bytes().len(),
            tx.orchard_actions().count()
        );

        // Pool values agree with Zebra's own amounts, and the wide total is their exact sum.
        let sapling = tx.sapling_value_balance().sapling_amount().zatoshis();
        let orchard = tx.orchard_value_balance().orchard_amount().zatoshis();
        assert_eq!(BatchableTx::sapling_value_out(tx), sapling);
        assert_eq!(BatchableTx::orchard_value_out(tx), orchard);
        assert_eq!(
            BatchableTx::shielded_value_out(tx),
            i128::from(sapling) + i128::from(orchard)
        );

        // Anchors: the Sapling anchors are exactly Zebra's deduplicated roots.
        let ours = tx.sapling_anchor_roots();
        let zebras: Vec<[u8; 32]> = Transaction::sapling_anchors(tx)
            .into_iter()
            .map(<[u8; 32]>::from)
            .collect();
        assert_eq!(ours, zebras);

        sapling_seen += tx.sapling_commitment_bytes().len();
        orchard_seen += tx.orchard_commitment_bytes().len();
    }
    assert!(
        sapling_seen > 0 && orchard_seen > 0,
        "the vectors exercise both pools"
    );
}

#[test]
fn real_note_commitments_are_valid_tree_leaves() {
    // Every note commitment in the real vectors must be accepted as a leaf by the trees, in both
    // pools. Apply them through output-only transactions (no anchors needed).
    let mut state = ShieldedState::new();
    let heights = [
        1_687_106, 1_687_107, 1_687_108, 1_687_113, 1_687_118, 1_687_121,
    ];
    let txs = transactions(&heights);

    let mut sapling = 0u64;
    let mut orchard = 0u64;
    for tx in &txs {
        // Strip anchors by checking commitments alone through a stand-in with the same leaves.
        for bytes in tx.sapling_commitment_bytes() {
            let leaf: Arc<dyn BatchableTx> = Arc::new(
                volt_core::DevTx::new(vec![], vec![], vec![], true, sapling).with_sapling(
                    0,
                    vec![],
                    vec![bytes],
                ),
            );
            state
                .apply_block(&[vec![leaf]])
                .expect("a real Sapling commitment is a valid leaf");
            sapling += 1;
        }
        for bytes in tx.orchard_commitment_bytes() {
            let leaf: Arc<dyn BatchableTx> = Arc::new(
                volt_core::DevTx::new(vec![], vec![], vec![], true, 1_000_000 + orchard)
                    .with_orchard(0, None, vec![bytes]),
            );
            state
                .apply_block(&[vec![leaf]])
                .expect("a real Orchard commitment is a valid leaf");
            orchard += 1;
        }
    }
    assert_eq!(state.sapling_notes(), sapling);
    assert_eq!(state.orchard_notes(), orchard);
    assert!(sapling > 0 && orchard > 0);
}
