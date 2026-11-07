//! Shielded-pool rules enforced end to end through the consensus engine.
//!
//! These use `DevTx`, which declares its anchors, note commitments and pool values, so what is
//! being tested is the node's bookkeeping: commitment trees, anchors and the turnstile.

use std::sync::Arc;

use volt_consensus::{difficulty, Consensus, ConsensusConfig, TemplateContext};
use volt_core::{BatchableTx, DevTx, DevTxDecoder, Economics, VoltBlock, VoltHash};
use volt_crypto::Blake2bPowHasher;
use volt_state::{ShieldedError, StateError};
use zebra_chain::{
    amount::Amount,
    parameters::NetworkKind,
    transparent::{Address, OutPoint, Output, Script},
};

const COINBASE_OUTPUT: i64 = 250_000; // 2.5M miner half under fifty-fifty, over 10 payouts
const TRANSPARENT_FEE: i64 = 10_000;
const SHIELDED_FEE: i64 = 20_000;

fn new_consensus() -> Consensus {
    Consensus::new(
        Consensus::genesis_block(0),
        Arc::new(Blake2bPowHasher),
        Arc::new(DevTxDecoder),
        ConsensusConfig::devnet().with_economics(Economics::fifty_fifty()),
    )
    .unwrap()
}

fn miners() -> Vec<Address> {
    (0..10)
        .map(|i| Address::from_pub_key_hash(NetworkKind::Regtest, [i; 20]))
        .collect()
}

fn ctx_on(c: &Consensus, parents: &[VoltHash]) -> TemplateContext {
    let selected = c.dag().select_parent(parents);
    TemplateContext {
        parents: parents.to_vec(),
        bits: difficulty::next_bits(c.dag(), &selected),
        seed: difficulty::pow_seed(c.dag(), &selected),
        min_timestamp_ms: parents
            .iter()
            .map(|p| c.dag().get(p).unwrap().timestamp_ms)
            .max()
            .unwrap(),
        reward_score: c.dag().get(&selected).unwrap().ghostdag.blue_score,
    }
}

/// Mines a block on `parents` carrying `txs`, packed into rollup batches of ten.
fn mine_block(
    c: &Consensus,
    parents: &[VoltHash],
    txs: Vec<Arc<dyn BatchableTx>>,
    ts: u64,
) -> VoltBlock {
    let ctx = ctx_on(c, parents);
    let (batches, leftover) = Consensus::pack_batches(&txs).unwrap();
    assert_eq!(leftover, 0, "transactions must fill whole batches of ten");
    let template = c.build_template(&ctx, batches, &miners(), ts).unwrap();
    c.mine(template, &ctx.seed, 0, u64::MAX).unwrap().unwrap()
}

/// Mines and submits a block on the current best tip, returning its hash and what it changed.
fn push(
    c: &mut Consensus,
    ts: &mut u64,
    txs: Vec<Arc<dyn BatchableTx>>,
) -> (VoltHash, volt_consensus::SubmitOutcome) {
    *ts += 500;
    let tip = c.sink();
    let block = mine_block(c, &[tip], txs, *ts);
    let hash = block.hash();
    let outcome = c.submit_block(block, *ts).unwrap();
    (hash, outcome)
}

fn out(value: i64, tag: u8) -> Output {
    Output::new(Amount::new(value), Script::new(&[tag]))
}

fn filler(outpoint: OutPoint, nonce: u64) -> Arc<dyn BatchableTx> {
    Arc::new(DevTx::new(
        vec![outpoint],
        vec![out(COINBASE_OUTPUT - TRANSPARENT_FEE, 1)],
        vec![],
        false,
        nonce,
    ))
}

/// Nine transparent fillers spending `outputs[1..]`, plus `special` first, to make a batch of ten.
fn batch_of(special: DevTx, outputs: &[OutPoint], nonce_base: u64) -> Vec<Arc<dyn BatchableTx>> {
    let mut txs: Vec<Arc<dyn BatchableTx>> = vec![Arc::new(special)];
    for (i, outpoint) in outputs[1..].iter().enumerate() {
        txs.push(filler(*outpoint, nonce_base + i as u64));
    }
    assert_eq!(txs.len(), 10);
    txs
}

fn coinbase_outpoints(c: &Consensus, hash: &VoltHash) -> Vec<OutPoint> {
    c.block(hash)
        .unwrap()
        .coinbase
        .outputs()
        .into_iter()
        .map(|(outpoint, _)| outpoint)
        .collect()
}

/// A shielding transaction: spends `input`, puts `amount` into the Sapling pool as `note`.
fn shield(input: OutPoint, amount: i64, note: u64, nonce: u64) -> DevTx {
    let change = COINBASE_OUTPUT - amount - SHIELDED_FEE;
    DevTx::new(vec![input], vec![out(change, 2)], vec![], true, nonce).with_sapling(
        -amount,
        vec![],
        vec![DevTx::commitment(note)],
    )
}

/// An unshielding transaction: spends a note against `anchor` and pays `amount` out of the pool.
fn unshield(amount: i64, anchor: [u8; 32], nullifier: u8, nonce: u64) -> DevTx {
    DevTx::new(
        vec![],
        vec![out(amount - SHIELDED_FEE, 3)],
        vec![[nullifier; 32]],
        true,
        nonce,
    )
    .with_sapling(amount, vec![anchor], vec![])
}

/// Mines funding blocks and returns the engine, the clock, and the outputs of two funded blocks.
fn funded() -> (Consensus, u64, Vec<OutPoint>, Vec<OutPoint>) {
    let mut c = new_consensus();
    let mut ts = 0;
    let (b1, _) = push(&mut c, &mut ts, vec![]);
    let (b2, _) = push(&mut c, &mut ts, vec![]);
    push(&mut c, &mut ts, vec![]);
    let (o1, o2) = (coinbase_outpoints(&c, &b1), coinbase_outpoints(&c, &b2));
    (c, ts, o1, o2)
}

#[test]
fn shielding_then_unshielding_through_a_valid_anchor_works() {
    let (mut c, mut ts, o1, o2) = funded();
    assert_eq!(c.shielded().sapling_notes(), 0);
    let empty_root = c.shielded().sapling_root();

    // Shield 100_000 and create a note.
    let shield_tx = shield(o1[0], 100_000, 1, 1);
    let (shield_block, _) = push(&mut c, &mut ts, batch_of(shield_tx, &o1, 100));
    // A block takes effect when a later chain block merges it, so merge it with an empty block.
    let (_, merged) = push(&mut c, &mut ts, vec![]);
    assert!(merged.chain.as_ref().unwrap().rejected.is_empty());
    assert!(c.block(&shield_block).is_some());

    assert_eq!(c.shielded().sapling_notes(), 1);
    assert_eq!(c.shielded().sapling_pool(), 100_000);
    let root = c.shielded().sapling_root();
    assert_ne!(root, empty_root, "the note changed the tree");
    assert!(
        c.shielded().is_sapling_anchor(&root),
        "a sealed step's root is a valid anchor"
    );

    // Unshield against that anchor.
    let unshield_tx = unshield(100_000, root, 7, 2);
    let probe: Arc<dyn BatchableTx> = Arc::new(unshield_tx.clone());
    c.check_tx_anchors(probe.as_ref())
        .expect("the mempool check accepts a valid anchor");
    let created = OutPoint::from_usize(zebra_chain::transaction::Hash(probe.txid().0), 0);
    push(&mut c, &mut ts, batch_of(unshield_tx, &o2, 200));
    let (_, merged) = push(&mut c, &mut ts, vec![]);

    assert!(merged.chain.as_ref().unwrap().rejected.is_empty());
    assert_eq!(c.shielded().sapling_pool(), 0, "the pool is empty again");
    assert!(c.utxos().has_nullifier(&[7; 32]));
    assert!(c.utxos().contains(&created), "the unshielded output exists");
}

#[test]
fn a_spend_against_a_forged_anchor_is_rejected_whole() {
    let (mut c, mut ts, o1, o2) = funded();
    push(
        &mut c,
        &mut ts,
        batch_of(shield(o1[0], 100_000, 1, 1), &o1, 100),
    );
    push(&mut c, &mut ts, vec![]);
    let pool_before = c.shielded().sapling_pool();
    let notes_before = c.shielded().sapling_notes();
    let utxos_before = c.utxos().len();

    // A spend proven against a tree the spender made up.
    let forged = unshield(100_000, [0x42; 32], 9, 3);
    let probe: Arc<dyn BatchableTx> = Arc::new(forged.clone());
    assert!(matches!(
        c.check_tx_anchors(probe.as_ref()),
        Err(ShieldedError::UnknownSaplingAnchor { .. })
    ));

    push(&mut c, &mut ts, batch_of(forged, &o2, 300));
    let (_, merged) = push(&mut c, &mut ts, vec![]);
    let report = merged.chain.unwrap();

    assert_eq!(report.rejected.len(), 1);
    assert!(
        matches!(
            report.rejected[0].1,
            StateError::Shielded(ShieldedError::UnknownSaplingAnchor { .. })
        ),
        "{:?}",
        report.rejected[0].1
    );
    // Nothing from the rejected block took effect: not the pool, not the nullifier, and not even
    // the transparent fillers that shared its batch.
    assert_eq!(c.shielded().sapling_pool(), pool_before);
    assert_eq!(c.shielded().sapling_notes(), notes_before);
    assert!(!c.utxos().has_nullifier(&[9; 32]));
    for outpoint in &o2[1..] {
        assert!(c.utxos().contains(outpoint), "fillers were not spent");
    }
    assert!(c.utxos().len() > utxos_before - 1);
}

#[test]
fn a_transaction_cannot_spend_a_note_created_in_its_own_step() {
    let (mut c, mut ts, _o1, o2) = funded();
    // Fund a third set of outputs, so the spending block has valid fillers of its own.
    let (b4, _) = push(&mut c, &mut ts, vec![]);
    push(&mut c, &mut ts, vec![]);
    let o3 = coinbase_outpoints(&c, &b4);
    assert_eq!(c.shielded().sapling_notes(), 0);

    // Y creates note 1. The root that results is what Z will try to spend against.
    let mut after_y = ShieldedPreview::of(&c);
    after_y.add_note(1);
    let root_after_y = after_y.root();
    assert_ne!(root_after_y, c.shielded().sapling_root());

    // Y and Z are siblings on the same tips, so one chain step merges both. Whichever of them is
    // applied first, the root Y produces is not a valid anchor until that step is sealed.
    let tips = c.dag().select_parents();
    ts += 500;
    let y = mine_block(
        &c,
        &tips,
        batch_of(shield(o2[0], 50_000, 1, 1), &o2, 600),
        ts,
    );
    let z = mine_block(
        &c,
        &tips,
        batch_of(unshield(50_000, root_after_y, 5, 2), &o3, 700),
        ts + 1,
    );
    c.submit_block(y, ts).unwrap();
    c.submit_block(z, ts + 1).unwrap();

    let tips = c.dag().select_parents();
    assert_eq!(tips.len(), 2, "Y and Z are parallel tips");
    ts += 500;
    let merge = mine_block(&c, &tips, vec![], ts + 2);
    let outcome = c.submit_block(merge, ts + 2).unwrap();
    let report = outcome.chain.unwrap();

    // Exactly one block is rejected, for the reason under test: an anchor that is not valid.
    assert_eq!(report.rejected.len(), 1, "{:?}", report.rejected);
    assert!(
        matches!(
            report.rejected[0].1,
            StateError::Shielded(ShieldedError::UnknownSaplingAnchor { .. })
        ),
        "{:?}",
        report.rejected[0].1
    );
    // Y was applied: its note exists and its fillers are spent.
    assert_eq!(c.shielded().sapling_notes(), 1);
    assert_eq!(c.shielded().sapling_pool(), 50_000);
    for outpoint in &o2 {
        assert!(!c.utxos().contains(outpoint), "Y's inputs were spent");
    }
    // Z was rejected whole: its nullifier is unrevealed and its fillers are still unspent.
    assert!(!c.utxos().has_nullifier(&[5; 32]));
    for outpoint in &o3[1..] {
        assert!(c.utxos().contains(outpoint), "Z's fillers were not spent");
    }
}
/// A throwaway copy of the shielded trees, to compute what a root would be after more notes.
struct ShieldedPreview {
    state: volt_state::ShieldedState,
}

impl ShieldedPreview {
    fn of(c: &Consensus) -> Self {
        // Rebuild by replaying the notes: the tests only ever add small numbered notes.
        let mut state = volt_state::ShieldedState::new();
        let notes = c.shielded().sapling_notes();
        for n in 1..=notes {
            Self::append(&mut state, n);
        }
        Self { state }
    }

    fn append(state: &mut volt_state::ShieldedState, note: u64) {
        let tx: Arc<dyn BatchableTx> =
            Arc::new(DevTx::new(vec![], vec![], vec![], true, note).with_sapling(
                0,
                vec![],
                vec![DevTx::commitment(note)],
            ));
        state.apply_block(&[vec![tx]]).unwrap();
    }

    fn add_note(&mut self, note: u64) {
        Self::append(&mut self.state, note);
    }

    fn root(&self) -> [u8; 32] {
        self.state.sapling_root()
    }
}

#[test]
fn the_turnstile_rejects_drawing_out_more_than_was_shielded() {
    let (mut c, mut ts, o1, o2) = funded();
    push(
        &mut c,
        &mut ts,
        batch_of(shield(o1[0], 100_000, 1, 1), &o1, 100),
    );
    push(&mut c, &mut ts, vec![]);
    let root = c.shielded().sapling_root();

    // The pool holds 100_000; try to take 100_001 out with a perfectly valid anchor.
    push(
        &mut c,
        &mut ts,
        batch_of(unshield(100_001, root, 8, 3), &o2, 500),
    );
    let (_, merged) = push(&mut c, &mut ts, vec![]);
    let report = merged.chain.unwrap();

    assert_eq!(report.rejected.len(), 1);
    assert!(
        matches!(
            report.rejected[0].1,
            StateError::Shielded(ShieldedError::PoolOverdrawn {
                pool: "Sapling",
                ..
            })
        ),
        "{:?}",
        report.rejected[0].1
    );
    assert_eq!(
        c.shielded().sapling_pool(),
        100_000,
        "the pool is unchanged"
    );
    assert!(!c.utxos().has_nullifier(&[8; 32]));
}

#[test]
fn a_reorg_restores_the_trees_pools_and_anchors_exactly() {
    let (mut c, mut ts, o1, _) = funded();
    let base = c.sink();
    let empty_root = c.shielded().sapling_root();
    let accepted_before = c.accepted_blocks();

    // Branch A: a block that shields, then one that merges it.
    ts += 500;
    let a1 = mine_block(
        &c,
        &[base],
        batch_of(shield(o1[0], 100_000, 1, 1), &o1, 100),
        ts,
    );
    let a1_hash = a1.hash();
    c.submit_block(a1, ts).unwrap();
    ts += 500;
    let a2 = mine_block(&c, &[a1_hash], vec![], ts);
    c.submit_block(a2, ts).unwrap();

    assert_eq!(c.shielded().sapling_notes(), 1);
    assert_eq!(c.shielded().sapling_pool(), 100_000);
    let root_on_a = c.shielded().sapling_root();
    assert!(c.shielded().is_sapling_anchor(&root_on_a));

    // Branch B from the same base, with no shielding and heavier than A.
    let mut tip = base;
    let mut reorgs = 0;
    for _ in 0..4 {
        ts += 500;
        let block = mine_block(&c, &[tip], vec![], ts);
        tip = block.hash();
        let outcome = c.submit_block(block, ts).unwrap();
        reorgs += outcome.chain.map_or(0, |r| r.reverted_steps);
    }
    assert!(reorgs > 0, "branch B overtook branch A");

    // The shielding is gone: trees, pool and the anchor it made valid.
    assert_eq!(c.shielded().sapling_notes(), 0);
    assert_eq!(c.shielded().sapling_pool(), 0);
    assert_eq!(c.shielded().sapling_root(), empty_root);
    assert!(!c.shielded().is_sapling_anchor(&root_on_a));
    assert!(c.shielded().is_sapling_anchor(&empty_root));
    assert!(
        c.accepted_blocks() >= accepted_before,
        "the heavier branch kept going"
    );
}
