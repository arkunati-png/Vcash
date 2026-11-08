//! What a light wallet is told about the chain: steps in consensus order, from which it must be
//! able to rebuild the node's exact Sapling note commitment tree.
//!
//! The wallet side is a second tree, driven only by the step feed. If its root ever differs from
//! the node's, a wallet could not build a witness for its own notes, so these tests compare them
//! after every step, with parallel blocks merged in one step and across a reorg.

use std::sync::Arc;

use sapling_crypto::note::ExtractedNoteCommitment;
use volt_consensus::{difficulty, Consensus, ConsensusConfig, TemplateContext};
use volt_core::{BatchableTx, DevTx, DevTxDecoder, Economics, VoltBlock, VoltHash};
use volt_crypto::RandomXEngine;
use zebra_chain::{
    amount::Amount,
    parameters::NetworkKind,
    sapling,
    transparent::{Address, OutPoint, Output, Script},
};

const COINBASE_OUTPUT: i64 = 250_000;
const SHIELDED_FEE: i64 = 20_000;
const TRANSPARENT_FEE: i64 = 10_000;

fn new_consensus() -> Consensus {
    Consensus::new(
        Consensus::test_genesis_block(0),
        RandomXEngine::shared(),
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

fn mine_block(
    c: &Consensus,
    parents: &[VoltHash],
    txs: Vec<Arc<dyn BatchableTx>>,
    ts: u64,
) -> VoltBlock {
    let ctx = ctx_on(c, parents);
    let (batches, leftover) = Consensus::pack_batches(&txs).unwrap();
    assert_eq!(leftover, 0);
    let template = c.build_template(&ctx, batches, &miners(), ts).unwrap();
    c.mine(template, &ctx.seed, 0, u64::MAX).unwrap().unwrap()
}

fn push(c: &mut Consensus, ts: &mut u64, txs: Vec<Arc<dyn BatchableTx>>) -> VoltHash {
    *ts += 850;
    let tip = c.sink();
    let block = mine_block(c, &[tip], txs, *ts);
    let hash = block.hash();
    c.submit_block(block, *ts).unwrap();
    hash
}

fn out(value: i64, tag: u8) -> Output {
    Output::new(Amount::new(value), Script::new(&[tag]))
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

/// A shielding transaction first, then nine transparent fillers: one full batch.
fn shield_batch(outputs: &[OutPoint], notes: &[u64], nonce: u64) -> Vec<Arc<dyn BatchableTx>> {
    let amount = 10_000;
    let commitments = notes.iter().map(|n| DevTx::commitment(*n)).collect();
    let change = COINBASE_OUTPUT - amount * notes.len() as i64 - SHIELDED_FEE;
    let special = DevTx::new(vec![outputs[0]], vec![out(change, 2)], vec![], true, nonce)
        .with_sapling(-amount * notes.len() as i64, vec![], commitments);
    let mut txs: Vec<Arc<dyn BatchableTx>> = vec![Arc::new(special)];
    for (i, outpoint) in outputs[1..].iter().enumerate() {
        txs.push(Arc::new(DevTx::new(
            vec![*outpoint],
            vec![out(COINBASE_OUTPUT - TRANSPARENT_FEE, 1)],
            vec![],
            false,
            nonce * 100 + i as u64,
        )));
    }
    assert_eq!(txs.len(), 10);
    txs
}

/// A wallet's view of the Sapling tree, driven only by the step feed.
struct Replica {
    tree: sapling::tree::NoteCommitmentTree,
}

impl Replica {
    /// Replays every step the node reports and checks the root after each one. Returns the
    /// replica and the number of notes seen.
    fn scan(c: &Consensus) -> (Self, u64) {
        let mut replica = Self {
            tree: sapling::tree::NoteCommitmentTree::default(),
        };
        let mut notes = 0u64;
        let mut last_root = <[u8; 32]>::from(replica.tree.root());
        let views = c.step_views(0, usize::MAX);
        for view in &views {
            for hash in &view.accepted {
                let batches = c.block_txs(hash).expect("an accepted block has a body");
                for tx in batches.iter().flatten() {
                    for bytes in tx.sapling_commitment_bytes() {
                        let cmu = Option::from(ExtractedNoteCommitment::from_bytes(&bytes))
                            .expect("the node accepted this commitment");
                        replica.tree.append(cmu).expect("room in the tree");
                        notes += 1;
                    }
                }
            }
            last_root = <[u8; 32]>::from(replica.tree.root());
            assert_eq!(
                last_root, view.sapling_root,
                "step {}: the wallet's root differs from the node's",
                view.index
            );
            assert_eq!(notes, view.sapling_notes, "step {} note count", view.index);
        }
        assert_eq!(c.step_count(), views.len());
        assert_eq!(last_root, c.shielded().sapling_root());
        (replica, notes)
    }
}

fn funded() -> (Consensus, u64, Vec<VoltHash>) {
    let mut c = new_consensus();
    let mut ts = 0;
    let blocks: Vec<VoltHash> = (0..6).map(|_| push(&mut c, &mut ts, vec![])).collect();
    (c, ts, blocks)
}

#[test]
fn a_wallet_rebuilds_the_node_tree_from_parallel_blocks() {
    let (mut c, mut ts, funding) = funded();
    let (o1, o2, o3) = (
        coinbase_outpoints(&c, &funding[0]),
        coinbase_outpoints(&c, &funding[1]),
        coinbase_outpoints(&c, &funding[2]),
    );
    let (_, notes) = Replica::scan(&c);
    assert_eq!(notes, 0, "nothing shielded yet");

    // Two sibling blocks, each shielding notes, merged by one chain step.
    let tips = c.dag().select_parents();
    assert_eq!(tips.len(), 1);
    ts += 850;
    let y = mine_block(&c, &tips, shield_batch(&o1, &[1, 2], 1), ts);
    let z = mine_block(&c, &tips, shield_batch(&o2, &[3], 2), ts + 1);
    c.submit_block(y, ts).unwrap();
    c.submit_block(z, ts + 1).unwrap();
    let tips = c.dag().select_parents();
    assert_eq!(tips.len(), 2, "Y and Z are parallel");
    ts += 850;
    let merge = mine_block(&c, &tips, vec![], ts + 2);
    let report = c.submit_block(merge, ts + 2).unwrap().chain.unwrap();
    assert!(report.rejected.is_empty());

    // The merge step holds both blocks, in a fixed order.
    let views = c.step_views(0, usize::MAX);
    let merged = views.last().unwrap();
    assert_eq!(merged.sapling_notes, 3, "{merged:?}");
    // A chain block applies in the next step, so this step holds the two parallel blocks.
    assert_eq!(merged.accepted.len(), 2);
    let (_, notes) = Replica::scan(&c);
    assert_eq!(notes, 3);

    // More shielding after that, then a later block merges it.
    push(&mut c, &mut ts, shield_batch(&o3, &[4, 5], 3));
    push(&mut c, &mut ts, vec![]);
    let (replica, notes) = Replica::scan(&c);
    assert_eq!(notes, 5);
    assert_eq!(
        <[u8; 32]>::from(replica.tree.root()),
        c.shielded().sapling_root()
    );
}

#[test]
fn the_feed_follows_a_reorg_and_the_wallet_still_matches() {
    let (mut c, mut ts, funding) = funded();
    let o1 = coinbase_outpoints(&c, &funding[0]);
    let fork_point = *funding.last().unwrap();

    // The main branch shields two notes.
    push(&mut c, &mut ts, shield_batch(&o1, &[1, 2], 1));
    push(&mut c, &mut ts, vec![]);
    let (_, notes) = Replica::scan(&c);
    assert_eq!(notes, 2);
    let old_steps = c.step_views(0, usize::MAX);

    // A heavier branch from before the shielding carries no notes at all. It is shallow enough
    // to be allowed, so state moves onto it and the notes disappear.
    let mut tip = fork_point;
    let mut fork_ts = ts;
    for _ in 0..6 {
        fork_ts += 850;
        let block = mine_block(&c, &[tip], vec![], fork_ts);
        tip = block.hash();
        c.submit_block(block, fork_ts).unwrap();
    }
    let new_steps = c.step_views(0, usize::MAX);
    assert_ne!(
        old_steps.last().unwrap().block,
        new_steps.last().unwrap().block,
        "the chain switched branches"
    );
    assert_eq!(
        c.shielded().sapling_notes(),
        0,
        "the shielded notes were undone"
    );

    // The wallet, rescanning, matches the new chain at every step.
    let (_, notes) = Replica::scan(&c);
    assert_eq!(notes, 0);
}
