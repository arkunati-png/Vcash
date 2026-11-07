//! A node that is stopped and restarted comes back to exactly the same state.

use std::{fs::OpenOptions, path::Path, sync::Arc};

use volt_consensus::{Consensus, ConsensusConfig};
use volt_core::{DevTxDecoder, Economics, VoltBlock};
use volt_crypto::Blake2bPowHasher;
use volt_storage::{PersistentConsensus, StorageError, SyncPolicy};
use zebra_chain::{parameters::NetworkKind, transparent::Address};

fn config() -> ConsensusConfig {
    ConsensusConfig::devnet().with_economics(Economics::fifty_fifty())
}

fn open(path: &Path) -> Result<PersistentConsensus, StorageError> {
    PersistentConsensus::open(
        path,
        Consensus::genesis_block(0),
        Arc::new(Blake2bPowHasher),
        Arc::new(DevTxDecoder),
        config(),
        SyncPolicy::Always,
    )
    .map(|(node, _)| node)
}

fn miners() -> Vec<Address> {
    (0..4)
        .map(|i| Address::from_pub_key_hash(NetworkKind::Regtest, [i; 20]))
        .collect()
}

/// Mines `count` empty blocks on top of the current tips.
fn mine(node: &mut PersistentConsensus, count: u64, ts: &mut u64) -> Vec<VoltBlock> {
    let mut blocks = Vec::new();
    for _ in 0..count {
        let ctx = node.consensus().template_context();
        *ts += 500;
        let template = node
            .consensus()
            .build_template(&ctx, vec![], &miners(), *ts)
            .unwrap();
        let block = node
            .consensus()
            .mine(template, &ctx.seed, 0, u64::MAX)
            .unwrap()
            .unwrap();
        node.submit_block(block.clone(), *ts).unwrap();
        blocks.push(block);
    }
    blocks
}

struct Snapshot {
    sink: volt_core::VoltHash,
    dag_blocks: usize,
    accepted: u64,
    utxos: usize,
    nullifiers: usize,
    locked: i64,
    epoch_blocks: u64,
}

fn snapshot(node: &PersistentConsensus) -> Snapshot {
    let c = node.consensus();
    Snapshot {
        sink: c.sink(),
        dag_blocks: c.dag().len(),
        accepted: c.accepted_blocks(),
        utxos: c.utxos().len(),
        nullifiers: c.utxos().nullifier_count(),
        locked: c.reserve().locked().zatoshis(),
        epoch_blocks: c.epoch().blocks(),
    }
}

fn assert_same(a: &Snapshot, b: &Snapshot) {
    assert_eq!(a.sink, b.sink);
    assert_eq!(a.dag_blocks, b.dag_blocks);
    assert_eq!(a.accepted, b.accepted);
    assert_eq!(a.utxos, b.utxos);
    assert_eq!(a.nullifiers, b.nullifiers);
    assert_eq!(a.locked, b.locked);
    assert_eq!(a.epoch_blocks, b.epoch_blocks);
}

#[test]
fn a_restarted_node_has_the_same_dag_state_and_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.log");

    // Enough blocks to complete and lock an epoch (200 accepted + 50 steps of finality).
    let before = {
        let mut node = open(&path).unwrap();
        let mut ts = 0;
        mine(&mut node, 260, &mut ts);
        let s = snapshot(&node);
        assert_eq!(node.consensus().reserve().settlements().len(), 1);
        s
    };

    let after = open(&path).unwrap();
    assert_same(&before, &snapshot(&after));
    assert_eq!(after.consensus().reserve().settlements().len(), 1);
}

#[test]
fn a_restarted_node_keeps_working() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.log");
    let mut ts = 0;

    {
        let mut node = open(&path).unwrap();
        mine(&mut node, 20, &mut ts);
    }
    let mut node = open(&path).unwrap();
    let accepted = node.consensus().accepted_blocks();
    mine(&mut node, 10, &mut ts);
    assert_eq!(node.consensus().accepted_blocks(), accepted + 10);

    // And a second restart sees all 30.
    let blocks = node.consensus().dag().len();
    drop(node);
    assert_eq!(open(&path).unwrap().consensus().dag().len(), blocks);
}

#[test]
fn a_crash_that_tears_the_last_block_loses_only_that_block() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.log");
    let mut ts = 0;

    let blocks_before_last = {
        let mut node = open(&path).unwrap();
        mine(&mut node, 9, &mut ts);
        let count = node.consensus().dag().len();
        mine(&mut node, 1, &mut ts);
        count
    };

    // Simulate a crash mid-write: the file ends part-way through the last block.
    let length = std::fs::metadata(&path).unwrap().len();
    OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(length - 20)
        .unwrap();

    let node = open(&path).unwrap();
    assert_eq!(node.consensus().dag().len(), blocks_before_last);
}

#[test]
fn invalid_blocks_never_reach_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.log");
    let mut ts = 0;
    let mut node = open(&path).unwrap();
    let blocks = mine(&mut node, 3, &mut ts);
    let length = std::fs::metadata(&path).unwrap().len();

    // Re-submitting a known block, and submitting an unmined one, are both rejected.
    assert!(node.submit_block(blocks[0].clone(), ts).is_err());
    let ctx = node.consensus().template_context();
    let unmined = node
        .consensus()
        .build_template(&ctx, vec![], &miners(), ts + 500)
        .unwrap();
    assert!(node.submit_block(unmined, ts + 500).is_err());

    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        length,
        "the log is unchanged"
    );
    drop(node);
    assert_eq!(open(&path).unwrap().consensus().dag().len(), 4);
}

#[test]
fn replay_revalidates_so_a_forged_log_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.log");
    let mut ts = 0;

    // Mine under flat economics, then try to replay under the production schedule: the
    // coinbases no longer match the rules, so replay must refuse rather than trust the file.
    {
        let mut node = open(&path).unwrap();
        mine(&mut node, 3, &mut ts);
    }
    let result = PersistentConsensus::open(
        &path,
        Consensus::genesis_block(0),
        Arc::new(Blake2bPowHasher),
        Arc::new(DevTxDecoder),
        ConsensusConfig::devnet(), // mainnet economics: 70/30
        SyncPolicy::Never,
    );
    assert!(matches!(
        result,
        Err(StorageError::ReplayRejected { index: 0, .. })
    ));
}

#[test]
fn a_log_from_another_network_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.log");
    {
        let mut node = open(&path).unwrap();
        mine(&mut node, 1, &mut 0);
    }

    // A different genesis timestamp is a different network.
    let result = PersistentConsensus::open(
        &path,
        Consensus::genesis_block(12345),
        Arc::new(Blake2bPowHasher),
        Arc::new(DevTxDecoder),
        config(),
        SyncPolicy::Never,
    );
    assert!(matches!(
        result,
        Err(StorageError::Log(
            volt_storage::LogError::WrongGenesis { .. }
        ))
    ));
}
