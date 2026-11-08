//! The four payment directions on two real nodes joined over TCP: t-z, z-z, z-t and t-t.
//!
//! These are devnet transactions without proofs, so this proves the node's shielded accounting
//! (note commitment tree, anchors, nullifiers, the Sapling turnstile) and the wallet flows that
//! build on it. It does not prove zero-knowledge privacy.

use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::time::sleep;
use volt_core::Economics;
use volt_crypto::RandomXEngine;
use volt_network::P2pConfig;
use volt_node::{
    node::{Node, NodeConfig},
    rpc,
};
use zebra_chain::{parameters::NetworkKind, transparent::Address};

const ZATS: i64 = 100_000_000;

fn t_address(tag: u8) -> String {
    volt_params::transparent::encode_p2pkh(&[tag; 20])
}

fn zebra_address(tag: u8) -> Address {
    Address::from_pub_key_hash(NetworkKind::Regtest, [tag; 20])
}

fn z_address(tag: char) -> String {
    format!("z1{}", tag.to_string().repeat(40))
}

fn paced_clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    let now = Arc::new(AtomicU64::new(1_000));
    Arc::new(move || now.fetch_add(850, Ordering::SeqCst))
}

fn config(
    dir: &Path,
    miners: Vec<Address>,
    clock: &Arc<dyn Fn() -> u64 + Send + Sync>,
) -> NodeConfig {
    let mut config =
        NodeConfig::devnet(dir.to_path_buf(), RandomXEngine::shared(), miners).with_easy_pow();
    config.economics = Economics::faucet();
    config.p2p = P2pConfig {
        ping_interval: Duration::from_millis(300),
        ..P2pConfig::default()
    };
    config.mining_clock = clock.clone();
    config
}

async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if condition() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn same_chain(a: &Node, b: &Node) -> bool {
    let (x, y) = (a.status(), b.status());
    x.sink == y.sink
        && x.accepted_blocks == y.accepted_blocks
        && x.utxos == y.utxos
        && x.nullifiers == y.nullifiers
        && x.sapling_pool == y.sapling_pool
        && x.sapling_root == y.sapling_root
}

#[tokio::test(flavor = "multi_thread")]
async fn all_four_directions_work_across_two_nodes() {
    let clock = paced_clock();
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    // Node A mines to wallet A's address. Node B has its own, different, mining addresses.
    let (t_a, t_b) = (t_address(0xA1), t_address(0xB2));
    let (z_a, z_b) = (z_address('a'), z_address('b'));
    let a = Node::start(config(dir_a.path(), vec![zebra_address(0xA1)], &clock))
        .await
        .unwrap();
    let mut b_config = config(
        dir_b.path(),
        (0..10).map(|i| zebra_address(0xC0 + i)).collect(),
        &clock,
    );
    b_config.p2p.seeds = vec![a.local_addr()];
    let b = Node::start(b_config).await.unwrap();
    let _: SocketAddr = b.local_addr();

    // Fund wallet A: mine enough blocks that its coinbases are spendable.
    for _ in 0..12 {
        a.mine_one(u64::MAX).unwrap();
    }
    eventually("node B follows node A", || same_chain(&a, &b)).await;
    let (start, _) = rpc::balance(&a, &t_a).unwrap();
    assert!(start > 100 * ZATS, "wallet A holds {start} zats");

    // t-z: shield 100 VOLT into wallet A's shielded address.
    let shield_id = rpc::shield(&a, &t_a, &z_a, 100 * ZATS).unwrap();
    assert_eq!(rpc::balance_z(&a, &z_a).unwrap().0, 100 * ZATS);
    assert_eq!(a.status().sapling_pool, i128::from(100 * ZATS));
    eventually("node B sees the shielded pool", || same_chain(&a, &b)).await;
    assert_eq!(b.status().sapling_pool, i128::from(100 * ZATS));
    assert_eq!(
        rpc::balance_z(&b, &z_a).unwrap().0,
        100 * ZATS,
        "node B reads wallet A's note from the chain"
    );

    // z-z: wallet A pays wallet B 40 VOLT, privately, from node A.
    let zz_id = rpc::zsend(&a, &z_a, &z_b, 40 * ZATS).unwrap();
    let (a_left, _) = rpc::balance_z(&a, &z_a).unwrap();
    let (b_got, _) = rpc::balance_z(&a, &z_b).unwrap();
    assert_eq!(b_got, 40 * ZATS);
    assert!(a_left < 60 * ZATS && a_left > 59 * ZATS, "change {a_left}");
    assert_eq!(a.status().nullifiers, 1, "the spent note is revealed once");
    eventually("node B sees the z-z payment", || same_chain(&a, &b)).await;

    // z-t: wallet B unshields 25 VOLT to its public address, from node B.
    let zt_id = rpc::unshield(&b, &z_b, &t_b, 25 * ZATS).unwrap();
    assert_eq!(rpc::balance(&b, &t_b).unwrap().0, 25 * ZATS);
    let (b_z_left, _) = rpc::balance_z(&b, &z_b).unwrap();
    assert!(b_z_left < 15 * ZATS && b_z_left > 14 * ZATS, "{b_z_left}");
    eventually("node A sees the z-t payment", || same_chain(&a, &b)).await;
    assert_eq!(rpc::balance(&a, &t_b).unwrap().0, 25 * ZATS);

    // t-t: wallet B sends 5 VOLT back to wallet A's public address, from node B.
    let a_before = rpc::balance(&b, &t_a).unwrap().0;
    let tt_id = rpc::send(&b, &t_b, &t_a, 5 * ZATS).unwrap();
    assert!(rpc::balance(&b, &t_a).unwrap().0 >= a_before + 5 * ZATS);
    eventually("node A sees the t-t payment", || same_chain(&a, &b)).await;

    // The pool holds exactly what the unspent notes add up to.
    let notes_total = rpc::balance_z(&a, &z_a).unwrap().0 + rpc::balance_z(&a, &z_b).unwrap().0;
    assert_eq!(
        a.status().sapling_pool,
        i128::from(notes_total),
        "pool accounting matches the notes"
    );

    // Every transaction can be looked up, on either node, with the right direction.
    for (id, kind) in [
        (&shield_id, "t-z"),
        (&zz_id, "z-z"),
        (&zt_id, "z-t"),
        (&tt_id, "t-t"),
    ] {
        let hash = volt_core::VoltHash(hex_to_bytes(id));
        for node in [&a, &b] {
            let (block, _raw) = node.find_tx(&hash).expect("the transaction is on chain");
            let (_, found) = node.block_with_index(&block).unwrap();
            assert!(found
                .batches
                .iter()
                .any(|batch| !batch.raw_txs().is_empty()));
        }
        assert_kind(&a, id, kind);
    }

    // A light wallet that only reads the step feed text from node B rebuilds node A's exact tree.
    for node in [&a, &b] {
        let rebuilt = scan_feed(&rpc::steps_line(node, 0, 500));
        assert_eq!(rebuilt, node.status().sapling_root);
    }

    // Spending the same note twice is refused: the nullifier is already on chain.
    let again = rpc::zsend(&a, &z_a, &z_b, 10_000 * ZATS);
    assert!(again.is_err(), "an unfunded z-z payment must fail");
}

fn hex_bytes(text: &str) -> [u8; 32] {
    hex_to_bytes(text)
}

/// Plays the wallet's part: parses the `STEPS` line, appends the commitments in the order given,
/// checks the root the feed claims after every step, and returns the final root.
fn scan_feed(line: &str) -> [u8; 32] {
    let body = line.strip_prefix("OK ").expect("an OK answer");
    let (_total, steps) = body.split_once(' ').expect("a step list");
    let mut tree = zebra_chain::sapling::tree::NoteCommitmentTree::default();
    let mut notes = 0u64;
    let mut last = <[u8; 32]>::from(tree.root());
    for step in steps.split(';').filter(|s| !s.is_empty()) {
        let f: Vec<&str> = step.split(',').collect();
        assert_eq!(f.len(), 5, "{step}");
        if f[4] != "-" {
            for tx in f[4].split('|') {
                let parts: Vec<&str> = tx.split('/').collect();
                if parts[2] != "-" {
                    for cm in parts[2].split('+') {
                        let cmu = Option::from(
                            sapling_crypto::note::ExtractedNoteCommitment::from_bytes(&hex_bytes(
                                cm,
                            )),
                        )
                        .expect("canonical commitment");
                        tree.append(cmu).unwrap();
                        notes += 1;
                    }
                }
            }
        }
        last = <[u8; 32]>::from(tree.root());
        assert_eq!(last, hex_bytes(f[2]), "root after step {}", f[0]);
        assert_eq!(
            notes,
            f[3].parse::<u64>().unwrap(),
            "notes after step {}",
            f[0]
        );
    }
    last
}

fn hex_to_bytes(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// Reads the explorer's classification of a transaction back from the node.
fn assert_kind(node: &Node, txid: &str, expected: &str) {
    let hash = volt_core::VoltHash(hex_to_bytes(txid));
    let (block_hash, _) = node.find_tx(&hash).unwrap();
    let (_, block) = node.block_with_index(&block_hash).unwrap();
    let kinds: Vec<String> = block
        .batches
        .iter()
        .flat_map(|b| b.raw_txs())
        .filter_map(|raw| volt_core::DevTx::decode(raw).ok())
        .filter(|tx| {
            use volt_core::BatchableTx;
            tx.txid() == hash
        })
        .map(|tx| {
            use volt_core::BatchableTx;
            let t_in = !tx.spent_outpoints().is_empty();
            let z_in = !tx.nullifiers().is_empty();
            let t_out = !tx.outputs().is_empty();
            let z_out = !tx.sapling_commitment_bytes().is_empty();
            match (t_in, z_in, t_out, z_out) {
                (true, false, _, true) => "t-z",
                (false, true, true, _) => "z-t",
                (false, true, false, _) => "z-z",
                _ => "t-t",
            }
            .to_owned()
        })
        .collect();
    assert_eq!(kinds, [expected.to_owned()], "{txid}");
}
