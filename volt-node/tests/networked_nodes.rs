//! Real nodes: persistent consensus, mempool and miner, connected over real TCP.

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
use volt_core::{BatchableTx, Economics, VoltHash};
use volt_crypto::Blake2bPowHasher;
use volt_network::P2pConfig;
use volt_node::{
    node::{Node, NodeConfig},
    wallet::{DevWallet, Spendability},
};
use zebra_chain::{parameters::NetworkKind, transparent::Address};

fn miner_addresses(tag: u8) -> Vec<Address> {
    (0..10)
        .map(|i| {
            Address::from_pub_key_hash(
                NetworkKind::Regtest,
                [tag, i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            )
        })
        .collect()
}

/// A clock shared by every node in a test, advancing 500 ms per reading, so block times stay on
/// the difficulty target and never run backwards.
fn paced_clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    let now = Arc::new(AtomicU64::new(1_000));
    Arc::new(move || now.fetch_add(500, Ordering::SeqCst))
}

fn config(dir: &Path, tag: u8, clock: &Arc<dyn Fn() -> u64 + Send + Sync>) -> NodeConfig {
    let mut config = NodeConfig::devnet(
        dir.to_path_buf(),
        Arc::new(Blake2bPowHasher),
        miner_addresses(tag),
    );
    config.economics = Economics::fifty_fifty();
    config.p2p = P2pConfig {
        ping_interval: Duration::from_millis(300),
        ..P2pConfig::default()
    };
    config.mining_clock = clock.clone();
    config
}

async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..500 {
        if condition() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn converged(a: &Node, b: &Node) -> bool {
    let (x, y) = (a.status(), b.status());
    x.sink == y.sink
        && x.dag_blocks == y.dag_blocks
        && x.accepted_blocks == y.accepted_blocks
        && x.utxos == y.utxos
        && x.nullifiers == y.nullifiers
        && x.sapling_root == y.sapling_root
        && x.orchard_root == y.orchard_root
        && x.sapling_pool == y.sapling_pool
        && x.orchard_pool == y.orchard_pool
}

fn mine(node: &Node, count: usize) -> Vec<VoltHash> {
    (0..count)
        .map(|_| node.mine_one(u64::MAX).unwrap().expect("a block is found"))
        .collect()
}

fn connect(from: &Node, to: &Node) {
    let addr: SocketAddr = to.local_addr();
    from.connect(addr);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nodes_sync_relay_and_restart_into_the_same_state() {
    let clock = paced_clock();
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

    let a = Node::start(config(dir_a.path(), 1, &clock)).await.unwrap();
    let b = Node::start(config(dir_b.path(), 2, &clock)).await.unwrap();
    connect(&b, &a);
    eventually("a and b are connected", || {
        a.status().peers == 1 && b.status().peers == 1
    })
    .await;

    // 1. A mines; B follows by announcement and fetch.
    let a_blocks = mine(&a, 30);
    eventually("b follows a's chain", || converged(&a, &b)).await;
    assert_eq!(a.status().dag_blocks, 31);

    // 2. A late joiner catches up in bulk through the locator protocol, with real validation.
    let dir_c = tempfile::tempdir().unwrap();
    let c = Node::start(config(dir_c.path(), 3, &clock)).await.unwrap();
    connect(&c, &a);
    eventually("a late joiner catches up", || converged(&a, &c)).await;
    c.shutdown().await;

    // 3. Transactions: build 20 from A's matured coinbases, submit them to B only.
    let mut wallet = DevWallet::new();
    for hash in &a_blocks[..20] {
        wallet.on_accepted(&a.block(hash).unwrap());
    }
    let txs = wallet.make_txs(20, |outpoint| {
        if a.is_unspent(outpoint) {
            Spendability::Now
        } else {
            Spendability::Never
        }
    });
    assert_eq!(txs.len(), 20);
    let spent: Vec<_> = txs.iter().flat_map(|tx| tx.spent_outpoints()).collect();
    let created: Vec<_> = txs
        .iter()
        .map(|tx| {
            zebra_chain::transparent::OutPoint::from_usize(
                zebra_chain::transaction::Hash(tx.txid().0),
                0,
            )
        })
        .collect();
    for tx in &txs {
        b.submit_tx(tx.to_bytes())
            .expect("a valid transaction is pooled");
    }

    // B relayed them: A's pool fills without anyone telling A directly.
    eventually("the transactions reach a's mempool", || {
        a.status().mempool == 20
    })
    .await;
    assert_eq!(b.status().mempool, 20);

    // 4. A mines them (2 batches of 10) and, once merged, they are in state on both nodes.
    mine(&a, 3);
    eventually("the block propagates and pools drain", || {
        converged(&a, &b) && a.status().mempool == 0 && b.status().mempool == 0
    })
    .await;
    for outpoint in &spent {
        assert!(!a.is_unspent(outpoint), "spent on a");
        assert!(!b.is_unspent(outpoint), "spent on b");
    }
    for outpoint in &created {
        assert!(
            a.is_unspent(outpoint) && b.is_unspent(outpoint),
            "created on both"
        );
    }

    // 5. Both mine at the same time: parallel blocks, and both converge on one order.
    std::thread::scope(|scope| {
        scope.spawn(|| mine(&a, 4));
        scope.spawn(|| mine(&b, 4));
    });
    eventually("parallel mining converges", || converged(&a, &b)).await;
    assert_eq!(a.status().dag_blocks, 31 + 3 + 8);

    // 6. B restarts from its own disk and rejoins with identical state.
    let before = b.status();
    b.shutdown().await;
    let b = Node::start(config(dir_b.path(), 2, &clock)).await.unwrap();
    let restored = b.status();
    assert_eq!(restored.sink, before.sink);
    assert_eq!(restored.dag_blocks, before.dag_blocks);
    assert_eq!(restored.utxos, before.utxos);
    assert_eq!(restored.accepted_blocks, before.accepted_blocks);

    connect(&b, &a);
    mine(&a, 2);
    eventually("the restarted node catches up", || converged(&a, &b)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nodes_on_different_networks_do_not_connect() {
    let clock = paced_clock();
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a = Node::start(config(dir_a.path(), 1, &clock)).await.unwrap();
    let mut other = config(dir_b.path(), 2, &clock);
    other.genesis_timestamp_ms = 99; // a different genesis block
    let b = Node::start(other).await.unwrap();

    connect(&b, &a);
    sleep(Duration::from_millis(600)).await;
    assert_eq!((a.status().peers, b.status().peers), (0, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_never_accepts_an_invalid_transaction() {
    let clock = paced_clock();
    let dir = tempfile::tempdir().unwrap();
    let a = Node::start(config(dir.path(), 1, &clock)).await.unwrap();
    mine(&a, 3);

    // Spends an output that does not exist.
    let ghost = zebra_chain::transparent::OutPoint {
        hash: zebra_chain::transaction::Hash([9; 32]),
        index: 0,
    };
    let tx = volt_core::DevTx::new(vec![ghost], vec![], vec![], false, 1);
    assert!(a.submit_tx(tx.to_bytes()).is_err());
    assert!(
        a.submit_tx(vec![1, 2, 3]).is_err(),
        "garbage does not even decode"
    );
    assert_eq!(a.status().mempool, 0);
}
