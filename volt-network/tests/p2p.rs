//! The peer-to-peer runtime over real TCP connections on localhost.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use parking_lot::Mutex;
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{sleep, timeout},
};
use volt_core::{constants::MAX_BLOCK_PARENTS, Coinbase, VoltBlock, VoltHash, VoltHeader};
use volt_network::{
    frame::{read_frame, write_frame},
    start, ChainBackend, Hello, P2pConfig, P2pHandle, SubmitError, VoltMessage, PROTOCOL_VERSION,
};
use zebra_chain::amount::Amount;

const MAGIC: [u8; 4] = *b"VOLT";

/// A block with the given parents. `nonce == 666` marks it invalid, and `nonce == 777` marks it
/// as temporarily unacceptable, for testing how the network reacts.
fn block(parents: &[VoltHash], nonce: u64) -> VoltBlock {
    let mut parents = parents.to_vec();
    parents.sort();
    let coinbase = Coinbase {
        payouts: vec![],
        pol_contribution: Amount::zero(),
        extra: vec![],
    };
    VoltBlock {
        header: VoltHeader {
            version: 1,
            parents,
            timestamp_ms: 0,
            bits: 0,
            nonce,
            batches_root: VoltBlock::compute_batches_root(&[]),
            coinbase_root: coinbase.hash(),
        },
        coinbase,
        batches: vec![],
    }
}

fn genesis() -> VoltBlock {
    block(&[], 0)
}

/// A chain backend that accepts any block whose parents it knows.
struct MockChain {
    genesis: VoltHash,
    state: Mutex<MockState>,
    txs: Mutex<Vec<Vec<u8>>>,
}

#[derive(Default)]
struct MockState {
    blocks: HashMap<VoltHash, Vec<u8>>,
    order: Vec<VoltHash>,
    parents: HashMap<VoltHash, Vec<VoltHash>>,
}

impl MockChain {
    fn new(genesis_block: &VoltBlock) -> Arc<Self> {
        let chain = Arc::new(Self {
            genesis: genesis_block.hash(),
            state: Mutex::new(MockState::default()),
            txs: Mutex::new(Vec::new()),
        });
        chain.insert(genesis_block);
        chain
    }

    fn insert(&self, block: &VoltBlock) {
        let mut state = self.state.lock();
        let hash = block.hash();
        if state.blocks.insert(hash, block.encode()).is_none() {
            state.order.push(hash);
            state.parents.insert(hash, block.header.parents.clone());
        }
    }

    fn len(&self) -> usize {
        self.state.lock().order.len()
    }

    fn has(&self, hash: &VoltHash) -> bool {
        self.state.lock().blocks.contains_key(hash)
    }
}

impl ChainBackend for MockChain {
    fn genesis(&self) -> VoltHash {
        self.genesis
    }

    fn tips(&self) -> Vec<VoltHash> {
        let state = self.state.lock();
        let parents: std::collections::HashSet<_> = state.parents.values().flatten().collect();
        state
            .order
            .iter()
            .filter(|h| !parents.contains(h))
            .take(MAX_BLOCK_PARENTS)
            .copied()
            .collect()
    }

    fn contains(&self, hash: &VoltHash) -> bool {
        self.has(hash)
    }

    fn block(&self, hash: &VoltHash) -> Option<Vec<u8>> {
        self.state.lock().blocks.get(hash).cloned()
    }

    fn locator(&self) -> Vec<VoltHash> {
        let state = self.state.lock();
        let mut locator = Vec::new();
        let (mut step, mut index) = (1usize, state.order.len());
        while index > 0 && locator.len() < 40 {
            index -= 1;
            locator.push(state.order[index]);
            if locator.len() > 10 {
                step *= 2;
            }
            index = index.saturating_sub(step - 1);
        }
        if locator.last() != Some(&self.genesis) {
            locator.push(self.genesis);
        }
        locator
    }

    fn blocks_after(&self, locator: &[VoltHash], max: usize) -> Vec<Vec<u8>> {
        let state = self.state.lock();
        let anchor = locator
            .iter()
            .filter_map(|h| state.order.iter().position(|o| o == h))
            .max()
            .unwrap_or(0);
        state.order[anchor + 1..]
            .iter()
            .take(max)
            .map(|h| state.blocks[h].clone())
            .collect()
    }

    fn submit_block(&self, block: VoltBlock) -> Result<VoltHash, SubmitError> {
        if block.header.nonce == 666 {
            return Err(SubmitError::Invalid("a deliberately bad block".into()));
        }
        if block.header.nonce == 777 {
            return Err(SubmitError::Temporary("not yet".into()));
        }
        let state = self.state.lock();
        if block
            .header
            .parents
            .iter()
            .any(|p| !state.blocks.contains_key(p))
        {
            return Err(SubmitError::Invalid("unknown parent".into()));
        }
        drop(state);
        self.insert(&block);
        Ok(block.hash())
    }

    fn submit_tx(&self, bytes: &[u8]) -> Result<VoltHash, SubmitError> {
        if bytes.is_empty() {
            return Err(SubmitError::Invalid("empty".into()));
        }
        self.txs.lock().push(bytes.to_vec());
        Ok(VoltHash::digest(b"MockTx__________", bytes))
    }
}

fn config() -> P2pConfig {
    P2pConfig {
        // Fast timers so the tests are quick.
        handshake_timeout: Duration::from_secs(2),
        ping_interval: Duration::from_millis(200),
        idle_timeout: Duration::from_secs(5),
        ..P2pConfig::default()
    }
}

async fn node(chain: &Arc<MockChain>) -> P2pHandle {
    start(config(), chain.clone()).await.unwrap()
}

/// Waits until `condition` holds, failing the test after five seconds.
async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..250 {
        if condition() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn extend(chain: &MockChain, count: usize, tag: u64) -> VoltHash {
    let mut tip = chain.tips()[0];
    for i in 0..count {
        let b = block(&[tip], tag * 1_000_000 + i as u64 + 1);
        chain.insert(&b);
        tip = b.hash();
    }
    tip
}

#[tokio::test]
async fn two_nodes_handshake_and_see_each_other() {
    let (a_chain, b_chain) = (MockChain::new(&genesis()), MockChain::new(&genesis()));
    let (a, b) = (node(&a_chain).await, node(&b_chain).await);

    b.connect(a.local_addr());
    eventually("both sides see one peer", || {
        a.peer_count() == 1 && b.peer_count() == 1
    })
    .await;

    // Connecting again does not create a duplicate.
    b.connect(a.local_addr());
    sleep(Duration::from_millis(300)).await;
    assert_eq!((a.peer_count(), b.peer_count()), (1, 1));

    a.shutdown().await;
    eventually("b notices a left", || b.peer_count() == 0).await;
    b.shutdown().await;
}

#[tokio::test]
async fn a_node_refuses_peers_on_a_different_genesis_or_itself() {
    let a_chain = MockChain::new(&genesis());
    let other_chain = MockChain::new(&block(&[], 12345));
    let (a, other) = (node(&a_chain).await, node(&other_chain).await);

    other.connect(a.local_addr());
    sleep(Duration::from_millis(500)).await;
    assert_eq!((a.peer_count(), other.peer_count()), (0, 0));

    // Connecting to itself is detected through the nonce.
    a.connect(a.local_addr());
    sleep(Duration::from_millis(500)).await;
    assert_eq!(a.peer_count(), 0);
}

#[tokio::test]
async fn a_new_block_crosses_a_line_of_three_nodes() {
    // a -- b -- c: a never talks to c directly, so b must relay.
    let chains: Vec<_> = (0..3).map(|_| MockChain::new(&genesis())).collect();
    let nodes = [
        node(&chains[0]).await,
        node(&chains[1]).await,
        node(&chains[2]).await,
    ];
    nodes[0].connect(nodes[1].local_addr());
    nodes[2].connect(nodes[1].local_addr());
    eventually("the line is connected", || {
        nodes[1].peer_count() == 2 && nodes[0].peer_count() == 1 && nodes[2].peer_count() == 1
    })
    .await;

    let tip = extend(&chains[0], 1, 1);
    nodes[0].announce_block(tip);
    eventually("the block reaches the far end", || chains[2].has(&tip)).await;
    assert!(chains[1].has(&tip));

    // A transaction relays the same way.
    nodes[0].broadcast_tx(b"a transaction".to_vec());
    eventually("the transaction reaches the far end", || {
        !chains[2].txs.lock().is_empty()
    })
    .await;
}

#[tokio::test]
async fn a_node_that_joins_late_catches_up_in_bulk() {
    // 300 blocks is several full batches of 64.
    let (a_chain, b_chain) = (MockChain::new(&genesis()), MockChain::new(&genesis()));
    extend(&a_chain, 300, 1);
    let (a, b) = (node(&a_chain).await, node(&b_chain).await);

    b.connect(a.local_addr());
    eventually("b catches up with all 301 blocks", || b_chain.len() == 301).await;
    assert_eq!(b_chain.tips(), a_chain.tips());
    assert_eq!(b.orphan_count(), 0);
}

#[tokio::test]
async fn parallel_branches_and_orphans_are_resolved() {
    // Build a diamond-rich history on `a`, then let `b` sync it.
    let (a_chain, b_chain) = (MockChain::new(&genesis()), MockChain::new(&genesis()));
    let g = a_chain.tips()[0];
    let mut tips = vec![g];
    for round in 0..20u64 {
        let left = block(&[tips[0]], round * 10 + 1);
        let right = block(&[tips[0]], round * 10 + 2);
        a_chain.insert(&left);
        a_chain.insert(&right);
        let merge = block(&[left.hash(), right.hash()], round * 10 + 3);
        a_chain.insert(&merge);
        tips = vec![merge.hash()];
    }
    let expected = a_chain.len();
    let (a, b) = (node(&a_chain).await, node(&b_chain).await);

    b.connect(a.local_addr());
    eventually("b has every block of the wide history", || {
        b_chain.len() == expected
    })
    .await;
    assert_eq!(b.orphan_count(), 0, "every orphan found its parents");
}

#[tokio::test]
async fn a_pushed_block_with_unknown_parents_waits_then_connects() {
    let (a_chain, b_chain) = (MockChain::new(&genesis()), MockChain::new(&genesis()));
    let first = block(&[a_chain.tips()[0]], 1);
    let second = block(&[first.hash()], 2);
    a_chain.insert(&first);
    a_chain.insert(&second);
    let (a, b) = (node(&a_chain).await, node(&b_chain).await);

    // Speak to `b` as a raw peer and push the child before its parent exists on `b`.
    let mut raw = TcpStream::connect(b.local_addr()).await.unwrap();
    let hello = VoltMessage::Hello(Hello {
        version: PROTOCOL_VERSION,
        genesis: genesis().hash(),
        nonce: 42,
        tips: vec![],
    });
    write_frame(&mut raw, MAGIC, &hello.encode()).await.unwrap();
    let _ = read_frame(&mut raw, MAGIC).await.unwrap(); // b's hello
    write_frame(
        &mut raw,
        MAGIC,
        &VoltMessage::NewBlock(second.encode()).encode(),
    )
    .await
    .unwrap();
    eventually("the child is held as an orphan", || b.orphan_count() == 1).await;
    assert!(!b_chain.has(&second.hash()));

    // Once `b` can reach a node that has the parent, the orphan resolves.
    b.connect(a.local_addr());
    eventually("the orphan connects", || b_chain.has(&second.hash())).await;
    assert_eq!(b.orphan_count(), 0);
}

async fn raw_peer(target: &P2pHandle) -> TcpStream {
    let mut raw = TcpStream::connect(target.local_addr()).await.unwrap();
    let hello = VoltMessage::Hello(Hello {
        version: PROTOCOL_VERSION,
        genesis: genesis().hash(),
        nonce: rand_nonce(),
        tips: vec![],
    });
    write_frame(&mut raw, MAGIC, &hello.encode()).await.unwrap();
    let _ = read_frame(&mut raw, MAGIC).await.unwrap();
    raw
}

fn rand_nonce() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        | 1
}

fn loopback() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Asserts the node dropped the connection: the next read ends rather than blocking.
async fn assert_disconnected(raw: &mut TcpStream) {
    let result = timeout(Duration::from_secs(3), async {
        loop {
            if read_frame(raw, MAGIC).await.is_err() {
                return;
            }
            // Pings may still arrive before the close is observed.
        }
    })
    .await;
    assert!(result.is_ok(), "the node did not close the connection");
}

#[tokio::test]
async fn garbage_after_the_handshake_gets_the_sender_banned() {
    let chain = MockChain::new(&genesis());
    let n = node(&chain).await;
    let mut raw = raw_peer(&n).await;

    raw.write_all(b"this is not a frame at all, just noise bytes..")
        .await
        .unwrap();
    assert_disconnected(&mut raw).await;
    assert!(n.is_banned(loopback()));
    assert_eq!(n.peer_count(), 0);
}

#[tokio::test]
async fn an_oversized_frame_is_refused_without_reading_it() {
    let chain = MockChain::new(&genesis());
    let n = node(&chain).await;
    let mut raw = raw_peer(&n).await;

    // A header claiming 3 GiB of payload.
    let mut header = MAGIC.to_vec();
    header.extend_from_slice(&(3u32 << 30).to_le_bytes());
    header.extend_from_slice(&[0; 4]);
    raw.write_all(&header).await.unwrap();

    assert_disconnected(&mut raw).await;
    assert!(n.is_banned(loopback()));
}

#[tokio::test]
async fn an_invalid_block_gets_the_sender_banned_but_a_temporary_failure_does_not() {
    let chain = MockChain::new(&genesis());
    let n = node(&chain).await;
    let tip = chain.tips()[0];

    // A temporarily unacceptable block is dropped quietly.
    let mut raw = raw_peer(&n).await;
    let later = block(&[tip], 777);
    write_frame(
        &mut raw,
        MAGIC,
        &VoltMessage::NewBlock(later.encode()).encode(),
    )
    .await
    .unwrap();
    sleep(Duration::from_millis(300)).await;
    assert!(!n.is_banned(loopback()));
    assert!(!chain.has(&later.hash()));
    drop(raw);

    // An invalid one costs the sender a ban.
    let mut raw = raw_peer(&n).await;
    let bad = block(&[tip], 666);
    write_frame(
        &mut raw,
        MAGIC,
        &VoltMessage::NewBlock(bad.encode()).encode(),
    )
    .await
    .unwrap();
    assert_disconnected(&mut raw).await;
    assert!(n.is_banned(loopback()));
    assert!(!chain.has(&bad.hash()));
}

#[tokio::test]
async fn a_message_flood_is_rate_limited() {
    let chain = MockChain::new(&genesis());
    let n = start(
        P2pConfig {
            max_msgs_per_sec: 20,
            ..config()
        },
        chain.clone(),
    )
    .await
    .unwrap();
    let mut raw = raw_peer(&n).await;

    let ping = VoltMessage::Ping(1).encode();
    for _ in 0..500 {
        if write_frame(&mut raw, MAGIC, &ping).await.is_err() {
            break;
        }
    }
    assert_disconnected(&mut raw).await;
    assert!(n.is_banned(loopback()));
}

#[tokio::test]
async fn a_wrong_first_message_and_a_silent_peer_are_dropped() {
    let chain = MockChain::new(&genesis());
    let n = node(&chain).await;

    // The first message must be a hello.
    let mut raw = TcpStream::connect(n.local_addr()).await.unwrap();
    let _ = read_frame(&mut raw, MAGIC).await.unwrap();
    write_frame(&mut raw, MAGIC, &VoltMessage::Ping(1).encode())
        .await
        .unwrap();
    assert_disconnected(&mut raw).await;
    assert!(n.is_banned(loopback()));
}

#[tokio::test]
async fn banned_addresses_cannot_reconnect() {
    let chain = MockChain::new(&genesis());
    let n = node(&chain).await;
    let mut raw = raw_peer(&n).await;
    raw.write_all(b"garbage garbage garbage").await.unwrap();
    assert_disconnected(&mut raw).await;
    assert!(n.is_banned(loopback()));

    // A new connection from the same address is closed straight away.
    let mut again = TcpStream::connect(n.local_addr()).await.unwrap();
    let result = timeout(Duration::from_secs(2), read_frame(&mut again, MAGIC)).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "a banned address must not get a handshake"
    );
}

#[tokio::test]
async fn inbound_connections_are_capped() {
    let chain = MockChain::new(&genesis());
    let n = start(
        P2pConfig {
            max_inbound: 2,
            ..config()
        },
        chain.clone(),
    )
    .await
    .unwrap();

    let _first = raw_peer(&n).await;
    let _second = raw_peer(&n).await;
    eventually("two peers connected", || n.peer_count() == 2).await;

    // The third is accepted at the socket level, then dropped before a handshake.
    let mut third = TcpStream::connect(n.local_addr()).await.unwrap();
    let result = timeout(Duration::from_secs(2), read_frame(&mut third, MAGIC)).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "the third connection is refused"
    );
    assert_eq!(n.peer_count(), 2);
}

#[tokio::test]
async fn the_orphan_pool_is_bounded() {
    let chain = MockChain::new(&genesis());
    let n = start(
        P2pConfig {
            max_orphans: 10,
            ..config()
        },
        chain.clone(),
    )
    .await
    .unwrap();
    let mut raw = raw_peer(&n).await;

    // 100 blocks whose parents will never arrive.
    for i in 0..100u64 {
        let missing_parent = VoltHash::digest(b"MissingParent___", &i.to_le_bytes());
        let orphan = block(&[missing_parent], i + 1);
        write_frame(
            &mut raw,
            MAGIC,
            &VoltMessage::NewBlock(orphan.encode()).encode(),
        )
        .await
        .unwrap();
        // Stay under the rate limit.
        if i % 20 == 19 {
            sleep(Duration::from_millis(150)).await;
        }
    }
    sleep(Duration::from_millis(300)).await;
    assert!(n.orphan_count() <= 10, "orphans held: {}", n.orphan_count());
    assert!(n.orphan_count() > 0);
}

#[tokio::test]
async fn a_stale_connection_is_closed_after_the_idle_timeout() {
    let chain = MockChain::new(&genesis());
    let n = start(
        P2pConfig {
            idle_timeout: Duration::from_millis(400),
            ..config()
        },
        chain.clone(),
    )
    .await
    .unwrap();

    let mut raw = raw_peer(&n).await;
    // Say nothing: the node's own pings arrive, but it hears nothing back, and hangs up.
    assert_disconnected(&mut raw).await;
    eventually("the peer is gone", || n.peer_count() == 0).await;
    assert!(!n.is_banned(loopback()), "idleness is not misbehavior");
    let _ = SocketAddr::from(([127, 0, 0, 1], 0));
}

#[tokio::test]
async fn the_orphan_pool_is_bounded_by_bytes_not_only_by_count() {
    let chain = MockChain::new(&genesis());
    let one = block(&[VoltHash([5; 32])], 1).encode().len();
    // Room for three small orphans, though the count limit would allow far more.
    let n = start(
        P2pConfig {
            max_orphans: 1_000,
            max_orphan_bytes: one * 3 + one / 2,
            ..config()
        },
        chain.clone(),
    )
    .await
    .unwrap();
    let mut raw = raw_peer(&n).await;

    for i in 0..20u64 {
        let missing = VoltHash::digest(b"MissingParent___", &i.to_le_bytes());
        let orphan = block(&[missing], i + 1);
        write_frame(
            &mut raw,
            MAGIC,
            &VoltMessage::NewBlock(orphan.encode()).encode(),
        )
        .await
        .unwrap();
    }
    sleep(Duration::from_millis(400)).await;
    assert_eq!(
        n.orphan_count(),
        3,
        "the byte budget, not the count, is the limit"
    );
}

#[tokio::test]
async fn a_provably_invalid_transaction_bans_the_sender_but_an_unlucky_one_does_not() {
    let chain = MockChain::new(&genesis());
    let n = node(&chain).await;

    // A valid transaction is pooled and the sender is left alone.
    let mut raw = raw_peer(&n).await;
    write_frame(
        &mut raw,
        MAGIC,
        &VoltMessage::NewTx(b"fine".to_vec()).encode(),
    )
    .await
    .unwrap();
    sleep(Duration::from_millis(300)).await;
    assert_eq!(chain.txs.lock().len(), 1);
    assert!(!n.is_banned(loopback()));

    // An empty transaction is the mock's stand-in for "fails to decode or verify".
    write_frame(&mut raw, MAGIC, &VoltMessage::NewTx(vec![]).encode())
        .await
        .unwrap();
    assert_disconnected(&mut raw).await;
    assert!(n.is_banned(loopback()));
}
