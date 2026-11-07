//! The peer-to-peer runtime.
//!
//! - **Handshake**: each side sends a [`Hello`] naming its protocol version, genesis block and a
//!   random nonce. A different version or genesis, a connection to oneself, or a second
//!   connection to the same node is dropped.
//! - **Relay**: a new block is announced with an inventory message and fetched on demand. A new
//!   transaction is pushed.
//! - **Catch-up**: a peer that is behind asks for the blocks after its newest known block (a
//!   locator) in bulk. Blocks whose parents are missing wait in a bounded orphan pool while the
//!   parents are fetched.
//! - **Defence**: frames and messages have hard size limits, each peer is rate limited, invalid
//!   data gets the sender banned, and connection counts are capped.

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch},
    task::JoinHandle,
    time::{interval, sleep, timeout},
};
use tracing::{debug, info, warn};
use volt_core::{constants::MAX_BLOCK_PARENTS, VoltBlock, VoltHash};

use crate::{
    backend::{ChainBackend, SubmitError},
    frame::{read_frame, write_frame, FrameError},
    message::{Hello, VoltMessage, MAX_BLOCKS_PER_MESSAGE, MAX_GET_BLOCKS, PROTOCOL_VERSION},
};

/// Settings for the peer layer.
#[derive(Clone, Debug)]
pub struct P2pConfig {
    /// The address to listen on. Port 0 picks a free port.
    pub listen: SocketAddr,
    /// Peers to keep outbound connections to.
    pub seeds: Vec<SocketAddr>,
    /// Four bytes that tell this network's frames apart from any other's.
    pub magic: [u8; 4],
    /// The most inbound connections to accept.
    pub max_inbound: usize,
    /// The most outbound connections to keep.
    pub max_outbound: usize,
    /// How long a peer has to complete the handshake.
    pub handshake_timeout: Duration,
    /// A peer that sends nothing for this long is dropped.
    pub idle_timeout: Duration,
    /// How often to ping a quiet peer.
    pub ping_interval: Duration,
    /// The sustained message rate allowed per peer. Twice this is allowed as a burst.
    pub max_msgs_per_sec: u32,
    /// How long a misbehaving address stays banned.
    pub ban_duration: Duration,
    /// The most blocks held while waiting for their parents.
    pub max_orphans: usize,
    /// The most bytes of blocks held while waiting for their parents.
    pub max_orphan_bytes: usize,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            seeds: Vec::new(),
            magic: *b"VOLT",
            max_inbound: 64,
            max_outbound: 8,
            handshake_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(90),
            ping_interval: Duration::from_secs(20),
            max_msgs_per_sec: 200,
            ban_duration: Duration::from_secs(600),
            max_orphans: 500,
            max_orphan_bytes: 64 * 1024 * 1024,
        }
    }
}

struct PeerEntry {
    tx: mpsc::Sender<VoltMessage>,
    addr: SocketAddr,
    inbound: bool,
    remote_nonce: u64,
}

struct Orphan {
    bytes: Vec<u8>,
    missing: Vec<VoltHash>,
    from: IpAddr,
    seq: u64,
}

struct Shared {
    config: P2pConfig,
    backend: Arc<dyn ChainBackend>,
    nonce: u64,
    next_id: AtomicU64,
    peers: Mutex<HashMap<u64, PeerEntry>>,
    orphans: Mutex<HashMap<VoltHash, Orphan>>,
    orphan_seq: AtomicU64,
    bans: Mutex<HashMap<IpAddr, Instant>>,
    requested: Mutex<HashMap<VoltHash, Instant>>,
    /// Addresses we are connected, or connecting, to as a client.
    outbound_targets: Mutex<HashSet<SocketAddr>>,
    inbound_connections: AtomicUsize,
    shutdown: watch::Receiver<bool>,
}

/// A running peer layer.
pub struct P2pHandle {
    shared: Arc<Shared>,
    local_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for P2pHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pHandle")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

/// Starts listening and connecting. Returns once the listener is bound.
pub async fn start(config: P2pConfig, backend: Arc<dyn ChainBackend>) -> io::Result<P2pHandle> {
    let listener = TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let (shutdown, shutdown_rx) = watch::channel(false);

    let shared = Arc::new(Shared {
        nonce: rand::random(),
        next_id: AtomicU64::new(1),
        peers: Mutex::new(HashMap::new()),
        orphans: Mutex::new(HashMap::new()),
        orphan_seq: AtomicU64::new(0),
        bans: Mutex::new(HashMap::new()),
        requested: Mutex::new(HashMap::new()),
        outbound_targets: Mutex::new(HashSet::new()),
        inbound_connections: AtomicUsize::new(0),
        shutdown: shutdown_rx,
        config,
        backend,
    });

    let mut tasks = vec![tokio::spawn(accept_loop(shared.clone(), listener))];
    if !shared.config.seeds.is_empty() {
        tasks.push(tokio::spawn(connect_loop(shared.clone())));
    }
    info!(%local_addr, "peer-to-peer listening");
    Ok(P2pHandle {
        shared,
        local_addr,
        shutdown,
        tasks,
    })
}

impl P2pHandle {
    /// The address actually bound.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The number of peers that completed the handshake.
    pub fn peer_count(&self) -> usize {
        self.shared.peers.lock().len()
    }

    /// The remote addresses of the connected peers.
    pub fn peer_addrs(&self) -> Vec<SocketAddr> {
        self.shared.peers.lock().values().map(|p| p.addr).collect()
    }

    /// The number of blocks waiting for their parents.
    pub fn orphan_count(&self) -> usize {
        self.shared.orphans.lock().len()
    }

    /// Whether `ip` is currently banned.
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.shared.is_banned(ip)
    }

    /// Connects to `addr` as an outbound peer, in the background.
    pub fn connect(&self, addr: SocketAddr) {
        spawn_outbound(self.shared.clone(), addr);
    }

    /// Announces a block this node has just accepted or mined.
    pub fn announce_block(&self, hash: VoltHash) {
        self.shared.broadcast(&VoltMessage::Inv(vec![hash]), None);
    }

    /// Relays a transaction to every peer.
    pub fn broadcast_tx(&self, bytes: Vec<u8>) {
        self.shared.broadcast(&VoltMessage::NewTx(bytes), None);
    }

    /// Stops accepting and disconnects every peer.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            task.abort();
            let _ = task.await;
        }
        // Dropping the peer table closes the writers, which closes the sockets.
        self.shared.peers.lock().clear();
    }
}

impl Shared {
    fn is_banned(&self, ip: IpAddr) -> bool {
        let mut bans = self.bans.lock();
        match bans.get(&ip) {
            Some(until) if *until > Instant::now() => true,
            Some(_) => {
                bans.remove(&ip);
                false
            }
            None => false,
        }
    }

    fn ban(&self, ip: IpAddr, why: &str) {
        warn!(%ip, why, "banning peer");
        self.bans
            .lock()
            .insert(ip, Instant::now() + self.config.ban_duration);
    }

    fn broadcast(&self, message: &VoltMessage, except: Option<u64>) {
        for (id, peer) in self.peers.lock().iter() {
            if Some(*id) != except {
                // A full queue means a slow peer: skipping it is better than blocking everyone.
                let _ = peer.tx.try_send(message.clone());
            }
        }
    }

    /// Returns the hashes not yet requested recently, and records them as requested.
    fn mark_requested(&self, hashes: impl IntoIterator<Item = VoltHash>) -> Vec<VoltHash> {
        let now = Instant::now();
        let mut requested = self.requested.lock();
        if requested.len() > 10_000 {
            requested.retain(|_, at| now.duration_since(*at) < Duration::from_secs(10));
        }
        hashes
            .into_iter()
            .filter(|hash| match requested.get(hash) {
                Some(at) if now.duration_since(*at) < Duration::from_secs(10) => false,
                _ => {
                    requested.insert(*hash, now);
                    true
                }
            })
            .collect()
    }
}

struct ConnectionGuard {
    shared: Arc<Shared>,
    inbound: bool,
    target: Option<SocketAddr>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if self.inbound {
            self.shared
                .inbound_connections
                .fetch_sub(1, Ordering::SeqCst);
        }
        if let Some(target) = self.target {
            self.shared.outbound_targets.lock().remove(&target);
        }
    }
}

async fn accept_loop(shared: Arc<Shared>, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                if shared.is_banned(addr.ip()) {
                    debug!(%addr, "refusing a banned address");
                    continue;
                }
                // Bound connections that have not finished the handshake as well as peers.
                let pending = shared.inbound_connections.fetch_add(1, Ordering::SeqCst);
                if pending >= shared.config.max_inbound {
                    shared.inbound_connections.fetch_sub(1, Ordering::SeqCst);
                    debug!(%addr, "inbound connection limit reached");
                    continue;
                }
                let guard = ConnectionGuard {
                    shared: shared.clone(),
                    inbound: true,
                    target: None,
                };
                tokio::spawn(run_peer(shared.clone(), stream, addr, true, guard));
            }
            Err(error) => {
                warn!(%error, "accept failed");
                sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

async fn connect_loop(shared: Arc<Shared>) {
    let mut tick = interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        for addr in shared.config.seeds.clone() {
            spawn_outbound(shared.clone(), addr);
        }
    }
}

fn spawn_outbound(shared: Arc<Shared>, addr: SocketAddr) {
    if shared.is_banned(addr.ip()) {
        return;
    }
    {
        // `outbound_targets` holds both connected and still-connecting addresses.
        let mut targets = shared.outbound_targets.lock();
        if targets.len() >= shared.config.max_outbound {
            return;
        }
        if !targets.insert(addr) {
            return; // already connected or connecting
        }
    }
    let guard = ConnectionGuard {
        shared: shared.clone(),
        inbound: false,
        target: Some(addr),
    };
    tokio::spawn(async move {
        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => run_peer(shared, stream, addr, false, guard).await,
            Ok(Err(error)) => debug!(%addr, %error, "outbound connection failed"),
            Err(_) => debug!(%addr, "outbound connection timed out"),
        }
    });
}

/// A token bucket: `rate` messages per second sustained, twice that as a burst.
struct RateLimiter {
    tokens: f64,
    rate: f64,
    last: Instant,
}

impl RateLimiter {
    fn new(rate: u32) -> Self {
        let rate = f64::from(rate.max(1));
        Self {
            tokens: rate * 2.0,
            rate,
            last: Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.rate * 2.0);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

enum Next {
    Continue,
    Ban(&'static str),
}

async fn run_peer(
    shared: Arc<Shared>,
    stream: TcpStream,
    addr: SocketAddr,
    inbound: bool,
    _guard: ConnectionGuard,
) {
    let magic = shared.config.magic;
    let _ = stream.set_nodelay(true);
    let (mut reader, mut writer) = stream.into_split();

    // Handshake: both sides speak first, then check what the other said.
    let mut tips = shared.backend.tips();
    tips.truncate(MAX_BLOCK_PARENTS);
    let ours = VoltMessage::Hello(Hello {
        version: PROTOCOL_VERSION,
        genesis: shared.backend.genesis(),
        nonce: shared.nonce,
        tips,
    });
    if write_frame(&mut writer, magic, &ours.encode())
        .await
        .is_err()
    {
        return;
    }
    let hello = match timeout(
        shared.config.handshake_timeout,
        read_frame(&mut reader, magic),
    )
    .await
    {
        Ok(Ok(bytes)) => match VoltMessage::decode(&bytes) {
            Ok(VoltMessage::Hello(hello)) => hello,
            _ => {
                shared.ban(addr.ip(), "the first message was not a valid hello");
                return;
            }
        },
        Ok(Err(FrameError::Io(_))) | Err(_) => return,
        Ok(Err(_)) => {
            shared.ban(addr.ip(), "malformed handshake frame");
            return;
        }
    };
    if hello.version != PROTOCOL_VERSION {
        debug!(%addr, version = hello.version, "unsupported protocol version");
        return;
    }
    if hello.genesis != shared.backend.genesis() {
        debug!(%addr, "peer is on a different genesis");
        return;
    }
    if hello.nonce == shared.nonce {
        debug!(%addr, "connected to ourselves");
        return;
    }

    let (tx, mut rx) = mpsc::channel::<VoltMessage>(256);
    let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
    {
        let mut peers = shared.peers.lock();
        if peers.values().any(|p| p.remote_nonce == hello.nonce) {
            debug!(%addr, "already connected to this node");
            return;
        }
        let (in_count, out_count) = {
            let inbound_now = peers.values().filter(|p| p.inbound).count();
            (inbound_now, peers.len() - inbound_now)
        };
        let full = if inbound {
            in_count >= shared.config.max_inbound
        } else {
            out_count >= shared.config.max_outbound
        };
        if full {
            debug!(%addr, "connection limit reached");
            return;
        }
        peers.insert(
            id,
            PeerEntry {
                tx: tx.clone(),
                addr,
                inbound,
                remote_nonce: hello.nonce,
            },
        );
    }
    debug!(%addr, inbound, "peer connected");

    // The writer owns the socket's write half; it ends when every sender is gone.
    let writer_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if write_frame(&mut writer, magic, &message.encode())
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Keep-alive lives in its own task: it must not share a `select!` with the frame reader,
    // because dropping a half-read frame would desynchronise the stream.
    let ping_tx = tx.clone();
    let ping_every = shared.config.ping_interval;
    let ping_task = tokio::spawn(async move {
        let mut tick = interval(ping_every);
        let mut n = 0u64;
        loop {
            tick.tick().await;
            n += 1;
            if ping_tx.send(VoltMessage::Ping(n)).await.is_err() {
                break;
            }
        }
    });

    // Catch up: ask for the tips we lack, and for everything after our newest block.
    let unknown: Vec<VoltHash> = hello
        .tips
        .iter()
        .filter(|tip| !shared.backend.contains(tip))
        .copied()
        .collect();
    if !unknown.is_empty() {
        let wanted = shared.mark_requested(unknown);
        if !wanted.is_empty() {
            let _ = tx.send(VoltMessage::GetBlocks(wanted)).await;
        }
        let _ = tx
            .send(VoltMessage::GetChain(shared.backend.locator()))
            .await;
    }

    let mut limiter = RateLimiter::new(shared.config.max_msgs_per_sec);
    let mut shutdown = shared.shutdown.clone();
    loop {
        let frame = tokio::select! {
            _ = shutdown.changed() => break,
            frame = timeout(shared.config.idle_timeout, read_frame(&mut reader, magic)) => frame,
        };
        let bytes = match frame {
            Err(_) => {
                debug!(%addr, "idle timeout");
                break;
            }
            Ok(Err(FrameError::Io(_))) => break,
            Ok(Err(error)) => {
                shared.ban(addr.ip(), &format!("bad frame: {error}"));
                break;
            }
            Ok(Ok(bytes)) => bytes,
        };

        if !limiter.allow() {
            shared.ban(addr.ip(), "message rate limit exceeded");
            break;
        }
        let message = match VoltMessage::decode(&bytes) {
            Ok(message) => message,
            Err(error) => {
                shared.ban(addr.ip(), &format!("malformed message: {error}"));
                break;
            }
        };

        match handle_message(&shared, &tx, id, addr.ip(), message).await {
            Next::Continue => {}
            Next::Ban(why) => {
                shared.ban(addr.ip(), why);
                break;
            }
        }
    }

    shared.peers.lock().remove(&id);
    ping_task.abort();
    drop(tx);
    let _ = writer_task.await;
    debug!(%addr, "peer disconnected");
}

async fn handle_message(
    shared: &Arc<Shared>,
    tx: &mpsc::Sender<VoltMessage>,
    peer: u64,
    ip: IpAddr,
    message: VoltMessage,
) -> Next {
    match message {
        VoltMessage::Hello(_) => return Next::Ban("a second hello"),
        VoltMessage::Ping(n) => {
            let _ = tx.send(VoltMessage::Pong(n)).await;
        }
        VoltMessage::Pong(_) => {}
        VoltMessage::Inv(hashes) => {
            let unknown: Vec<VoltHash> = hashes
                .into_iter()
                .filter(|hash| !shared.backend.contains(hash))
                .collect();
            let wanted = shared.mark_requested(unknown);
            if !wanted.is_empty() {
                let _ = tx.send(VoltMessage::GetBlocks(wanted)).await;
            }
        }
        VoltMessage::GetBlocks(hashes) => {
            let blocks: Vec<Vec<u8>> = hashes
                .iter()
                .take(MAX_GET_BLOCKS)
                .filter_map(|hash| shared.backend.block(hash))
                .collect();
            send_blocks(tx, blocks).await;
        }
        VoltMessage::GetChain(locator) => {
            let backend = shared.backend.clone();
            let blocks = tokio::task::spawn_blocking(move || {
                backend.blocks_after(&locator, MAX_BLOCKS_PER_MESSAGE)
            })
            .await
            .unwrap_or_default();
            send_blocks(tx, blocks).await;
        }
        VoltMessage::Blocks(blocks) => {
            let full = blocks.len() == MAX_BLOCKS_PER_MESSAGE;
            for bytes in blocks {
                match process_block(shared, peer, ip, tx, bytes).await {
                    Next::Continue => {}
                    other => return other,
                }
            }
            // A full batch means there is probably more: keep catching up.
            if full {
                let _ = tx
                    .send(VoltMessage::GetChain(shared.backend.locator()))
                    .await;
            }
        }
        VoltMessage::NewBlock(bytes) => return process_block(shared, peer, ip, tx, bytes).await,
        VoltMessage::NewTx(bytes) => {
            let backend = shared.backend.clone();
            let relayed = bytes.clone();
            let result = tokio::task::spawn_blocking(move || backend.submit_tx(&bytes)).await;
            match result {
                Ok(Ok(_)) => shared.broadcast(&VoltMessage::NewTx(relayed), Some(peer)),
                // Provably invalid (undecodable, or failing proof verification, which costs us
                // real CPU): punish the sender.
                Ok(Err(SubmitError::Invalid(_))) => return Next::Ban("an invalid transaction"),
                // Merely not acceptable now, for example while the output it spends is still
                // being confirmed: drop it without punishment.
                Ok(Err(SubmitError::Temporary(_))) | Err(_) => {}
            }
        }
    }
    Next::Continue
}

/// Sends blocks in messages that respect both the block count and a byte budget.
async fn send_blocks(tx: &mpsc::Sender<VoltMessage>, blocks: Vec<Vec<u8>>) {
    const BUDGET: usize = 4 * 1024 * 1024;
    let mut batch = Vec::new();
    let mut size = 0;
    for block in blocks {
        if !batch.is_empty()
            && (size + block.len() > BUDGET || batch.len() == MAX_BLOCKS_PER_MESSAGE)
        {
            let _ = tx
                .send(VoltMessage::Blocks(std::mem::take(&mut batch)))
                .await;
            size = 0;
        }
        size += block.len();
        batch.push(block);
    }
    if !batch.is_empty() {
        let _ = tx.send(VoltMessage::Blocks(batch)).await;
    }
}

async fn submit(shared: &Arc<Shared>, block: VoltBlock) -> Result<VoltHash, SubmitError> {
    let backend = shared.backend.clone();
    match tokio::task::spawn_blocking(move || backend.submit_block(block)).await {
        Ok(result) => result,
        Err(error) => Err(SubmitError::Temporary(format!(
            "validation task failed: {error}"
        ))),
    }
}

async fn process_block(
    shared: &Arc<Shared>,
    peer: u64,
    ip: IpAddr,
    tx: &mpsc::Sender<VoltMessage>,
    bytes: Vec<u8>,
) -> Next {
    let Ok(block) = VoltBlock::decode(&bytes) else {
        return Next::Ban("a malformed block");
    };
    let hash = block.hash();
    shared.requested.lock().remove(&hash);
    if shared.backend.contains(&hash) {
        return Next::Continue;
    }

    // Parents first: a block we cannot connect yet waits in the orphan pool.
    let missing: Vec<VoltHash> = block
        .header
        .parents
        .iter()
        .filter(|parent| !shared.backend.contains(parent))
        .copied()
        .collect();
    if !missing.is_empty() {
        {
            let mut orphans = shared.orphans.lock();
            // Evict the oldest until the newcomer fits within both the count and byte budgets.
            let mut held: usize = orphans.values().map(|o| o.bytes.len()).sum();
            while !orphans.is_empty()
                && !orphans.contains_key(&hash)
                && (orphans.len() >= shared.config.max_orphans
                    || held + bytes.len() > shared.config.max_orphan_bytes)
            {
                let oldest = orphans
                    .iter()
                    .min_by_key(|(_, o)| o.seq)
                    .map(|(h, _)| *h)
                    .expect("the pool is not empty");
                if let Some(evicted) = orphans.remove(&oldest) {
                    held -= evicted.bytes.len();
                }
            }
            if bytes.len() <= shared.config.max_orphan_bytes {
                orphans.insert(
                    hash,
                    Orphan {
                        bytes,
                        missing: missing.clone(),
                        from: ip,
                        seq: shared.orphan_seq.fetch_add(1, Ordering::SeqCst),
                    },
                );
            }
        }
        let wanted = shared.mark_requested(missing);
        if !wanted.is_empty() {
            let _ = tx.send(VoltMessage::GetBlocks(wanted)).await;
        }
        return Next::Continue;
    }

    match submit(shared, block).await {
        Ok(accepted) => {
            shared.broadcast(&VoltMessage::Inv(vec![accepted]), Some(peer));
            resolve_orphans(shared).await;
            Next::Continue
        }
        Err(SubmitError::Invalid(reason)) => {
            warn!(%ip, reason, "peer sent an invalid block");
            Next::Ban("an invalid block")
        }
        Err(SubmitError::Temporary(reason)) => {
            debug!(reason, "block dropped for now");
            Next::Continue
        }
    }
}

/// Submits every orphan whose parents have all arrived, repeating until none are ready.
async fn resolve_orphans(shared: &Arc<Shared>) {
    loop {
        let ready: Vec<(VoltHash, Orphan)> = {
            let mut orphans = shared.orphans.lock();
            let ready: Vec<VoltHash> = orphans
                .iter()
                .filter(|(_, o)| o.missing.iter().all(|p| shared.backend.contains(p)))
                .map(|(hash, _)| *hash)
                .collect();
            ready
                .into_iter()
                .filter_map(|hash| orphans.remove(&hash).map(|o| (hash, o)))
                .collect()
        };
        if ready.is_empty() {
            return;
        }

        for (hash, orphan) in ready {
            if shared.backend.contains(&hash) {
                continue;
            }
            let Ok(block) = VoltBlock::decode(&orphan.bytes) else {
                continue;
            };
            // Parents may have been missing more than the first time; re-check.
            if block
                .header
                .parents
                .iter()
                .any(|p| !shared.backend.contains(p))
            {
                continue;
            }
            match submit(shared, block).await {
                Ok(accepted) => shared.broadcast(&VoltMessage::Inv(vec![accepted]), None),
                Err(SubmitError::Invalid(reason)) => {
                    shared.ban(
                        orphan.from,
                        &format!("an invalid block, once connected: {reason}"),
                    );
                }
                Err(SubmitError::Temporary(_)) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rate_limiter_allows_a_burst_then_throttles() {
        let mut limiter = RateLimiter::new(10);
        let allowed = (0..100).filter(|_| limiter.allow()).count();
        // A burst of twice the rate, plus whatever refilled while the loop ran.
        assert!((20..=25).contains(&allowed), "allowed {allowed}");
    }
}
