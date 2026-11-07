//! A full Voltcash node: persistent consensus, a mempool, TCP peers and a miner.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tracing::{debug, info, warn};
use volt_consensus::{Consensus, ConsensusConfig, ConsensusError, Mempool, MempoolError};
use volt_core::{
    constants::{MAX_BLOCK_PARENTS, MEMPOOL_MAX_TXS},
    DevTxDecoder, Economics, NoVerification, TxDecoder, TxVerifier, VoltBlock, VoltHash,
};
use volt_crypto::{meets_target, PowHasher};
use volt_network::{
    start, ChainBackend, P2pConfig, P2pHandle, SubmitError, MAX_BLOCKS_PER_MESSAGE,
};
use volt_state::ApplyRules;
use volt_storage::{PersistentConsensus, StorageError, SyncPolicy};
use zebra_chain::{block::Height, transparent::Address};

/// Everything needed to start a node.
#[derive(Clone)]
pub struct NodeConfig {
    /// The directory holding the block log.
    pub data_dir: PathBuf,
    /// Peer-to-peer settings.
    pub p2p: P2pConfig,
    /// The monetary policy.
    pub economics: Economics,
    /// How many chain steps a coinbase output must age before it can be spent.
    pub coinbase_maturity: u32,
    /// The proof-of-work function.
    pub pow: Arc<dyn PowHasher>,
    /// Verifies transaction proofs and signatures.
    pub verifier: Arc<dyn TxVerifier>,
    /// Decodes transactions.
    pub decoder: Arc<dyn TxDecoder>,
    /// Where this node's mining rewards go (at most 100 are used per block).
    pub miner_addresses: Vec<Address>,
    /// The most rollup batches this node packs into a block it mines.
    pub batches_per_block: usize,
    /// The genesis timestamp. It identifies the network, so every node must agree.
    pub genesis_timestamp_ms: u64,
    /// When appended blocks are forced to disk.
    pub sync: SyncPolicy,
    /// The time, in milliseconds, written into the blocks this node mines. Production uses the
    /// system clock. Tests inject a paced clock to keep the difficulty adjustment stable.
    pub mining_clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl NodeConfig {
    /// A devnet node: proof-less `DevTx` transactions, no verification and no maturity.
    pub fn devnet(
        data_dir: PathBuf,
        pow: Arc<dyn PowHasher>,
        miner_addresses: Vec<Address>,
    ) -> Self {
        Self {
            data_dir,
            p2p: P2pConfig::default(),
            economics: Economics::mainnet(),
            coinbase_maturity: 0,
            pow,
            verifier: Arc::new(NoVerification),
            decoder: Arc::new(DevTxDecoder),
            miner_addresses,
            batches_per_block: 2,
            genesis_timestamp_ms: 0,
            sync: SyncPolicy::Never,
            mining_clock: Arc::new(now_ms),
        }
    }
}

/// A snapshot of a node's state.
#[derive(Clone, Debug)]
pub struct NodeStatus {
    /// The DAG's best tip.
    pub sink: VoltHash,
    /// Blocks in the DAG, genesis included.
    pub dag_blocks: usize,
    /// Blocks accepted into UTXO state.
    pub accepted_blocks: u64,
    /// Unspent outputs.
    pub utxos: usize,
    /// Revealed nullifiers.
    pub nullifiers: usize,
    /// Settled epochs.
    pub epochs_locked: usize,
    /// VOLT permanently locked in the POL reserve, in zatoshis.
    pub pol_locked: i64,
    /// Transactions waiting in the mempool.
    pub mempool: usize,
    /// Connected peers.
    pub peers: usize,
}

struct Inner {
    chain: Mutex<PersistentConsensus>,
    mempool: Mutex<Mempool>,
    config: NodeConfig,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Maps a consensus rejection onto what the network layer does about the sender.
fn classify(error: StorageError) -> SubmitError {
    match error {
        StorageError::Consensus(
            ConsensusError::TimestampInFuture { .. } | ConsensusError::Ghostdag(_),
        ) => SubmitError::Temporary(error.to_string()),
        StorageError::Consensus(_) => SubmitError::Invalid(error.to_string()),
        // A disk or log failure is our problem, not the peer's.
        other => SubmitError::Temporary(other.to_string()),
    }
}

impl Inner {
    /// The height transactions would be mined at, for coinbase maturity.
    fn next_height(chain: &PersistentConsensus) -> Height {
        let step = chain.consensus().state_height() + 2;
        Height(u32::try_from(step).unwrap_or(u32::MAX / 2))
    }

    /// Drops mined transactions from the pool after blocks are accepted into state.
    fn forget_mined(&self, chain: &PersistentConsensus, hashes: &[VoltHash]) {
        let mut mined = Vec::new();
        for hash in hashes {
            let Some(block) = chain.consensus().block(hash) else {
                continue;
            };
            for batch in &block.batches {
                for raw in batch.raw_txs() {
                    if let Ok(tx) = self.config.decoder.decode(raw) {
                        mined.push(tx);
                    }
                }
            }
        }
        self.mempool.lock().remove_confirmed(&mined);
    }
}

impl ChainBackend for Inner {
    fn genesis(&self) -> VoltHash {
        self.chain.lock().arrival_order()[0]
    }

    fn tips(&self) -> Vec<VoltHash> {
        let chain = self.chain.lock();
        chain
            .consensus()
            .dag()
            .tips()
            .take(MAX_BLOCK_PARENTS)
            .copied()
            .collect()
    }

    fn contains(&self, hash: &VoltHash) -> bool {
        self.chain.lock().consensus().dag().contains(hash)
    }

    fn block(&self, hash: &VoltHash) -> Option<Vec<u8>> {
        self.chain
            .lock()
            .consensus()
            .block(hash)
            .map(VoltBlock::encode)
    }

    fn locator(&self) -> Vec<VoltHash> {
        let chain = self.chain.lock();
        let order = chain.arrival_order();
        // The newest blocks one by one, then exponentially sparser, always ending at genesis.
        let mut locator = Vec::new();
        let (mut step, mut index) = (1usize, order.len());
        while index > 0 && locator.len() < 40 {
            index -= 1;
            locator.push(order[index]);
            if locator.len() > 10 {
                step *= 2;
            }
            index = index.saturating_sub(step - 1);
        }
        if locator.last() != Some(&order[0]) {
            locator.push(order[0]);
        }
        locator
    }

    fn blocks_after(&self, locator: &[VoltHash], max: usize) -> Vec<Vec<u8>> {
        let chain = self.chain.lock();
        let anchor = locator
            .iter()
            .filter_map(|hash| chain.position(hash))
            .max()
            .unwrap_or(0);
        chain.arrival_order()[anchor + 1..]
            .iter()
            .take(max.min(MAX_BLOCKS_PER_MESSAGE))
            .filter_map(|hash| chain.consensus().block(hash).map(VoltBlock::encode))
            .collect()
    }

    fn submit_block(&self, block: VoltBlock) -> Result<VoltHash, SubmitError> {
        let mut chain = self.chain.lock();
        let outcome = chain.submit_block(block, now_ms()).map_err(classify)?;
        if let Some(report) = &outcome.chain {
            self.forget_mined(&chain, &report.accepted);
        }
        Ok(outcome.hash)
    }

    fn submit_tx(&self, bytes: &[u8]) -> Result<VoltHash, SubmitError> {
        let tx = self
            .config
            .decoder
            .decode(bytes)
            .map_err(|e| SubmitError::Invalid(e.to_string()))?;
        let txid = tx.txid();

        let chain = self.chain.lock();
        let rules = ApplyRules {
            verifier: self.config.verifier.as_ref(),
            coinbase_maturity: self.config.coinbase_maturity,
        };
        self.mempool
            .lock()
            .admit(
                tx,
                chain.consensus().utxos(),
                Self::next_height(&chain),
                &rules,
            )
            .map_err(|e: MempoolError| match e {
                // Proof failures and coinbases are provable misbehavior and cost us CPU.
                MempoolError::Invalid(volt_state::StateError::Verification(_))
                | MempoolError::Coinbase => SubmitError::Invalid(e.to_string()),
                // Everything else (missing inputs, conflicts, a full pool, ...) can be innocent.
                other => SubmitError::Temporary(other.to_string()),
            })?;
        Ok(txid)
    }
}

/// A running node.
pub struct Node {
    inner: Arc<Inner>,
    p2p: P2pHandle,
}

impl Node {
    /// Opens the block log (replaying it), then starts listening and connecting to seeds.
    pub async fn start(config: NodeConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("cannot create {}", config.data_dir.display()))?;
        let log_path = config.data_dir.join("blocks.log");

        let consensus_config = ConsensusConfig {
            economics: config.economics,
            verifier: config.verifier.clone(),
            coinbase_maturity: config.coinbase_maturity,
        };
        let (chain, report) = PersistentConsensus::open(
            &log_path,
            Consensus::genesis_block(config.genesis_timestamp_ms),
            config.pow.clone(),
            config.decoder.clone(),
            consensus_config,
            config.sync,
        )
        .with_context(|| format!("cannot open the block log {}", log_path.display()))?;
        info!(
            replayed = report.records,
            repaired_bytes = report.truncated_bytes,
            "node state restored"
        );

        let p2p_config = config.p2p.clone();
        let inner = Arc::new(Inner {
            chain: Mutex::new(chain),
            mempool: Mutex::new(Mempool::new(MEMPOOL_MAX_TXS, 100 * 1024 * 1024)),
            config,
        });
        let p2p = start(p2p_config, inner.clone())
            .await
            .context("cannot start the peer-to-peer layer")?;
        Ok(Self { inner, p2p })
    }

    /// The peer-to-peer address this node listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.p2p.local_addr()
    }

    /// Connects to a peer in the background.
    pub fn connect(&self, addr: SocketAddr) {
        self.p2p.connect(addr);
    }

    /// A snapshot of the node's state.
    pub fn status(&self) -> NodeStatus {
        let chain = self.inner.chain.lock();
        let consensus = chain.consensus();
        NodeStatus {
            sink: consensus.sink(),
            dag_blocks: consensus.dag().len(),
            accepted_blocks: consensus.accepted_blocks(),
            utxos: consensus.utxos().len(),
            nullifiers: consensus.utxos().nullifier_count(),
            epochs_locked: consensus.reserve().settlements().len(),
            pol_locked: consensus.reserve().locked().zatoshis(),
            mempool: self.inner.mempool.lock().len(),
            peers: self.p2p.peer_count(),
        }
    }

    /// Whether `outpoint` is currently unspent.
    pub fn is_unspent(&self, outpoint: &zebra_chain::transparent::OutPoint) -> bool {
        self.inner
            .chain
            .lock()
            .consensus()
            .utxos()
            .contains(outpoint)
    }

    /// Returns the block with this hash, if known.
    pub fn block(&self, hash: &VoltHash) -> Option<VoltBlock> {
        self.inner.chain.lock().consensus().block(hash).cloned()
    }

    /// Validates a transaction, pools it and relays it to peers.
    pub fn submit_tx(&self, bytes: Vec<u8>) -> Result<VoltHash, SubmitError> {
        let txid = self.inner.submit_tx(&bytes)?;
        self.p2p.broadcast_tx(bytes);
        Ok(txid)
    }

    /// Mines one block on top of the current tips, submits it and announces it.
    ///
    /// The consensus lock is not held while searching for a nonce, so the node keeps processing
    /// peers' blocks meanwhile. Returns `None` if no nonce was found within `max_attempts`.
    pub fn mine_one(&self, max_attempts: u64) -> Result<Option<VoltHash>> {
        let config = &self.inner.config;

        let (template, seed) = {
            let chain = self.inner.chain.lock();
            let consensus = chain.consensus();
            let ctx = consensus.template_context();
            let txs = self
                .inner
                .mempool
                .lock()
                .take_batches(config.batches_per_block);
            let (batches, _) = Consensus::pack_batches(&txs)?;
            let template = consensus.build_template(
                &ctx,
                batches,
                &config.miner_addresses,
                (config.mining_clock)().max(ctx.min_timestamp_ms),
            )?;
            (template, ctx.seed)
        };

        let mut block = template;
        for nonce in 0..max_attempts {
            block.header.nonce = nonce;
            let hash = config.pow.pow_hash(&seed, &block.header.encode())?;
            if meets_target(&hash, block.header.bits) {
                let accepted = {
                    let mut chain = self.inner.chain.lock();
                    let outcome = chain.submit_block(block, now_ms())?;
                    if let Some(report) = &outcome.chain {
                        self.inner.forget_mined(&chain, &report.accepted);
                    }
                    outcome.hash
                };
                debug!(%accepted, "mined a block");
                self.p2p.announce_block(accepted);
                return Ok(Some(accepted));
            }
        }
        warn!("no valid nonce within the attempt budget");
        Ok(None)
    }

    /// Stops the node.
    pub async fn shutdown(self) {
        self.p2p.shutdown().await;
    }
}
