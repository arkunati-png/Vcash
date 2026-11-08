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
    BatchableTx, DevTxDecoder, Economics, NoVerification, TxDecoder, TxVerifier, VoltBlock,
    VoltHash,
};
use volt_crypto::{meets_target, PowHasher};
use volt_network::{
    start, ChainBackend, P2pConfig, P2pHandle, SubmitError, MAX_BLOCKS_PER_MESSAGE,
};
use volt_state::{ApplyRules, ShieldedError};
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
    /// The easiest target the network allows, committed in the genesis block. The production
    /// value takes about 512 RandomX hashes per block; [`NodeConfig::with_easy_pow`] makes it
    /// about 8, for tests and local chains.
    pub pow_limit_bits: u32,
    /// How much of the block log to check again on start. Checking everything takes one RandomX
    /// hash per block and every proof again.
    pub replay: volt_storage::ReplayMode,
    /// When appended blocks are forced to disk.
    pub sync: SyncPolicy,
    /// The time, in milliseconds, written into the blocks this node mines. Production uses the
    /// system clock. Tests inject a paced clock to keep the difficulty adjustment stable.
    pub mining_clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl NodeConfig {
    /// Makes blocks about 64 times easier to find (still RandomX), for tests and local chains.
    /// This is a different network from the production one: the limit is part of the genesis
    /// hash.
    pub fn with_easy_pow(mut self) -> Self {
        self.pow_limit_bits = volt_core::constants::TEST_POW_LIMIT_BITS;
        self
    }

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
            pow_limit_bits: volt_core::constants::POW_LIMIT_BITS,
            replay: volt_storage::ReplayMode::DEFAULT_TRUSTING,
            sync: SyncPolicy::Never,
            mining_clock: Arc::new(now_ms),
        }
    }
}

/// One shielded transaction as a light wallet sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepTx {
    /// The transaction id.
    pub txid: VoltHash,
    /// The nullifiers it reveals.
    pub nullifiers: Vec<[u8; 32]>,
    /// The Sapling note commitments it creates, in tree order.
    pub sapling_commitments: Vec<[u8; 32]>,
    /// The Sapling outputs with their encrypted notes, in the same order. Empty for devnet
    /// transactions, which have no encrypted notes.
    pub sapling_outputs: Vec<volt_core::SaplingOutputData>,
}

/// One chain step as a light wallet sees it: the shielded transactions applied, in the exact
/// order they were applied, and the Sapling tree root and size once the step is done.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepFeed {
    /// The step's position in the chain. Genesis is step 0.
    pub index: usize,
    /// The chain block that closes the step. A wallet that sees this change knows there was a reorg.
    pub block: VoltHash,
    /// The Sapling tree root after the step.
    pub sapling_root: [u8; 32],
    /// The number of Sapling notes after the step.
    pub sapling_notes: u64,
    /// The shielded transactions of the step, in application order.
    pub txs: Vec<StepTx>,
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
    /// The Sapling note commitment tree root.
    pub sapling_root: [u8; 32],
    /// The Orchard note commitment tree root.
    pub orchard_root: [u8; 32],
    /// Value in the Sapling pool, in zatoshis.
    pub sapling_pool: i128,
    /// Value in the Orchard pool, in zatoshis.
    pub orchard_pool: i128,
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
        // A block containing a transaction with an unknown anchor, an unsupported pool, would be
        // rejected whole, so refuse it up front. A missing anchor may just not have arrived yet.
        chain
            .consensus()
            .check_tx_anchors(tx.as_ref())
            .map_err(|e| match e {
                ShieldedError::UnsupportedPool(_) => SubmitError::Invalid(e.to_string()),
                other => SubmitError::Temporary(other.to_string()),
            })?;
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
        let (chain, report) = PersistentConsensus::open_with(
            &log_path,
            Consensus::genesis_block_with_limit(config.genesis_timestamp_ms, config.pow_limit_bits),
            config.pow.clone(),
            config.decoder.clone(),
            consensus_config,
            config.sync,
            config.replay,
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
            sapling_root: consensus.shielded().sapling_root(),
            orchard_root: consensus.shielded().orchard_root(),
            sapling_pool: consensus.shielded().sapling_pool(),
            orchard_pool: consensus.shielded().orchard_pool(),
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

    /// Every unspent output locked by `script`, with its value in zatoshis.
    pub fn unspent_for(
        &self,
        script: &zebra_chain::transparent::Script,
    ) -> Vec<(zebra_chain::transparent::OutPoint, i64)> {
        self.inner
            .chain
            .lock()
            .consensus()
            .utxos()
            .unspent_for_script(script)
    }

    /// The newest `count` blocks in the order this node received them, newest first, with their
    /// position in that order, plus the total number of blocks.
    pub fn recent_blocks(&self, count: usize) -> (usize, Vec<(usize, VoltBlock)>) {
        let chain = self.inner.chain.lock();
        let order = chain.arrival_order();
        let blocks = order
            .iter()
            .enumerate()
            .rev()
            .take(count)
            .filter_map(|(i, hash)| chain.consensus().block(hash).map(|b| (i, b.clone())))
            .collect();
        (order.len(), blocks)
    }

    /// A block and its position in arrival order.
    pub fn block_with_index(&self, hash: &VoltHash) -> Option<(usize, VoltBlock)> {
        let chain = self.inner.chain.lock();
        let index = chain.position(hash)?;
        chain.consensus().block(hash).map(|b| (index, b.clone()))
    }

    /// Up to `max` chain steps from step `from`, and the total number of steps.
    ///
    /// This is the feed a light wallet scans. Appending the commitments of every step's
    /// transactions in order reproduces each step's `sapling_root`.
    pub fn chain_steps(&self, from: usize, max: usize) -> (usize, Vec<StepFeed>) {
        let chain = self.inner.chain.lock();
        let consensus = chain.consensus();
        let steps = consensus
            .step_views(from, max)
            .into_iter()
            .map(|view| {
                let txs = view
                    .accepted
                    .iter()
                    .filter_map(|hash| consensus.block_txs(hash))
                    .flat_map(|batches| batches.iter().flatten())
                    .filter_map(|tx| {
                        let nullifiers = tx.nullifiers();
                        let sapling_commitments = tx.sapling_commitment_bytes();
                        (!nullifiers.is_empty() || !sapling_commitments.is_empty()).then(|| {
                            StepTx {
                                txid: tx.txid(),
                                nullifiers,
                                sapling_outputs: tx.sapling_output_data(),
                                sapling_commitments,
                            }
                        })
                    })
                    .collect();
                StepFeed {
                    index: view.index,
                    block: view.block,
                    sapling_root: view.sapling_root,
                    sapling_notes: view.sapling_notes,
                    txs,
                }
            })
            .collect();
        (consensus.step_count(), steps)
    }

    /// Every Sapling note commitment in the blocks this node holds, in the order received.
    ///
    /// Devnet wallets read their notes from these. It scans the whole chain, so it is not for
    /// consensus.
    pub fn sapling_commitments(&self) -> Vec<[u8; 32]> {
        let chain = self.inner.chain.lock();
        let mut found = Vec::new();
        for hash in chain.arrival_order() {
            let Some(block) = chain.consensus().block(hash) else {
                continue;
            };
            for raw in block.batches.iter().flat_map(|b| b.raw_txs()) {
                if let Ok(tx) = self.inner.config.decoder.decode(raw) {
                    found.extend(tx.sapling_commitment_bytes());
                }
            }
        }
        found
    }

    /// Whether this nullifier has been revealed on chain.
    pub fn has_nullifier(&self, nullifier: &[u8; 32]) -> bool {
        self.inner
            .chain
            .lock()
            .consensus()
            .utxos()
            .has_nullifier(nullifier)
    }

    /// Finds a transaction by id: the hash of the block holding it and its raw bytes.
    pub fn find_tx(&self, txid: &VoltHash) -> Option<(VoltHash, Vec<u8>)> {
        let chain = self.inner.chain.lock();
        for hash in chain.arrival_order().iter().rev() {
            let Some(block) = chain.consensus().block(hash) else {
                continue;
            };
            for raw in block.batches.iter().flat_map(|b| b.raw_txs()) {
                if let Ok(tx) = self.inner.config.decoder.decode(raw) {
                    if tx.txid() == *txid {
                        return Some((*hash, raw.clone()));
                    }
                }
            }
        }
        None
    }

    /// Decodes a transaction with this node's decoder.
    pub fn decode_tx(&self, raw: &[u8]) -> Option<Arc<dyn BatchableTx>> {
        self.inner.config.decoder.decode(raw).ok()
    }

    /// The height a transaction submitted now would be mined at, and how many chain steps a
    /// coinbase output must age before it can be spent.
    pub fn spend_context(&self) -> (u32, u32) {
        let chain = self.inner.chain.lock();
        (
            Inner::next_height(&chain).0,
            self.inner.config.coinbase_maturity,
        )
    }

    /// Every unspent output locked by `script` with its value and whether it can be spent in the
    /// next block (a coinbase output has to age first).
    pub fn spendable_for(
        &self,
        script: &zebra_chain::transparent::Script,
    ) -> Vec<(zebra_chain::transparent::OutPoint, i64, bool)> {
        let chain = self.inner.chain.lock();
        let next = Inner::next_height(&chain).0;
        let maturity = self.inner.config.coinbase_maturity;
        let utxos = chain.consensus().utxos();
        utxos
            .unspent_for_script(script)
            .into_iter()
            .filter_map(|(outpoint, value)| {
                let utxo = utxos.get(&outpoint)?;
                let age = next.saturating_sub(utxo.height.0);
                Some((outpoint, value, !utxo.from_coinbase || age >= maturity))
            })
            .collect()
    }

    /// The addresses this node's mining rewards are paid to.
    pub fn miner_addresses(&self) -> &[Address] {
        &self.inner.config.miner_addresses
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

    /// An unmined block on the current tips, paying `miners`, and the RandomX key to mine it
    /// under. The mempool is left alone: its transactions leave only when a block holding them
    /// is accepted. This is what a stratum miner is given.
    pub fn mining_template(
        &self,
        miners: &[zebra_chain::transparent::Address],
    ) -> Result<(VoltBlock, [u8; 32])> {
        let config = &self.inner.config;
        let chain = self.inner.chain.lock();
        let consensus = chain.consensus();
        let ctx = consensus.template_context();
        let txs = self
            .inner
            .mempool
            .lock()
            .best_batches(config.batches_per_block);
        let (batches, _) = Consensus::pack_batches(&txs)?;
        let template = consensus.build_template(
            &ctx,
            batches,
            miners,
            (config.mining_clock)().max(ctx.min_timestamp_ms),
        )?;
        Ok((template, ctx.seed))
    }

    /// The proof-of-work function this node verifies with.
    pub fn pow(&self) -> Arc<dyn PowHasher> {
        self.inner.config.pow.clone()
    }

    /// Submits a block somebody else found, and announces it to peers.
    pub fn submit_found_block(&self, block: VoltBlock) -> Result<VoltHash> {
        let accepted = {
            let mut chain = self.inner.chain.lock();
            let outcome = chain.submit_block(block, now_ms())?;
            if let Some(report) = &outcome.chain {
                self.inner.forget_mined(&chain, &report.accepted);
            }
            outcome.hash
        };
        self.p2p.announce_block(accepted);
        Ok(accepted)
    }

    /// Mines one block on top of the current tips, submits it and announces it.
    ///
    /// The consensus lock is not held while searching for a nonce, so the node keeps processing
    /// peers' blocks meanwhile. Returns `None` if no nonce was found within `max_attempts`.
    pub fn mine_one(&self, max_attempts: u64) -> Result<Option<VoltHash>> {
        self.mine_one_to(None, max_attempts)
    }

    /// Like [`Node::mine_one`], but the reward goes to `miners` instead of this node's own
    /// addresses when they are given.
    pub fn mine_one_to(
        &self,
        miners: Option<&[zebra_chain::transparent::Address]>,
        max_attempts: u64,
    ) -> Result<Option<VoltHash>> {
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
                miners.unwrap_or(&config.miner_addresses),
                (config.mining_clock)().max(ctx.min_timestamp_ms),
            )?;
            (template, ctx.seed)
        };

        let mut block = template;
        let commitment = block.header.pow_commitment();
        for nonce in 0..max_attempts {
            block.header.nonce = nonce;
            let blob = volt_core::pow_blob_for(&commitment, nonce);
            let hash = config.pow.pow_hash(&seed, &blob)?;
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
