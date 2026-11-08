//! The consensus engine: GHOSTDAG, validation, state and POL settlement wired together.

use std::{collections::HashMap, sync::Arc};

use tracing::{debug, warn};
use volt_core::{
    constants::{COINBASE_MATURITY, POW_LIMIT_BITS, TEST_POW_LIMIT_BITS},
    BatchableTx, Coinbase, Economics, NoVerification, RollupBatch, TxDecoder, TxVerifier,
    VoltBlock, VoltHash, VoltHeader,
};
use volt_crypto::{meets_target, PowHasher};
use volt_state::{PolReserve, RamUtxoStore, ShieldedError, ShieldedState};
use zebra_chain::{
    amount::{Amount, NonNegative},
    transparent::Address,
};

use crate::{
    chain::{AdvanceReport, ChainState},
    coinbase::build_coinbase,
    difficulty::{next_bits, pow_seed},
    epoch::EpochAccumulator,
    error::ConsensusError,
    ghostdag::BlockDag,
    validator::{BlockValidator, StoredBlock},
};

/// The result of submitting a block.
#[derive(Debug)]
pub struct SubmitOutcome {
    /// The block hash.
    pub hash: VoltHash,
    /// The block's blue score.
    pub blue_score: u64,
    /// The number of blue blocks in its mergeset.
    pub merged_blues: usize,
    /// The number of red blocks in its mergeset.
    pub merged_reds: usize,
    /// Whether the block is now the DAG's sink (best tip).
    pub is_sink: bool,
    /// What changed in state, if the accepted chain moved.
    pub chain: Option<AdvanceReport>,
    /// Set when the accepted chain could not follow the new sink because that would revert a
    /// final step. The block is still part of the DAG.
    pub chain_blocked_by_finality: bool,
}

/// Settings for a [`Consensus`] engine.
#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    /// The emission schedule and miner / POL split.
    pub economics: Economics,
    /// Verifies transaction proofs and signatures when a block is accepted into state.
    pub verifier: Arc<dyn TxVerifier>,
    /// How many chain steps a coinbase output must age before it can be spent.
    pub coinbase_maturity: u32,
}

impl ConsensusConfig {
    /// A configuration for real transactions: the caller supplies the proof verifier, and the
    /// production schedule and coinbase maturity apply.
    pub fn new(verifier: Arc<dyn TxVerifier>) -> Self {
        Self {
            economics: Economics::mainnet(),
            verifier,
            coinbase_maturity: COINBASE_MATURITY,
        }
    }

    /// A configuration for proof-less devnet transactions: **no proof or signature checking** and
    /// no coinbase maturity. Never use it with real value.
    pub fn devnet() -> Self {
        Self {
            economics: Economics::mainnet(),
            verifier: Arc::new(NoVerification),
            coinbase_maturity: 0,
        }
    }

    /// Replaces the monetary policy.
    pub fn with_economics(mut self, economics: Economics) -> Self {
        self.economics = economics;
        self
    }

    /// Replaces the coinbase maturity.
    pub fn with_coinbase_maturity(mut self, steps: u32) -> Self {
        self.coinbase_maturity = steps;
        self
    }
}

/// What a miner needs to build the next block.
#[derive(Clone, Debug)]
pub struct TemplateContext {
    /// The parents to reference, in canonical order.
    pub parents: Vec<VoltHash>,
    /// The required difficulty bits.
    pub bits: u32,
    /// The RandomX seed for the PoW hash.
    pub seed: [u8; 32],
    /// The earliest allowed timestamp, in milliseconds.
    pub min_timestamp_ms: u64,
    /// The score the reward schedule is evaluated at: the selected parent's blue score.
    pub reward_score: u64,
}

/// The Voltcash consensus engine.
#[derive(Debug)]
pub struct Consensus {
    dag: BlockDag,
    bodies: HashMap<VoltHash, StoredBlock>,
    chain: ChainState,
    validator: BlockValidator,
}

impl Consensus {
    /// Builds the genesis block for a network started at `timestamp_ms`, at the production PoW
    /// limit.
    pub fn genesis_block(timestamp_ms: u64) -> VoltBlock {
        Self::genesis_block_with_limit(timestamp_ms, POW_LIMIT_BITS)
    }

    /// A genesis block for tests and local development chains, with the easy PoW limit. It is a
    /// different network from the production one: the limit is part of the genesis hash.
    pub fn test_genesis_block(timestamp_ms: u64) -> VoltBlock {
        Self::genesis_block_with_limit(timestamp_ms, TEST_POW_LIMIT_BITS)
    }

    /// Builds a genesis block whose PoW limit (its `bits`) is `pow_limit_bits`.
    pub fn genesis_block_with_limit(timestamp_ms: u64, pow_limit_bits: u32) -> VoltBlock {
        let coinbase = Coinbase {
            payouts: Vec::new(),
            pol_contribution: Amount::zero(),
            extra: b"voltcash genesis".to_vec(),
        };
        VoltBlock {
            header: VoltHeader {
                version: 1,
                parents: Vec::new(),
                timestamp_ms,
                bits: pow_limit_bits,
                nonce: 0,
                batches_root: VoltBlock::compute_batches_root(&[]),
                coinbase_root: coinbase.hash(),
            },
            coinbase,
            batches: Vec::new(),
        }
    }

    /// Creates the engine from a genesis block.
    pub fn new(
        genesis: VoltBlock,
        pow: Arc<dyn PowHasher>,
        decoder: Arc<dyn TxDecoder>,
        config: ConsensusConfig,
    ) -> Result<Self, ConsensusError> {
        let validator = BlockValidator::new(pow, decoder, config.economics);
        let stored = validator.validate_genesis(genesis)?;
        let hash = stored.block.hash();

        let mut dag = BlockDag::default();
        dag.add_genesis(
            hash,
            stored.work,
            stored.block.header.timestamp_ms,
            stored.block.header.bits,
        )?;
        let mut bodies = HashMap::new();
        bodies.insert(hash, stored);

        Ok(Self {
            dag,
            bodies,
            chain: ChainState::new(
                hash,
                config.economics,
                config.verifier,
                config.coinbase_maturity,
            ),
            validator,
        })
    }

    /// The block DAG.
    pub fn dag(&self) -> &BlockDag {
        &self.dag
    }

    /// The RAM UTXO store.
    pub fn utxos(&self) -> &RamUtxoStore {
        self.chain.utxos()
    }

    /// The POL reserve.
    pub fn reserve(&self) -> &PolReserve {
        self.chain.reserve()
    }

    /// The shielded state: note commitment trees, valid anchors and pool balances.
    pub fn shielded(&self) -> &ShieldedState {
        self.chain.shielded()
    }

    /// Checks that `tx` uses no unsupported pool and spends against valid shielded anchors.
    ///
    /// A block containing a transaction that fails this is rejected, so a miner or a mempool
    /// should refuse such transactions up front.
    pub fn check_tx_anchors(&self, tx: &dyn BatchableTx) -> Result<(), ShieldedError> {
        self.chain.shielded().check_anchors(tx)
    }

    /// The epoch in progress.
    pub fn epoch(&self) -> &EpochAccumulator {
        self.chain.epoch()
    }

    /// The number of blocks accepted into state.
    pub fn accepted_blocks(&self) -> u64 {
        self.chain.accepted_blocks()
    }

    /// The blue score of the chain block the UTXO state is currently at.
    ///
    /// Coinbase maturity is measured against this height.
    pub fn state_height(&self) -> u64 {
        self.dag
            .get(&self.chain.tip())
            .expect("the chain tip is in the DAG")
            .ghostdag
            .blue_score
    }

    /// The number of chain steps, genesis included.
    pub fn step_count(&self) -> usize {
        self.chain.step_count()
    }

    /// Up to `max` chain steps from step `from`: what a light wallet scans, in consensus order.
    pub fn step_views(&self, from: usize, max: usize) -> Vec<crate::chain::StepView> {
        self.chain.step_views(from, max)
    }

    /// The decoded transactions of a block's batches, in the order they were applied.
    pub fn block_txs(&self, hash: &VoltHash) -> Option<&[Vec<Arc<dyn BatchableTx>>]> {
        self.bodies.get(hash).map(|stored| stored.txs.as_slice())
    }

    /// The block with the given hash, if known.
    pub fn block(&self, hash: &VoltHash) -> Option<&VoltBlock> {
        self.bodies.get(hash).map(|stored| &stored.block)
    }

    /// The DAG's best tip.
    pub fn sink(&self) -> VoltHash {
        self.dag.sink().expect("the DAG always has a genesis block")
    }

    /// Validates `block`, adds it to the DAG and moves the accepted chain to the new sink.
    pub fn submit_block(
        &mut self,
        block: VoltBlock,
        now_ms: u64,
    ) -> Result<SubmitOutcome, ConsensusError> {
        let stored = self.validator.validate(&self.dag, block, now_ms)?;
        let hash = stored.block.hash();
        let header = &stored.block.header;

        let ghostdag = self
            .dag
            .add_block(
                hash,
                &header.parents,
                stored.work,
                header.timestamp_ms,
                header.bits,
            )?
            .clone();
        self.bodies.insert(hash, stored);

        let sink = self.sink();
        let (chain, blocked) = if sink != self.chain.tip() {
            match self.chain.advance(&self.dag, &self.bodies, sink) {
                Ok(report) => (Some(report), false),
                Err(ConsensusError::ReorgPastFinality { finalized_steps }) => {
                    warn!(finalized_steps, %hash, "ignoring a reorg that would revert a final step");
                    (None, true)
                }
                Err(other) => return Err(other),
            }
        } else {
            (None, false)
        };

        if let Some(report) = &chain {
            for (rejected, error) in &report.rejected {
                debug!(%rejected, %error, "blue block not accepted: conflicts with an earlier block");
            }
        }

        Ok(SubmitOutcome {
            hash,
            blue_score: ghostdag.blue_score,
            merged_blues: ghostdag.mergeset_blues.len(),
            merged_reds: ghostdag.mergeset_reds.len(),
            is_sink: sink == hash,
            chain,
            chain_blocked_by_finality: blocked,
        })
    }

    /// The parents, difficulty and PoW seed for the next block.
    pub fn template_context(&self) -> TemplateContext {
        let parents = self.dag.select_parents();
        let selected_parent = self.dag.select_parent(&parents);
        let min_timestamp_ms = parents
            .iter()
            .map(|p| self.dag.get(p).expect("tips are in the DAG").timestamp_ms)
            .max()
            .expect("the DAG always has at least one tip");
        TemplateContext {
            bits: next_bits(&self.dag, &selected_parent),
            seed: pow_seed(&self.dag, &selected_parent),
            reward_score: self
                .dag
                .get(&selected_parent)
                .expect("the selected parent is in the DAG")
                .ghostdag
                .blue_score,
            parents,
            min_timestamp_ms,
        }
    }

    /// Packs transactions into rollup batches of ten, with a smaller last batch for the rest.
    ///
    /// Returns the batches and the number of transactions left over, which is always zero now
    /// that a batch may hold fewer than ten.
    pub fn pack_batches(
        txs: &[Arc<dyn BatchableTx>],
    ) -> Result<(Vec<RollupBatch>, usize), ConsensusError> {
        let size = volt_core::constants::BATCH_SIZE;
        let batches = txs
            .chunks(size)
            .map(RollupBatch::pack)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((batches, 0))
    }

    /// Builds an unmined block: the coinbase pays `miners` half of `emission + fees` and the
    /// POL reserve the other half.
    pub fn build_template(
        &self,
        ctx: &TemplateContext,
        batches: Vec<RollupBatch>,
        miners: &[Address],
        timestamp_ms: u64,
    ) -> Result<VoltBlock, ConsensusError> {
        let mut fees = Amount::<NonNegative>::zero();
        for batch in &batches {
            fees = (fees + batch.total_fees()).map_err(|_| ConsensusError::FeeOverflow)?;
        }

        let timestamp_ms = timestamp_ms.max(ctx.min_timestamp_ms);
        // Distinct extra data keeps coinbase outpoints unique between competing blocks.
        let mut extra = timestamp_ms.to_le_bytes().to_vec();
        extra.extend_from_slice(&ctx.parents[0].0[..8]);
        let coinbase = build_coinbase(
            fees,
            miners,
            extra,
            self.validator.economics(),
            ctx.reward_score,
        )?;

        Ok(VoltBlock {
            header: VoltHeader {
                version: 1,
                parents: ctx.parents.clone(),
                timestamp_ms,
                bits: ctx.bits,
                nonce: 0,
                batches_root: VoltBlock::compute_batches_root(&batches),
                coinbase_root: coinbase.hash(),
            },
            coinbase,
            batches,
        })
    }

    /// Searches nonces from `start_nonce` for a header that meets its target.
    ///
    /// Returns `None` if no solution is found within `max_attempts`.
    pub fn mine(
        &self,
        mut block: VoltBlock,
        seed: &[u8; 32],
        start_nonce: u64,
        max_attempts: u64,
    ) -> Result<Option<VoltBlock>, ConsensusError> {
        let commitment = block.header.pow_commitment();
        for attempt in 0..max_attempts {
            block.header.nonce = start_nonce.wrapping_add(attempt);
            let blob = volt_core::pow_blob_for(&commitment, block.header.nonce);
            let hash = self.validator.pow().pow_hash(seed, &blob)?;
            if meets_target(&hash, block.header.bits) {
                return Ok(Some(block));
            }
        }
        Ok(None)
    }
}
