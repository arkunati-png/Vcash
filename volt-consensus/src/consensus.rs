//! The consensus engine: GHOSTDAG, validation, state and POL settlement wired together.

use std::{collections::HashMap, sync::Arc};

use tracing::{debug, warn};
use volt_core::{
    constants::POW_LIMIT_BITS, BatchableTx, Coinbase, RollupBatch, TxDecoder, VoltBlock, VoltHash,
    VoltHeader,
};
use volt_crypto::{meets_target, PowHasher};
use volt_state::{PolReserve, RamUtxoStore};
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
    /// Builds the genesis block for a network started at `timestamp_ms`.
    pub fn genesis_block(timestamp_ms: u64) -> VoltBlock {
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
                bits: POW_LIMIT_BITS,
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
    ) -> Result<Self, ConsensusError> {
        let validator = BlockValidator::new(pow, decoder);
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
            chain: ChainState::new(hash),
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

    /// The epoch in progress.
    pub fn epoch(&self) -> &EpochAccumulator {
        self.chain.epoch()
    }

    /// The number of blocks accepted into state.
    pub fn accepted_blocks(&self) -> u64 {
        self.chain.accepted_blocks()
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
            parents,
            min_timestamp_ms,
        }
    }

    /// Packs transactions into 10-to-1 rollup batches, discarding any remainder.
    ///
    /// Returns the batches and the number of transactions left over.
    pub fn pack_batches(
        txs: &[Arc<dyn BatchableTx>],
    ) -> Result<(Vec<RollupBatch>, usize), ConsensusError> {
        let size = volt_core::constants::BATCH_SIZE;
        let batches = txs
            .chunks_exact(size)
            .map(RollupBatch::pack)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((batches, txs.len() % size))
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
        let coinbase = build_coinbase(fees, miners, extra)?;

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
        for attempt in 0..max_attempts {
            block.header.nonce = start_nonce.wrapping_add(attempt);
            let hash = self
                .validator
                .pow()
                .pow_hash(seed, &block.header.encode())?;
            if meets_target(&hash, block.header.bits) {
                return Ok(Some(block));
            }
        }
        Ok(None)
    }
}
