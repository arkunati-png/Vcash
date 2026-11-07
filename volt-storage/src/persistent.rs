//! A consensus engine whose blocks survive restarts.

use std::{collections::HashMap, path::Path, sync::Arc};

use thiserror::Error;
use tracing::info;
use volt_consensus::{Consensus, ConsensusConfig, ConsensusError, SubmitOutcome};
use volt_core::{BlockError, TxDecoder, VoltBlock, VoltHash};
use volt_crypto::PowHasher;

use crate::log::{BlockLog, LogError, OpenReport, SyncPolicy};

/// Errors from a persistent engine.
#[derive(Debug, Error)]
pub enum StorageError {
    /// The block log failed.
    #[error(transparent)]
    Log(#[from] LogError),

    /// A block was rejected by consensus.
    #[error(transparent)]
    Consensus(#[from] ConsensusError),

    /// A stored block could not be decoded.
    #[error("stored block {index} is malformed: {source}")]
    BadRecord {
        /// The record's position in the log, starting at zero.
        index: u64,
        /// Why it failed to decode.
        source: BlockError,
    },

    /// A stored block no longer passes consensus.
    ///
    /// Either the log was edited, or the consensus rules changed since it was written.
    #[error("stored block {index} was rejected during replay: {source}")]
    ReplayRejected {
        /// The record's position in the log, starting at zero.
        index: u64,
        /// Why consensus rejected it.
        source: ConsensusError,
    },
}

/// A [`Consensus`] engine backed by a [`BlockLog`].
#[derive(Debug)]
pub struct PersistentConsensus {
    consensus: Consensus,
    log: BlockLog,
    /// Every block in the order it was accepted, genesis first. Each block comes after its
    /// parents, so a peer can be served a contiguous slice of it during catch-up.
    order: Vec<VoltHash>,
    positions: HashMap<VoltHash, usize>,
}

impl PersistentConsensus {
    /// Opens the log at `path` (creating it for `genesis` if needed) and replays it.
    ///
    /// Every stored block is run through full validation again, in the order it was stored.
    pub fn open(
        path: impl AsRef<Path>,
        genesis: VoltBlock,
        pow: Arc<dyn PowHasher>,
        decoder: Arc<dyn TxDecoder>,
        config: ConsensusConfig,
        sync: SyncPolicy,
    ) -> Result<(Self, OpenReport), StorageError> {
        let genesis_hash = genesis.hash();
        let (log, report) = BlockLog::open(path, &genesis_hash, sync)?;
        let mut consensus = Consensus::new(genesis, pow, decoder, config)?;
        let mut order = vec![genesis_hash];
        let mut positions = HashMap::from([(genesis_hash, 0)]);

        for (index, record) in log.records()?.enumerate() {
            let index = index as u64; // lossless: a usize index fits in u64
            let block = VoltBlock::decode(&record?)
                .map_err(|source| StorageError::BadRecord { index, source })?;
            // Replay has no wall clock: a block that was valid when stored stays valid, so the
            // future-timestamp rule is waived by passing the largest possible `now`.
            let outcome = consensus
                .submit_block(block, u64::MAX)
                .map_err(|source| StorageError::ReplayRejected { index, source })?;
            positions.insert(outcome.hash, order.len());
            order.push(outcome.hash);
        }

        info!(
            records = report.records,
            truncated_bytes = report.truncated_bytes,
            blocks = consensus.dag().len(),
            accepted = consensus.accepted_blocks(),
            "block log replayed"
        );
        Ok((
            Self {
                consensus,
                log,
                order,
                positions,
            },
            report,
        ))
    }

    /// Validates `block` and, only if it is valid, appends it to the log.
    ///
    /// An invalid block never reaches the log. If the append itself fails, the block has already
    /// been applied in memory, so the caller should treat that as fatal and restart: the next
    /// open replays the log and discards the unlogged block.
    pub fn submit_block(
        &mut self,
        block: VoltBlock,
        now_ms: u64,
    ) -> Result<SubmitOutcome, StorageError> {
        let encoded = block.encode();
        let outcome = self.consensus.submit_block(block, now_ms)?;
        self.log.append(&encoded)?;
        self.positions.insert(outcome.hash, self.order.len());
        self.order.push(outcome.hash);
        Ok(outcome)
    }

    /// Every block in the order it was accepted, genesis first.
    pub fn arrival_order(&self) -> &[VoltHash] {
        &self.order
    }

    /// The position of `hash` in [`PersistentConsensus::arrival_order`].
    pub fn position(&self, hash: &VoltHash) -> Option<usize> {
        self.positions.get(hash).copied()
    }

    /// The consensus engine, for queries and for building templates.
    pub fn consensus(&self) -> &Consensus {
        &self.consensus
    }

    /// The block log.
    pub fn log(&self) -> &BlockLog {
        &self.log
    }
}
