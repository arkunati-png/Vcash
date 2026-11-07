//! Consensus errors.

use thiserror::Error;
use volt_core::{BatchError, BlockError, VoltHash};
use volt_crypto::PowError;
use volt_state::{PolError, StateError};

use crate::{coinbase::CoinbaseError, epoch::EpochError, ghostdag::GhostdagError};

/// Why a block, or a chain update, was rejected.
#[derive(Debug, Error)]
pub enum ConsensusError {
    /// The block failed the DAG rules.
    #[error(transparent)]
    Ghostdag(#[from] GhostdagError),

    /// The block's structure is malformed.
    #[error(transparent)]
    Block(#[from] BlockError),

    /// A rollup batch is invalid.
    #[error(transparent)]
    Batch(#[from] BatchError),

    /// The coinbase breaks the payout rules.
    #[error(transparent)]
    Coinbase(#[from] CoinbaseError),

    /// Epoch accounting failed.
    #[error(transparent)]
    Epoch(#[from] EpochError),

    /// The POL reserve refused a settlement.
    #[error(transparent)]
    Pol(#[from] PolError),

    /// The PoW engine failed.
    #[error(transparent)]
    Pow(#[from] PowError),

    /// State could not be reverted or applied.
    #[error(transparent)]
    State(#[from] StateError),

    /// The block has no parents but is not the genesis block.
    #[error("block has no parents")]
    NoParents,

    /// A parent is unknown.
    #[error("unknown parent {0}")]
    UnknownParent(VoltHash),

    /// The genesis block is malformed.
    #[error("invalid genesis block: {0}")]
    InvalidGenesis(&'static str),

    /// The header's difficulty does not match the adjustment algorithm.
    #[error("wrong difficulty bits: expected {expected:#x}, got {got:#x}")]
    WrongBits {
        /// The value the difficulty adjustment requires.
        expected: u32,
        /// The value in the header.
        got: u32,
    },

    /// The header's difficulty bits are not a valid target.
    #[error("invalid difficulty bits {0:#x}")]
    InvalidBits(u32),

    /// The block is older than one of its parents.
    #[error("timestamp {got} ms is earlier than a parent's {parent} ms")]
    TimestampTooEarly {
        /// The header timestamp.
        got: u64,
        /// The latest parent timestamp.
        parent: u64,
    },

    /// The block is too far in the future.
    #[error("timestamp {got} ms is more than the allowed drift past {now} ms")]
    TimestampInFuture {
        /// The header timestamp.
        got: u64,
        /// The local time.
        now: u64,
    },

    /// The PoW hash does not meet the target.
    #[error("proof of work does not meet the target")]
    InsufficientPow,

    /// A header commitment does not match the block body.
    #[error("{0} commitment mismatch")]
    CommitmentMismatch(&'static str),

    /// The block has too many batches.
    #[error("block has {0} batches")]
    TooManyBatches(usize),

    /// A fee sum is out of range.
    #[error("fee total out of range")]
    FeeOverflow,

    /// Switching to the new best chain would revert a final step.
    #[error("reorg would revert one of the {finalized_steps} final chain steps")]
    ReorgPastFinality {
        /// How many leading chain steps are final.
        finalized_steps: usize,
    },
}
