//! Durable storage for a Voltcash node.
//!
//! The chain state (the DAG, GHOSTDAG colors, the UTXO set, epochs and the POL reserve) is a pure,
//! deterministic function of the blocks and their arrival order. So the only thing that has to be
//! durable is the blocks themselves, and everything else is rebuilt by replaying them.
//!
//! - [`BlockLog`] is an append-only file of checksummed block records. A torn final record, the
//!   usual result of a crash mid-write, is detected and truncated on open. Corruption anywhere
//!   else is an error, never silently skipped.
//! - [`PersistentConsensus`] wraps a [`volt_consensus::Consensus`]: a block is validated first and
//!   written to the log only if it is valid, and reopening replays the log through full
//!   validation, so a tampered or stale log cannot smuggle in invalid state.
//!
//! Replay costs time proportional to the chain. A snapshot of the UTXO set would speed up
//! restarts and is a natural next step; the log itself stays the source of truth.

mod log;
mod persistent;

pub use log::{BlockLog, LogError, OpenReport, SyncPolicy};
pub use persistent::{PersistentConsensus, StorageError};
