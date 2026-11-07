//! Core Voltcash ($VOLT) data structures.
//!
//! This crate is sync-only and depends only on `zebra-chain` for the Zcash
//! primitives Voltcash reuses: [`Amount`](zebra_chain::amount::Amount),
//! transparent [`OutPoint`](zebra_chain::transparent::OutPoint)s, outputs,
//! addresses and [`CompactDifficulty`](zebra_chain::work::difficulty::CompactDifficulty).
//!
//! It defines:
//! - consensus [`constants`] (GHOSTDAG `k`, block interval, batching, epochs, fees),
//! - the dual-tier fee schedule ([`fee::calculate_tx_fee`]),
//! - the [`BatchableTx`] abstraction over transaction formats,
//! - the 10-to-1 [`RollupBatch`] container,
//! - DAG [`VoltBlock`]s, their headers and coinbases,
//! - a bounded binary [`codec`] used for consensus serialization.

pub mod batch;
pub mod block;
pub mod codec;
pub mod constants;
pub mod dev_tx;
pub mod fee;
pub mod hash;
pub mod tx;

pub use batch::{BatchError, RollupBatch};
pub use block::{BlockError, Coinbase, Payout, VoltBlock, VoltHeader};
pub use codec::CodecError;
pub use dev_tx::{DevTx, DevTxDecoder};
pub use fee::{calculate_tx_fee, fee_for_kind};
pub use hash::{merkle_root, VoltHash};
pub use tx::{BatchableTx, Nullifier, TxDecoder, TxKind, ZebraTxDecoder};
