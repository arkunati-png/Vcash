//! Voltcash state.
//!
//! - [`RamUtxoStore`]: a sharded in-memory UTXO and nullifier set built on `dashmap`, so state
//!   validation never touches the disk.
//! - [`PolReserve`]: the protocol-owned liquidity reserve. It can only grow.

mod pol;
mod utxo;

pub use pol::{EpochSettlement, PolError, PolReserve};
pub use utxo::{ApplyRules, BlockUndo, RamUtxoStore, StateError};
