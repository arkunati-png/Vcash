//! Voltcash state.
//!
//! - [`RamUtxoStore`]: a sharded in-memory UTXO and nullifier set built on `dashmap`, so state
//!   validation never touches the disk.
//! - [`ShieldedState`]: the Sapling and Orchard note commitment trees, valid anchors and pool
//!   balances, without which a shielded proof proves nothing.
//! - [`PolReserve`]: the protocol-owned liquidity reserve. It can only grow.

mod pol;
mod shielded;
mod utxo;

pub use pol::{EpochSettlement, PolError, PolReserve};
pub use shielded::{ShieldedError, ShieldedSnapshot, ShieldedState, StepSeal};
pub use utxo::{ApplyRules, BlockUndo, RamUtxoStore, StateError};
