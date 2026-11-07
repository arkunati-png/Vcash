//! Voltcash proof-of-work.
//!
//! Voltcash replaces Zebra's Equihash check (`zebra_consensus::block::check::equihash_solution_is_valid`)
//! with a CPU-friendly RandomX check behind the [`PowHasher`] trait:
//!
//! - [`RandomXEngine`] is the production hasher, available with the `randomx` feature.
//! - [`Blake2bPowHasher`] is a fast stand-in for tests and devnets, available always.
//!
//! Both are checked against the same Zcash compact-difficulty targets from
//! `zebra_chain::work::difficulty`.

mod pow;

#[cfg(feature = "randomx")]
mod randomx_engine;

pub use pow::{meets_target, target_work, Blake2bPowHasher, PowError, PowHasher};

#[cfg(feature = "randomx")]
pub use randomx_engine::RandomXEngine;
