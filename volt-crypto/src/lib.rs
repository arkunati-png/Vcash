//! Voltcash proof-of-work.
//!
//! Voltcash replaces Zebra's Equihash check (`zebra_consensus::block::check::equihash_solution_is_valid`)
//! with a CPU-friendly RandomX check behind the [`PowHasher`] trait. There is no other proof of
//! work: tests and simulations use RandomX too, with an easy target (see `TEST_POW_LIMIT_BITS`
//! in `volt-core`), so they exercise the real thing.
//!
//! The target is checked against the same Zcash compact-difficulty targets from
//! `zebra_chain::work::difficulty`.

mod pow;
mod randomx_engine;

pub use pow::{meets_target, target_top64, target_work, PowError, PowHasher};
pub use randomx_engine::RandomXEngine;
