//! Voltcash consensus.
//!
//! - [`ghostdag`]: the GHOSTDAG block DAG with `k = 32`.
//! - [`reachability`]: the index that answers "is this block in that block's past?" quickly.
//! - [`difficulty`]: the 500 ms difficulty adjustment and the RandomX key schedule.
//! - [`coinbase`]: the 100-payout cap and the exact 50/50 miner / POL split.
//! - [`mempool`]: the bounded, fee-rate-ordered transaction pool.
//! - [`epoch`]: aggregation and settlement of each 200-block Thermodynamic POL epoch.
//! - [`validator`]: block validation, with RandomX behind [`volt_crypto::PowHasher`] in place of Equihash.
//! - [`chain`]: UTXO state and POL settlement following the selected-parent chain.
//! - [`consensus`]: the [`Consensus`] engine that wires them together.

pub mod chain;
pub mod coinbase;
pub mod consensus;
pub mod difficulty;
pub mod epoch;
pub mod error;
pub mod ghostdag;
pub mod mempool;
pub mod reachability;
pub mod validator;

pub use consensus::{Consensus, ConsensusConfig, SubmitOutcome, TemplateContext};
pub use error::ConsensusError;
pub use mempool::{Mempool, MempoolError};
