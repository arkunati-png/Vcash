//! The Voltcash devnet node.
//!
//! [`sim::run`] starts several miners, each with its own [`volt_consensus::Consensus`] engine.
//! Every round they mine concurrently from the same view, which makes the DAG wide, then gossip
//! their blocks through [`volt_network::GossipHub`]. Every node validates every block and they
//! converge on the same GHOSTDAG order, UTXO set and POL reserve.
//!
//! The wiring, per block:
//!
//! 1. the [`wallet::DevWallet`] builds transactions (transparent and shielded);
//! 2. [`volt_consensus::Consensus::pack_batches`] packs them 10-to-1 into
//!    [`volt_core::RollupBatch`]es;
//! 3. `build_template` fills the coinbase with the exact 50/50 miner / POL split, paying at most
//!    100 unique addresses;
//! 4. the miner searches nonces with the configured [`volt_crypto::PowHasher`];
//! 5. `submit_block` validates, colors the block with GHOSTDAG (`k = 32`), moves the UTXO state
//!    along the selected chain and settles each 200-block epoch into the POL reserve.

pub mod sim;
pub mod wallet;
