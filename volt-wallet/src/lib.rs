//! Voltcash Core: the wallet, node controls and miner controls as a library, so the same code
//! the app runs can be tested against a real node.

pub mod app;
pub mod chain;
pub mod keys;
pub mod localnode;
pub mod network;
pub mod node;
pub mod pay;
pub mod rpc;
pub mod scancache;
pub mod settings;
pub mod vault;
