//! Voltcash networking.
//!
//! This crate defines the bounded wire [`VoltMessage`]s and an in-process [`GossipHub`] that
//! connects several simulated nodes through `tokio` channels.
//!
//! It is **not** a TCP peer-to-peer stack: there is no peer discovery, handshake, rate limiting
//! or DoS scoring. A production network layer would carry the same [`VoltMessage`]s over real
//! connections, the way `zebra-network` does for Zcash.

mod gossip;
mod message;

pub use gossip::{GossipHub, GossipPeer};
pub use message::{
    MessageError, VoltMessage, MAX_BLOCKS_PER_MESSAGE, MAX_GET_BLOCKS, MAX_MESSAGE_BYTES,
};
