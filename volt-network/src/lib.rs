//! Voltcash networking.
//!
//! - [`VoltMessage`]: the bounded wire messages, and [`frame`] for putting them on a byte stream.
//! - [`p2p`]: a TCP peer-to-peer runtime with a version and genesis handshake, inventory relay,
//!   bulk catch-up, an orphan pool, rate limiting, bans and connection limits. It talks to the
//!   node through the [`ChainBackend`] trait, so it does not depend on consensus.
//! - [`GossipHub`]: an in-process hub for simulated nodes that share one process.
//!
//! What it deliberately leaves out: peer discovery beyond a configured seed list, address
//! gossip, encryption and authentication of the transport, and NAT traversal. Peers are
//! identified by IP address only, so ban and connection limits can be sidestepped by an attacker
//! with many addresses. Run it behind a firewall or a VPN until those exist.

mod backend;
pub mod frame;
mod gossip;
mod message;
pub mod p2p;

pub use backend::{ChainBackend, SubmitError};
pub use gossip::{GossipHub, GossipPeer};
pub use message::{
    Hello, MessageError, VoltMessage, MAX_BLOCKS_PER_MESSAGE, MAX_GET_BLOCKS, MAX_LOCATOR,
    MAX_MESSAGE_BYTES, PROTOCOL_VERSION,
};
pub use p2p::{start, P2pConfig, P2pHandle};
