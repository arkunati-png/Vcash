//! What the network layer needs from the node.
//!
//! The peer layer knows how to move messages and manage peers, but not what a valid block is.
//! It asks a [`ChainBackend`] for that, so this crate does not depend on consensus.

use volt_core::{VoltBlock, VoltHash};

/// Why the backend refused a block or transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmitError {
    /// The data is provably bad: it does not decode, or its proofs or signatures fail. The peer
    /// that sent it is misbehaving and gets banned.
    Invalid(String),
    /// The data is not acceptable *right now* but is not proof of misbehavior, for example a
    /// block timestamp slightly in the future, or a transaction spending an output that is not
    /// confirmed yet. It is dropped without punishing the peer.
    Temporary(String),
}

/// The node's view of the chain, as the peer layer needs it.
///
/// Methods are synchronous and may take a lock. The peer layer calls the expensive ones, block
/// and transaction submission, from a blocking thread.
pub trait ChainBackend: Send + Sync + 'static {
    /// The hash of the genesis block. Peers on a different genesis are refused.
    fn genesis(&self) -> VoltHash;

    /// The current DAG tips.
    fn tips(&self) -> Vec<VoltHash>;

    /// Whether the block is known.
    fn contains(&self, hash: &VoltHash) -> bool;

    /// The encoded block with this hash, if known.
    fn block(&self, hash: &VoltHash) -> Option<Vec<u8>>;

    /// A locator describing this node's chain: recent block hashes, then exponentially sparser
    /// ones back to genesis.
    fn locator(&self) -> Vec<VoltHash>;

    /// Up to `max` encoded blocks that follow the newest block of `locator` this node knows, in an
    /// order where every block comes after its parents.
    fn blocks_after(&self, locator: &[VoltHash], max: usize) -> Vec<Vec<u8>>;

    /// Validates and adds a block whose parents are all known.
    fn submit_block(&self, block: VoltBlock) -> Result<VoltHash, SubmitError>;

    /// Validates and pools a transaction.
    fn submit_tx(&self, bytes: &[u8]) -> Result<VoltHash, SubmitError>;
}
