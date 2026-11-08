//! Cheaper replay of a node's own block log.
//!
//! A node checks a block's proof of work and the proofs and signatures of its transactions once,
//! when the block first arrives, and only then writes it to the log. Checking all of that again
//! at every restart costs one RandomX hash per block, and a Groth16 batch per shielded
//! transaction, so a long chain would take hours to come back.
//!
//! In [`ReplayMode::TrustOwnLog`] those two checks are skipped for the older records and kept for
//! the newest ones. Everything else still runs on every record: decoding, the DAG rules, the
//! value and fee rules, the shielded anchors and turnstile, the coinbase and epoch accounting.
//! A damaged record is still caught by the log's checksum.
//!
//! What this gives up: a log that someone edited on disk *and* recomputed the checksums for could
//! carry blocks with forged work into the older part of the chain. Anyone who can do that already
//! owns the machine; [`ReplayMode::Full`] exists for anyone who wants the guarantee anyway.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use volt_core::{TxVerifier, TxVerifyItem, VerifyError};
use volt_crypto::{PowError, PowHasher};

/// How much of the log to check again when it is replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayMode {
    /// Check every block's proof of work and every transaction's proofs and signatures again.
    Full,
    /// Skip those two checks for all but the newest `recheck_tail` records.
    TrustOwnLog {
        /// How many of the newest records are still checked in full.
        recheck_tail: u64,
    },
}

impl ReplayMode {
    /// The mode a node uses by default: trust the log except for its newest 2,000 records.
    pub const DEFAULT_TRUSTING: ReplayMode = ReplayMode::TrustOwnLog {
        recheck_tail: 2_000,
    };

    /// Whether record `index` of `total` may skip the expensive checks.
    pub(crate) fn trusts(self, index: u64, total: u64) -> bool {
        match self {
            ReplayMode::Full => false,
            ReplayMode::TrustOwnLog { recheck_tail } => index.saturating_add(recheck_tail) < total,
        }
    }
}

/// A [`PowHasher`] that, while trusting, accepts every block's work without computing it.
///
/// It answers with the all-zero hash, which meets every target.
pub(crate) struct ReplayPow {
    pub(crate) inner: Arc<dyn PowHasher>,
    pub(crate) trusting: Arc<AtomicBool>,
}

impl PowHasher for ReplayPow {
    fn pow_hash(&self, seed: &[u8; 32], input: &[u8]) -> Result<[u8; 32], PowError> {
        if self.trusting.load(Ordering::Relaxed) {
            Ok([0; 32])
        } else {
            self.inner.pow_hash(seed, input)
        }
    }
}

/// A [`TxVerifier`] that, while trusting, accepts every transaction without checking it.
#[derive(Debug)]
pub(crate) struct ReplayVerifier {
    pub(crate) inner: Arc<dyn TxVerifier>,
    pub(crate) trusting: Arc<AtomicBool>,
}

impl TxVerifier for ReplayVerifier {
    fn verify_batch(&self, items: &[TxVerifyItem<'_>]) -> Result<(), VerifyError> {
        if self.trusting.load(Ordering::Relaxed) {
            Ok(())
        } else {
            self.inner.verify_batch(items)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_old_records_are_trusted() {
        let mode = ReplayMode::TrustOwnLog { recheck_tail: 10 };
        assert!(mode.trusts(0, 100));
        assert!(mode.trusts(89, 100));
        assert!(!mode.trusts(90, 100), "the newest ten are checked in full");
        assert!(!mode.trusts(99, 100));
        assert!(!ReplayMode::Full.trusts(0, 100));
        // A log shorter than the tail is checked entirely.
        assert!(!mode.trusts(0, 5));
    }
}
