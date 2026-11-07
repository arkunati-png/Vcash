//! The proof-of-work abstraction and the test hasher.

use thiserror::Error;
use zebra_chain::{
    block,
    work::difficulty::{CompactDifficulty, Work},
};

/// Errors from computing a proof-of-work hash.
#[derive(Debug, Error)]
pub enum PowError {
    /// The PoW engine failed to initialize or hash.
    #[error("pow engine error: {0}")]
    Engine(String),
}

/// A proof-of-work hash function keyed by a 32-byte seed.
///
/// For RandomX the seed is the cache key, which rotates every epoch.
pub trait PowHasher: Send + Sync {
    /// Hashes `input` under `seed`.
    fn pow_hash(&self, seed: &[u8; 32], input: &[u8]) -> Result<[u8; 32], PowError>;
}

/// A Blake2b-256 stand-in for RandomX, for tests and fast devnets.
///
/// It is **not** CPU-hard and must never be used on a public network.
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake2bPowHasher;

impl PowHasher for Blake2bPowHasher {
    fn pow_hash(&self, seed: &[u8; 32], input: &[u8]) -> Result<[u8; 32], PowError> {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"VoltTestPoW_____")
            .to_state()
            .update(seed)
            .update(input)
            .finalize();
        let mut out = [0; 32];
        out.copy_from_slice(hash.as_bytes());
        Ok(out)
    }
}

/// Returns `true` if `hash` is at or below the target encoded by compact `bits`.
///
/// Uses Zcash's rules: the hash is read as a little-endian 256-bit integer, and
/// negative, zero or overflowing `bits` are invalid and never met.
pub fn meets_target(hash: &[u8; 32], bits: u32) -> bool {
    let Ok(compact) = CompactDifficulty::from_bytes_in_display_order(&bits.to_be_bytes()) else {
        return false;
    };
    match compact.to_expanded() {
        Some(target) => target >= block::Hash(*hash),
        None => false,
    }
}

/// Returns the expected work to meet the target encoded by compact `bits`, if `bits` is valid.
pub fn target_work(bits: u32) -> Option<Work> {
    CompactDifficulty::from_bytes_in_display_order(&bits.to_be_bytes())
        .ok()?
        .to_work()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_comparison() {
        // Regtest limit: a target of 0x7fffff * 256^29, so a hash whose top (last, little-endian)
        // bytes are zero is below it, and an all-ones hash is above it.
        let bits = 0x207f_ffff;
        assert!(meets_target(&[0; 32], bits));
        assert!(!meets_target(&[0xff; 32], bits));
        assert!(
            !meets_target(&[0; 32], 0x0080_0000),
            "negative bits are invalid"
        );
        assert!(!meets_target(&[0; 32], 0), "zero bits are invalid");
    }

    #[test]
    fn blake2b_hasher_is_seeded_and_deterministic() {
        let h = Blake2bPowHasher;
        let a = h.pow_hash(&[1; 32], b"x").unwrap();
        assert_eq!(a, h.pow_hash(&[1; 32], b"x").unwrap());
        assert_ne!(a, h.pow_hash(&[2; 32], b"x").unwrap());
        assert_ne!(a, h.pow_hash(&[1; 32], b"y").unwrap());
    }

    #[test]
    fn work_decreases_as_target_grows() {
        let easy = target_work(0x207f_ffff).unwrap();
        let hard = target_work(0x1f07_ffff).unwrap();
        assert!(hard > easy);
        assert!(target_work(0).is_none());
    }
}
