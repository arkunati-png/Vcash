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
/// The seed is the RandomX cache key, which rotates every `POW_KEY_EPOCH_LENGTH` blocks.
pub trait PowHasher: Send + Sync {
    /// Hashes `input` under `seed`.
    fn pow_hash(&self, seed: &[u8; 32], input: &[u8]) -> Result<[u8; 32], PowError>;
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

/// The top 64 bits of the target encoded by compact `bits`, as stratum miners compare them.
///
/// A hash whose top 64 bits (its last eight bytes, little-endian) are below this meets the
/// target, which is what XMRig checks before it reports a share.
pub fn target_top64(bits: u32) -> Option<u64> {
    use zebra_chain::serialization::BytesInDisplayOrder;
    let compact = CompactDifficulty::from_bytes_in_display_order(&bits.to_be_bytes()).ok()?;
    let target = compact.to_expanded()?;
    let bytes = target.bytes_in_serialized_order();
    Some(u64::from_be_bytes(bytes[..8].try_into().ok()?))
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
    fn work_decreases_as_target_grows() {
        let easy = target_work(0x207f_ffff).unwrap();
        let hard = target_work(0x1f07_ffff).unwrap();
        assert!(hard > easy);
        assert!(target_work(0).is_none());
    }
}
