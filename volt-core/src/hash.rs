//! Voltcash hashes and Merkle commitments.

use std::fmt;

/// A 32-byte Voltcash identifier: block hashes, batch roots and commitments.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VoltHash(pub [u8; 32]);

impl VoltHash {
    /// The all-zero hash, used for empty commitments.
    pub const ZERO: VoltHash = VoltHash([0; 32]);

    /// Returns the Blake2b-256 hash of `data` under the 16-byte `personal` domain separator.
    pub fn digest(personal: &[u8; 16], data: &[u8]) -> VoltHash {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(personal)
            .hash(data);
        let mut bytes = [0; 32];
        bytes.copy_from_slice(hash.as_bytes());
        VoltHash(bytes)
    }
}

impl fmt::Debug for VoltHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VoltHash")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl fmt::Display for VoltHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

const LEAF_PERSONAL: &[u8; 16] = b"VoltMerkleLeaf__";
const NODE_PERSONAL: &[u8; 16] = b"VoltMerkleNode__";

/// Returns the Merkle root of `leaves`.
///
/// Leaves and inner nodes use different domain separators, and an odd node is
/// paired with [`VoltHash::ZERO`] instead of with itself, so the CVE-2012-2459
/// duplicate-leaf ambiguity of the Bitcoin tree does not apply.
/// An empty list has the root [`VoltHash::ZERO`].
pub fn merkle_root(leaves: &[VoltHash]) -> VoltHash {
    if leaves.is_empty() {
        return VoltHash::ZERO;
    }

    let mut level: Vec<VoltHash> = leaves
        .iter()
        .map(|leaf| VoltHash::digest(LEAF_PERSONAL, &leaf.0))
        .collect();

    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let right = pair.get(1).copied().unwrap_or(VoltHash::ZERO);
                let mut data = [0; 64];
                data[..32].copy_from_slice(&pair[0].0);
                data[32..].copy_from_slice(&right.0);
                VoltHash::digest(NODE_PERSONAL, &data)
            })
            .collect();
    }

    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_root_is_order_sensitive_and_domain_separated() {
        let a = VoltHash([1; 32]);
        let b = VoltHash([2; 32]);

        assert_eq!(merkle_root(&[]), VoltHash::ZERO);
        assert_ne!(merkle_root(&[a]), a, "leaves are hashed, not used directly");
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]));
        assert_ne!(
            merkle_root(&[a, b, b]),
            merkle_root(&[a, b]),
            "odd nodes are not duplicated"
        );
    }
}
