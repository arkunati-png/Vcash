//! Voltcash network parameters: the single source of truth for address prefixes, the ZIP 32 coin
//! type and network upgrade activation.
//!
//! librustzcash's `NetworkType` is a closed enum (main, test, regtest), so the wallet's vendored
//! `zcash_address` and `zcash_protocol` take their Voltcash constants from here instead of
//! repeating literals, and the node uses the transparent codec below for payout addresses.
//!
//! Everything here is a placeholder until the network launches: changing a prefix changes every
//! address, so freeze them together with the genesis block.

/// The ZIP 32 / BIP 44 coin type. Deliberately not 1 (Zcash testnet), so a Voltcash seed never
/// derives the same keys as a Zcash wallet.
pub const COIN_TYPE: u32 = 22083;

/// Bech32 prefix for Sapling payment addresses.
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "volts";
/// Bech32m prefix for ZIP 320 TEX addresses.
pub const HRP_TEX_ADDRESS: &str = "volttex";
/// Bech32m prefix for revision 0 unified addresses.
pub const HRP_UNIFIED_ADDRESS: &str = "volt";
/// Bech32m prefix for revision 0 unified full viewing keys.
pub const HRP_UNIFIED_FVK: &str = "voltview";
/// Bech32m prefix for revision 0 unified incoming viewing keys.
pub const HRP_UNIFIED_IVK: &str = "voltivk";
/// Bech32m prefix for shielded-only revision 2 unified addresses.
pub const HRP_UNIFIED_ADDRESS_R2: &str = "voltr2";
/// Bech32m prefix for transparent-including revision 2 unified addresses.
pub const HRP_UNIFIED_ADDRESS_R2_TI: &str = "voltr2t";
/// Bech32m prefix for revision 2 unified full viewing keys.
pub const HRP_UNIFIED_FVK_R2: &str = "voltvf";
/// Bech32m prefix for revision 2 unified incoming viewing keys.
pub const HRP_UNIFIED_IVK_R2: &str = "voltvi";

/// Base58Check prefix for transparent P2PKH addresses. Every address starts with `Vo`.
pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 2] = [0x10, 0x37];
/// Base58Check prefix for transparent P2SH addresses.
pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 2] = [0x10, 0x3c];

/// Voltcash has no activation schedule: every upgrade it supports (through NU6.3) is active from
/// the first block. Ironwood and later upgrades are refused by consensus.
pub const ACTIVE_FROM_HEIGHT: u32 = 1;

/// Transparent (P2PKH) address encoding.
pub mod transparent {
    use core::fmt;

    use super::B58_PUBKEY_ADDRESS_PREFIX;

    /// Why a transparent address could not be decoded.
    #[derive(Debug, PartialEq, Eq)]
    pub enum AddressError {
        /// Not valid Base58Check (bad characters or checksum).
        Encoding,
        /// Valid Base58Check, but not a 22-byte `prefix || hash` payload.
        Length,
        /// A different network's prefix, for example a Zcash address.
        WrongNetwork,
    }

    impl fmt::Display for AddressError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Encoding => write!(f, "not a valid Base58Check address"),
                Self::Length => write!(f, "address has the wrong length"),
                Self::WrongNetwork => write!(f, "not a Voltcash transparent address"),
            }
        }
    }

    impl std::error::Error for AddressError {}

    /// Encodes a 20-byte public key hash as a Voltcash transparent address.
    pub fn encode_p2pkh(hash: &[u8; 20]) -> String {
        let mut payload = [0u8; 22];
        payload[..2].copy_from_slice(&B58_PUBKEY_ADDRESS_PREFIX);
        payload[2..].copy_from_slice(hash);
        bs58::encode(payload).with_check().into_string()
    }

    /// Decodes a Voltcash transparent address into its 20-byte public key hash.
    pub fn decode_p2pkh(address: &str) -> Result<[u8; 20], AddressError> {
        let bytes = bs58::decode(address.trim())
            .with_check(None)
            .into_vec()
            .map_err(|_| AddressError::Encoding)?;
        if bytes.len() != 22 {
            return Err(AddressError::Length);
        }
        if bytes[..2] != B58_PUBKEY_ADDRESS_PREFIX {
            return Err(AddressError::WrongNetwork);
        }
        Ok(bytes[2..].try_into().expect("length was checked to be 22"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn round_trips_and_always_starts_with_vo() {
            // A simple deterministic spread of hashes, including the extremes.
            let mut hashes = vec![[0u8; 20], [0xffu8; 20]];
            let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
            for _ in 0..2_000 {
                let mut h = [0u8; 20];
                for b in &mut h {
                    x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    *b = (x >> 56) as u8;
                }
                hashes.push(h);
            }
            for hash in hashes {
                let address = encode_p2pkh(&hash);
                assert!(address.starts_with("Vo"), "{address}");
                assert_eq!(address.len(), 35, "{address}");
                assert_eq!(decode_p2pkh(&address), Ok(hash));
            }
        }

        #[test]
        fn rejects_other_networks_and_damage() {
            // A Zcash mainnet and a Zcash testnet transparent address.
            assert_eq!(
                decode_p2pkh("t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs"),
                Err(AddressError::WrongNetwork)
            );
            assert_eq!(
                decode_p2pkh("tm9ofD7kHR7AF8MsJomEzLqGcrLCBkD9gDj"),
                Err(AddressError::WrongNetwork)
            );
            let good = encode_p2pkh(&[7; 20]);
            let mut bad = good.clone().into_bytes();
            let last = bad.len() - 1;
            bad[last] = if bad[last] == b'2' { b'3' } else { b'2' };
            assert_eq!(
                decode_p2pkh(&String::from_utf8(bad).unwrap()),
                Err(AddressError::Encoding)
            );
            assert_eq!(decode_p2pkh(""), Err(AddressError::Encoding));
            // Valid Base58Check, but the payload is not 22 bytes.
            let short = bs58::encode([0x10, 0x37, 1, 2, 3])
                .with_check()
                .into_string();
            assert_eq!(decode_p2pkh(&short), Err(AddressError::Length));
            assert_eq!(decode_p2pkh("0OIl"), Err(AddressError::Encoding));
        }
    }
}
