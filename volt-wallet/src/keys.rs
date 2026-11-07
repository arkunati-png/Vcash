//! Key and address derivation. Everything cryptographic here is librustzcash (`zcash_keys`,
//! ZIP 32 / ZIP 316) or the `bip0039` crate; this module only wires the pieces together.

use bip0039::{Count, English, Mnemonic};
use zcash_address::{ConversionError, ToAddress, TryFromAddress, ZcashAddress};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_protocol::consensus::NetworkType;
use zcash_transparent::address::TransparentAddress;
use zeroize::Zeroizing;
use zip32::AccountId;

use crate::network::{VoltNetwork, NETWORK_TYPE};

/// The addresses of account 0, all encoded with Voltcash prefixes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Addresses {
    /// Orchard + Sapling + transparent receivers in one unified address.
    pub unified: String,
    /// Orchard + Sapling only: nothing about it can be linked to a transparent address.
    pub shielded: String,
    /// Sapling only, for senders that do not support unified addresses.
    pub sapling: String,
    /// Transparent P2PKH.
    pub transparent: String,
}

/// Generates a fresh 24-word recovery phrase.
pub fn generate_phrase() -> Zeroizing<String> {
    let mnemonic = <Mnemonic<English>>::generate(Count::Words24);
    Zeroizing::new(mnemonic.phrase().to_owned())
}

/// Normalises whitespace and validates the phrase (word list and checksum).
pub fn normalize_phrase(phrase: &str) -> Result<Zeroizing<String>, String> {
    let joined = Zeroizing::new(
        phrase
            .split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>()
            .join(" "),
    );
    <Mnemonic<English>>::from_phrase(joined.as_str())
        .map_err(|e| format!("not a valid recovery phrase: {e}"))?;
    Ok(joined)
}

/// Derives the ZIP 32 spending key for account 0. Callers should drop it as soon as they
/// have signed; the app itself only keeps the viewing key.
pub fn spending_key(phrase: &str) -> Result<UnifiedSpendingKey, String> {
    let mnemonic = <Mnemonic<English>>::from_phrase(phrase)
        .map_err(|e| format!("not a valid recovery phrase: {e}"))?;
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    UnifiedSpendingKey::from_seed(&VoltNetwork, seed.as_ref(), AccountId::ZERO)
        .map_err(|e| format!("key derivation failed: {e:?}"))
}

/// Derives the unified full viewing key for account 0.
pub fn viewing_key(phrase: &str) -> Result<UnifiedFullViewingKey, String> {
    Ok(spending_key(phrase)?.to_unified_full_viewing_key())
}

/// The default (diversifier index 0) addresses for a viewing key.
pub fn addresses(ufvk: &UnifiedFullViewingKey) -> Result<Addresses, String> {
    let params = VoltNetwork;
    let (unified, _) = ufvk
        .default_address(UnifiedAddressRequest::ALLOW_ALL)
        .map_err(|e| format!("unified address: {e}"))?;
    let (shielded, _) = ufvk
        .default_address(UnifiedAddressRequest::SHIELDED)
        .map_err(|e| format!("shielded address: {e}"))?;

    let sapling = ufvk
        .sapling()
        .ok_or("the key has no Sapling component")?
        .default_address()
        .1;
    let sapling = ZcashAddress::from_sapling(NETWORK_TYPE, sapling.to_bytes()).encode();

    let transparent = match unified.transparent() {
        Some(TransparentAddress::PublicKeyHash(hash)) => {
            ZcashAddress::from_transparent_p2pkh(NETWORK_TYPE, *hash).encode()
        }
        _ => return Err("the key has no transparent component".into()),
    };

    Ok(Addresses {
        unified: unified.encode(&params),
        shielded: shielded.encode(&params),
        sapling,
        transparent,
    })
}

/// What kind of recipient an address is, as far as the Send screen needs to know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecipientKind {
    Unified,
    Sapling,
    Transparent,
}

struct Parsed(RecipientKind);

impl TryFromAddress for Parsed {
    type Error = std::convert::Infallible;

    fn try_from_sapling(
        _net: NetworkType,
        _data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Parsed(RecipientKind::Sapling))
    }

    fn try_from_unified(
        _net: NetworkType,
        _data: zcash_address::unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Parsed(RecipientKind::Unified))
    }

    fn try_from_transparent_p2pkh(
        _net: NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Parsed(RecipientKind::Transparent))
    }
}

/// Checks that `text` is a Voltcash address and says what kind. Zcash addresses are rejected
/// with a specific message instead of a generic parse error.
pub fn check_recipient(text: &str) -> Result<RecipientKind, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("enter a recipient address".into());
    }
    let address =
        ZcashAddress::try_from_encoded(text).map_err(|_| "not a Voltcash address".to_string())?;
    match address.convert_if_network::<Parsed>(NETWORK_TYPE) {
        Ok(Parsed(kind)) => Ok(kind),
        Err(ConversionError::IncorrectNetwork { .. }) => {
            Err("this is a Zcash address, not a Voltcash address".into())
        }
        Err(_) => Err("this address type is not supported".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The standard BIP-39 test phrase: fixed so the test is reproducible.
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn derivation_is_deterministic_and_uses_voltcash_prefixes() {
        let a = addresses(&viewing_key(PHRASE).unwrap()).unwrap();
        let b = addresses(&viewing_key(PHRASE).unwrap()).unwrap();
        assert_eq!(a, b);
        assert!(a.unified.starts_with("volt1"), "{}", a.unified);
        assert!(a.shielded.starts_with("volt1"), "{}", a.shielded);
        assert!(a.sapling.starts_with("volts1"), "{}", a.sapling);
        assert!(a.transparent.starts_with("Vo"), "{}", a.transparent);
        assert_ne!(a.unified, a.shielded);
    }

    #[test]
    fn generated_phrase_is_24_valid_words() {
        let phrase = generate_phrase();
        assert_eq!(phrase.split(' ').count(), 24);
        assert!(normalize_phrase(&phrase).is_ok());
        assert!(normalize_phrase("abandon abandon abandon").is_err());
    }

    #[test]
    fn recipients_are_checked_against_the_voltcash_network() {
        let a = addresses(&viewing_key(PHRASE).unwrap()).unwrap();
        assert_eq!(check_recipient(&a.unified), Ok(RecipientKind::Unified));
        assert_eq!(check_recipient(&a.sapling), Ok(RecipientKind::Sapling));
        assert_eq!(
            check_recipient(&a.transparent),
            Ok(RecipientKind::Transparent)
        );
        // A real Zcash mainnet transparent address and unified address must be refused.
        assert_eq!(
            check_recipient("t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs"),
            Err("this is a Zcash address, not a Voltcash address".into())
        );
        // Zcash testnet and mainnet unified/shielded addresses are refused too.
        for foreign in [
            "tm9ofD7kHR7AF8MsJomEzLqGcrLCBkD9gDj",
            "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpq6d8g",
        ] {
            assert!(check_recipient(foreign).is_err(), "{foreign}");
        }
        assert!(check_recipient("garbage").is_err());
        assert!(check_recipient("").is_err());
    }
}
