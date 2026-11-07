//! # Regtest constants
//!
//! `regtest` is a `zcashd`-specific environment used for local testing. They mostly reuse
//! the testnet constants.
//! These constants are defined in [the `zcashd` codebase].
//!
//! [the `zcashd` codebase]: <https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L482-L496>

/// Voltcash cointype (ZIP 32 / BIP 44 account path). Deliberately not 1, so that a Voltcash
/// seed never derives the same keys as a Zcash testnet or regtest wallet.
pub const COIN_TYPE: u32 = 22083;

/// The HRP for a Bech32-encoded regtest Sapling [`ExtendedSpendingKey`].
///
/// It is defined in [the `zcashd` codebase].
///
/// [`ExtendedSpendingKey`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/zip32/struct.ExtendedSpendingKey.html
/// [the `zcashd` codebase]: <https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L496>
#[deprecated(
    since = "0.11.0",
    note = "Use `zcash_keys::constants::regtest::HRP_SAPLING_EXTENDED_SPENDING_KEY` instead."
)]
pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = "secret-extended-key-regtest";

/// The HRP for a Bech32-encoded regtest Sapling [`ExtendedFullViewingKey`].
///
/// It is defined in [the `zcashd` codebase].
///
/// [`ExtendedFullViewingKey`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/zip32/struct.ExtendedFullViewingKey.html
/// [the `zcashd` codebase]: <https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L494>
#[deprecated(
    since = "0.11.0",
    note = "Use `zcash_keys::constants::regtest::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY` instead."
)]
pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = "zxviewregtestsapling";

/// The HRP for a Bech32-encoded regtest Sapling [`PaymentAddress`].
///
/// It is defined in [the `zcashd` codebase].
///
/// [`PaymentAddress`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/struct.PaymentAddress.html
/// [the `zcashd` codebase]: <https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L493>
#[deprecated(
    since = "0.11.0",
    note = "Use `zcash_address::constants::regtest::HRP_SAPLING_PAYMENT_ADDRESS` instead."
)]
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "volts";

/// The prefix for a Base58Check-encoded regtest Sprout address.
///
/// Defined in the [Zcash Protocol Specification section 5.6.3][sproutpaymentaddrencoding].
/// Same as the testnet prefix.
///
/// [sproutpaymentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#sproutpaymentaddrencoding
#[deprecated(
    since = "0.11.0",
    note = "Use `zcash_address::constants::regtest::B58_SPROUT_ADDRESS_PREFIX` instead."
)]
pub const B58_SPROUT_ADDRESS_PREFIX: [u8; 2] = [0x16, 0xb6];

/// The prefix for a Base58Check-encoded DER-encoded regtest [`SecretKey`], as specified via the
/// bitcoin-derived [`EncodeSecret`] format function.
///
/// [`SecretKey`]: https://docs.rs/secp256k1/latest/secp256k1/struct.SecretKey.html
/// [`EncodeSecret`]: https://github.com/zcash/zcash/blob/1f1f7a385adc048154e7f25a3a0de76f3658ca09/src/key_io.cpp#L298
#[deprecated(
    since = "0.11.0",
    note = "Use `zcash_keys::constants::regtest::B58_SECRET_KEY_PREFIX` instead."
)]
pub const B58_SECRET_KEY_PREFIX: [u8; 1] = [0xef];

/// The prefix for a Base58Check-encoded regtest transparent [`PublicKeyHash`].
/// Same as the testnet prefix.
///
/// [`PublicKeyHash`]: https://docs.rs/zcash_primitives/latest/zcash_primitives/legacy/enum.TransparentAddress.html
#[deprecated(
    since = "0.11.0",
    note = "Use `zcash_address::constants::regtest::B58_PUBKEY_ADDRESS_PREFIX` instead."
)]
pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 2] = [0x10, 0x37];

/// The prefix for a Base58Check-encoded regtest transparent [`ScriptHash`].
/// Same as the testnet prefix.
///
/// [`ScriptHash`]: https://docs.rs/zcash_primitives/latest/zcash_primitives/legacy/enum.TransparentAddress.html
#[deprecated(
    since = "0.11.0",
    note = "Use `zcash_address::constants::regtest::B58_SCRIPT_ADDRESS_PREFIX` instead."
)]
pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 2] = [0x10, 0x3c];

/// The HRP for a Bech32m-encoded regtest [ZIP 320] TEX address.
///
/// [ZIP 320]: https://zips.z.cash/zip-0320
#[deprecated(
    since = "0.11.0",
    note = "Use `zcash_address::constants::regtest::HRP_TEX_ADDRESS` instead."
)]
pub const HRP_TEX_ADDRESS: &str = "volttex";

/// The HRP for a Bech32m-encoded regtest Unified Address.
///
/// Defined in [ZIP 316][zip-0316].
///
/// [zip-0316]: https://zips.z.cash/zip-0316
#[deprecated(
    since = "0.11.0",
    note = "Use `zcash_address::constants::regtest::HRP_UNIFIED_ADDRESS` instead."
)]
pub const HRP_UNIFIED_ADDRESS: &str = "volt";

/// The HRP for a Bech32m-encoded regtest Unified FVK.
#[deprecated(
    since = "0.11.0",
    note = "Use `zcash_address::constants::regtest::HRP_UNIFIED_FVK` instead."
)]
pub const HRP_UNIFIED_FVK: &str = "voltview";

/// The HRP for a Bech32m-encoded regtest Unified IVK.
#[deprecated(
    since = "0.11.0",
    note = "Use `zcash_address::constants::regtest::HRP_UNIFIED_IVK` instead."
)]
pub const HRP_UNIFIED_IVK: &str = "voltivk";
