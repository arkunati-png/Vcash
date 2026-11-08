//! Voltcash's librustzcash network parameters. The values themselves live in `volt-params`.
//!
//! librustzcash's `NetworkType` is a closed enum (main, test, regtest). Voltcash uses the
//! `Regtest` slot, and `vendor/zcash_address` plus `vendor/zcash_protocol` replace that slot's
//! prefixes and coin type with Voltcash's, so Voltcash and Zcash addresses can never be confused.

use zcash_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters};

/// One VOLT in zats, the same 10^8 scale as Zcash.
pub const ZATS_PER_VOLT: u64 = 100_000_000;

/// Where the blocks mined only to confirm a payment send their reward.
///
/// A local development node has nobody else to mine a payment, so after a send the app asks it
/// to mine a couple of blocks. If those paid the sender, a payment would seem to leave the
/// public balance untouched while the private one grew. The reward goes here instead: nobody
/// holds a key for it, so those coins are simply not in circulation.
pub fn dev_sink_address() -> String {
    volt_params::transparent::encode_p2pkh(&[0xde; 20])
}

/// The network type Voltcash occupies inside librustzcash.
pub const NETWORK_TYPE: NetworkType = NetworkType::Regtest;

#[derive(Clone, Copy, Debug, Default)]
pub struct VoltNetwork;

impl Parameters for VoltNetwork {
    fn network_type(&self) -> NetworkType {
        NETWORK_TYPE
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            // Voltcash accepts Sapling and Orchard v5 transactions only and refuses Ironwood,
            // so everything up to NU6.3 is active from the first block and nothing newer is.
            NetworkUpgrade::Nu7 => None,
            _ => Some(BlockHeight::from_u32(volt_params::ACTIVE_FROM_HEIGHT)),
        }
    }
}

/// Formats an amount in zats as a VOLT decimal string with all eight places.
pub fn format_volt(zats: u64) -> String {
    format!("{}.{:08}", zats / ZATS_PER_VOLT, zats % ZATS_PER_VOLT)
}

/// Parses a decimal VOLT amount (at most eight places) into zats without using floats.
pub fn parse_volt(text: &str) -> Result<u64, &'static str> {
    let text = text.trim();
    if text.is_empty() {
        return Err("enter an amount");
    }
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() && frac.is_empty() {
        return Err("enter an amount");
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err("use digits and one decimal point");
    }
    if frac.len() > 8 {
        return Err("at most 8 decimal places");
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| "amount too large")?
    };
    let frac: u64 = format!("{frac:0<8}").parse().expect("eight ASCII digits");
    whole
        .checked_mul(ZATS_PER_VOLT)
        .and_then(|w| w.checked_add(frac))
        .ok_or("amount too large")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_round_trip() {
        assert_eq!(parse_volt("1"), Ok(100_000_000));
        assert_eq!(parse_volt("0.05"), Ok(5_000_000));
        assert_eq!(parse_volt(".00010000"), Ok(10_000));
        assert_eq!(parse_volt("12.345678901"), Err("at most 8 decimal places"));
        assert_eq!(parse_volt("1e5"), Err("use digits and one decimal point"));
        assert_eq!(parse_volt("-1"), Err("use digits and one decimal point"));
        assert_eq!(parse_volt("99999999999999999999"), Err("amount too large"));
        assert_eq!(format_volt(5_000_000), "0.05000000");
        assert_eq!(format_volt(parse_volt("21.5").unwrap()), "21.50000000");
    }
}
