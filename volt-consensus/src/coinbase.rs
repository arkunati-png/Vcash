//! Coinbase rules: the 100-payout cap and the 50/50 miner / POL split.

use std::collections::HashSet;

use thiserror::Error;
use volt_core::{
    constants::{BASE_EMISSION_PER_BLOCK, MAX_COINBASE_EXTRA_BYTES, MAX_COINBASE_PAYOUTS},
    Coinbase, Payout,
};
use zebra_chain::{
    amount::{Amount, NonNegative},
    transparent::Address,
};

/// Ways a coinbase can break consensus.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum CoinbaseError {
    /// More than 100 unique payout addresses.
    #[error("coinbase pays {count} unique addresses, the maximum is {max}")]
    TooManyPayoutAddresses {
        /// The number of unique addresses.
        count: usize,
        /// The maximum allowed.
        max: usize,
    },

    /// A payout is zero.
    #[error("coinbase contains a zero payout")]
    ZeroPayout,

    /// The block reward cannot be split into two equal halves.
    #[error("block reward {0} cannot be split evenly")]
    OddReward(i64),

    /// The miners are not paid exactly half of the block reward.
    #[error("miners are paid {got}, expected exactly half of the reward: {expected}")]
    WrongMinerTotal {
        /// Half of the block reward.
        expected: i64,
        /// The sum of the payouts.
        got: i64,
    },

    /// The POL contribution is not exactly half of the block reward.
    #[error("POL contribution is {got}, expected exactly half of the reward: {expected}")]
    WrongPolContribution {
        /// Half of the block reward.
        expected: i64,
        /// The POL amount in the coinbase.
        got: i64,
    },

    /// The extra data is too long.
    #[error("coinbase extra data is {0} bytes")]
    ExtraTooLong(usize),

    /// A reward sum is out of range.
    #[error("reward out of range")]
    Overflow,

    /// There is a miner share but nobody to pay it to.
    #[error("no payout addresses")]
    NoPayouts,
}

/// The reward of a block: the base emission plus the fees of its batches.
pub fn block_reward(fees: Amount<NonNegative>) -> Result<Amount<NonNegative>, CoinbaseError> {
    (Amount::<NonNegative>::new(BASE_EMISSION_PER_BLOCK) + fees)
        .map_err(|_| CoinbaseError::Overflow)
}

/// Splits `total` exactly in half: `(miners, pol)`.
///
/// Fails if `total` is odd, because an exact 50/50 split is then impossible. Emission and both
/// fee tiers are even, so a valid block reward is always even.
pub fn split_reward(
    total: Amount<NonNegative>,
) -> Result<(Amount<NonNegative>, Amount<NonNegative>), CoinbaseError> {
    let zats = total.zatoshis();
    if zats % 2 != 0 {
        return Err(CoinbaseError::OddReward(zats));
    }
    Ok((Amount::new(zats / 2), Amount::new(zats / 2)))
}

/// Checks a coinbase against the rewards of its block.
///
/// 1. At most [`MAX_COINBASE_PAYOUTS`] **unique** payout addresses.
/// 2. No zero payouts.
/// 3. Payouts to miners sum to exactly 50% of `emission + fees`.
/// 4. The POL contribution is exactly the other 50%.
pub fn check_coinbase(coinbase: &Coinbase, fees: Amount<NonNegative>) -> Result<(), CoinbaseError> {
    if coinbase.extra.len() > MAX_COINBASE_EXTRA_BYTES {
        return Err(CoinbaseError::ExtraTooLong(coinbase.extra.len()));
    }

    let unique: HashSet<&Address> = coinbase.payouts.iter().map(|p| &p.address).collect();
    if unique.len() > MAX_COINBASE_PAYOUTS {
        return Err(CoinbaseError::TooManyPayoutAddresses {
            count: unique.len(),
            max: MAX_COINBASE_PAYOUTS,
        });
    }

    let mut paid = Amount::<NonNegative>::zero();
    for payout in &coinbase.payouts {
        if payout.amount.is_zero() {
            return Err(CoinbaseError::ZeroPayout);
        }
        paid = (paid + payout.amount).map_err(|_| CoinbaseError::Overflow)?;
    }

    let (miners_half, pol_half) = split_reward(block_reward(fees)?)?;
    if paid != miners_half {
        return Err(CoinbaseError::WrongMinerTotal {
            expected: miners_half.zatoshis(),
            got: paid.zatoshis(),
        });
    }
    if coinbase.pol_contribution != pol_half {
        return Err(CoinbaseError::WrongPolContribution {
            expected: pol_half.zatoshis(),
            got: coinbase.pol_contribution.zatoshis(),
        });
    }
    if !miners_half.is_zero() && coinbase.payouts.is_empty() {
        return Err(CoinbaseError::NoPayouts);
    }
    Ok(())
}

/// Builds a valid coinbase for a block with `fees`, paying the miner half evenly to up to
/// [`MAX_COINBASE_PAYOUTS`] unique addresses taken from `miners` (the first payout absorbs any
/// rounding remainder).
pub fn build_coinbase(
    fees: Amount<NonNegative>,
    miners: &[Address],
    extra: Vec<u8>,
) -> Result<Coinbase, CoinbaseError> {
    let (miners_half, pol_half) = split_reward(block_reward(fees)?)?;

    let mut seen = HashSet::new();
    let addresses: Vec<Address> = miners
        .iter()
        .filter(|a| seen.insert(**a))
        .take(MAX_COINBASE_PAYOUTS)
        .copied()
        .collect();
    if addresses.is_empty() {
        return Err(CoinbaseError::NoPayouts);
    }

    // Never create zero payouts: use fewer addresses if the share is tiny.
    let half = miners_half.zatoshis();
    let count = addresses
        .len()
        .min(usize::try_from(half).unwrap_or(usize::MAX).max(1));
    let each = half / count as i64; // lossless: count <= 100
    let remainder = half - each * count as i64; // lossless: count <= 100

    let payouts = addresses
        .into_iter()
        .take(count)
        .enumerate()
        .map(|(i, address)| Payout {
            address,
            amount: Amount::new(if i == 0 { each + remainder } else { each }),
        })
        .collect();

    Ok(Coinbase {
        payouts,
        pol_contribution: pol_half,
        extra,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zebra_chain::parameters::NetworkKind;

    fn addr(n: u8) -> Address {
        Address::from_pub_key_hash(NetworkKind::Regtest, [n; 20])
    }

    fn addrs(n: usize) -> Vec<Address> {
        (0..n).map(|i| addr(i as u8)).collect()
    }

    #[test]
    fn built_coinbase_is_valid_and_splits_50_50() {
        let fees = Amount::new(150_000);
        let cb = build_coinbase(fees, &addrs(7), vec![]).unwrap();
        check_coinbase(&cb, fees).unwrap();

        let reward = BASE_EMISSION_PER_BLOCK + 150_000;
        let paid: i64 = cb.payouts.iter().map(|p| p.amount.zatoshis()).sum();
        assert_eq!(paid, reward / 2);
        assert_eq!(cb.pol_contribution.zatoshis(), reward / 2);
    }

    #[test]
    fn exactly_100_unique_addresses_pass_and_101_fail() {
        let fees = Amount::new(10_000);

        let cb = build_coinbase(fees, &addrs(100), vec![]).unwrap();
        assert_eq!(cb.payouts.len(), 100);
        check_coinbase(&cb, fees).unwrap();

        // The builder caps at 100; a hand-made 101-address coinbase must be rejected.
        let mut cb101 = cb.clone();
        let half = cb101.payouts[1].amount;
        cb101.payouts[1].amount = Amount::new(half.zatoshis() - 1);
        cb101.payouts.push(Payout {
            address: addr(200),
            amount: Amount::new(1),
        });
        assert_eq!(
            check_coinbase(&cb101, fees),
            Err(CoinbaseError::TooManyPayoutAddresses {
                count: 101,
                max: 100
            })
        );
        assert_eq!(
            build_coinbase(fees, &addrs(150), vec![])
                .unwrap()
                .payouts
                .len(),
            100
        );
    }

    #[test]
    fn duplicate_addresses_count_once() {
        let fees = Amount::new(0);
        let mut cb = build_coinbase(fees, &addrs(100), vec![]).unwrap();
        // Split the first payout into two payouts to the same address: still 100 unique.
        let first = cb.payouts[0].clone();
        let part = first.amount.zatoshis() / 2;
        cb.payouts[0].amount = Amount::new(first.amount.zatoshis() - part);
        cb.payouts.push(Payout {
            address: first.address,
            amount: Amount::new(part),
        });
        assert_eq!(cb.payouts.len(), 101);
        check_coinbase(&cb, fees).unwrap();
    }

    #[test]
    fn rejects_wrong_split_and_zero_payouts() {
        let fees = Amount::new(20_000);
        let good = build_coinbase(fees, &addrs(3), vec![]).unwrap();

        let mut skim = good.clone();
        skim.pol_contribution = Amount::new(good.pol_contribution.zatoshis() - 2);
        assert!(matches!(
            check_coinbase(&skim, fees),
            Err(CoinbaseError::WrongPolContribution { .. })
        ));

        let mut greedy = good.clone();
        greedy.payouts[0].amount = Amount::new(greedy.payouts[0].amount.zatoshis() + 2);
        assert!(matches!(
            check_coinbase(&greedy, fees),
            Err(CoinbaseError::WrongMinerTotal { .. })
        ));

        let mut zero = good;
        zero.payouts[0].amount = Amount::new(0);
        assert_eq!(check_coinbase(&zero, fees), Err(CoinbaseError::ZeroPayout));
    }

    #[test]
    fn odd_rewards_cannot_split() {
        assert_eq!(
            split_reward(Amount::new(7)),
            Err(CoinbaseError::OddReward(7))
        );
        assert!(build_coinbase(Amount::new(1), &addrs(1), vec![]).is_err());
    }
}
