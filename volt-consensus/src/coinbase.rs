//! Coinbase rules: the 100-payout cap, the minimum payout and the scheduled miner / POL split.

use std::collections::HashSet;

use thiserror::Error;
use volt_core::{
    constants::{MAX_COINBASE_EXTRA_BYTES, MAX_COINBASE_PAYOUTS},
    Coinbase, Economics, EconomicsError, Payout,
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

    /// A payout is below the minimum, which includes zero.
    #[error("payout of {amount} is below the minimum of {min}")]
    DustPayout {
        /// The offending payout.
        amount: i64,
        /// The minimum payout.
        min: i64,
    },

    /// The block reward cannot be split.
    #[error(transparent)]
    Split(#[from] EconomicsError),

    /// The miners are not paid exactly their scheduled share of the block reward.
    #[error("miners are paid {got}, expected exactly their scheduled share: {expected}")]
    WrongMinerTotal {
        /// The scheduled miner share of the reward.
        expected: i64,
        /// The sum of the payouts.
        got: i64,
    },

    /// The POL contribution is not exactly the rest of the block reward.
    #[error("POL contribution is {got}, expected exactly the scheduled rest: {expected}")]
    WrongPolContribution {
        /// The scheduled POL share of the reward.
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

    /// There is a miner share but nobody to pay it to, or it is too small to pay anyone.
    #[error("no payout addresses")]
    NoPayouts,
}

/// The reward of a block: the scheduled emission plus the fees of its batches.
pub fn block_reward(
    economics: &Economics,
    score: u64,
    fees: Amount<NonNegative>,
) -> Result<Amount<NonNegative>, CoinbaseError> {
    (Amount::<NonNegative>::new(economics.emission(score)) + fees)
        .map_err(|_| CoinbaseError::Overflow)
}

/// Splits `reward` into `(miners, pol)` for a block with the given reward score.
pub fn split_reward(
    economics: &Economics,
    score: u64,
    reward: Amount<NonNegative>,
) -> Result<(Amount<NonNegative>, Amount<NonNegative>), CoinbaseError> {
    let (miners, pol) = economics.split(reward.zatoshis(), score)?;
    Ok((Amount::new(miners), Amount::new(pol)))
}

/// Checks a coinbase against the rewards of its block.
///
/// 1. At most [`MAX_COINBASE_PAYOUTS`] **unique** payout addresses.
/// 2. Every payout is at least the minimum payout, which also rules out zero payouts.
/// 3. Payouts to miners sum to exactly the scheduled miner share of `emission + fees`.
/// 4. The POL contribution is exactly the rest.
pub fn check_coinbase(
    coinbase: &Coinbase,
    fees: Amount<NonNegative>,
    economics: &Economics,
    score: u64,
) -> Result<(), CoinbaseError> {
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
        if payout.amount.zatoshis() < economics.min_payout {
            return Err(CoinbaseError::DustPayout {
                amount: payout.amount.zatoshis(),
                min: economics.min_payout,
            });
        }
        paid = (paid + payout.amount).map_err(|_| CoinbaseError::Overflow)?;
    }

    let reward = block_reward(economics, score, fees)?;
    let (miners_share, pol_share) = split_reward(economics, score, reward)?;
    if paid != miners_share {
        return Err(CoinbaseError::WrongMinerTotal {
            expected: miners_share.zatoshis(),
            got: paid.zatoshis(),
        });
    }
    if coinbase.pol_contribution != pol_share {
        return Err(CoinbaseError::WrongPolContribution {
            expected: pol_share.zatoshis(),
            got: coinbase.pol_contribution.zatoshis(),
        });
    }
    if !miners_share.is_zero() && coinbase.payouts.is_empty() {
        return Err(CoinbaseError::NoPayouts);
    }
    Ok(())
}

/// Builds a valid coinbase for a block with `fees`, paying the miner share evenly to up to
/// [`MAX_COINBASE_PAYOUTS`] unique addresses taken from `miners` (the first payout absorbs any
/// rounding remainder).
///
/// Uses fewer addresses when the share is too small to give each at least the minimum payout.
pub fn build_coinbase(
    fees: Amount<NonNegative>,
    miners: &[Address],
    extra: Vec<u8>,
    economics: &Economics,
    score: u64,
) -> Result<Coinbase, CoinbaseError> {
    let reward = block_reward(economics, score, fees)?;
    let (miners_share, pol_share) = split_reward(economics, score, reward)?;

    let mut seen = HashSet::new();
    let addresses: Vec<Address> = miners
        .iter()
        .filter(|a| seen.insert(**a))
        .take(MAX_COINBASE_PAYOUTS)
        .copied()
        .collect();

    let share = miners_share.zatoshis();
    let affordable = usize::try_from(share / economics.min_payout.max(1)).unwrap_or(usize::MAX);
    let count = addresses.len().min(affordable);
    if count == 0 {
        return Err(CoinbaseError::NoPayouts);
    }

    let each = share / count as i64; // lossless: count <= 100
    let remainder = share - each * count as i64; // lossless: count <= 100

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
        pol_contribution: pol_share,
        extra,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use volt_core::constants::VOLT;
    use zebra_chain::parameters::NetworkKind;

    fn addr(n: u8) -> Address {
        Address::from_pub_key_hash(NetworkKind::Regtest, [n; 20])
    }

    fn addrs(n: usize) -> Vec<Address> {
        (0..n).map(|i| addr(i as u8)).collect()
    }

    const FLAT: Economics = Economics::fifty_fifty();
    const EMISSION: i64 = VOLT / 20;

    fn build(fees: i64, n: usize) -> Coinbase {
        build_coinbase(Amount::new(fees), &addrs(n), vec![], &FLAT, 0).unwrap()
    }

    #[test]
    fn built_coinbase_is_valid_and_splits_50_50() {
        let fees = Amount::new(150_000);
        let cb = build_coinbase(fees, &addrs(7), vec![], &FLAT, 0).unwrap();
        check_coinbase(&cb, fees, &FLAT, 0).unwrap();

        let reward = EMISSION + 150_000;
        let paid: i64 = cb.payouts.iter().map(|p| p.amount.zatoshis()).sum();
        assert_eq!(paid, reward / 2);
        assert_eq!(cb.pol_contribution.zatoshis(), reward / 2);
    }

    #[test]
    fn the_split_follows_the_taper() {
        let econ = Economics::mainnet();
        let fees = Amount::new(0);

        // Early: 70% to miners, 30% to POL.
        let early = build_coinbase(fees, &addrs(5), vec![], &econ, 0).unwrap();
        check_coinbase(&early, fees, &econ, 0).unwrap();
        let paid: i64 = early.payouts.iter().map(|p| p.amount.zatoshis()).sum();
        assert_eq!(paid, EMISSION * 7 / 10);
        assert_eq!(early.pol_contribution.zatoshis(), EMISSION * 3 / 10);

        // The same coinbase is wrong once the schedule has moved on to 50%.
        let late = 4 * econ.miner_share_taper_interval;
        assert!(matches!(
            check_coinbase(&early, fees, &econ, late),
            Err(CoinbaseError::WrongMinerTotal { .. })
        ));
    }

    #[test]
    fn exactly_100_unique_addresses_pass_and_101_fail() {
        let fees = Amount::new(10_000);

        let cb = build(10_000, 100);
        assert_eq!(cb.payouts.len(), 100);
        check_coinbase(&cb, fees, &FLAT, 0).unwrap();

        // The builder caps at 100; a hand-made 101-address coinbase must be rejected.
        let mut cb101 = cb.clone();
        let half = cb101.payouts[1].amount;
        cb101.payouts[1].amount = Amount::new(half.zatoshis() - 10_000);
        cb101.payouts.push(Payout {
            address: addr(200),
            amount: Amount::new(10_000),
        });
        assert_eq!(
            check_coinbase(&cb101, fees, &FLAT, 0),
            Err(CoinbaseError::TooManyPayoutAddresses {
                count: 101,
                max: 100
            })
        );
        assert_eq!(build(10_000, 150).payouts.len(), 100);
    }

    #[test]
    fn duplicate_addresses_count_once() {
        let fees = Amount::new(0);
        let mut cb = build(0, 100);
        // Split the first payout into two payouts to the same address: still 100 unique.
        let first = cb.payouts[0].clone();
        let part = first.amount.zatoshis() / 2;
        cb.payouts[0].amount = Amount::new(first.amount.zatoshis() - part);
        cb.payouts.push(Payout {
            address: first.address,
            amount: Amount::new(part),
        });
        assert_eq!(cb.payouts.len(), 101);
        check_coinbase(&cb, fees, &FLAT, 0).unwrap();
    }

    #[test]
    fn dust_payouts_are_rejected_so_splitting_costs_something() {
        let fees = Amount::new(20_000);
        let good = build(20_000, 3);

        let mut dusty = good.clone();
        // Peel 5_000 off the first payout into a new address: below the 10_000 minimum.
        dusty.payouts[0].amount = Amount::new(dusty.payouts[0].amount.zatoshis() - 5_000);
        dusty.payouts.push(Payout {
            address: addr(77),
            amount: Amount::new(5_000),
        });
        assert_eq!(
            check_coinbase(&dusty, fees, &FLAT, 0),
            Err(CoinbaseError::DustPayout {
                amount: 5_000,
                min: 10_000
            })
        );

        let mut zero = good;
        zero.payouts[0].amount = Amount::new(0);
        assert!(matches!(
            check_coinbase(&zero, fees, &FLAT, 0),
            Err(CoinbaseError::DustPayout { amount: 0, .. })
        ));
    }

    #[test]
    fn builder_uses_fewer_addresses_when_the_share_is_small() {
        // A share of 25_000 with a 10_000 minimum can only pay 2 addresses.
        let tiny = Economics {
            initial_emission: 50_000,
            tail_emission: 50_000,
            ..FLAT
        };
        let cb = build_coinbase(Amount::new(0), &addrs(10), vec![], &tiny, 0).unwrap();
        assert_eq!(cb.payouts.len(), 2);
        check_coinbase(&cb, Amount::new(0), &tiny, 0).unwrap();

        let none = Economics {
            initial_emission: 10_000,
            tail_emission: 10_000,
            ..FLAT
        };
        assert_eq!(
            build_coinbase(Amount::new(0), &addrs(10), vec![], &none, 0),
            Err(CoinbaseError::NoPayouts)
        );
    }

    #[test]
    fn rejects_a_skimmed_split() {
        let fees = Amount::new(20_000);
        let good = build(20_000, 3);

        let mut skim = good.clone();
        skim.pol_contribution = Amount::new(good.pol_contribution.zatoshis() - 2);
        assert!(matches!(
            check_coinbase(&skim, fees, &FLAT, 0),
            Err(CoinbaseError::WrongPolContribution { .. })
        ));

        let mut greedy = good;
        greedy.payouts[0].amount = Amount::new(greedy.payouts[0].amount.zatoshis() + 2);
        assert!(matches!(
            check_coinbase(&greedy, fees, &FLAT, 0),
            Err(CoinbaseError::WrongMinerTotal { .. })
        ));
    }

    #[test]
    fn odd_rewards_cannot_split_at_fifty_percent() {
        assert!(matches!(
            build_coinbase(Amount::new(1), &addrs(1), vec![], &FLAT, 0),
            Err(CoinbaseError::Split(EconomicsError::OddReward(_)))
        ));
    }
}
