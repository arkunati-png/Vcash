//! The emission schedule and the miner / protocol-owned-liquidity split.
//!
//! Both are pure functions of a block's *reward score*: the blue score of its selected parent.
//! Every node derives the same score from the same DAG, so the schedule is consensus-safe.

use thiserror::Error;

use crate::constants::VOLT;

/// Basis points in 100%.
pub const BPS: u64 = 10_000;

/// Errors from splitting a reward.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum EconomicsError {
    /// The reward is odd, so an exact 50/50 split is impossible.
    #[error("reward {0} cannot be split exactly in half")]
    OddReward(i64),

    /// The reward is negative.
    #[error("negative reward {0}")]
    NegativeReward(i64),

    /// The miner share is more than 100%.
    #[error("miner share of {0} basis points is more than 100%")]
    InvalidShare(u64),
}

/// The monetary policy parameters.
///
/// - **Emission** starts at `initial_emission` per block, halves every `halving_interval`
///   blocks, and never falls below `tail_emission`, so miners are still paid once the halvings
///   run out.
/// - **Miner share** starts at `miner_share_start_bps` and falls by `miner_share_step_bps` every
///   `miner_share_taper_interval` blocks until it reaches `miner_share_end_bps`. Early on miners
///   keep more of the reward to bootstrap security. The rest of every reward is locked as
///   protocol-owned liquidity.
/// - **Minimum payout** stops a miner from splitting a coinbase into dust payouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Economics {
    /// Emission per block before the first halving, in zatoshis. Must be even.
    pub initial_emission: i64,
    /// The floor emission per block, in zatoshis. Must be even.
    pub tail_emission: i64,
    /// Blocks (by reward score) between halvings.
    pub halving_interval: u64,
    /// The miner share at score zero, in basis points.
    pub miner_share_start_bps: u64,
    /// The miner share once the taper is complete, in basis points.
    pub miner_share_end_bps: u64,
    /// How much the miner share falls per taper interval, in basis points.
    pub miner_share_step_bps: u64,
    /// Blocks (by reward score) between taper steps.
    pub miner_share_taper_interval: u64,
    /// The smallest allowed coinbase payout, in zatoshis.
    pub min_payout: i64,
}

impl Default for Economics {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl Economics {
    /// The intended production schedule.
    ///
    /// - 0.05 VOLT per block, halving yearly (63,072,000 blocks at 2 per second), with a
    ///   0.001 VOLT tail;
    /// - miners start with 70% of each reward and fall by 5 points every ~36 days to 50%.
    pub const fn mainnet() -> Self {
        Self {
            initial_emission: VOLT / 20,
            tail_emission: VOLT / 1_000,
            halving_interval: 63_072_000,
            miner_share_start_bps: 7_000,
            miner_share_end_bps: 5_000,
            miner_share_step_bps: 500,
            miner_share_taper_interval: 6_307_200,
            min_payout: 10_000,
        }
    }

    /// A flat schedule with an exact 50/50 split from the first block. Useful for tests and
    /// for networks that want the simplest possible policy.
    pub const fn fifty_fifty() -> Self {
        Self {
            initial_emission: VOLT / 20,
            tail_emission: VOLT / 20,
            halving_interval: u64::MAX,
            miner_share_start_bps: 5_000,
            miner_share_end_bps: 5_000,
            miner_share_step_bps: 0,
            miner_share_taper_interval: u64::MAX,
            min_payout: 10_000,
        }
    }

    /// The emission for a block with the given reward score, in zatoshis.
    ///
    /// Always even, so a 50/50 split of `emission + fees` has no remainder.
    pub fn emission(&self, score: u64) -> i64 {
        let halvings = score / self.halving_interval.max(1);
        let halved = if halvings >= 63 {
            0
        } else {
            self.initial_emission >> halvings
        };
        halved.max(self.tail_emission) & !1
    }

    /// The share of a block's reward paid to miners, in basis points.
    pub fn miner_share_bps(&self, score: u64) -> u64 {
        let steps = score / self.miner_share_taper_interval.max(1);
        let drop = steps.saturating_mul(self.miner_share_step_bps);
        self.miner_share_start_bps
            .saturating_sub(drop)
            .max(self.miner_share_end_bps)
    }

    /// Splits `reward` into `(miners, pol)` for a block with the given reward score.
    ///
    /// The miner part is rounded down, so any remainder goes to the protocol-owned liquidity.
    /// At exactly 50% an odd reward is an error, because an exact half does not exist.
    pub fn split(&self, reward: i64, score: u64) -> Result<(i64, i64), EconomicsError> {
        let reward_u = u64::try_from(reward).map_err(|_| EconomicsError::NegativeReward(reward))?;
        let bps = self.miner_share_bps(score);
        if bps == BPS / 2 && reward_u % 2 != 0 {
            return Err(EconomicsError::OddReward(reward));
        }

        // A share above 100% would make the POL part negative, so it is refused.
        let miners = u128::from(reward_u) * u128::from(bps) / u128::from(BPS);
        let miners = i64::try_from(miners)
            .ok()
            .filter(|miners| *miners <= reward)
            .ok_or(EconomicsError::InvalidShare(bps))?;
        Ok((miners, reward - miners))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emission_halves_and_floors_at_the_tail() {
        let e = Economics::mainnet();
        let year = e.halving_interval;

        assert_eq!(e.emission(0), 5_000_000);
        assert_eq!(e.emission(year - 1), 5_000_000);
        assert_eq!(e.emission(year), 2_500_000);
        assert_eq!(e.emission(2 * year), 1_250_000);
        assert_eq!(e.emission(3 * year), 625_000);
        assert_eq!(e.emission(4 * year), 312_500);
        assert_eq!(e.emission(5 * year), 156_250);
        // 78_125 would be next, but it is below the tail, which takes over for good.
        assert_eq!(e.emission(6 * year), 100_000);
        assert_eq!(e.emission(30 * year), 100_000);

        // A schedule without a tail rounds odd values down to even.
        let no_tail = Economics {
            tail_emission: 0,
            ..e
        };
        assert_eq!(no_tail.emission(6 * year), 78_124);
        assert_eq!(e.emission(u64::MAX), 100_000);

        for score in [0, 1, year, 4 * year + 7, 9 * year] {
            assert_eq!(e.emission(score) % 2, 0, "emission is always even");
        }
    }

    #[test]
    fn total_supply_is_bounded() {
        // Sum the emission over the halving periods: 2x the first period, plus a small tail
        // per period afterwards. 40 years must stay far below the 21M cap of an Amount.
        let e = Economics::mainnet();
        let mut total: i128 = 0;
        for period in 0..40u64 {
            total += i128::from(e.emission(period * e.halving_interval))
                * i128::from(e.halving_interval);
        }
        assert!(total < i128::from(21_000_000 * VOLT), "supply {total}");
    }

    #[test]
    fn miner_share_tapers_from_70_to_50_percent() {
        let e = Economics::mainnet();
        let step = e.miner_share_taper_interval;

        assert_eq!(e.miner_share_bps(0), 7_000);
        assert_eq!(e.miner_share_bps(step - 1), 7_000);
        assert_eq!(e.miner_share_bps(step), 6_500);
        assert_eq!(e.miner_share_bps(2 * step), 6_000);
        assert_eq!(e.miner_share_bps(3 * step), 5_500);
        assert_eq!(e.miner_share_bps(4 * step), 5_000);
        assert_eq!(
            e.miner_share_bps(1_000 * step),
            5_000,
            "it never goes below the floor"
        );
        assert_eq!(e.miner_share_bps(u64::MAX), 5_000);
    }

    #[test]
    fn split_follows_the_share_and_conserves_value() {
        let e = Economics::mainnet();

        let (miners, pol) = e.split(1_000_000, 0).unwrap();
        assert_eq!((miners, pol), (700_000, 300_000));

        // Rounding goes to the protocol-owned liquidity.
        let (miners, pol) = e.split(10, 1).unwrap();
        assert_eq!(miners + pol, 10);
        assert_eq!(miners, 7);

        // At the 50% floor an odd reward cannot be split exactly.
        let late = 4 * e.miner_share_taper_interval;
        assert_eq!(e.split(1_000, late).unwrap(), (500, 500));
        assert_eq!(e.split(1_001, late), Err(EconomicsError::OddReward(1_001)));
        assert_eq!(e.split(-1, 0), Err(EconomicsError::NegativeReward(-1)));
    }

    #[test]
    fn a_miner_share_above_100_percent_is_refused_not_turned_into_negative_pol() {
        let broken = Economics {
            miner_share_start_bps: 12_000,
            miner_share_end_bps: 12_000,
            ..Economics::fifty_fifty()
        };
        assert_eq!(
            broken.split(1_000, 0),
            Err(EconomicsError::InvalidShare(12_000))
        );
        // Exactly 100% is allowed: all of the reward to miners, none to POL.
        let all = Economics {
            miner_share_start_bps: 10_000,
            miner_share_end_bps: 10_000,
            ..Economics::fifty_fifty()
        };
        assert_eq!(all.split(1_000, 0), Ok((1_000, 0)));
    }

    #[test]
    fn fifty_fifty_is_flat_and_exact() {
        let e = Economics::fifty_fifty();
        for score in [0, 1, 1_000_000_000, u64::MAX] {
            assert_eq!(e.emission(score), 5_000_000);
            assert_eq!(e.split(5_000_000, score).unwrap(), (2_500_000, 2_500_000));
        }
    }
}
