//! POL settlement epochs.
//!
//! Every [`EPOCH_LENGTH`] accepted blocks, the epoch's total reward (scheduled emission plus fees)
//! is settled: miners were paid their scheduled share block by block, and the rest is locked
//! forever into the on-chain DEX reserves as protocol-owned liquidity.
//!
//! The accumulator derives the expected split from the monetary schedule on its own, separately
//! from the per-block coinbase check, so a bug or a gap in one is caught by the other.

use thiserror::Error;
use volt_core::{constants::EPOCH_LENGTH, Coinbase, Economics};
use volt_state::EpochSettlement;
use zebra_chain::amount::{Amount, NonNegative};

use crate::coinbase::{block_reward, split_reward, CoinbaseError};

/// Errors from epoch accounting.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EpochError {
    /// A block's coinbase pays out more or less than its reward.
    #[error("coinbase pays {paid} but the block reward is {reward}")]
    CoinbaseDoesNotMatchReward {
        /// Miner payouts plus the POL contribution.
        paid: i64,
        /// Emission plus fees.
        reward: i64,
    },

    /// A block's coinbase does not follow the scheduled split.
    #[error("coinbase pays miners {miner} and POL {pol}, the schedule requires {expected_miner} and {expected_pol}")]
    OffSchedule {
        /// What miners were paid.
        miner: i64,
        /// What was assigned to POL.
        pol: i64,
        /// What the schedule requires miners to be paid.
        expected_miner: i64,
        /// What the schedule requires POL to receive.
        expected_pol: i64,
    },

    /// The epoch's accumulated split does not match the accumulated schedule.
    #[error("epoch {epoch} is off schedule: miners {miner} (expected {expected_miner}), pol {pol} (expected {expected_pol})")]
    SplitMismatch {
        /// The epoch.
        epoch: u64,
        /// What miners were paid.
        miner: i64,
        /// What was assigned to POL.
        pol: i64,
        /// What the schedule requires miners to be paid.
        expected_miner: i64,
        /// What the schedule requires POL to receive.
        expected_pol: i64,
    },

    /// The halves do not add up to the epoch total.
    #[error("epoch {epoch} parts {miner} + {pol} do not sum to total {total}")]
    PartsDoNotSumToTotal {
        /// The epoch.
        epoch: u64,
        /// What miners were paid.
        miner: i64,
        /// What was assigned to POL.
        pol: i64,
        /// The independently accumulated total reward.
        total: i64,
    },

    /// Settlement was requested before the epoch was complete.
    #[error("epoch has {0} of {EPOCH_LENGTH} blocks")]
    Incomplete(u64),

    /// A reward calculation failed.
    #[error(transparent)]
    Reward(#[from] CoinbaseError),

    /// A sum is out of the valid money range.
    #[error("epoch total out of range")]
    Overflow,
}

/// Running totals for the epoch in progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochAccumulator {
    epoch: u64,
    blocks: u64,
    /// Emission plus fees, from the schedule.
    total_reward: Amount<NonNegative>,
    /// What coinbases actually paid to miners.
    miner_paid: Amount<NonNegative>,
    /// What coinbases actually assigned to POL.
    pol: Amount<NonNegative>,
    /// What the schedule says miners should have been paid.
    expected_miner: Amount<NonNegative>,
    /// What the schedule says POL should have received.
    expected_pol: Amount<NonNegative>,
}

impl Default for EpochAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl EpochAccumulator {
    /// Starts epoch 0.
    pub fn new() -> Self {
        Self {
            epoch: 0,
            blocks: 0,
            total_reward: Amount::zero(),
            miner_paid: Amount::zero(),
            pol: Amount::zero(),
            expected_miner: Amount::zero(),
            expected_pol: Amount::zero(),
        }
    }

    /// The epoch in progress.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The number of blocks accumulated so far in this epoch.
    pub fn blocks(&self) -> u64 {
        self.blocks
    }

    /// Whether the epoch has reached [`EPOCH_LENGTH`] blocks.
    pub fn is_complete(&self) -> bool {
        self.blocks >= EPOCH_LENGTH
    }

    /// The reward accumulated so far.
    pub fn total_reward(&self) -> Amount<NonNegative> {
        self.total_reward
    }

    /// Adds one accepted block whose reward score is `score`.
    ///
    /// The reward and the split are derived from the monetary schedule and the block's `fees`.
    /// Independently, the coinbase's payouts are summed. They must agree.
    pub fn add_block(
        &mut self,
        coinbase: &Coinbase,
        fees: Amount<NonNegative>,
        economics: &Economics,
        score: u64,
    ) -> Result<(), EpochError> {
        let reward = block_reward(economics, score, fees)?;
        let (expected_miner, expected_pol) = split_reward(economics, score, reward)?;

        let mut paid = Amount::<NonNegative>::zero();
        for payout in &coinbase.payouts {
            paid = (paid + payout.amount).map_err(|_| EpochError::Overflow)?;
        }
        let all = (paid + coinbase.pol_contribution).map_err(|_| EpochError::Overflow)?;
        if all != reward {
            return Err(EpochError::CoinbaseDoesNotMatchReward {
                paid: all.zatoshis(),
                reward: reward.zatoshis(),
            });
        }
        if paid != expected_miner || coinbase.pol_contribution != expected_pol {
            return Err(EpochError::OffSchedule {
                miner: paid.zatoshis(),
                pol: coinbase.pol_contribution.zatoshis(),
                expected_miner: expected_miner.zatoshis(),
                expected_pol: expected_pol.zatoshis(),
            });
        }

        let add = |sum: Amount<NonNegative>, part: Amount<NonNegative>| {
            (sum + part).map_err(|_| EpochError::Overflow)
        };
        let total_reward = add(self.total_reward, reward)?;
        let miner_paid = add(self.miner_paid, paid)?;
        let pol = add(self.pol, coinbase.pol_contribution)?;
        let expected_miner = add(self.expected_miner, expected_miner)?;
        let expected_pol = add(self.expected_pol, expected_pol)?;

        self.total_reward = total_reward;
        self.miner_paid = miner_paid;
        self.pol = pol;
        self.expected_miner = expected_miner;
        self.expected_pol = expected_pol;
        self.blocks += 1;
        Ok(())
    }

    /// Settles the completed epoch and starts the next one.
    ///
    /// Enforces the schedule: the miners were paid exactly the scheduled share of the epoch's
    /// total, and exactly the rest goes to the reserve (an exact 50/50 under a flat 50/50 schedule).
    /// On error the accumulator is unchanged.
    pub fn settle(&mut self) -> Result<EpochSettlement, EpochError> {
        if !self.is_complete() {
            return Err(EpochError::Incomplete(self.blocks));
        }

        let (miner, pol, total) = (
            self.miner_paid.zatoshis(),
            self.pol.zatoshis(),
            self.total_reward.zatoshis(),
        );
        if miner.checked_add(pol) != Some(total) {
            return Err(EpochError::PartsDoNotSumToTotal {
                epoch: self.epoch,
                miner,
                pol,
                total,
            });
        }
        if self.miner_paid != self.expected_miner || self.pol != self.expected_pol {
            return Err(EpochError::SplitMismatch {
                epoch: self.epoch,
                miner,
                pol,
                expected_miner: self.expected_miner.zatoshis(),
                expected_pol: self.expected_pol.zatoshis(),
            });
        }

        let settlement = EpochSettlement {
            epoch: self.epoch,
            blocks: self.blocks,
            total_reward: self.total_reward,
            miner_amount: self.miner_paid,
            pol_amount: self.pol,
        };
        *self = Self {
            epoch: self.epoch + 1,
            ..Self::new()
        };
        Ok(settlement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coinbase::build_coinbase;
    use volt_core::constants::VOLT;
    use zebra_chain::{parameters::NetworkKind, transparent::Address};

    const FLAT: Economics = Economics::fifty_fifty();
    const EMISSION: i64 = VOLT / 20;

    fn miners() -> Vec<Address> {
        (0..5)
            .map(|i| Address::from_pub_key_hash(NetworkKind::Regtest, [i; 20]))
            .collect()
    }

    fn fill(acc: &mut EpochAccumulator, econ: &Economics, fees: i64, score: u64) {
        for _ in 0..EPOCH_LENGTH {
            let fees = Amount::new(fees);
            let cb = build_coinbase(fees, &miners(), vec![], econ, score).unwrap();
            acc.add_block(&cb, fees, econ, score).unwrap();
        }
    }

    #[test]
    fn settles_exactly_half_and_half_after_200_blocks() {
        let mut acc = EpochAccumulator::new();
        assert!(acc.settle().is_err(), "not complete yet");

        fill(&mut acc, &FLAT, 30_000, 0);
        assert!(acc.is_complete());
        let s = acc.settle().unwrap();

        let total = EPOCH_LENGTH as i64 * (EMISSION + 30_000);
        assert_eq!(s.epoch, 0);
        assert_eq!(s.total_reward.zatoshis(), total);
        assert_eq!(s.miner_amount.zatoshis(), total / 2);
        assert_eq!(s.pol_amount.zatoshis(), total / 2);
        assert_eq!(acc.epoch(), 1);
        assert_eq!(acc.blocks(), 0);
    }

    #[test]
    fn a_tapered_epoch_settles_at_the_scheduled_share() {
        let econ = Economics::tapered();
        let mut acc = EpochAccumulator::new();
        fill(&mut acc, &econ, 0, 0);
        let s = acc.settle().unwrap();

        let total = EPOCH_LENGTH as i64 * EMISSION;
        assert_eq!(s.miner_amount.zatoshis(), total * 7 / 10);
        assert_eq!(s.pol_amount.zatoshis(), total * 3 / 10);
        assert_eq!(s.miner_amount.zatoshis() + s.pol_amount.zatoshis(), total);
    }

    #[test]
    fn an_epoch_may_span_a_taper_step() {
        // Half the blocks are rewarded at 70%, half at 65%: the totals still follow the schedule.
        let econ = Economics::tapered();
        let step = econ.miner_share_taper_interval;
        let mut acc = EpochAccumulator::new();
        for i in 0..EPOCH_LENGTH {
            let score = if i < EPOCH_LENGTH / 2 { step - 1 } else { step };
            let cb = build_coinbase(Amount::new(0), &miners(), vec![], &econ, score).unwrap();
            acc.add_block(&cb, Amount::new(0), &econ, score).unwrap();
        }
        let s = acc.settle().unwrap();
        let half = (EPOCH_LENGTH / 2) as i64 * EMISSION;
        assert_eq!(s.miner_amount.zatoshis(), half * 7 / 10 + half * 65 / 100);
    }

    #[test]
    fn a_skimmed_coinbase_is_rejected() {
        let mut acc = EpochAccumulator::new();
        let fees = Amount::new(10_000);
        let mut cb = build_coinbase(fees, &miners(), vec![], &FLAT, 0).unwrap();
        cb.pol_contribution = Amount::new(cb.pol_contribution.zatoshis() - 2);
        assert!(matches!(
            acc.add_block(&cb, fees, &FLAT, 0),
            Err(EpochError::CoinbaseDoesNotMatchReward { .. })
        ));

        // Moving value from POL to miners keeps the total but breaks the schedule.
        let mut cb = build_coinbase(fees, &miners(), vec![], &FLAT, 0).unwrap();
        cb.payouts[0].amount = Amount::new(cb.payouts[0].amount.zatoshis() + 2);
        cb.pol_contribution = Amount::new(cb.pol_contribution.zatoshis() - 2);
        assert!(matches!(
            acc.add_block(&cb, fees, &FLAT, 0),
            Err(EpochError::OffSchedule { .. })
        ));
        assert_eq!(acc.blocks(), 0);
    }

    #[test]
    fn an_unbalanced_epoch_does_not_settle() {
        // Simulate corrupted accounting: miners paid 2 zats more than POL, same total.
        let mut acc = EpochAccumulator::new();
        fill(&mut acc, &FLAT, 0, 0);
        acc.miner_paid = Amount::new(acc.miner_paid.zatoshis() + 2);
        acc.pol = Amount::new(acc.pol.zatoshis() - 2);
        assert!(matches!(
            acc.settle(),
            Err(EpochError::SplitMismatch { .. })
        ));
        assert!(acc.is_complete(), "a failed settlement changes nothing");
    }
}
