//! Thermodynamic POL epochs.
//!
//! Every [`EPOCH_LENGTH`] accepted blocks, the epoch's total reward (base emission plus fees)
//! is settled: exactly half went to RandomX miners, and exactly half is locked forever into
//! the on-chain DEX reserves as protocol-owned, electricity-backed liquidity.

use thiserror::Error;
use volt_core::{constants::EPOCH_LENGTH, Coinbase};
use volt_state::EpochSettlement;
use zebra_chain::amount::{Amount, NonNegative};

use crate::coinbase::{block_reward, CoinbaseError};

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

    /// The epoch's miner and POL halves are not equal.
    #[error("epoch {epoch} is not split 50/50: miners {miner}, pol {pol}")]
    NotFiftyFifty {
        /// The epoch.
        epoch: u64,
        /// What miners were paid.
        miner: i64,
        /// What was assigned to POL.
        pol: i64,
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
    total_reward: Amount<NonNegative>,
    miner_paid: Amount<NonNegative>,
    pol: Amount<NonNegative>,
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

    /// Adds one accepted block.
    ///
    /// The total reward is derived from the block's `fees` and the emission schedule, and
    /// independently the coinbase's payouts are summed. They must agree.
    pub fn add_block(
        &mut self,
        coinbase: &Coinbase,
        fees: Amount<NonNegative>,
    ) -> Result<(), EpochError> {
        let reward = block_reward(fees)?;

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

        let total_reward = (self.total_reward + reward).map_err(|_| EpochError::Overflow)?;
        let miner_paid = (self.miner_paid + paid).map_err(|_| EpochError::Overflow)?;
        let pol = (self.pol + coinbase.pol_contribution).map_err(|_| EpochError::Overflow)?;

        self.total_reward = total_reward;
        self.miner_paid = miner_paid;
        self.pol = pol;
        self.blocks += 1;
        Ok(())
    }

    /// Settles the completed epoch and starts the next one.
    ///
    /// Enforces the exact 50/50 split: the miners were paid `total / 2`, and `total / 2` goes
    /// to the reserve. On error the accumulator is unchanged.
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
        if miner != pol {
            return Err(EpochError::NotFiftyFifty {
                epoch: self.epoch,
                miner,
                pol,
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
    use zebra_chain::{parameters::NetworkKind, transparent::Address};

    fn miners() -> Vec<Address> {
        (0..5)
            .map(|i| Address::from_pub_key_hash(NetworkKind::Regtest, [i; 20]))
            .collect()
    }

    fn fill(acc: &mut EpochAccumulator, fees: i64) {
        for _ in 0..EPOCH_LENGTH {
            let fees = Amount::new(fees);
            let cb = build_coinbase(fees, &miners(), vec![]).unwrap();
            acc.add_block(&cb, fees).unwrap();
        }
    }

    #[test]
    fn settles_exactly_half_and_half_after_200_blocks() {
        let mut acc = EpochAccumulator::new();
        assert!(acc.settle().is_err(), "not complete yet");

        fill(&mut acc, 30_000);
        assert!(acc.is_complete());
        let s = acc.settle().unwrap();

        let total = EPOCH_LENGTH as i64 * (volt_core::constants::BASE_EMISSION_PER_BLOCK + 30_000);
        assert_eq!(s.epoch, 0);
        assert_eq!(s.total_reward.zatoshis(), total);
        assert_eq!(s.miner_amount.zatoshis(), total / 2);
        assert_eq!(s.pol_amount.zatoshis(), total / 2);
        assert_eq!(acc.epoch(), 1);
        assert_eq!(acc.blocks(), 0);
    }

    #[test]
    fn a_skimmed_coinbase_is_rejected() {
        let mut acc = EpochAccumulator::new();
        let fees = Amount::new(10_000);
        let mut cb = build_coinbase(fees, &miners(), vec![]).unwrap();
        cb.pol_contribution = Amount::new(cb.pol_contribution.zatoshis() - 2);
        assert!(matches!(
            acc.add_block(&cb, fees),
            Err(EpochError::CoinbaseDoesNotMatchReward { .. })
        ));
        assert_eq!(acc.blocks(), 0);
    }

    #[test]
    fn an_unbalanced_epoch_does_not_settle() {
        // Simulate corrupted accounting: miners paid 2 zats more than POL, same total.
        let mut acc = EpochAccumulator::new();
        fill(&mut acc, 0);
        acc.miner_paid = Amount::new(acc.miner_paid.zatoshis() + 2);
        acc.pol = Amount::new(acc.pol.zatoshis() - 2);
        assert!(matches!(
            acc.settle(),
            Err(EpochError::NotFiftyFifty { .. })
        ));
        assert!(acc.is_complete(), "a failed settlement changes nothing");
    }
}
