//! The protocol-owned liquidity (POL) reserve.

use thiserror::Error;
use zebra_chain::amount::{Amount, NonNegative};

/// The result of settling one 200-block epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochSettlement {
    /// The epoch number, starting at 0.
    pub epoch: u64,
    /// The number of blocks credited in this epoch.
    pub blocks: u64,
    /// The epoch's total reward: base emission plus fees.
    pub total_reward: Amount<NonNegative>,
    /// The part paid to RandomX miners, according to the schedule.
    pub miner_amount: Amount<NonNegative>,
    /// The part locked into the DEX reserves, according to the schedule.
    pub pol_amount: Amount<NonNegative>,
}

/// Errors from locking a settlement into the reserve.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolError {
    /// The miner and POL amounts do not add up to the total.
    #[error("settlement parts {miner} + {pol} do not sum to total {total}")]
    PartsDoNotSumToTotal {
        /// The miner amount.
        miner: i64,
        /// The POL amount.
        pol: i64,
        /// The stated total.
        total: i64,
    },

    /// The epoch is not the next one to settle.
    #[error("expected to settle epoch {expected}, got {got}")]
    OutOfOrder {
        /// The next epoch the reserve expects.
        expected: u64,
        /// The epoch it was given.
        got: u64,
    },

    /// The locked total would exceed the valid money range.
    #[error("locked reserve overflow")]
    Overflow,
}

/// The on-chain DEX reserve of permanently locked, protocol-owned liquidity.
///
/// There is deliberately no way to withdraw: the only mutation is [`PolReserve::lock`].
#[derive(Clone, Debug, Default)]
pub struct PolReserve {
    locked: Amount<NonNegative>,
    settlements: Vec<EpochSettlement>,
}

impl PolReserve {
    /// Creates an empty reserve.
    pub fn new() -> Self {
        Self::default()
    }

    /// The total VOLT permanently locked so far.
    pub fn locked(&self) -> Amount<NonNegative> {
        self.locked
    }

    /// Every settled epoch, in order.
    pub fn settlements(&self) -> &[EpochSettlement] {
        &self.settlements
    }

    /// The number of the next epoch this reserve will accept.
    pub fn next_epoch(&self) -> u64 {
        self.settlements.len() as u64 // lossless: a Vec length always fits in u64
    }

    /// Locks the POL part of an epoch settlement forever.
    ///
    /// Checks that the epoch is the next one and that the parts add up to the total. Whether the
    /// split follows the monetary schedule is verified by consensus before it gets here: the
    /// schedule can change the miner share over time, so the reserve does not hard-code one.
    pub fn lock(&mut self, settlement: EpochSettlement) -> Result<(), PolError> {
        if settlement.epoch != self.next_epoch() {
            return Err(PolError::OutOfOrder {
                expected: self.next_epoch(),
                got: settlement.epoch,
            });
        }

        let miner = settlement.miner_amount.zatoshis();
        let pol = settlement.pol_amount.zatoshis();
        let total = settlement.total_reward.zatoshis();
        if miner.checked_add(pol) != Some(total) {
            return Err(PolError::PartsDoNotSumToTotal { miner, pol, total });
        }
        self.locked = (self.locked + settlement.pol_amount).map_err(|_| PolError::Overflow)?;
        self.settlements.push(settlement);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settlement(epoch: u64, miner: i64, pol: i64) -> EpochSettlement {
        EpochSettlement {
            epoch,
            blocks: 200,
            total_reward: Amount::new(miner + pol),
            miner_amount: Amount::new(miner),
            pol_amount: Amount::new(pol),
        }
    }

    #[test]
    fn locks_consistent_settlements_in_order() {
        let mut reserve = PolReserve::new();
        reserve.lock(settlement(0, 500, 500)).unwrap();
        // A 70/30 epoch (a tapered schedule): only the POL part (300) is locked.
        reserve.lock(settlement(1, 700, 300)).unwrap();
        assert_eq!(reserve.locked().zatoshis(), 800);

        let mut lying = settlement(2, 301, 300);
        lying.total_reward = Amount::new(999);
        assert_eq!(
            reserve.lock(lying),
            Err(PolError::PartsDoNotSumToTotal {
                miner: 301,
                pol: 300,
                total: 999
            })
        );
        assert_eq!(
            reserve.lock(settlement(5, 10, 10)),
            Err(PolError::OutOfOrder {
                expected: 2,
                got: 5
            })
        );
        assert_eq!(
            reserve.locked().zatoshis(),
            800,
            "failed locks change nothing"
        );
    }
}
