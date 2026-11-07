//! Size-aware, dual-tier transaction fees.
//!
//! A transaction pays the **largest** of three amounts:
//!
//! 1. its tier: 0.0001 VOLT if transparent, 0.0002 VOLT if shielded;
//! 2. [`MARGINAL_FEE_PER_ACTION`] for each logical action;
//! 3. [`FEE_PER_KB`] for each started kilobyte of serialized size.
//!
//! The tier keeps small transactions at the headline price, while the other two make a
//! transaction that costs the network more to verify or relay pay proportionally more.
//! The fee is exact: a transaction's value must balance to `inputs = outputs + fee`.

use zebra_chain::amount::{Amount, NonNegative};

use crate::{
    constants::{FEE_PER_KB, MARGINAL_FEE_PER_ACTION, SHIELDED_FEE, TRANSPARENT_FEE},
    tx::{BatchableTx, TxKind},
};

/// Returns the tier fee for a transaction of `kind`, the minimum any transaction of that kind pays.
pub fn fee_for_kind(kind: TxKind) -> Amount<NonNegative> {
    match kind {
        TxKind::Transparent => Amount::new(TRANSPARENT_FEE),
        TxKind::Shielded => Amount::new(SHIELDED_FEE),
    }
}

/// Returns the fee for a transaction with the given shape.
pub fn fee_for(kind: TxKind, actions: u64, size_bytes: usize) -> Amount<NonNegative> {
    let tier = fee_for_kind(kind).zatoshis();

    let per_action = i64::try_from(actions)
        .unwrap_or(i64::MAX)
        .saturating_mul(MARGINAL_FEE_PER_ACTION);
    let kilobytes = i64::try_from(size_bytes.div_ceil(1_000)).unwrap_or(i64::MAX);
    let per_size = kilobytes.saturating_mul(FEE_PER_KB);

    // An absurdly large transaction saturates at the largest valid amount rather than panicking;
    // it can never balance, so it is rejected by the state rules anyway.
    let fee = tier
        .max(per_action)
        .max(per_size)
        .min(zebra_chain::amount::MAX_MONEY);
    // Round down to even so a block reward built from fees can split exactly in half.
    Amount::new(fee & !1)
}

/// Returns the fee `tx` must pay.
pub fn calculate_tx_fee<T: BatchableTx + ?Sized>(tx: &T) -> Amount<NonNegative> {
    fee_for(tx.kind(), tx.logical_actions(), tx.size_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_tx::DevTx;
    use zebra_chain::transparent::{Output, Script};

    fn out() -> Output {
        Output::new(Amount::new(1), Script::new(&[]))
    }

    #[test]
    fn small_transactions_pay_the_headline_tier() {
        let transparent = DevTx::new(vec![], vec![], vec![], false, 1);
        let shielded = DevTx::new(vec![], vec![], vec![[9; 32]], true, 2);

        assert_eq!(calculate_tx_fee(&transparent).zatoshis(), 10_000);
        assert_eq!(calculate_tx_fee(&shielded).zatoshis(), 20_000);
        assert_eq!(fee_for_kind(TxKind::Shielded), Amount::new(20_000));
    }

    #[test]
    fn big_transactions_pay_more_than_the_tier() {
        // 50 outputs = 50 actions = 100_000, well above the 10_000 tier.
        let many_outputs = DevTx::new(vec![], vec![out(); 50], vec![], false, 1);
        assert_eq!(many_outputs.logical_actions(), 50);
        assert_eq!(calculate_tx_fee(&many_outputs).zatoshis(), 100_000);

        // A large script pays by size: 5,000 bytes of script is 6 started kilobytes at least.
        let fat = Output::new(Amount::new(1), Script::new(&[0u8; 5_000]));
        let fat_tx = DevTx::new(vec![], vec![fat], vec![], false, 2);
        assert!(fat_tx.size_bytes() > 5_000);
        let expected = (fat_tx.size_bytes().div_ceil(1_000) as i64) * FEE_PER_KB;
        assert_eq!(
            calculate_tx_fee(&fat_tx).zatoshis(),
            expected.max(10_000) & !1
        );
        assert!(calculate_tx_fee(&fat_tx).zatoshis() > 10_000);
    }

    #[test]
    fn spam_cost_scales_with_work() {
        // The same total number of outputs costs the same whether packed in one transaction or many.
        let one_big = calculate_tx_fee(&DevTx::new(vec![], vec![out(); 40], vec![], false, 1));
        let many_small: i64 = (0..8)
            .map(|n| {
                calculate_tx_fee(&DevTx::new(vec![], vec![out(); 5], vec![], false, n)).zatoshis()
            })
            .sum();
        // 8 small transactions pay 8 tiers (80_000); one 40-action transaction pays 80_000 too.
        assert_eq!(one_big.zatoshis(), 80_000);
        assert_eq!(many_small, 80_000);
    }

    #[test]
    fn fees_are_always_even_and_never_panic() {
        for actions in [0, 1, 7, 1_000, u64::MAX] {
            for size in [0, 1, 999, 1_001, usize::MAX] {
                for kind in [TxKind::Transparent, TxKind::Shielded] {
                    assert_eq!(fee_for(kind, actions, size).zatoshis() % 2, 0);
                }
            }
        }
    }
}
