//! Dual-tier transaction fees.

use zebra_chain::amount::{Amount, NonNegative};

use crate::{
    constants::{SHIELDED_FEE, TRANSPARENT_FEE},
    tx::{BatchableTx, TxKind},
};

/// Returns the fee for a transaction of `kind`.
pub fn fee_for_kind(kind: TxKind) -> Amount<NonNegative> {
    match kind {
        TxKind::Transparent => Amount::new(TRANSPARENT_FEE),
        TxKind::Shielded => Amount::new(SHIELDED_FEE),
    }
}

/// Returns the fee `tx` must pay: 0.0001 VOLT if transparent, 0.0002 VOLT if shielded.
pub fn calculate_tx_fee<T: BatchableTx + ?Sized>(tx: &T) -> Amount<NonNegative> {
    fee_for_kind(tx.kind())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_tx::DevTx;

    #[test]
    fn fee_tiers() {
        let transparent = DevTx::new(vec![], vec![], vec![], false, 1);
        let shielded = DevTx::new(vec![], vec![], vec![[9; 32]], true, 2);

        assert_eq!(calculate_tx_fee(&transparent).zatoshis(), 10_000);
        assert_eq!(calculate_tx_fee(&shielded).zatoshis(), 20_000);
        assert_eq!(fee_for_kind(TxKind::Shielded), Amount::new(20_000));
    }
}
