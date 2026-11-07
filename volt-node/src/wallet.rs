//! A proof-less wallet that generates devnet traffic.

use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use volt_core::{
    constants::{SHIELDED_FEE, TRANSPARENT_FEE},
    BatchableTx, DevTx, VoltBlock, VoltHash,
};
use zebra_chain::{
    amount::Amount,
    transaction,
    transparent::{OutPoint, Output, Script},
};

/// Spends accepted outputs, alternating transparent and shielded transactions.
///
/// Every third transaction is shielded (it pays the higher fee and reveals a nullifier).
/// A transaction's own outputs become spendable again once its block is accepted.
#[derive(Debug, Default)]
pub struct DevWallet {
    spendable: VecDeque<(OutPoint, i64)>,
    /// Every outpoint ever queued, so a step that is reverted and re-applied is not counted twice.
    known: HashSet<OutPoint>,
    nonce: u64,
}

impl DevWallet {
    /// Creates an empty wallet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of outputs available to spend.
    pub fn spendable(&self) -> usize {
        self.spendable.len()
    }

    fn add(&mut self, outpoint: OutPoint, value: i64) {
        if self.known.insert(outpoint) {
            self.spendable.push_back((outpoint, value));
        }
    }

    /// Records that `block` was accepted: its coinbase outputs and the outputs of its batched
    /// transactions become spendable.
    pub fn on_accepted(&mut self, block: &VoltBlock) {
        for (outpoint, output) in block.coinbase.outputs() {
            self.add(outpoint, output.value().zatoshis());
        }
        for batch in &block.batches {
            for raw in batch.raw_txs() {
                let Ok(tx) = DevTx::decode(raw) else { continue };
                let txid = transaction::Hash(tx.txid().0);
                for (index, output) in tx.outputs().into_iter().enumerate() {
                    self.add(OutPoint::from_usize(txid, index), output.value().zatoshis());
                }
            }
        }
    }

    /// Builds up to `count` transactions, fewer if the wallet runs out of outputs.
    ///
    /// `is_unspent` reports whether an outpoint is currently unspent in the node's state, so
    /// outputs lost to a reorg are dropped instead of spent.
    pub fn make_txs(
        &mut self,
        count: usize,
        is_unspent: impl Fn(&OutPoint) -> bool,
    ) -> Vec<Arc<dyn BatchableTx>> {
        let mut txs: Vec<Arc<dyn BatchableTx>> = Vec::with_capacity(count);
        while txs.len() < count {
            let Some((outpoint, value)) = self.spendable.pop_front() else {
                break;
            };
            if !is_unspent(&outpoint) {
                // Reverted or already spent: forget it so a later re-acceptance can re-add it.
                self.known.remove(&outpoint);
                continue;
            }

            self.nonce += 1;
            let shielded = self.nonce.rem_euclid(3) == 0;
            let fee = if shielded {
                SHIELDED_FEE
            } else {
                TRANSPARENT_FEE
            };
            if value <= fee {
                continue; // dust: not worth spending
            }

            let nullifiers = if shielded {
                vec![VoltHash::digest(b"VoltDevNullifier", &self.nonce.to_le_bytes()).0]
            } else {
                Vec::new()
            };
            let output = Output::new(
                Amount::new(value - fee),
                Script::new(&self.nonce.to_le_bytes()),
            );
            txs.push(Arc::new(DevTx::new(
                vec![outpoint],
                vec![output],
                nullifiers,
                shielded,
                self.nonce,
            )));
        }
        txs
    }
}
