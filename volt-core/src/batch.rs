//! The 10-to-1 rollup batch.
//!
//! A [`RollupBatch`] packs up to [`BATCH_SIZE`] transactions into one payload, so the base
//! layer carries one compressed state transition instead of ten separate transactions and
//! charges one block-space slot for them. Miners fill batches to ten whenever they can; a quiet
//! chain closes a smaller batch rather than leaving a lone transaction waiting forever.

use std::{collections::HashSet, io::Read, io::Write, sync::Arc};

use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use thiserror::Error;
use zebra_chain::amount::{Amount, NonNegative};

use crate::{
    codec::{CodecError, Reader, Writer},
    constants::{BATCH_SIZE, MAX_TX_BYTES},
    fee::calculate_tx_fee,
    hash::{merkle_root, VoltHash},
    tx::{BatchableTx, TxDecoder},
};

/// The maximum size of a decompressed batch payload, in bytes.
const MAX_PAYLOAD_BYTES: usize = BATCH_SIZE * (MAX_TX_BYTES + 4) + 64;

const TX_LEAF_PERSONAL: &[u8; 16] = b"VoltBatchTxLeaf_";

/// Errors from building, decoding or checking a [`RollupBatch`].
#[derive(Debug, Error, PartialEq, Clone)]
pub enum BatchError {
    /// The batch holds no transactions, or more than [`BATCH_SIZE`].
    #[error("a rollup batch must contain 1 to {BATCH_SIZE} transactions, got {0}")]
    WrongSize(usize),

    /// A coinbase transaction was placed in a batch.
    #[error("coinbase transactions cannot be batched")]
    CoinbaseInBatch,

    /// Two transactions in the batch have the same id.
    #[error("duplicate transaction {0} in batch")]
    DuplicateTx(VoltHash),

    /// The stored batch root does not match the transactions.
    #[error("batch root mismatch")]
    RootMismatch,

    /// The stored fee total does not match the transactions.
    #[error("batch fee total mismatch: stored {stored}, computed {computed}")]
    FeeMismatch {
        /// The total in the batch header.
        stored: i64,
        /// The total recomputed from the transactions.
        computed: i64,
    },

    /// The fee total is not a valid amount.
    #[error("batch fee total out of range")]
    FeeOverflow,

    /// The payload could not be decoded.
    #[error("batch payload: {0}")]
    Codec(#[from] CodecError),

    /// The payload could not be decompressed, or is larger than allowed.
    #[error("batch payload compression error")]
    Compression,
}

/// Ten transactions packed into one compressed state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollupBatch {
    txs: Vec<Vec<u8>>,
    batch_root: VoltHash,
    total_fees: Amount<NonNegative>,
}

impl RollupBatch {
    /// Packs 1 to [`BATCH_SIZE`] transactions into a batch.
    pub fn pack(txs: &[Arc<dyn BatchableTx>]) -> Result<Self, BatchError> {
        if txs.is_empty() || txs.len() > BATCH_SIZE {
            return Err(BatchError::WrongSize(txs.len()));
        }

        let mut seen = HashSet::with_capacity(BATCH_SIZE);
        let mut total_fees = Amount::<NonNegative>::zero();
        for tx in txs {
            if tx.is_coinbase() {
                return Err(BatchError::CoinbaseInBatch);
            }
            if !seen.insert(tx.txid()) {
                return Err(BatchError::DuplicateTx(tx.txid()));
            }
            total_fees = (total_fees + calculate_tx_fee(tx.as_ref()))
                .map_err(|_| BatchError::FeeOverflow)?;
        }

        let txs: Vec<Vec<u8>> = txs.iter().map(|tx| tx.to_bytes()).collect();
        let batch_root = Self::root_of(&txs);
        Ok(Self {
            txs,
            batch_root,
            total_fees,
        })
    }

    fn root_of(txs: &[Vec<u8>]) -> VoltHash {
        let leaves: Vec<VoltHash> = txs
            .iter()
            .map(|bytes| VoltHash::digest(TX_LEAF_PERSONAL, bytes))
            .collect();
        merkle_root(&leaves)
    }

    /// The Merkle root committing to the batched transactions.
    pub fn batch_root(&self) -> VoltHash {
        self.batch_root
    }

    /// The sum of the fees of the batched transactions.
    pub fn total_fees(&self) -> Amount<NonNegative> {
        self.total_fees
    }

    /// The serialized transactions in this batch.
    pub fn raw_txs(&self) -> &[Vec<u8>] {
        &self.txs
    }

    /// Decodes and fully checks the batch: size, root, coinbases, duplicates and fees.
    pub fn unpack(&self, decoder: &dyn TxDecoder) -> Result<Vec<Arc<dyn BatchableTx>>, BatchError> {
        if self.txs.is_empty() || self.txs.len() > BATCH_SIZE {
            return Err(BatchError::WrongSize(self.txs.len()));
        }
        if Self::root_of(&self.txs) != self.batch_root {
            return Err(BatchError::RootMismatch);
        }

        let mut seen = HashSet::with_capacity(self.txs.len());
        let mut fees = Amount::<NonNegative>::zero();
        let mut decoded = Vec::with_capacity(self.txs.len());
        for bytes in &self.txs {
            let tx = decoder.decode(bytes)?;
            if tx.is_coinbase() {
                return Err(BatchError::CoinbaseInBatch);
            }
            if !seen.insert(tx.txid()) {
                return Err(BatchError::DuplicateTx(tx.txid()));
            }
            fees = (fees + calculate_tx_fee(tx.as_ref())).map_err(|_| BatchError::FeeOverflow)?;
            decoded.push(tx);
        }

        if fees != self.total_fees {
            return Err(BatchError::FeeMismatch {
                stored: self.total_fees.zatoshis(),
                computed: fees.zatoshis(),
            });
        }
        Ok(decoded)
    }

    /// Serializes and zlib-compresses the batch into its on-chain payload.
    pub fn compress(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.i64(self.total_fees.zatoshis()).count(self.txs.len());
        for tx in &self.txs {
            w.bytes(tx);
        }

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder
            .write_all(&w.finish())
            .expect("writing to a Vec cannot fail");
        encoder
            .finish()
            .expect("finishing a Vec writer cannot fail")
    }

    /// Decompresses and parses an on-chain payload.
    ///
    /// The decompressed size is bounded, so a small payload cannot expand without limit.
    /// This checks the structure only; call [`RollupBatch::unpack`] for the full checks.
    pub fn decompress(payload: &[u8]) -> Result<Self, BatchError> {
        let mut raw = Vec::new();
        ZlibDecoder::new(payload)
            .take(MAX_PAYLOAD_BYTES as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|_| BatchError::Compression)?;
        if raw.len() > MAX_PAYLOAD_BYTES {
            return Err(BatchError::Compression);
        }

        let mut r = Reader::new(&raw);
        let total_fees =
            Amount::<NonNegative>::try_from(r.i64()?).map_err(|_| BatchError::FeeOverflow)?;
        let n = r.count("batch transactions", BATCH_SIZE)?;
        if n == 0 {
            return Err(BatchError::WrongSize(n));
        }

        let mut txs = Vec::with_capacity(n);
        for _ in 0..n {
            txs.push(r.bytes("transaction", MAX_TX_BYTES)?.to_vec());
        }
        r.finish()?;

        let batch_root = Self::root_of(&txs);
        Ok(Self {
            txs,
            batch_root,
            total_fees,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dev_tx::DevTxDecoder, DevTx};

    fn txs(n: usize) -> Vec<Arc<dyn BatchableTx>> {
        (0..n as u64)
            .map(|i| {
                let shielded = i % 2 == 1;
                let nullifiers = if shielded {
                    vec![[i as u8; 32]]
                } else {
                    vec![]
                };
                Arc::new(DevTx::new(vec![], vec![], nullifiers, shielded, i))
                    as Arc<dyn BatchableTx>
            })
            .collect()
    }

    #[test]
    fn packs_one_to_ten() {
        assert!(RollupBatch::pack(&txs(10)).is_ok());
        for n in [1, 3, 9] {
            let batch = RollupBatch::pack(&txs(n)).unwrap();
            let decoded = RollupBatch::decompress(&batch.compress()).unwrap();
            assert_eq!(decoded.unpack(&DevTxDecoder).unwrap().len(), n);
        }
        assert_eq!(RollupBatch::pack(&txs(0)), Err(BatchError::WrongSize(0)));
        assert_eq!(RollupBatch::pack(&txs(11)), Err(BatchError::WrongSize(11)));
    }

    #[test]
    fn fee_total_mixes_tiers() {
        // 5 transparent (10_000) + 5 shielded (20_000)
        let batch = RollupBatch::pack(&txs(10)).unwrap();
        assert_eq!(batch.total_fees().zatoshis(), 150_000);
    }

    #[test]
    fn compress_round_trip_and_unpack() {
        let batch = RollupBatch::pack(&txs(10)).unwrap();
        let decoded = RollupBatch::decompress(&batch.compress()).unwrap();
        assert_eq!(decoded, batch);
        assert_eq!(decoded.unpack(&DevTxDecoder).unwrap().len(), 10);
    }

    #[test]
    fn rejects_duplicates_and_tampering() {
        let mut dup = txs(10);
        dup[3] = dup[2].clone();
        assert!(matches!(
            RollupBatch::pack(&dup),
            Err(BatchError::DuplicateTx(_))
        ));

        let mut batch = RollupBatch::pack(&txs(10)).unwrap();
        batch.txs[0][1] ^= 1;
        assert_eq!(
            batch.unpack(&DevTxDecoder).err(),
            Some(BatchError::RootMismatch)
        );

        let mut batch = RollupBatch::pack(&txs(10)).unwrap();
        batch.total_fees = Amount::new(1);
        assert!(matches!(
            batch.unpack(&DevTxDecoder),
            Err(BatchError::FeeMismatch { .. })
        ));
    }

    #[test]
    fn decompress_is_bounded() {
        assert!(RollupBatch::decompress(&[1, 2, 3]).is_err());
    }
}
