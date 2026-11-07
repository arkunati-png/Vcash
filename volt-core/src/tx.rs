//! The transaction abstraction used by batches, fees and the UTXO store.
//!
//! Voltcash reuses Zebra's transaction type for real Zcash-format transactions, but the
//! rollup, fee and state logic only needs the small [`BatchableTx`] view, so it can also
//! be driven by the light [`DevTx`](crate::DevTx) format on a devnet.

use std::sync::Arc;

use zebra_chain::{
    amount::{Amount, NegativeAllowed},
    serialization::{ZcashDeserializeInto, ZcashSerialize},
    transaction::Transaction,
    transparent::{OutPoint, Output},
};

use crate::{codec::CodecError, hash::VoltHash};

/// A shielded nullifier: a 32-byte tag that must never appear twice on chain.
pub type Nullifier = [u8; 32];

/// The two fee tiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TxKind {
    /// Only transparent inputs and outputs.
    Transparent,
    /// Touches a Sprout, Sapling or Orchard shielded pool.
    Shielded,
}

/// The view of a transaction that Voltcash consensus needs.
pub trait BatchableTx: Send + Sync + std::fmt::Debug {
    /// The transaction id.
    fn txid(&self) -> VoltHash;

    /// The fee tier of this transaction.
    fn kind(&self) -> TxKind;

    /// Whether this is a coinbase transaction. Batches never contain coinbases.
    fn is_coinbase(&self) -> bool;

    /// The transparent outputs spent by this transaction.
    fn spent_outpoints(&self) -> Vec<OutPoint>;

    /// The transparent outputs created by this transaction.
    fn outputs(&self) -> Vec<Output>;

    /// The shielded nullifiers revealed by this transaction.
    fn nullifiers(&self) -> Vec<Nullifier>;

    /// The net value this transaction moves from the shielded pools into the
    /// transparent pool. Negative when it shields value.
    fn shielded_value_out(&self) -> Amount<NegativeAllowed>;

    /// The canonical serialization.
    fn to_bytes(&self) -> Vec<u8>;
}

/// Decodes transactions from batch payloads.
pub trait TxDecoder: Send + Sync {
    /// Decodes one transaction from exactly `bytes`.
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn BatchableTx>, CodecError>;
}

/// A [`TxDecoder`] for Zcash-format transactions.
#[derive(Clone, Copy, Debug, Default)]
pub struct ZebraTxDecoder;

impl TxDecoder for ZebraTxDecoder {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn BatchableTx>, CodecError> {
        let tx: Transaction = bytes
            .zcash_deserialize_into()
            .map_err(|_| CodecError::Invalid("zcash transaction"))?;
        Ok(Arc::new(tx))
    }
}

impl BatchableTx for Transaction {
    fn txid(&self) -> VoltHash {
        VoltHash(self.hash().0)
    }

    fn kind(&self) -> TxKind {
        if self.has_sapling_shielded_data()
            || self.has_orchard_shielded_data()
            || self.has_sprout_joinsplit_data()
        {
            TxKind::Shielded
        } else {
            TxKind::Transparent
        }
    }

    fn is_coinbase(&self) -> bool {
        Transaction::is_coinbase(self)
    }

    fn spent_outpoints(&self) -> Vec<OutPoint> {
        Transaction::spent_outpoints(self).collect()
    }

    fn outputs(&self) -> Vec<Output> {
        Transaction::outputs(self)
    }

    fn nullifiers(&self) -> Vec<Nullifier> {
        self.sapling_nullifiers()
            .map(Nullifier::from)
            .chain(self.orchard_nullifiers().map(Nullifier::from))
            .chain(self.sprout_nullifiers().map(Nullifier::from))
            .collect()
    }

    fn shielded_value_out(&self) -> Amount<NegativeAllowed> {
        let sapling = self.sapling_value_balance().sapling_amount();
        let orchard = self.orchard_value_balance().orchard_amount();
        (sapling + orchard).unwrap_or_else(|_| Amount::zero())
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.zcash_serialize_to_vec()
            .expect("serializing a transaction into a Vec cannot fail")
    }
}
