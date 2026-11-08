//! The transaction abstraction used by batches, fees and the UTXO store.
//!
//! Voltcash reuses Zebra's transaction type for real Zcash-format transactions, but the
//! rollup, fee and state logic only needs the small [`BatchableTx`] view, so it can also
//! be driven by the light [`DevTx`](crate::DevTx) format on a devnet.

use std::{any::Any, sync::Arc};

use thiserror::Error;
use zebra_chain::{
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

    /// The value this transaction moves out of the Sapling pool into the transparent pool.
    /// Negative when it shields value into the pool.
    fn sapling_value_out(&self) -> i64 {
        0
    }

    /// The value this transaction moves out of the Orchard pool. Negative when it shields value.
    fn orchard_value_out(&self) -> i64 {
        0
    }

    /// The net value this transaction moves from the shielded pools into the transparent pool.
    /// Negative when it shields value.
    ///
    /// A wide integer, so adding the pools can never overflow or be clamped.
    fn shielded_value_out(&self) -> i128 {
        i128::from(self.sapling_value_out()) + i128::from(self.orchard_value_out())
    }

    /// The Sapling anchors this transaction spends against, without duplicates.
    ///
    /// Each must be the root of the Sapling note commitment tree at the end of an earlier chain
    /// step, or a spend could be proven against a tree the spender made up.
    fn sapling_anchor_roots(&self) -> Vec<[u8; 32]> {
        Vec::new()
    }

    /// The Orchard anchor, if the transaction has an Orchard bundle. The same rule applies.
    fn orchard_anchor_root(&self) -> Option<[u8; 32]> {
        None
    }

    /// The Sapling note commitments this transaction creates, in order.
    fn sapling_commitment_bytes(&self) -> Vec<[u8; 32]> {
        Vec::new()
    }

    /// The Sapling outputs this transaction creates, in tree order, with their encrypted notes.
    /// Devnet transactions have no encrypted notes and return nothing.
    fn sapling_output_data(&self) -> Vec<SaplingOutputData> {
        Vec::new()
    }

    /// The Orchard note commitments this transaction creates, in order.
    fn orchard_commitment_bytes(&self) -> Vec<[u8; 32]> {
        Vec::new()
    }

    /// Whether the transaction uses a shielded pool the node does not track (Sprout, Ironwood).
    ///
    /// Value could be created in an untracked pool without limit, so such transactions are refused.
    fn has_unsupported_shielded_data(&self) -> bool {
        false
    }

    /// The canonical serialization.
    fn to_bytes(&self) -> Vec<u8>;

    /// The number of logical actions: the unit proof-verification work and fees scale with.
    ///
    /// Following ZIP 317, transparent inputs and outputs count as `max(inputs, outputs)`,
    /// Sapling as `max(spends, outputs)`, plus every Orchard action and two per Sprout JoinSplit.
    fn logical_actions(&self) -> u64;

    /// The serialized size in bytes.
    fn size_bytes(&self) -> usize {
        self.to_bytes().len()
    }

    /// Returns `self` as [`Any`], so a [`TxVerifier`] can recover the concrete transaction type.
    fn as_any(&self) -> &dyn Any;
}

/// A Sapling output as a light wallet needs it: enough to try to decrypt the note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaplingOutputData {
    /// The note commitment (`cmu`), as appended to the tree.
    pub cmu: [u8; 32],
    /// The ephemeral public key the note was encrypted to.
    pub ephemeral_key: [u8; 32],
    /// The 580-byte encrypted note: value, recipient details and the 512-byte memo.
    pub enc_ciphertext: Vec<u8>,
}

/// Decodes transactions from batch payloads.
pub trait TxDecoder: Send + Sync {
    /// Decodes one transaction from exactly `bytes`.
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn BatchableTx>, CodecError>;
}

/// A transaction together with the outputs it spends, in input order.
#[derive(Debug)]
pub struct TxVerifyItem<'a> {
    /// The transaction to verify.
    pub tx: &'a dyn BatchableTx,
    /// The outputs spent by `tx`'s transparent inputs, in input order.
    pub spent_outputs: Vec<Output>,
}

/// Why a transaction failed cryptographic verification.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
#[error("transaction {txid} failed verification: {reason}")]
pub struct VerifyError {
    /// The offending transaction.
    pub txid: VoltHash,
    /// What failed.
    pub reason: String,
}

/// Verifies the proofs and signatures of transactions.
///
/// It runs when a block is *accepted into state*, because transparent signature hashes commit to
/// the spent outputs, and those are only known once the block's place in the consensus order is.
/// Implementations should cache successes: a block's transactions are verified again if a
/// reorg re-applies it.
pub trait TxVerifier: Send + Sync + std::fmt::Debug {
    /// Verifies every item, returning the first failure.
    fn verify_batch(&self, items: &[TxVerifyItem<'_>]) -> Result<(), VerifyError>;
}

/// A [`TxVerifier`] that accepts everything. For devnets using proof-less transactions only.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoVerification;

impl TxVerifier for NoVerification {
    fn verify_batch(&self, _items: &[TxVerifyItem<'_>]) -> Result<(), VerifyError> {
        Ok(())
    }
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

    fn sapling_value_out(&self) -> i64 {
        self.sapling_value_balance().sapling_amount().zatoshis()
    }

    fn orchard_value_out(&self) -> i64 {
        self.orchard_value_balance().orchard_amount().zatoshis()
    }

    fn sapling_anchor_roots(&self) -> Vec<[u8; 32]> {
        let mut anchors: Vec<[u8; 32]> = Vec::new();
        for spend in self.sapling_spends() {
            let anchor = spend.anchor().to_bytes();
            if !anchors.contains(&anchor) {
                anchors.push(anchor);
            }
        }
        anchors
    }

    fn orchard_anchor_root(&self) -> Option<[u8; 32]> {
        self.orchard_bundle()
            .map(|bundle| bundle.anchor().to_bytes())
    }

    fn sapling_commitment_bytes(&self) -> Vec<[u8; 32]> {
        self.sapling_note_commitments()
            .map(|commitment| commitment.to_bytes())
            .collect()
    }

    fn sapling_output_data(&self) -> Vec<SaplingOutputData> {
        self.sapling_outputs()
            .map(|output| SaplingOutputData {
                cmu: output.cmu().to_bytes(),
                ephemeral_key: output.ephemeral_key().0,
                enc_ciphertext: output.enc_ciphertext().to_vec(),
            })
            .collect()
    }

    fn orchard_commitment_bytes(&self) -> Vec<[u8; 32]> {
        self.orchard_note_commitments()
            .map(|commitment| commitment.to_bytes())
            .collect()
    }

    fn has_unsupported_shielded_data(&self) -> bool {
        self.has_sprout_joinsplit_data() || self.has_ironwood_shielded_data()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.zcash_serialize_to_vec()
            .expect("serializing a transaction into a Vec cannot fail")
    }

    fn logical_actions(&self) -> u64 {
        let transparent = self.inputs().len().max(self.outputs().len()) as u64; // lossless: usize fits in u64
        let sapling = self
            .sapling_spends_count()
            .max(self.sapling_outputs().count()) as u64; // lossless: usize fits in u64
        let orchard = self.orchard_actions().count() as u64; // lossless: usize fits in u64
        let sprout = 2 * self.joinsplit_count() as u64; // lossless: usize fits in u64
        transparent + sapling + orchard + sprout
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
