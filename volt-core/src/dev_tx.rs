//! A light transaction format for devnets and tests.
//!
//! Real Zcash-format transactions are supported through [`ZebraTxDecoder`](crate::ZebraTxDecoder).
//! Building valid Sapling or Orchard transactions needs proving keys, so the devnet node and the
//! unit tests drive the same rollup, fee and UTXO logic with [`DevTx`], which declares its
//! shielded-ness, nullifiers, anchors, note commitments and pool values directly. It carries no
//! proofs or signatures, so what it exercises is the node's *bookkeeping*: commitment trees, anchor
//! validity and the turnstile.

use std::sync::Arc;

use zebra_chain::{
    amount::{Amount, NonNegative},
    transaction,
    transparent::{OutPoint, Output, Script},
};

use crate::{
    codec::{CodecError, Reader, Writer},
    constants::{MAX_SCRIPT_BYTES, MAX_TX_ITEMS},
    hash::VoltHash,
    tx::{BatchableTx, Nullifier, TxDecoder, TxKind},
};

/// What a [`DevTx`] declares about one shielded pool.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct PoolData {
    /// Value moved out of the pool; negative when value is shielded into it.
    value_out: i64,
    /// The anchors spent against. Orchard has at most one.
    anchors: Vec<[u8; 32]>,
    /// The note commitments created, in order.
    commitments: Vec<[u8; 32]>,
}

impl PoolData {
    fn write(&self, w: &mut Writer) {
        w.i64(self.value_out).count(self.anchors.len());
        for anchor in &self.anchors {
            w.raw(anchor);
        }
        w.count(self.commitments.len());
        for commitment in &self.commitments {
            w.raw(commitment);
        }
    }

    fn read(r: &mut Reader<'_>, max_anchors: usize) -> Result<Self, CodecError> {
        let value_out = r.i64()?;
        let n = r.count("anchors", max_anchors)?;
        let mut anchors = Vec::with_capacity(n);
        for _ in 0..n {
            anchors.push(r.array32()?);
        }
        let n = r.count("commitments", MAX_TX_ITEMS)?;
        let mut commitments = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            commitments.push(r.array32()?);
        }
        Ok(Self {
            value_out,
            anchors,
            commitments,
        })
    }
}

/// A proof-less transaction for devnets and tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevTx {
    inputs: Vec<OutPoint>,
    outputs: Vec<Output>,
    nullifiers: Vec<Nullifier>,
    shielded: bool,
    /// Value moved out of the shielded pools without being tracked by any pool. Only for tests
    /// of the transparent value rule.
    shielded_out: i64,
    sapling: PoolData,
    orchard: PoolData,
    nonce: u64,
}

impl DevTx {
    /// Creates a transaction. `nonce` makes otherwise identical transactions distinct.
    pub fn new(
        inputs: Vec<OutPoint>,
        outputs: Vec<Output>,
        nullifiers: Vec<Nullifier>,
        shielded: bool,
        nonce: u64,
    ) -> Self {
        Self {
            inputs,
            outputs,
            nullifiers,
            shielded,
            shielded_out: 0,
            sapling: PoolData::default(),
            orchard: PoolData::default(),
            nonce,
        }
    }

    /// A valid note commitment for tests: a small canonical field element, distinct for each `n`.
    ///
    /// It is offset so it never equals the reserved "uncommitted" leaf values (`1` for Sapling and
    /// `2` for Orchard). Appending one of those leaves a tree's root unchanged.
    pub fn commitment(n: u64) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&(n + 1_000).to_le_bytes());
        bytes
    }

    /// Sets the net value this transaction moves out of the shielded pools, without any pool
    /// tracking it.
    pub fn with_shielded_value_out(mut self, zatoshis: i64) -> Self {
        self.shielded_out = zatoshis;
        self
    }

    /// Gives the transaction a Sapling part and marks it shielded (the higher fee tier).
    ///
    /// `value_out` is the value leaving the pool, negative when shielding. `anchors` are the tree
    /// roots the spends are made against, and `commitments` the notes created.
    pub fn with_sapling(
        mut self,
        value_out: i64,
        anchors: Vec<[u8; 32]>,
        commitments: Vec<[u8; 32]>,
    ) -> Self {
        self.shielded = true;
        self.sapling = PoolData {
            value_out,
            anchors,
            commitments,
        };
        self
    }

    /// Gives the transaction an Orchard part and marks it shielded. See [`DevTx::with_sapling`].
    pub fn with_orchard(
        mut self,
        value_out: i64,
        anchor: Option<[u8; 32]>,
        commitments: Vec<[u8; 32]>,
    ) -> Self {
        self.shielded = true;
        self.orchard = PoolData {
            value_out,
            anchors: anchor.into_iter().collect(),
            commitments,
        };
        self
    }

    /// Decodes a transaction from exactly `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let shielded = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(CodecError::Invalid("shielded flag")),
        };
        let nonce = r.u64()?;
        let shielded_out = r.i64()?;

        let n = r.count("inputs", MAX_TX_ITEMS)?;
        let mut inputs = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            let hash = transaction::Hash(r.array32()?);
            let index = r.u32()?;
            inputs.push(OutPoint { hash, index });
        }

        let n = r.count("outputs", MAX_TX_ITEMS)?;
        let mut outputs = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            let value = Amount::<NonNegative>::try_from(r.i64()?)
                .map_err(|_| CodecError::Invalid("output value"))?;
            let script = r.bytes("script", MAX_SCRIPT_BYTES)?;
            outputs.push(Output::new(value, Script::new(script)));
        }

        let n = r.count("nullifiers", MAX_TX_ITEMS)?;
        let mut nullifiers = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            nullifiers.push(r.array32()?);
        }

        let sapling = PoolData::read(&mut r, MAX_TX_ITEMS)?;
        let orchard = PoolData::read(&mut r, 1)?;

        r.finish()?;
        Ok(Self {
            inputs,
            outputs,
            nullifiers,
            shielded,
            shielded_out,
            sapling,
            orchard,
            nonce,
        })
    }
}

impl BatchableTx for DevTx {
    fn txid(&self) -> VoltHash {
        VoltHash::digest(b"VoltDevTxId_____", &self.to_bytes())
    }

    fn kind(&self) -> TxKind {
        if self.shielded {
            TxKind::Shielded
        } else {
            TxKind::Transparent
        }
    }

    fn is_coinbase(&self) -> bool {
        false
    }

    fn spent_outpoints(&self) -> Vec<OutPoint> {
        self.inputs.clone()
    }

    fn outputs(&self) -> Vec<Output> {
        self.outputs.clone()
    }

    fn nullifiers(&self) -> Vec<Nullifier> {
        self.nullifiers.clone()
    }

    fn sapling_value_out(&self) -> i64 {
        self.sapling.value_out
    }

    fn orchard_value_out(&self) -> i64 {
        self.orchard.value_out
    }

    fn shielded_value_out(&self) -> i128 {
        i128::from(self.shielded_out)
            + i128::from(self.sapling.value_out)
            + i128::from(self.orchard.value_out)
    }

    fn sapling_anchor_roots(&self) -> Vec<[u8; 32]> {
        self.sapling.anchors.clone()
    }

    fn orchard_anchor_root(&self) -> Option<[u8; 32]> {
        self.orchard.anchors.first().copied()
    }

    fn sapling_commitment_bytes(&self) -> Vec<[u8; 32]> {
        self.sapling.commitments.clone()
    }

    fn orchard_commitment_bytes(&self) -> Vec<[u8; 32]> {
        self.orchard.commitments.clone()
    }

    fn logical_actions(&self) -> u64 {
        let transparent = self.inputs.len().max(self.outputs.len()) as u64; // lossless: usize fits in u64
        transparent + self.nullifiers.len() as u64 // lossless: usize fits in u64
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(u8::from(self.shielded))
            .u64(self.nonce)
            .i64(self.shielded_out);

        w.count(self.inputs.len());
        for input in &self.inputs {
            w.raw(&input.hash.0).u32(input.index);
        }

        w.count(self.outputs.len());
        for output in &self.outputs {
            w.i64(output.value.zatoshis())
                .bytes(output.lock_script.as_raw_bytes());
        }

        w.count(self.nullifiers.len());
        for nullifier in &self.nullifiers {
            w.raw(nullifier);
        }

        self.sapling.write(&mut w);
        self.orchard.write(&mut w);
        w.finish()
    }
}

/// A [`TxDecoder`] for [`DevTx`].
#[derive(Clone, Copy, Debug, Default)]
pub struct DevTxDecoder;

impl TxDecoder for DevTxDecoder {
    fn decode(&self, bytes: &[u8]) -> Result<Arc<dyn BatchableTx>, CodecError> {
        Ok(Arc::new(DevTx::decode(bytes)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_tx_round_trips() {
        let out = Output::new(Amount::new(5), Script::new(&[1, 2, 3]));
        let tx = DevTx::new(
            vec![OutPoint {
                hash: transaction::Hash([4; 32]),
                index: 2,
            }],
            vec![out],
            vec![[8; 32]],
            true,
            77,
        )
        .with_shielded_value_out(-12)
        .with_sapling(
            40,
            vec![[1; 32], [2; 32]],
            vec![DevTx::commitment(1), DevTx::commitment(2)],
        )
        .with_orchard(-7, Some([3; 32]), vec![DevTx::commitment(9)]);

        let decoded = DevTx::decode(&tx.to_bytes()).unwrap();
        assert_eq!(decoded, tx);
        assert_eq!(decoded.txid(), tx.txid());
        assert_eq!(decoded.shielded_value_out(), -12 + 40 - 7);
        assert_eq!(decoded.orchard_anchor_root(), Some([3; 32]));
        assert!(DevTx::decode(&[1, 2, 3]).is_err());
    }

    #[test]
    fn the_shielded_total_cannot_overflow_or_be_clamped() {
        // Two pools each paying out the most an i64 can hold: the wide sum is exact.
        let tx = DevTx::new(vec![], vec![], vec![], true, 1)
            .with_sapling(i64::MAX, vec![], vec![])
            .with_orchard(i64::MAX, None, vec![]);
        assert_eq!(tx.shielded_value_out(), i128::from(i64::MAX) * 2);
    }

    #[test]
    fn an_orchard_part_with_two_anchors_is_refused() {
        // Orchard has one anchor per bundle: a hand-built encoding with two must not decode.
        let tx = DevTx::new(vec![], vec![], vec![], true, 1).with_orchard(0, Some([1; 32]), vec![]);
        let mut bytes = tx.to_bytes();
        // The orchard section is the tail: value (8), anchor count (4), anchor (32), commitments (4).
        let tail = bytes.len() - (8 + 4 + 32 + 4);
        bytes[tail + 8..tail + 12].copy_from_slice(&2u32.to_le_bytes());
        assert!(DevTx::decode(&bytes).is_err());
    }
}
