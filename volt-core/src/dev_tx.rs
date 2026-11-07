//! A light transaction format for devnets and tests.
//!
//! Real Zcash-format transactions are supported through [`ZebraTxDecoder`](crate::ZebraTxDecoder).
//! Building valid Sapling or Orchard transactions needs proving keys, so the devnet node and the
//! unit tests drive the same rollup, fee and UTXO logic with [`DevTx`], which declares its
//! shielded-ness and nullifiers directly. It carries no proofs or signatures.

use std::sync::Arc;

use zebra_chain::{
    amount::{Amount, NegativeAllowed, NonNegative},
    transaction,
    transparent::{OutPoint, Output, Script},
};

use crate::{
    codec::{CodecError, Reader, Writer},
    constants::{MAX_SCRIPT_BYTES, MAX_TX_ITEMS},
    hash::VoltHash,
    tx::{BatchableTx, Nullifier, TxDecoder, TxKind},
};

/// A proof-less transaction for devnets and tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevTx {
    inputs: Vec<OutPoint>,
    outputs: Vec<Output>,
    nullifiers: Vec<Nullifier>,
    shielded: bool,
    shielded_out: i64,
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
            nonce,
        }
    }

    /// Sets the net value this transaction moves out of the shielded pools.
    pub fn with_shielded_value_out(mut self, zatoshis: i64) -> Self {
        self.shielded_out = zatoshis;
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

        r.finish()?;
        Ok(Self {
            inputs,
            outputs,
            nullifiers,
            shielded,
            shielded_out,
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

    fn shielded_value_out(&self) -> Amount<NegativeAllowed> {
        Amount::try_from(self.shielded_out).unwrap_or_else(|_| Amount::zero())
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
        .with_shielded_value_out(-12);

        let decoded = DevTx::decode(&tx.to_bytes()).unwrap();
        assert_eq!(decoded, tx);
        assert_eq!(decoded.txid(), tx.txid());
        assert!(DevTx::decode(&[1, 2, 3]).is_err());
    }
}
