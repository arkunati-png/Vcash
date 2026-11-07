//! Voltcash DAG blocks.

use thiserror::Error;
use zebra_chain::{
    amount::{Amount, NonNegative},
    parameters::NetworkKind,
    transaction,
    transparent::{Address, OutPoint, Output},
};

use crate::{
    batch::{BatchError, RollupBatch},
    codec::{CodecError, Reader, Writer},
    constants::{
        MAX_BATCHES_PER_BLOCK, MAX_BLOCK_PARENTS, MAX_COINBASE_EXTRA_BYTES, MAX_COINBASE_PAYOUTS,
    },
    hash::{merkle_root, VoltHash},
};

/// Errors from decoding or structurally checking a block.
#[derive(Debug, Error, PartialEq, Clone)]
pub enum BlockError {
    /// The block bytes could not be decoded.
    #[error("block encoding: {0}")]
    Codec(#[from] CodecError),

    /// A batch payload is malformed.
    #[error("block batch: {0}")]
    Batch(#[from] BatchError),

    /// The header lists the same parent twice.
    #[error("duplicate parent {0}")]
    DuplicateParent(VoltHash),

    /// The header's parents are not in canonical (sorted) order.
    #[error("parents are not sorted")]
    UnsortedParents,
}

/// A DAG block header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoltHeader {
    /// The block version.
    pub version: u32,
    /// The hashes of the parent blocks, sorted, with no duplicates.
    pub parents: Vec<VoltHash>,
    /// The block time, in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// The PoW target, in Zcash compact `nBits` form.
    pub bits: u32,
    /// The miner's nonce.
    pub nonce: u64,
    /// The Merkle root of the block's batch roots.
    pub batches_root: VoltHash,
    /// The hash of the coinbase.
    pub coinbase_root: VoltHash,
}

impl VoltHeader {
    /// The canonical header serialization. This is also the PoW input.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.version).count(self.parents.len());
        for parent in &self.parents {
            w.raw(&parent.0);
        }
        w.u64(self.timestamp_ms)
            .u32(self.bits)
            .u64(self.nonce)
            .raw(&self.batches_root.0)
            .raw(&self.coinbase_root.0);
        w.finish()
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, BlockError> {
        let version = r.u32()?;
        let n = r.count("parents", MAX_BLOCK_PARENTS)?;
        let mut parents = Vec::with_capacity(n);
        for _ in 0..n {
            parents.push(VoltHash(r.array32()?));
        }
        let header = Self {
            version,
            parents,
            timestamp_ms: r.u64()?,
            bits: r.u32()?,
            nonce: r.u64()?,
            batches_root: VoltHash(r.array32()?),
            coinbase_root: VoltHash(r.array32()?),
        };
        header.check_parents()?;
        Ok(header)
    }

    /// Checks that the parents are sorted and unique.
    pub fn check_parents(&self) -> Result<(), BlockError> {
        for pair in self.parents.windows(2) {
            if pair[0] == pair[1] {
                return Err(BlockError::DuplicateParent(pair[0]));
            }
            if pair[0] > pair[1] {
                return Err(BlockError::UnsortedParents);
            }
        }
        Ok(())
    }

    /// The block hash: the Blake2b-256 digest of the encoded header.
    pub fn hash(&self) -> VoltHash {
        VoltHash::digest(b"VoltBlockHeader_", &self.encode())
    }
}

/// One coinbase payout to a transparent address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    /// The recipient.
    pub address: Address,
    /// The amount paid.
    pub amount: Amount<NonNegative>,
}

/// The coinbase of a block: miner payouts plus the protocol-owned liquidity contribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coinbase {
    /// The miner payouts. Consensus allows at most
    /// [`MAX_COINBASE_PAYOUTS`] unique addresses.
    pub payouts: Vec<Payout>,
    /// The amount locked permanently into the on-chain DEX reserves.
    pub pol_contribution: Amount<NonNegative>,
    /// Free-form miner data.
    pub extra: Vec<u8>,
}

fn write_address(w: &mut Writer, address: &Address) {
    let (tag, kind, hash) = match address {
        Address::PayToPublicKeyHash {
            network_kind,
            pub_key_hash,
        } => (0, network_kind, pub_key_hash),
        Address::PayToScriptHash {
            network_kind,
            script_hash,
        } => (1, network_kind, script_hash),
        Address::Tex {
            network_kind,
            validating_key_hash,
        } => (2, network_kind, validating_key_hash),
    };
    let kind = match kind {
        NetworkKind::Mainnet => 0,
        NetworkKind::Testnet => 1,
        NetworkKind::Regtest => 2,
    };
    w.u8(tag).u8(kind).raw(hash);
}

fn read_address(r: &mut Reader<'_>) -> Result<Address, CodecError> {
    let tag = r.u8()?;
    let network_kind = match r.u8()? {
        0 => NetworkKind::Mainnet,
        1 => NetworkKind::Testnet,
        2 => NetworkKind::Regtest,
        _ => return Err(CodecError::Invalid("network kind")),
    };
    let hash = r.array20()?;
    match tag {
        0 => Ok(Address::PayToPublicKeyHash {
            network_kind,
            pub_key_hash: hash,
        }),
        1 => Ok(Address::PayToScriptHash {
            network_kind,
            script_hash: hash,
        }),
        2 => Ok(Address::Tex {
            network_kind,
            validating_key_hash: hash,
        }),
        _ => Err(CodecError::Invalid("address type")),
    }
}

impl Coinbase {
    /// The canonical serialization.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.count(self.payouts.len());
        for payout in &self.payouts {
            write_address(&mut w, &payout.address);
            w.i64(payout.amount.zatoshis());
        }
        w.i64(self.pol_contribution.zatoshis()).bytes(&self.extra);
        w.finish()
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        // The count is checked against a loose bound here; the strict
        // 100-unique-address rule is a consensus check on the decoded value.
        let n = r.count("payouts", MAX_COINBASE_PAYOUTS * 4)?;
        let mut payouts = Vec::with_capacity(n);
        for _ in 0..n {
            let address = read_address(r)?;
            let amount =
                Amount::try_from(r.i64()?).map_err(|_| CodecError::Invalid("payout amount"))?;
            payouts.push(Payout { address, amount });
        }
        let pol_contribution =
            Amount::try_from(r.i64()?).map_err(|_| CodecError::Invalid("pol contribution"))?;
        let extra = r
            .bytes("coinbase extra", MAX_COINBASE_EXTRA_BYTES)?
            .to_vec();
        Ok(Self {
            payouts,
            pol_contribution,
            extra,
        })
    }

    /// The coinbase id, also the commitment stored in [`VoltHeader::coinbase_root`].
    pub fn hash(&self) -> VoltHash {
        VoltHash::digest(b"VoltCoinbase____", &self.encode())
    }

    /// The outputs this coinbase creates, in payout order, as `(outpoint, output)`.
    ///
    /// The POL contribution is not an output: it is locked in the reserve, never spendable.
    pub fn outputs(&self) -> Vec<(OutPoint, Output)> {
        let txid = transaction::Hash(self.hash().0);
        self.payouts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                (
                    OutPoint::from_usize(txid, i),
                    Output::new(p.amount, p.address.script()),
                )
            })
            .collect()
    }
}

/// A full DAG block: header, coinbase and rollup batches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoltBlock {
    /// The header.
    pub header: VoltHeader,
    /// The coinbase.
    pub coinbase: Coinbase,
    /// The rollup batches.
    pub batches: Vec<RollupBatch>,
}

impl VoltBlock {
    /// The block hash.
    pub fn hash(&self) -> VoltHash {
        self.header.hash()
    }

    /// The Merkle root over this block's batch roots.
    pub fn compute_batches_root(batches: &[RollupBatch]) -> VoltHash {
        let roots: Vec<VoltHash> = batches.iter().map(RollupBatch::batch_root).collect();
        merkle_root(&roots)
    }

    /// The sum of every batch's fees, or `None` on overflow.
    pub fn total_fees(&self) -> Option<Amount<NonNegative>> {
        self.batches
            .iter()
            .try_fold(Amount::zero(), |sum: Amount<NonNegative>, b| {
                (sum + b.total_fees()).ok()
            })
    }

    /// The canonical block serialization, with compressed batches.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.header.encode())
            .bytes(&self.coinbase.encode());
        w.count(self.batches.len());
        for batch in &self.batches {
            w.bytes(&batch.compress());
        }
        w.finish()
    }

    /// Decodes a block. This checks structure and bounds only, not consensus rules.
    pub fn decode(bytes: &[u8]) -> Result<Self, BlockError> {
        const MAX_PART: usize = 64 * 1024 * 1024;
        let mut r = Reader::new(bytes);

        let header_bytes = r.bytes("header", MAX_PART)?;
        let mut hr = Reader::new(header_bytes);
        let header = VoltHeader::read(&mut hr)?;
        hr.finish()?;

        let coinbase_bytes = r.bytes("coinbase", MAX_PART)?;
        let mut cr = Reader::new(coinbase_bytes);
        let coinbase = Coinbase::read(&mut cr)?;
        cr.finish()?;

        let n = r.count("batches", MAX_BATCHES_PER_BLOCK)?;
        let mut batches = Vec::with_capacity(n);
        for _ in 0..n {
            batches.push(RollupBatch::decompress(r.bytes("batch", MAX_PART)?)?);
        }
        r.finish()?;

        Ok(Self {
            header,
            coinbase,
            batches,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VoltBlock {
        let address = Address::from_pub_key_hash(NetworkKind::Regtest, [3; 20]);
        let coinbase = Coinbase {
            payouts: vec![Payout {
                address,
                amount: Amount::new(100),
            }],
            pol_contribution: Amount::new(100),
            extra: b"hi".to_vec(),
        };
        VoltBlock {
            header: VoltHeader {
                version: 1,
                parents: vec![VoltHash([1; 32]), VoltHash([2; 32])],
                timestamp_ms: 5,
                bits: 0x207f_ffff,
                nonce: 9,
                batches_root: VoltBlock::compute_batches_root(&[]),
                coinbase_root: coinbase.hash(),
            },
            coinbase,
            batches: vec![],
        }
    }

    #[test]
    fn block_round_trips() {
        let block = sample();
        assert_eq!(VoltBlock::decode(&block.encode()).unwrap(), block);
    }

    #[test]
    fn rejects_unsorted_and_duplicate_parents() {
        let mut block = sample();
        block.header.parents = vec![VoltHash([2; 32]), VoltHash([1; 32])];
        assert_eq!(
            VoltBlock::decode(&block.encode()),
            Err(BlockError::UnsortedParents)
        );
        block.header.parents = vec![VoltHash([1; 32]), VoltHash([1; 32])];
        assert!(matches!(
            VoltBlock::decode(&block.encode()),
            Err(BlockError::DuplicateParent(_))
        ));
    }

    #[test]
    fn coinbase_outputs_use_coinbase_hash() {
        let block = sample();
        let outs = block.coinbase.outputs();
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].0.hash.0, block.coinbase.hash().0);
    }
}
