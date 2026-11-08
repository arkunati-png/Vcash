//! Block validation: everything that can be checked without the UTXO state.
//!
//! State conflicts (a transaction spending something already spent by an earlier block in the
//! consensus order) are not a validity error in a DAG: both blocks are valid, and the later one
//! in the consensus order is simply not accepted. See [`crate::chain::ChainState`].

use std::sync::Arc;

use volt_core::{
    constants::{
        MAX_BATCHES_PER_BLOCK, MAX_BLOCK_ACTIONS, MAX_BLOCK_PARENTS, MAX_BLOCK_TX_BYTES,
        MAX_FUTURE_TIMESTAMP_DRIFT_MS, TEST_POW_LIMIT_BITS,
    },
    BatchableTx, Economics, TxDecoder, VoltBlock,
};
use volt_crypto::{meets_target, target_work, PowHasher};
use zebra_chain::amount::{Amount, NonNegative};

use crate::{
    coinbase::check_coinbase,
    difficulty::{next_bits, pow_seed},
    error::ConsensusError,
    ghostdag::BlockDag,
};

/// A block that passed validation, with its decoded transactions.
#[derive(Debug)]
pub struct StoredBlock {
    /// The block.
    pub block: VoltBlock,
    /// The decoded transactions of each batch, in order.
    pub txs: Vec<Vec<Arc<dyn BatchableTx>>>,
    /// The sum of all batch fees.
    pub fees: Amount<NonNegative>,
    /// The work this block represents.
    pub work: u128,
    /// The score the reward schedule was evaluated at: the selected parent's blue score.
    pub reward_score: u64,
}

/// Validates blocks against a DAG.
#[derive(Clone)]
pub struct BlockValidator {
    pow: Arc<dyn PowHasher>,
    decoder: Arc<dyn TxDecoder>,
    economics: Economics,
}

impl std::fmt::Debug for BlockValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlockValidator")
    }
}

impl BlockValidator {
    /// Creates a validator using `pow` for proof-of-work, `decoder` for batch transactions and
    /// `economics` for the reward schedule.
    pub fn new(pow: Arc<dyn PowHasher>, decoder: Arc<dyn TxDecoder>, economics: Economics) -> Self {
        Self {
            pow,
            decoder,
            economics,
        }
    }

    /// The monetary policy.
    pub fn economics(&self) -> &Economics {
        &self.economics
    }

    /// The PoW hasher.
    pub fn pow(&self) -> &Arc<dyn PowHasher> {
        &self.pow
    }

    /// Checks the genesis block: no parents, no payouts and no transactions.
    pub fn validate_genesis(&self, block: VoltBlock) -> Result<StoredBlock, ConsensusError> {
        let invalid = ConsensusError::InvalidGenesis;
        if !block.header.parents.is_empty() {
            return Err(invalid("genesis has parents"));
        }
        if !block.batches.is_empty() {
            return Err(invalid("genesis has batches"));
        }
        if !block.coinbase.payouts.is_empty() || !block.coinbase.pol_contribution.is_zero() {
            return Err(invalid("genesis pays out"));
        }
        // The genesis target is the network's PoW limit. It must be a real target, and no easier
        // than the test limit, which the difficulty arithmetic is built to handle.
        let limit = volt_crypto::target_work(block.header.bits);
        let easiest = volt_crypto::target_work(TEST_POW_LIMIT_BITS);
        if limit.is_none() || limit < easiest {
            return Err(invalid("genesis has an invalid or too easy PoW limit"));
        }
        if block.header.coinbase_root != block.coinbase.hash() {
            return Err(ConsensusError::CommitmentMismatch("coinbase"));
        }
        if block.header.batches_root != VoltBlock::compute_batches_root(&block.batches) {
            return Err(ConsensusError::CommitmentMismatch("batches"));
        }
        let work = target_work(block.header.bits)
            .ok_or(ConsensusError::InvalidBits(block.header.bits))?
            .as_u128();
        Ok(StoredBlock {
            block,
            txs: Vec::new(),
            fees: Amount::zero(),
            work,
            reward_score: 0,
        })
    }

    /// Validates a non-genesis block. `now_ms` is the local time in milliseconds.
    pub fn validate(
        &self,
        dag: &BlockDag,
        block: VoltBlock,
        now_ms: u64,
    ) -> Result<StoredBlock, ConsensusError> {
        let header = &block.header;

        // Parents.
        if header.parents.is_empty() {
            return Err(ConsensusError::NoParents);
        }
        if header.parents.len() > MAX_BLOCK_PARENTS {
            return Err(
                crate::ghostdag::GhostdagError::TooManyParents(header.parents.len()).into(),
            );
        }
        header.check_parents()?;
        for parent in &header.parents {
            if !dag.contains(parent) {
                return Err(ConsensusError::UnknownParent(*parent));
            }
        }
        if dag.contains(&block.hash()) {
            return Err(crate::ghostdag::GhostdagError::Duplicate(block.hash()).into());
        }

        // Difficulty is derived from the selected parent's chain.
        let selected_parent = dag.select_parent(&header.parents);
        let expected_bits = next_bits(dag, &selected_parent);
        if header.bits != expected_bits {
            return Err(ConsensusError::WrongBits {
                expected: expected_bits,
                got: header.bits,
            });
        }
        let work = target_work(header.bits)
            .ok_or(ConsensusError::InvalidBits(header.bits))?
            .as_u128();

        // Timestamps.
        let latest_parent = header
            .parents
            .iter()
            .map(|p| dag.get(p).expect("parents were checked above").timestamp_ms)
            .max()
            .expect("parents is not empty");
        if header.timestamp_ms < latest_parent {
            return Err(ConsensusError::TimestampTooEarly {
                got: header.timestamp_ms,
                parent: latest_parent,
            });
        }
        if header.timestamp_ms > now_ms.saturating_add(MAX_FUTURE_TIMESTAMP_DRIFT_MS) {
            return Err(ConsensusError::TimestampInFuture {
                got: header.timestamp_ms,
                now: now_ms,
            });
        }

        // Proof of work: the cheap checks above run first, so spam fails before hashing.
        let seed = pow_seed(dag, &selected_parent);
        let pow_hash = self.pow.pow_hash(&seed, &header.pow_blob())?;
        if !meets_target(&pow_hash, header.bits) {
            return Err(ConsensusError::InsufficientPow);
        }

        // Body commitments.
        if block.batches.len() > MAX_BATCHES_PER_BLOCK {
            return Err(ConsensusError::TooManyBatches(block.batches.len()));
        }
        if header.batches_root != VoltBlock::compute_batches_root(&block.batches) {
            return Err(ConsensusError::CommitmentMismatch("batches"));
        }
        if header.coinbase_root != block.coinbase.hash() {
            return Err(ConsensusError::CommitmentMismatch("coinbase"));
        }

        // Batches: size, root, fees, no coinbases, no duplicates.
        let mut txs = Vec::with_capacity(block.batches.len());
        let mut fees = Amount::<NonNegative>::zero();
        let mut tx_bytes = 0usize;
        let mut actions = 0u64;
        for batch in &block.batches {
            let unpacked = batch.unpack(self.decoder.as_ref())?;
            tx_bytes = tx_bytes.saturating_add(batch.raw_txs().iter().map(Vec::len).sum::<usize>());
            actions = actions.saturating_add(unpacked.iter().map(|tx| tx.logical_actions()).sum());
            txs.push(unpacked);
            fees = (fees + batch.total_fees()).map_err(|_| ConsensusError::FeeOverflow)?;
        }

        // Block-wide caps bound the relay and proof-verification work one block can cost.
        if tx_bytes > MAX_BLOCK_TX_BYTES {
            return Err(ConsensusError::BlockTooLarge {
                bytes: tx_bytes,
                max: MAX_BLOCK_TX_BYTES,
            });
        }
        if actions > MAX_BLOCK_ACTIONS {
            return Err(ConsensusError::TooManyActions {
                actions,
                max: MAX_BLOCK_ACTIONS,
            });
        }

        // The 100-address cap, the minimum payout and the scheduled miner / POL split.
        let reward_score = dag
            .get(&selected_parent)
            .expect("the selected parent was checked above")
            .ghostdag
            .blue_score;
        check_coinbase(&block.coinbase, fees, &self.economics, reward_score)?;

        Ok(StoredBlock {
            block,
            txs,
            fees,
            work,
            reward_score,
        })
    }
}
