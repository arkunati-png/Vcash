//! The accepted chain: UTXO state, epoch accounting and POL settlement.
//!
//! State follows the *selected-parent chain* of the DAG. Moving from chain block `P` to its
//! chain child `C` is one **step**: every block in `C`'s mergeset (the selected parent `P`
//! first, then the rest in consensus order) is processed:
//!
//! - **red** blocks are skipped entirely: no coinbase, no transactions;
//! - **blue** blocks are applied atomically (coinbase outputs, then batches). If a blue block
//!   conflicts with an earlier block in the order (for example a double spend across parallel
//!   blocks) it is *rejected*, which does not make it invalid in the DAG;
//! - every accepted block adds to the epoch, and the 200th accepted block *completes* the epoch.
//!
//! A block's own transactions therefore take effect when a later chain block merges it, one
//! chain step after it was mined.
//!
//! # Finality
//!
//! Tips of equal blue work swap places constantly, so the newest steps must stay revertible. A
//! completed epoch's POL half is only **locked** into the append-only [`PolReserve`] once its
//! step is [`FINALITY_DEPTH`] steps deep, and no step that deep is ever reverted. A reorg that
//! would cross that line is refused.

use std::collections::HashMap;

use volt_core::{constants::FINALITY_DEPTH, VoltHash};
use volt_state::{BlockUndo, EpochSettlement, PolReserve, RamUtxoStore, StateError};
use zebra_chain::block::Height;

use crate::{
    epoch::EpochAccumulator, error::ConsensusError, ghostdag::BlockDag, validator::StoredBlock,
};

/// What one chain step changed, kept so the step can be reverted.
#[derive(Debug)]
struct ChainStep {
    block: VoltHash,
    undo: BlockUndo,
    epoch_before: EpochAccumulator,
    accepted: Vec<VoltHash>,
    /// Epochs completed in this step. They are locked into the reserve once the step is final.
    completed_epochs: Vec<EpochSettlement>,
}

/// A summary of a [`ChainState::advance`] call.
#[derive(Debug, Default)]
pub struct AdvanceReport {
    /// Chain steps reverted by a reorg.
    pub reverted_steps: usize,
    /// Chain steps applied.
    pub applied_steps: usize,
    /// Blocks accepted into state, in order.
    pub accepted: Vec<VoltHash>,
    /// Blue blocks rejected because they conflict with earlier blocks in the order.
    pub rejected: Vec<(VoltHash, StateError)>,
    /// Red blocks skipped.
    pub skipped_red: Vec<VoltHash>,
    /// Epochs completed by the applied steps. These can still be reverted by a shallow reorg.
    pub epochs_completed: Vec<EpochSettlement>,
    /// Epochs that became final and were locked into the POL reserve.
    pub epochs_locked: Vec<EpochSettlement>,
}

/// UTXO state, epoch accounting and the POL reserve for the accepted chain.
#[derive(Debug)]
pub struct ChainState {
    store: RamUtxoStore,
    reserve: PolReserve,
    epoch: EpochAccumulator,
    steps: Vec<ChainStep>,
    /// How many leading steps are final: never reverted, their epochs locked.
    finalized_steps: usize,
    accepted_blocks: u64,
}

impl ChainState {
    /// Creates the state at genesis.
    pub fn new(genesis: VoltHash) -> Self {
        Self {
            store: RamUtxoStore::new(),
            reserve: PolReserve::new(),
            epoch: EpochAccumulator::new(),
            steps: vec![ChainStep {
                block: genesis,
                undo: BlockUndo::default(),
                epoch_before: EpochAccumulator::new(),
                accepted: Vec::new(),
                completed_epochs: Vec::new(),
            }],
            finalized_steps: 1, // the genesis step
            accepted_blocks: 0,
        }
    }

    /// The RAM UTXO store.
    pub fn utxos(&self) -> &RamUtxoStore {
        &self.store
    }

    /// The POL reserve. It holds only epochs that are final.
    pub fn reserve(&self) -> &PolReserve {
        &self.reserve
    }

    /// The epoch in progress.
    pub fn epoch(&self) -> &EpochAccumulator {
        &self.epoch
    }

    /// The chain block the state is currently at.
    pub fn tip(&self) -> VoltHash {
        self.steps
            .last()
            .expect("the genesis step is never reverted")
            .block
    }

    /// The number of blocks accepted into state (genesis excluded).
    pub fn accepted_blocks(&self) -> u64 {
        self.accepted_blocks
    }

    /// The number of chain steps that are final.
    pub fn finalized_steps(&self) -> usize {
        self.finalized_steps
    }

    /// Moves state to the selected-parent chain of `new_sink`, reverting and applying steps.
    ///
    /// Returns [`ConsensusError::ReorgPastFinality`] without changing anything if the move
    /// would revert a final step.
    pub fn advance(
        &mut self,
        dag: &BlockDag,
        bodies: &HashMap<VoltHash, StoredBlock>,
        new_sink: VoltHash,
    ) -> Result<AdvanceReport, ConsensusError> {
        let mut desired = dag.selected_chain(&new_sink);
        desired.reverse(); // genesis first

        let common = self
            .steps
            .iter()
            .zip(&desired)
            .take_while(|(step, hash)| step.block == **hash)
            .count();

        if common < self.finalized_steps {
            return Err(ConsensusError::ReorgPastFinality {
                finalized_steps: self.finalized_steps,
            });
        }

        let mut report = AdvanceReport::default();
        while self.steps.len() > common {
            let step = self.steps.pop().expect("length was just checked");
            self.store.revert_block(step.undo);
            self.epoch = step.epoch_before;
            self.accepted_blocks -= step.accepted.len() as u64; // lossless: a Vec length fits in u64
            report.reverted_steps += 1;
        }

        for chain_block in &desired[common..] {
            self.apply_step(dag, bodies, *chain_block, &mut report)?;
            report.applied_steps += 1;
        }

        self.finalize(&mut report)?;
        Ok(report)
    }

    /// Locks the epochs of every step that is now [`FINALITY_DEPTH`] steps deep.
    fn finalize(&mut self, report: &mut AdvanceReport) -> Result<(), ConsensusError> {
        let final_steps = self.steps.len().saturating_sub(FINALITY_DEPTH);
        while self.finalized_steps < final_steps {
            for settlement in &self.steps[self.finalized_steps].completed_epochs {
                self.reserve.lock(*settlement)?;
                report.epochs_locked.push(*settlement);
            }
            self.finalized_steps += 1;
        }
        Ok(())
    }

    fn apply_step(
        &mut self,
        dag: &BlockDag,
        bodies: &HashMap<VoltHash, StoredBlock>,
        chain_block: VoltHash,
        report: &mut AdvanceReport,
    ) -> Result<(), ConsensusError> {
        let blue_score = dag
            .get(&chain_block)
            .expect("chain blocks are in the DAG")
            .ghostdag
            .blue_score;
        let height = Height(u32::try_from(blue_score).unwrap_or(Height::MAX.0));

        let mut step = ChainStep {
            block: chain_block,
            undo: BlockUndo::default(),
            epoch_before: self.epoch.clone(),
            accepted: Vec::new(),
            completed_epochs: Vec::new(),
        };

        for member in dag.ordered_mergeset(&chain_block) {
            if !dag.is_blue_in(&chain_block, &member) {
                report.skipped_red.push(member);
                continue;
            }
            let body = bodies
                .get(&member)
                .expect("every DAG block has a stored body");

            let applied = self
                .store
                .apply_block(body.block.coinbase.outputs(), &body.txs, height);
            match applied {
                Ok(undo) => step.undo.merge(undo),
                Err(error) => {
                    report.rejected.push((member, error));
                    continue;
                }
            }

            if Some(member) == dag.genesis() {
                continue; // genesis pays nothing and is not part of any epoch
            }

            let completed = self
                .epoch
                .add_block(&body.block.coinbase, body.fees)
                .and_then(|()| {
                    if self.epoch.is_complete() {
                        self.epoch.settle().map(Some)
                    } else {
                        Ok(None)
                    }
                });
            match completed {
                Ok(Some(settlement)) => {
                    step.completed_epochs.push(settlement);
                    report.epochs_completed.push(settlement);
                }
                Ok(None) => {}
                Err(error) => {
                    // The block was validated, so this means corrupted accounting: undo the step.
                    self.store.revert_block(step.undo);
                    self.epoch = step.epoch_before;
                    return Err(error.into());
                }
            }
            step.accepted.push(member);
            self.accepted_blocks += 1;
            report.accepted.push(member);
        }

        self.steps.push(step);
        Ok(())
    }
}
