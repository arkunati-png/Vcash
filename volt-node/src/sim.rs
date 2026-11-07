//! The multi-miner devnet simulation.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use tracing::info;
use volt_consensus::Consensus;
use volt_core::{
    constants::{BATCH_SIZE, MAX_BLOCK_PARENTS, TARGET_BLOCK_INTERVAL_MS},
    DevTxDecoder, VoltBlock,
};
use volt_crypto::{Blake2bPowHasher, PowHasher};
use volt_network::{GossipHub, GossipPeer, VoltMessage};
use volt_state::EpochSettlement;
use zebra_chain::{
    amount::Amount, amount::NonNegative, parameters::NetworkKind, transparent::Address,
};

use crate::wallet::DevWallet;

/// Which proof-of-work function the miners use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowKind {
    /// Blake2b-256: fast, for devnets and tests. Not CPU-hard.
    Blake2b,
    /// RandomX in light mode.
    #[cfg(feature = "randomx")]
    RandomX,
}

impl PowKind {
    fn hasher(self) -> Result<Arc<dyn PowHasher>> {
        Ok(match self {
            Self::Blake2b => Arc::new(Blake2bPowHasher),
            #[cfg(feature = "randomx")]
            Self::RandomX => Arc::new(
                volt_crypto::RandomXEngine::new().context("could not start the RandomX engine")?,
            ),
        })
    }
}

/// Simulation parameters.
#[derive(Clone, Debug)]
pub struct SimConfig {
    /// Rounds to simulate. Each round, every miner mines one block from the same view.
    pub rounds: u64,
    /// The number of miners (and nodes). Rounds with several miners produce parallel blocks.
    pub miners: usize,
    /// How many 10-transaction rollup batches the first miner packs into each block.
    pub batches_per_block: usize,
    /// The proof-of-work function.
    pub pow: PowKind,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            rounds: 300,
            miners: 3,
            batches_per_block: 2,
            pow: PowKind::Blake2b,
        }
    }
}

/// What a simulation produced.
#[derive(Debug)]
pub struct SimReport {
    /// Blocks mined in total.
    pub blocks_mined: u64,
    /// Blocks in the first node's DAG, genesis included.
    pub dag_blocks: usize,
    /// Red blocks merged by any block.
    pub red_merges: usize,
    /// Blocks accepted into state.
    pub accepted_blocks: u64,
    /// Blue blocks rejected because they conflict with an earlier block.
    pub rejected_blocks: usize,
    /// Rollup batches in accepted blocks.
    pub accepted_batches: usize,
    /// User transactions in accepted blocks (10 per batch).
    pub accepted_txs: usize,
    /// Unspent outputs.
    pub utxos: usize,
    /// Revealed shielded nullifiers.
    pub nullifiers: usize,
    /// Every settled epoch.
    pub settlements: Vec<EpochSettlement>,
    /// Total VOLT permanently locked in the POL reserve, in zatoshis.
    pub pol_locked: Amount<NonNegative>,
    /// Whether every node ended with the same sink, UTXO set size, accepted blocks and reserve.
    pub converged: bool,
    /// Simulated chain time, in seconds.
    pub simulated_secs: f64,
    /// Wall-clock time the simulation took.
    pub elapsed: Duration,
}

impl SimReport {
    /// Accepted user transactions per simulated second.
    pub fn effective_tps(&self) -> f64 {
        if self.simulated_secs == 0.0 {
            0.0
        } else {
            self.accepted_txs as f64 / self.simulated_secs
        }
    }
}

struct SimNode {
    consensus: Consensus,
    peer: GossipPeer,
    payout_addresses: Vec<Address>,
}

fn payout_addresses(miner: usize) -> Vec<Address> {
    (0..10u8)
        .map(|i| {
            let mut hash = [0u8; 20];
            hash[0] = u8::try_from(miner).unwrap_or(u8::MAX);
            hash[1] = i;
            Address::from_pub_key_hash(NetworkKind::Regtest, hash)
        })
        .collect()
}

/// Runs the simulation.
pub fn run(config: SimConfig) -> Result<SimReport> {
    if config.miners == 0 || config.miners >= MAX_BLOCK_PARENTS {
        bail!("miners must be between 1 and {}", MAX_BLOCK_PARENTS - 1);
    }
    let started = Instant::now();

    let hub = GossipHub::new(4096);
    let genesis = Consensus::genesis_block(0);
    let mut nodes = Vec::new();
    for id in 0..config.miners {
        let consensus = Consensus::new(
            genesis.clone(),
            config.pow.hasher()?,
            Arc::new(DevTxDecoder),
        )
        .context("genesis block was rejected")?;
        nodes.push(SimNode {
            consensus,
            peer: hub.join(u32::try_from(id).context("too many miners")?),
            payout_addresses: payout_addresses(id),
        });
    }

    let mut wallet = DevWallet::new();
    let mut report = SimReport {
        blocks_mined: 0,
        dag_blocks: 0,
        red_merges: 0,
        accepted_blocks: 0,
        rejected_blocks: 0,
        accepted_batches: 0,
        accepted_txs: 0,
        utxos: 0,
        nullifiers: 0,
        settlements: Vec::new(),
        pol_locked: Amount::zero(),
        converged: false,
        simulated_secs: 0.0,
        elapsed: Duration::ZERO,
    };

    // One block per miner per round; rounds are spaced so the chain makes one block per 500 ms.
    let round_ms = TARGET_BLOCK_INTERVAL_MS * config.miners as u64; // lossless: miners < 33
    let mut round_start_ms = 0u64;

    for round in 1..=config.rounds {
        round_start_ms += round_ms;

        // Phase 1: every miner mines from its own, identical, view of the DAG.
        let mut mined: Vec<VoltBlock> = Vec::with_capacity(nodes.len());
        for (index, node) in nodes.iter().enumerate() {
            let ctx = node.consensus.template_context();
            let batches = if index == 0 {
                let wanted = config.batches_per_block * BATCH_SIZE;
                let txs =
                    wallet.make_txs(wanted, |outpoint| node.consensus.utxos().contains(outpoint));
                Consensus::pack_batches(&txs)?.0
            } else {
                Vec::new()
            };
            let timestamp_ms = round_start_ms + TARGET_BLOCK_INTERVAL_MS * index as u64; // lossless: index < 33
            let template = node.consensus.build_template(
                &ctx,
                batches,
                &node.payout_addresses,
                timestamp_ms,
            )?;
            let block = node
                .consensus
                .mine(template, &ctx.seed, 0, u64::MAX)?
                .context("the nonce space was exhausted")?;
            mined.push(block);
        }

        // Phase 2: each miner submits its own block and gossips it.
        for (index, (node, block)) in nodes.iter_mut().zip(&mined).enumerate() {
            let now_ms = round_start_ms + round_ms;
            let outcome = node.consensus.submit_block(block.clone(), now_ms)?;
            node.peer.broadcast(&VoltMessage::NewBlock(block.encode()));
            if index == 0 {
                track(&mut report, &mut wallet, &node.consensus, &outcome);
            }
        }
        report.blocks_mined += mined.len() as u64; // lossless: a Vec length fits in u64

        // Phase 3: every node receives and validates the other miners' blocks.
        for (index, node) in nodes.iter_mut().enumerate() {
            while let Some((_from, message)) = node.peer.try_recv() {
                let VoltMessage::NewBlock(bytes) = message else {
                    continue;
                };
                let block = VoltBlock::decode(&bytes).context("gossiped block is malformed")?;
                let now_ms = round_start_ms + round_ms;
                let outcome = node.consensus.submit_block(block, now_ms)?;

                if index == 0 {
                    track(&mut report, &mut wallet, &node.consensus, &outcome);
                }
            }
        }

        if round % 50 == 0 {
            let node0 = &nodes[0].consensus;
            info!(
                round,
                dag_blocks = node0.dag().len(),
                accepted = node0.accepted_blocks(),
                utxos = node0.utxos().len(),
                pol_locked = node0.reserve().locked().zatoshis(),
                "progress"
            );
        }
    }

    finish(&mut report, &nodes, round_start_ms, started);
    Ok(report)
}

fn track(
    report: &mut SimReport,
    wallet: &mut DevWallet,
    consensus: &Consensus,
    outcome: &volt_consensus::SubmitOutcome,
) {
    report.red_merges += outcome.merged_reds;
    let Some(chain) = &outcome.chain else {
        return;
    };
    report.rejected_blocks += chain.rejected.len();
    for hash in &chain.accepted {
        let block = consensus
            .block(hash)
            .expect("accepted blocks are stored by the consensus engine");
        wallet.on_accepted(block);
        report.accepted_batches += block.batches.len();
        report.accepted_txs += block.batches.len() * BATCH_SIZE;
    }
    for settlement in &chain.epochs_locked {
        info!(
            epoch = settlement.epoch,
            blocks = settlement.blocks,
            total_reward = settlement.total_reward.zatoshis(),
            to_miners = settlement.miner_amount.zatoshis(),
            locked_in_pol = settlement.pol_amount.zatoshis(),
            "epoch final: exact 50/50 split, POL half permanently locked"
        );
        report.settlements.push(*settlement);
    }
}

fn finish(report: &mut SimReport, nodes: &[SimNode], last_ms: u64, started: Instant) {
    let first = &nodes[0].consensus;
    report.dag_blocks = first.dag().len();
    report.accepted_blocks = first.accepted_blocks();
    report.utxos = first.utxos().len();
    report.nullifiers = first.utxos().nullifier_count();
    report.pol_locked = first.reserve().locked();
    report.simulated_secs = last_ms as f64 / 1000.0;
    report.elapsed = started.elapsed();
    report.converged = nodes.iter().all(|n| {
        let c = &n.consensus;
        c.sink() == first.sink()
            && c.utxos().len() == first.utxos().len()
            && c.utxos().nullifier_count() == first.utxos().nullifier_count()
            && c.accepted_blocks() == first.accepted_blocks()
            && c.reserve().locked() == first.reserve().locked()
            && c.reserve().settlements().len() == first.reserve().settlements().len()
    });
}
