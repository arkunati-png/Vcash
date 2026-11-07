//! End-to-end tests: DAG + batches + PoW + coinbase rules + UTXO state + POL epochs.

use std::sync::Arc;

use volt_consensus::{
    coinbase::CoinbaseError, difficulty, Consensus, ConsensusError, TemplateContext,
};
use volt_core::{
    constants::{BASE_EMISSION_PER_BLOCK, EPOCH_LENGTH, FINALITY_DEPTH},
    BatchableTx, DevTx, DevTxDecoder, Payout, RollupBatch, VoltBlock, VoltHash,
};
use volt_crypto::{meets_target, Blake2bPowHasher, PowHasher};
use zebra_chain::{
    amount::Amount,
    parameters::NetworkKind,
    transaction,
    transparent::{Address, OutPoint, Output, Script},
};

const HALF_EMISSION: i64 = BASE_EMISSION_PER_BLOCK / 2;

fn new_consensus() -> Consensus {
    Consensus::new(
        Consensus::genesis_block(0),
        Arc::new(Blake2bPowHasher),
        Arc::new(DevTxDecoder),
    )
    .unwrap()
}

fn miners(n: usize, tag: u8) -> Vec<Address> {
    (0..n)
        .map(|i| Address::from_pub_key_hash(NetworkKind::Regtest, [tag.wrapping_add(i as u8); 20]))
        .collect()
}

/// Template parents, bits and seed for a block on top of exactly `parents`.
fn ctx_on(c: &Consensus, parents: &[VoltHash]) -> TemplateContext {
    let selected = c.dag().select_parent(parents);
    TemplateContext {
        parents: parents.to_vec(),
        bits: difficulty::next_bits(c.dag(), &selected),
        seed: difficulty::pow_seed(c.dag(), &selected),
        min_timestamp_ms: parents
            .iter()
            .map(|p| c.dag().get(p).unwrap().timestamp_ms)
            .max()
            .unwrap(),
    }
}

fn mine_on(
    c: &Consensus,
    ctx: &TemplateContext,
    batches: Vec<RollupBatch>,
    miners: &[Address],
    ts: u64,
) -> VoltBlock {
    let template = c.build_template(ctx, batches, miners, ts).unwrap();
    c.mine(template, &ctx.seed, 0, u64::MAX).unwrap().unwrap()
}

/// Mines and submits an empty block on the current tips, advancing the fake clock.
fn extend(c: &mut Consensus, ts: &mut u64, miners: &[Address]) -> VoltBlock {
    let ctx = c.template_context();
    *ts += 500;
    let block = mine_on(c, &ctx, vec![], miners, *ts);
    c.submit_block(block.clone(), *ts).unwrap();
    block
}

fn spend_all(block: &VoltBlock, nonce_base: u64) -> Vec<Arc<dyn BatchableTx>> {
    block
        .coinbase
        .outputs()
        .into_iter()
        .enumerate()
        .map(|(i, (outpoint, output))| {
            let out = Output::new(
                Amount::new(output.value().zatoshis() - 10_000), // transparent fee
                Script::new(&[i as u8]),
            );
            Arc::new(DevTx::new(
                vec![outpoint],
                vec![out],
                vec![],
                false,
                nonce_base + i as u64,
            )) as Arc<dyn BatchableTx>
        })
        .collect()
}

fn out0(tx: &Arc<dyn BatchableTx>) -> OutPoint {
    OutPoint::from_usize(transaction::Hash(tx.txid().0), 0)
}

#[test]
fn ten_to_one_batches_flow_through_the_dag_into_state() {
    let mut c = new_consensus();
    let m = miners(10, 1);
    let mut ts = 0;

    let b1 = extend(&mut c, &mut ts, &m);
    extend(&mut c, &mut ts, &m);
    extend(&mut c, &mut ts, &m);
    // A block's coinbase is accepted when a later chain block merges it.
    assert_eq!(c.accepted_blocks(), 2);
    assert_eq!(c.utxos().len(), 20);

    // Ten transactions, one rollup batch, one block.
    let txs = spend_all(&b1, 0);
    let (batches, leftover) = Consensus::pack_batches(&txs).unwrap();
    assert_eq!((batches.len(), leftover), (1, 0));
    assert_eq!(
        batches[0].total_fees().zatoshis(),
        100_000,
        "10 x 0.0001 VOLT"
    );

    let ctx = c.template_context();
    ts += 500;
    let b4 = mine_on(&c, &ctx, batches, &m, ts);
    // The reward is emission + fees, split exactly in half.
    let paid: i64 = b4
        .coinbase
        .payouts
        .iter()
        .map(|p| p.amount.zatoshis())
        .sum();
    assert_eq!(paid, HALF_EMISSION + 50_000);
    assert_eq!(
        b4.coinbase.pol_contribution.zatoshis(),
        HALF_EMISSION + 50_000
    );
    c.submit_block(b4, ts).unwrap();
    assert_eq!(c.utxos().len(), 30, "b3 merged, b4's batch not yet");

    let before = c.utxos().len();
    extend(&mut c, &mut ts, &m); // merges b4
    assert_eq!(c.accepted_blocks(), 4);
    // -10 spent coinbase outputs, +10 new outputs, +10 from b4's coinbase.
    assert_eq!(c.utxos().len(), before - 10 + 10 + 10);
    for tx in &txs {
        assert!(c.utxos().contains(&out0(tx)));
    }
    for (outpoint, _) in b1.coinbase.outputs() {
        assert!(!c.utxos().contains(&outpoint), "spent");
    }
}

#[test]
fn parallel_blocks_double_spending_resolve_deterministically() {
    let mut c = new_consensus();
    let m = miners(10, 1);
    let mut ts = 0;
    let b1 = extend(&mut c, &mut ts, &m);
    extend(&mut c, &mut ts, &m);
    extend(&mut c, &mut ts, &m);

    // Two siblings on the same tip spend the same outputs to different destinations.
    let tip = c.sink();
    let ctx = ctx_on(&c, &[tip]);
    let make = |c: &Consensus, nonce_base: u64, tag: u8| {
        let txs = spend_all(&b1, nonce_base);
        let (batches, _) = Consensus::pack_batches(&txs).unwrap();
        (mine_on(c, &ctx, batches, &miners(10, tag), ts + 500), txs)
    };
    let (p, p_txs) = make(&c, 1_000, 50);
    let (q, q_txs) = make(&c, 2_000, 90);
    ts += 500;
    c.submit_block(p.clone(), ts).unwrap();
    c.submit_block(q.clone(), ts).unwrap();

    // Both are valid DAG blocks. A block merging both must accept exactly one of them.
    let merge_ctx = c.template_context();
    assert_eq!(merge_ctx.parents.len(), 2);
    ts += 500;
    let merge = mine_on(&c, &merge_ctx, vec![], &m, ts);
    let outcome = c.submit_block(merge, ts).unwrap();
    assert_eq!((outcome.merged_blues, outcome.merged_reds), (2, 0));

    let report = outcome.chain.expect("the chain moved");
    assert_eq!(
        report.rejected.len(),
        1,
        "the later block in the order conflicts"
    );
    assert!(matches!(
        report.rejected[0].1,
        volt_state::StateError::MissingInput(_)
    ));

    let p_applied = c.utxos().contains(&out0(&p_txs[0]));
    let q_applied = c.utxos().contains(&out0(&q_txs[0]));
    assert!(
        p_applied ^ q_applied,
        "exactly one side of the double spend wins"
    );
}

#[test]
fn a_heavier_branch_reorgs_state() {
    let mut c = new_consensus();
    let genesis = c.sink();
    let mut ts = 0;

    // Branch A: three blocks on genesis.
    let mut tip = genesis;
    let mut a_blocks = vec![];
    for _ in 0..3 {
        let ctx = ctx_on(&c, &[tip]);
        ts += 500;
        let block = mine_on(&c, &ctx, vec![], &miners(1, 10), ts);
        tip = block.hash();
        c.submit_block(block.clone(), ts).unwrap();
        a_blocks.push(block);
    }
    assert_eq!(c.accepted_blocks(), 2);
    assert_eq!(c.sink(), a_blocks[2].hash());

    // Branch B: four blocks on genesis (heavier).
    // With equal blue work the sink tie-breaks by hash, so the switch happens at B's third or
    // fourth block depending on the hashes. Totals across the branch are the same either way.
    let mut tip = genesis;
    let (mut reverted, mut accepted, mut is_sink) = (0, 0, false);
    for _ in 0..4 {
        let ctx = ctx_on(&c, &[tip]);
        ts += 500;
        let block = mine_on(&c, &ctx, vec![], &miners(1, 20), ts);
        tip = block.hash();
        let outcome = c.submit_block(block, ts).unwrap();
        is_sink = outcome.is_sink;
        if let Some(report) = outcome.chain {
            reverted += report.reverted_steps;
            accepted += report.accepted.len();
        }
    }
    assert!(is_sink);
    assert_eq!(reverted, 3, "A's three steps are undone");
    assert_eq!(accepted, 3, "B's first three blocks are accepted");

    for block in &a_blocks {
        for (outpoint, _) in block.coinbase.outputs() {
            assert!(!c.utxos().contains(&outpoint), "A's outputs were reverted");
        }
    }
    assert_eq!(c.accepted_blocks(), 3);
    assert_eq!(c.utxos().len(), 3);
}

#[test]
fn every_200_blocks_the_epoch_settles_exactly_50_50() {
    let mut c = new_consensus();
    let m = miners(5, 1);
    let mut ts = 0;

    // Each new block merges its parent, so N submitted blocks accept N - 1. The 200th accepted
    // block completes the epoch, but its POL half is only locked once that step is final.
    for _ in 0..=EPOCH_LENGTH {
        extend(&mut c, &mut ts, &m);
    }
    assert_eq!(c.accepted_blocks(), EPOCH_LENGTH);
    assert_eq!(c.epoch().epoch(), 1, "the epoch completed");
    assert!(
        c.reserve().settlements().is_empty(),
        "but it is not final yet"
    );

    // One block short of the finality depth: still not locked. One more: locked.
    for _ in 0..(FINALITY_DEPTH - 1) {
        extend(&mut c, &mut ts, &m);
    }
    assert!(c.reserve().settlements().is_empty());
    extend(&mut c, &mut ts, &m);
    assert_eq!(c.reserve().settlements().len(), 1);

    let s = c.reserve().settlements()[0];
    let total = EPOCH_LENGTH as i64 * BASE_EMISSION_PER_BLOCK;
    assert_eq!(s.epoch, 0);
    assert_eq!(s.blocks, EPOCH_LENGTH);
    assert_eq!(s.total_reward.zatoshis(), total);
    assert_eq!(s.miner_amount.zatoshis(), total / 2);
    assert_eq!(s.pol_amount.zatoshis(), total / 2);
    assert_eq!(c.reserve().locked().zatoshis(), total / 2);
    // 251 blocks submitted, 250 accepted: 200 settled, 50 into the next epoch.
    assert_eq!(
        c.epoch().blocks(),
        FINALITY_DEPTH as u64,
        "the next epoch is filling"
    );

    // A second epoch locks as much again.
    for _ in 0..EPOCH_LENGTH {
        extend(&mut c, &mut ts, &m);
    }
    assert_eq!(c.reserve().settlements().len(), 2);
    assert_eq!(c.reserve().locked().zatoshis(), total);
}

#[test]
fn a_reorg_past_finality_is_refused() {
    let mut c = new_consensus();
    let genesis = c.sink();
    let m = miners(1, 1);
    let mut ts = 0;
    let main_len = EPOCH_LENGTH + 1 + FINALITY_DEPTH as u64;
    for _ in 0..main_len {
        extend(&mut c, &mut ts, &m);
    }
    assert_eq!(c.reserve().settlements().len(), 1);
    let locked = c.reserve().locked();
    let sink = c.sink();

    // A competing branch from genesis, long enough to outweigh the main chain.
    let mut tip = genesis;
    let mut blocked = false;
    for _ in 0..(main_len + 5) {
        let ctx = ctx_on(&c, &[tip]);
        let block = mine_on(
            &c,
            &ctx,
            vec![],
            &miners(1, 77),
            1_000 + ctx.min_timestamp_ms,
        );
        tip = block.hash();
        let outcome = c.submit_block(block, 10_000_000).unwrap();
        blocked |= outcome.chain_blocked_by_finality;
    }
    assert!(
        blocked,
        "the heavier branch exists in the DAG but state refuses to follow it"
    );
    assert_eq!(c.reserve().locked(), locked, "locked liquidity never moves");
    assert_eq!(c.reserve().settlements().len(), 1);
    assert_ne!(c.sink(), sink, "the DAG itself did switch sink");
}

#[test]
fn rejects_unmined_blocks() {
    let c = new_consensus();
    let ctx = c.template_context();
    let template = c.build_template(&ctx, vec![], &miners(1, 1), 500).unwrap();

    // Find a nonce that does not meet the target.
    let mut bad = template;
    for nonce in 0.. {
        bad.header.nonce = nonce;
        let hash = Blake2bPowHasher
            .pow_hash(&ctx.seed, &bad.header.encode())
            .unwrap();
        if !meets_target(&hash, bad.header.bits) {
            break;
        }
    }
    let mut c = c;
    assert!(matches!(
        c.submit_block(bad, 1_000),
        Err(ConsensusError::InsufficientPow)
    ));
}

#[test]
fn rejects_a_coinbase_with_101_payout_addresses() {
    let mut c = new_consensus();
    let ctx = c.template_context();
    let mut block = c
        .build_template(&ctx, vec![], &miners(100, 1), 500)
        .unwrap();
    assert_eq!(block.coinbase.payouts.len(), 100);

    // Move one zatoshi from a payout to a 101st address: the 50/50 total is unchanged.
    block.coinbase.payouts[1].amount = Amount::new(block.coinbase.payouts[1].amount.zatoshis() - 1);
    block.coinbase.payouts.push(Payout {
        address: Address::from_pub_key_hash(NetworkKind::Regtest, [0xee; 20]),
        amount: Amount::new(1),
    });
    block.header.coinbase_root = block.coinbase.hash();
    let block = c.mine(block, &ctx.seed, 0, u64::MAX).unwrap().unwrap();

    match c.submit_block(block, 1_000) {
        Err(ConsensusError::Coinbase(CoinbaseError::TooManyPayoutAddresses { count, max })) => {
            assert_eq!((count, max), (101, 100));
        }
        other => panic!("expected the payout cap to reject the block, got {other:?}"),
    }
}

#[test]
fn rejects_a_coinbase_that_skims_the_pol_half() {
    let mut c = new_consensus();
    let ctx = c.template_context();
    let mut block = c.build_template(&ctx, vec![], &miners(3, 1), 500).unwrap();

    // The miner pays itself the POL half too.
    block.coinbase.payouts[0].amount = Amount::new(
        block.coinbase.payouts[0].amount.zatoshis() + block.coinbase.pol_contribution.zatoshis(),
    );
    block.coinbase.pol_contribution = Amount::new(0);
    block.header.coinbase_root = block.coinbase.hash();
    let block = c.mine(block, &ctx.seed, 0, u64::MAX).unwrap().unwrap();

    assert!(matches!(
        c.submit_block(block, 1_000),
        Err(ConsensusError::Coinbase(
            CoinbaseError::WrongMinerTotal { .. }
        ))
    ));
}

#[test]
fn rejects_wrong_difficulty_and_tampered_commitments() {
    let mut c = new_consensus();
    let ctx = c.template_context();

    let mut easy = c.build_template(&ctx, vec![], &miners(1, 1), 500).unwrap();
    easy.header.bits = 0x2000_ffff;
    let easy = c.mine(easy, &ctx.seed, 0, u64::MAX).unwrap().unwrap();
    assert!(matches!(
        c.submit_block(easy, 1_000),
        Err(ConsensusError::WrongBits { .. })
    ));

    let mut bad_root = c.build_template(&ctx, vec![], &miners(1, 1), 500).unwrap();
    bad_root.header.batches_root = VoltHash([7; 32]);
    let bad_root = c.mine(bad_root, &ctx.seed, 0, u64::MAX).unwrap().unwrap();
    assert!(matches!(
        c.submit_block(bad_root, 1_000),
        Err(ConsensusError::CommitmentMismatch("batches"))
    ));

    let future = c
        .build_template(&ctx, vec![], &miners(1, 1), 10_000_000)
        .unwrap();
    let future = c.mine(future, &ctx.seed, 0, u64::MAX).unwrap().unwrap();
    assert!(matches!(
        c.submit_block(future, 1_000),
        Err(ConsensusError::TimestampInFuture { .. })
    ));
}
