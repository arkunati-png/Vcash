//! Whole-system devnet tests.

use volt_node::sim::{self, SimConfig};

#[test]
fn parallel_miners_converge_and_settle_epochs() {
    // Three miners mine concurrently, so every round adds three parallel blocks and the sink flips
    // between siblings of equal blue work. Epoch 0 completes around round 67 and becomes final
    // 50 chain steps later.
    let report = sim::run(SimConfig {
        rounds: 170,
        miners: 3,
        batches_per_block: 2,
        ..SimConfig::default()
    })
    .unwrap();

    assert!(
        report.converged,
        "all nodes must agree on sink, UTXOs and reserve"
    );
    assert_eq!(report.blocks_mined, 170 * 3);
    assert_eq!(
        report.rejected_blocks, 0,
        "honest parallel blocks never conflict, so none may be rejected"
    );

    // Throughput: transactions only reach state in 10-transaction rollup batches.
    assert!(report.accepted_batches > 0);
    assert_eq!(report.accepted_txs, report.accepted_batches * 10);
    assert!(
        report.nullifiers > 0,
        "shielded transactions reveal nullifiers"
    );

    // Protocol-owned liquidity: every settled epoch follows the schedule. At the start of the production
    // schedule that is 80% to miners and 20% locked as protocol-owned liquidity.
    assert!(!report.settlements.is_empty());
    for (i, s) in report.settlements.iter().enumerate() {
        assert_eq!(s.epoch, i as u64);
        assert_eq!(s.blocks, 200);
        assert_eq!(
            s.miner_amount.zatoshis() * 10,
            s.total_reward.zatoshis() * 8,
            "80% of the epoch reward goes to miners"
        );
        assert_eq!(
            s.miner_amount.zatoshis() + s.pol_amount.zatoshis(),
            s.total_reward.zatoshis()
        );
    }
    let locked: i64 = report
        .settlements
        .iter()
        .map(|s| s.pol_amount.zatoshis())
        .sum();
    assert_eq!(report.pol_locked.zatoshis(), locked);
}

#[test]
fn a_single_miner_works_and_bad_configs_are_rejected() {
    let report = sim::run(SimConfig {
        rounds: 20,
        miners: 1,
        batches_per_block: 1,
        ..SimConfig::default()
    })
    .unwrap();
    assert!(report.converged);
    assert_eq!(report.red_merges, 0);

    let bad = |miners| {
        sim::run(SimConfig {
            rounds: 1,
            miners,
            batches_per_block: 1,
            ..SimConfig::default()
        })
    };
    assert!(bad(0).is_err());
    assert!(bad(33).is_err(), "a block can reference at most 33 parents");
}

#[test]
fn the_widest_dag_merges_32_parallel_blocks_without_reds() {
    // 32 miners mine in parallel every round: each block merges 32 siblings, which is exactly
    // within what a k = 32 cluster can hold (the selected parent plus 31 more blues).
    let report = sim::run(SimConfig {
        rounds: 6,
        miners: 32,
        batches_per_block: 0,
        ..SimConfig::default()
    })
    .unwrap();
    assert!(report.converged);
    assert_eq!(report.red_merges, 0);
    assert_eq!(report.blocks_mined, 6 * 32);
}
