//! `volt-node`: runs a Voltcash devnet simulation.
//!
//! ```text
//! volt-node [--blocks ROUNDS] [--miners N] [--batches PER_BLOCK] [--pow blake2b|randomx]
//! ```

use anyhow::{bail, Context, Result};
use tracing::info;
use volt_node::sim::{self, PowKind, SimConfig};

fn parse_args() -> Result<SimConfig> {
    let mut config = SimConfig::default();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = |name: &str| args.next().with_context(|| format!("{name} needs a value"));
        match flag.as_str() {
            "--blocks" | "--rounds" => config.rounds = value(&flag)?.parse().context("--blocks")?,
            "--miners" => config.miners = value(&flag)?.parse().context("--miners")?,
            "--batches" => {
                config.batches_per_block = value(&flag)?.parse().context("--batches")?;
            }
            "--pow" => {
                config.pow = match value(&flag)?.as_str() {
                    "blake2b" => PowKind::Blake2b,
                    #[cfg(feature = "randomx")]
                    "randomx" => PowKind::RandomX,
                    #[cfg(not(feature = "randomx"))]
                    "randomx" => {
                        bail!("this build has no RandomX: rebuild with --features randomx")
                    }
                    other => bail!("unknown --pow {other}"),
                }
            }
            "-h" | "--help" => {
                info!(
                    "usage: volt-node [--blocks ROUNDS] [--miners N] [--batches PER_BLOCK] \
                     [--pow blake2b|randomx]"
                );
                std::process::exit(0);
            }
            other => bail!("unknown argument {other}"),
        }
    }
    Ok(config)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let config = parse_args()?;
    info!(
        ?config,
        "starting Voltcash devnet: GHOSTDAG k=32, 500 ms blocks, 10-to-1 batches"
    );

    let report = sim::run(config)?;

    info!(
        blocks_mined = report.blocks_mined,
        dag_blocks = report.dag_blocks,
        accepted_blocks = report.accepted_blocks,
        rejected_blocks = report.rejected_blocks,
        red_merges = report.red_merges,
        "DAG"
    );
    info!(
        batches = report.accepted_batches,
        txs = report.accepted_txs,
        tps = format_args!("{:.1}", report.effective_tps()),
        utxos = report.utxos,
        nullifiers = report.nullifiers,
        "throughput and state"
    );
    info!(
        epochs_settled = report.settlements.len(),
        pol_locked_zatoshis = report.pol_locked.zatoshis(),
        pol_locked_volt = format_args!("{:.8}", report.pol_locked.zatoshis() as f64 / 1e8),
        "protocol-owned liquidity"
    );
    info!(
        converged = report.converged,
        simulated_secs = format_args!("{:.1}", report.simulated_secs),
        wall = ?report.elapsed,
        "done"
    );

    if !report.converged {
        bail!("nodes did not converge on the same state");
    }
    Ok(())
}
