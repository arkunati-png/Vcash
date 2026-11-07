//! `volt-node`: a Voltcash node, and a multi-miner devnet simulation.
//!
//! ```text
//! volt-node run [--data-dir DIR] [--listen ADDR] [--seed ADDR]... [--mine] [--blocks N]
//!               [--batches N] [--name TAG] [--economics mainnet|tapered|fifty-fifty] [--maturity STEPS]
//!               [--pow blake2b|randomx] [--real-txs]
//! volt-node sim [--blocks ROUNDS] [--miners N] [--batches PER_BLOCK] [--pow blake2b|randomx]
//!               [--economics mainnet|tapered|fifty-fifty] [--maturity STEPS]
//! ```
//!
//! `run` starts a persistent node that talks to other nodes over TCP. `sim` runs several miners
//! in one process and reports throughput. Without a subcommand, `sim` is assumed.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use tracing::{info, warn};
use volt_core::Economics;
use volt_crypto::{Blake2bPowHasher, PowHasher};
use volt_node::{
    node::{Node, NodeConfig},
    sim::{self, PowKind, SimConfig},
};
use zebra_chain::{parameters::NetworkKind, transparent::Address};

const SIM_USAGE: &str =
    "usage: volt-node sim [--blocks ROUNDS] [--miners N] [--batches PER_BLOCK] \
     [--pow blake2b|randomx] [--economics mainnet|tapered|fifty-fifty] [--maturity STEPS]";

const RUN_USAGE: &str = "usage: volt-node run [--data-dir DIR] [--listen ADDR] [--seed ADDR]... \
     [--mine] [--blocks N] [--batches N] [--name TAG] [--economics mainnet|tapered|fifty-fifty] \
     [--maturity STEPS] [--pow blake2b|randomx] [--real-txs]";

/// Pulls the value that follows a flag.
fn value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next().with_context(|| format!("{flag} needs a value"))
}

fn economics(name: &str) -> Result<Economics> {
    match name {
        "mainnet" => Ok(Economics::mainnet()),
        "tapered" => Ok(Economics::tapered()),
        "fifty-fifty" => Ok(Economics::fifty_fifty()),
        other => bail!("unknown --economics {other}"),
    }
}

fn pow_kind(name: &str) -> Result<PowKind> {
    match name {
        "blake2b" => Ok(PowKind::Blake2b),
        #[cfg(feature = "randomx")]
        "randomx" => Ok(PowKind::RandomX),
        #[cfg(not(feature = "randomx"))]
        "randomx" => bail!("this build has no RandomX: rebuild with --features randomx"),
        other => bail!("unknown --pow {other}"),
    }
}

fn parse_sim(args: Vec<String>) -> Result<SimConfig> {
    let mut config = SimConfig::default();
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--blocks" | "--rounds" => {
                config.rounds = value(&mut args, &flag)?.parse().context("--blocks")?;
            }
            "--miners" => config.miners = value(&mut args, &flag)?.parse().context("--miners")?,
            "--batches" => {
                config.batches_per_block = value(&mut args, &flag)?.parse().context("--batches")?;
            }
            "--pow" => config.pow = pow_kind(&value(&mut args, &flag)?)?,
            "--economics" => config.economics = economics(&value(&mut args, &flag)?)?,
            "--maturity" => {
                config.coinbase_maturity =
                    value(&mut args, &flag)?.parse().context("--maturity")?;
            }
            "-h" | "--help" => {
                info!("{SIM_USAGE}");
                std::process::exit(0);
            }
            other => bail!("unknown argument {other}"),
        }
    }
    Ok(config)
}

fn run_sim(args: Vec<String>) -> Result<()> {
    let config = parse_sim(args)?;
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

struct RunArgs {
    data_dir: PathBuf,
    listen: SocketAddr,
    seeds: Vec<SocketAddr>,
    mine: bool,
    blocks: Option<u64>,
    batches: usize,
    tag: u8,
    economics: Economics,
    maturity: Option<u32>,
    pow: PowKind,
    real_txs: bool,
}

fn parse_run(args: Vec<String>) -> Result<RunArgs> {
    let mut run = RunArgs {
        data_dir: PathBuf::from("volt-data"),
        listen: SocketAddr::from(([127, 0, 0, 1], 8445)),
        seeds: Vec::new(),
        mine: false,
        blocks: None,
        batches: 2,
        tag: 1,
        economics: Economics::mainnet(),
        maturity: None,
        pow: PowKind::Blake2b,
        real_txs: false,
    };
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--data-dir" => run.data_dir = PathBuf::from(value(&mut args, &flag)?),
            "--listen" => run.listen = value(&mut args, &flag)?.parse().context("--listen")?,
            "--seed" => run
                .seeds
                .push(value(&mut args, &flag)?.parse().context("--seed")?),
            "--mine" => run.mine = true,
            "--blocks" => run.blocks = Some(value(&mut args, &flag)?.parse().context("--blocks")?),
            "--batches" => run.batches = value(&mut args, &flag)?.parse().context("--batches")?,
            "--name" => {
                run.tag = value(&mut args, &flag)?
                    .parse()
                    .context("--name must be 0-255")?;
            }
            "--economics" => run.economics = economics(&value(&mut args, &flag)?)?,
            "--maturity" => {
                run.maturity = Some(value(&mut args, &flag)?.parse().context("--maturity")?);
            }
            "--pow" => run.pow = pow_kind(&value(&mut args, &flag)?)?,
            "--real-txs" => run.real_txs = true,
            "-h" | "--help" => {
                info!("{RUN_USAGE}");
                std::process::exit(0);
            }
            other => bail!("unknown argument {other}"),
        }
    }
    Ok(run)
}

fn pow_hasher(kind: PowKind) -> Result<Arc<dyn PowHasher>> {
    Ok(match kind {
        PowKind::Blake2b => Arc::new(Blake2bPowHasher),
        #[cfg(feature = "randomx")]
        PowKind::RandomX => Arc::new(
            volt_crypto::RandomXEngine::new().context("could not start the RandomX engine")?,
        ),
    })
}

fn miner_addresses(tag: u8) -> Vec<Address> {
    (0..10u8)
        .map(|i| {
            let mut hash = [0u8; 20];
            hash[0] = tag;
            hash[1] = i;
            Address::from_pub_key_hash(NetworkKind::Regtest, hash)
        })
        .collect()
}

fn run_node(args: Vec<String>) -> Result<()> {
    let run = parse_run(args)?;

    let mut config = NodeConfig::devnet(
        run.data_dir.clone(),
        pow_hasher(run.pow)?,
        miner_addresses(run.tag),
    );
    config.p2p.listen = run.listen;
    config.p2p.seeds = run.seeds.clone();
    config.economics = run.economics;
    config.batches_per_block = run.batches;
    if let Some(maturity) = run.maturity {
        config.coinbase_maturity = maturity;
    }

    if run.real_txs {
        #[cfg(feature = "zebra-proofs")]
        {
            config.decoder = Arc::new(volt_core::ZebraTxDecoder);
            config.verifier = Arc::new(volt_verify::ZebraTxVerifier::voltcash());
            config.coinbase_maturity = run
                .maturity
                .unwrap_or(volt_core::constants::COINBASE_MATURITY);
            info!("verifying Sapling/Orchard proofs and transparent scripts");
        }
        #[cfg(not(feature = "zebra-proofs"))]
        bail!("this build cannot verify real transactions: rebuild with --features zebra-proofs");
    } else {
        warn!(
            "DEVNET MODE: proof-less transactions, no signature or proof checking. \
             Never use with real value."
        );
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(async move {
        let node = Arc::new(Node::start(config).await?);
        info!(addr = %node.local_addr(), "node running");

        let miner = run.mine.then(|| {
            let node = node.clone();
            let limit = run.blocks;
            tokio::task::spawn_blocking(move || {
                let mut mined = 0u64;
                while limit.is_none_or(|n| mined < n) {
                    match node.mine_one(u64::MAX) {
                        Ok(Some(hash)) => {
                            mined += 1;
                            let status = node.status();
                            info!(
                                %hash,
                                mined,
                                dag = status.dag_blocks,
                                accepted = status.accepted_blocks,
                                peers = status.peers,
                                "mined a block"
                            );
                        }
                        Ok(None) => {}
                        Err(error) => {
                            warn!(%error, "mining failed");
                            std::thread::sleep(Duration::from_secs(1));
                        }
                    }
                }
            })
        });

        let status_node = node.clone();
        let status = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                let s = status_node.status();
                info!(
                    dag = s.dag_blocks,
                    accepted = s.accepted_blocks,
                    utxos = s.utxos,
                    mempool = s.mempool,
                    peers = s.peers,
                    epochs = s.epochs_locked,
                    pol_locked = s.pol_locked,
                    "status"
                );
            }
        });

        match miner {
            // Mining a fixed number of blocks, then stopping.
            Some(handle) if run.blocks.is_some() => {
                handle.await.context("the miner stopped unexpectedly")?;
                info!("finished mining {} blocks", run.blocks.unwrap_or(0));
            }
            _ => {
                tokio::signal::ctrl_c()
                    .await
                    .context("cannot wait for Ctrl-C")?;
                info!("shutting down");
            }
        }
        status.abort();
        // Stop the peer layer. A miner thread still running ends with the process.
        if let Ok(node) = Arc::try_unwrap(node) {
            node.shutdown().await;
        }
        anyhow::Ok(())
    })
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let mut args = std::env::args().skip(1).peekable();
    match args.peek().map(String::as_str) {
        Some("run") => {
            args.next();
            run_node(args.collect())
        }
        Some("sim") => {
            args.next();
            run_sim(args.collect())
        }
        _ => run_sim(args.collect()),
    }
}
