//! `volt-node`: a Voltcash node, and a multi-miner devnet simulation.
//!
//! ```text
//! volt-node run [--data-dir DIR] [--listen ADDR] [--seed ADDR]... [--mine] [--blocks N]
//!               [--batches N] [--name TAG] [--economics mainnet|tapered|fifty-fifty|faucet] [--maturity STEPS]
//!               [--easy-pow] [--verify-all] [--real-txs] [--rpc ADDR] [--stratum ADDR] [--payout ADDR]...
//! volt-node sim [--blocks ROUNDS] [--miners N] [--batches PER_BLOCK]
//!               [--economics mainnet|tapered|fifty-fifty|faucet] [--maturity STEPS]
//! ```
//!
//! `run` starts a persistent node that talks to other nodes over TCP. `sim` runs several miners
//! in one process and reports throughput. Without a subcommand, `sim` is assumed.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use tracing::{info, warn};
use volt_core::Economics;
use volt_crypto::{PowHasher, RandomXEngine};
use volt_node::{
    node::{Node, NodeConfig},
    rpc,
    sim::{self, SimConfig},
    stratum,
};
use zebra_chain::{parameters::NetworkKind, transparent::Address};

const SIM_USAGE: &str =
    "usage: volt-node sim [--blocks ROUNDS] [--miners N] [--batches PER_BLOCK] \
     [--economics mainnet|tapered|fifty-fifty|faucet] [--maturity STEPS]";

const RUN_USAGE: &str = "usage: volt-node run [--data-dir DIR] [--listen ADDR] [--seed ADDR]... \
     [--mine] [--blocks N] [--batches N] [--name TAG] [--economics mainnet|tapered|fifty-fifty|faucet] \
     [--maturity STEPS] [--easy-pow] [--real-txs] [--payout ADDR]...";

/// Pulls the value that follows a flag.
fn value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next().with_context(|| format!("{flag} needs a value"))
}

fn economics(name: &str) -> Result<Economics> {
    match name {
        "mainnet" => Ok(Economics::mainnet()),
        "tapered" => Ok(Economics::tapered()),
        "fifty-fifty" => Ok(Economics::fifty_fifty()),
        "faucet" => Ok(Economics::faucet()),
        other => bail!("unknown --economics {other}"),
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
        "starting Voltcash devnet: GHOSTDAG k=32, 850 ms blocks, 10-to-1 batches"
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
    /// Use the easy test target (still RandomX). A different network from the production one.
    easy_pow: bool,
    /// Check every block's work and every proof again when reading the block log on start.
    verify_all: bool,
    real_txs: bool,
    /// Where the devnet wallet service listens, if enabled.
    rpc: Option<SocketAddr>,
    /// Where the stratum (XMRig) server listens, if enabled.
    stratum: Option<SocketAddr>,
    /// Voltcash transparent addresses that mined rewards are paid to. Empty means the devnet
    /// placeholder addresses.
    payouts: Vec<Address>,
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
        easy_pow: false,
        verify_all: false,
        real_txs: false,
        rpc: None,
        stratum: None,
        payouts: Vec::new(),
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
            "--easy-pow" => run.easy_pow = true,
            "--verify-all" => run.verify_all = true,
            "--real-txs" => run.real_txs = true,
            "--rpc" => run.rpc = Some(value(&mut args, &flag)?.parse().context("--rpc")?),
            "--stratum" => {
                run.stratum = Some(value(&mut args, &flag)?.parse().context("--stratum")?);
            }
            "--payout" => {
                let text = value(&mut args, &flag)?;
                let hash = volt_params::transparent::decode_p2pkh(&text)
                    .with_context(|| format!("--payout {text}"))?;
                let address = Address::from_pub_key_hash(NetworkKind::Regtest, hash);
                if run.payouts.contains(&address) {
                    bail!("--payout {text} was given twice");
                }
                if run.payouts.len() >= volt_core::constants::MAX_COINBASE_PAYOUTS {
                    bail!(
                        "at most {} --payout addresses",
                        volt_core::constants::MAX_COINBASE_PAYOUTS
                    );
                }
                run.payouts.push(address);
            }
            "-h" | "--help" => {
                info!("{RUN_USAGE}");
                std::process::exit(0);
            }
            other => bail!("unknown argument {other}"),
        }
    }
    Ok(run)
}

fn pow_hasher() -> Result<Arc<dyn PowHasher>> {
    Ok(Arc::new(
        RandomXEngine::new().context("could not start the RandomX engine")?,
    ))
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
    if run.easy_pow {
        warn!(
            "EASY PROOF OF WORK: blocks take about 8 RandomX hashes instead of about 512. \
             This is a test network and cannot be joined by a node without --easy-pow."
        );
    }

    let mut config = NodeConfig::devnet(
        run.data_dir.clone(),
        pow_hasher()?,
        if run.payouts.is_empty() {
            miner_addresses(run.tag)
        } else {
            run.payouts.clone()
        },
    );
    if run.easy_pow {
        config = config.with_easy_pow();
    }
    if run.verify_all {
        config.replay = volt_storage::ReplayMode::Full;
    }
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
        if let Some(rpc) = run.rpc {
            rpc::start(node.clone(), rpc, !run.real_txs)?;
        }
        if let Some(stratum) = run.stratum {
            stratum::start(node.clone(), stratum)?;
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn payout_takes_voltcash_addresses_only() {
        let a = volt_params::transparent::encode_p2pkh(&[1; 20]);
        let b = volt_params::transparent::encode_p2pkh(&[2; 20]);
        let run = parse_run(args(&["--payout", &a, "--payout", &b])).unwrap();
        assert_eq!(run.payouts.len(), 2);

        // A Zcash address, a duplicate and garbage are all refused.
        assert!(parse_run(args(&["--payout", "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs"])).is_err());
        assert!(parse_run(args(&["--payout", &a, "--payout", &a])).is_err());
        assert!(parse_run(args(&["--payout", "nonsense"])).is_err());
        assert!(parse_run(args(&[])).unwrap().payouts.is_empty());
    }
}
