//! A client for the devnet wallet service in `volt-node --rpc`.
//!
//! The service answers `BALANCE <address>` and `SEND <from> <to> <zats>` over loopback TCP. It is
//! a devnet convenience: it builds and mines unsigned test transactions. A real network needs the
//! wallet to scan, sign and prove on its own, and this module does none of that.

use sapling_crypto::zip32::DiversifiableFullViewingKey;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::chain::{self, Scanner};
use crate::scancache;

/// Sending mines blocks on the node, so it gets much longer than a balance check.
const BALANCE_TIMEOUT: Duration = Duration::from_secs(5);
const SEND_TIMEOUT: Duration = Duration::from_secs(120);

fn call(service: &str, line: &str, timeout: Duration) -> Result<String, String> {
    let addr = service
        .to_socket_addrs()
        .map_err(|_| "invalid wallet service address".to_owned())?
        .next()
        .ok_or("invalid wallet service address")?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(1500))
        .map_err(|e| format!("cannot connect ({})", e.kind()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    writeln!(stream, "{line}").map_err(|e| e.to_string())?;
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .map_err(|e| format!("no answer ({})", e.kind()))?;
    let reply = reply.trim();
    match reply.strip_prefix("OK ") {
        Some(ok) => Ok(ok.to_owned()),
        None => Err(reply
            .strip_prefix("ERR ")
            .unwrap_or("unexpected answer from the node")
            .to_owned()),
    }
}

/// The unspent transparent balance of `address`, in zats.
pub fn balance(service: &str, address: &str) -> Result<u64, String> {
    let ok = call(service, &format!("BALANCE {address}"), BALANCE_TIMEOUT)?;
    ok.split_whitespace()
        .next()
        .and_then(|zats| zats.parse().ok())
        .ok_or_else(|| "unexpected balance answer".to_owned())
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return Err("bad hex from the node".to_owned());
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| "bad hex".to_owned()))
        .collect()
}

fn unhex32(text: &str) -> Result<[u8; 32], String> {
    unhex(text)?
        .try_into()
        .map_err(|_| "expected 32 bytes from the node".to_owned())
}

fn tohex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One shielded transaction in the chain feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepTx {
    pub txid: String,
    pub nullifiers: Vec<[u8; 32]>,
    pub commitments: Vec<[u8; 32]>,
    /// Ephemeral key and encrypted note for each commitment, when the node has them.
    pub outputs: Vec<([u8; 32], Vec<u8>)>,
}

/// One chain step in the feed: the shielded transactions in application order, and the Sapling
/// tree root and size the node reports once the step is done.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepData {
    pub index: usize,
    pub block: String,
    pub root: [u8; 32],
    pub notes: u64,
    pub txs: Vec<StepTx>,
}

/// Reads up to `max` chain steps starting at step `from`, and the total number of steps.
pub fn steps(service: &str, from: usize, max: usize) -> Result<(usize, Vec<StepData>), String> {
    let ok = call(service, &format!("STEPS {from} {max}"), SEND_TIMEOUT)?;
    let (total, rest) = ok.split_once(' ').unwrap_or((ok.as_str(), ""));
    let total: usize = total
        .parse()
        .map_err(|_| "unexpected step list".to_owned())?;
    let dash = |text: &str| -> Vec<String> {
        if text == "-" {
            Vec::new()
        } else {
            text.split('+').map(str::to_owned).collect()
        }
    };
    let mut out = Vec::new();
    for step in rest.split(';').filter(|s| !s.is_empty()) {
        let f: Vec<&str> = step.split(',').collect();
        let [index, block, root, notes, txs] = f.as_slice() else {
            return Err("unexpected step record".to_owned());
        };
        let mut parsed = Vec::new();
        if *txs != "-" {
            for tx in txs.split('|') {
                let p: Vec<&str> = tx.split('/').collect();
                let [txid, nullifiers, commitments, outputs] = p.as_slice() else {
                    return Err("unexpected transaction record".to_owned());
                };
                let mut out_pairs = Vec::new();
                for o in dash(outputs) {
                    let (epk, enc) = o.split_once(':').ok_or("unexpected output record")?;
                    out_pairs.push((unhex32(epk)?, unhex(enc)?));
                }
                parsed.push(StepTx {
                    txid: (*txid).to_owned(),
                    nullifiers: dash(nullifiers)
                        .iter()
                        .map(|n| unhex32(n))
                        .collect::<Result<_, _>>()?,
                    commitments: dash(commitments)
                        .iter()
                        .map(|c| unhex32(c))
                        .collect::<Result<_, _>>()?,
                    outputs: out_pairs,
                });
            }
        }
        out.push(StepData {
            index: index.parse().map_err(|_| "bad step index".to_owned())?,
            block: (*block).to_owned(),
            root: unhex32(root)?,
            notes: notes.parse().map_err(|_| "bad note count".to_owned())?,
            txs: parsed,
        });
    }
    Ok((total, out))
}

/// One unspent transparent output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoInfo {
    /// The transaction id in the byte order used inside transactions.
    pub txid: [u8; 32],
    pub index: u32,
    pub zats: u64,
    /// Whether it can be spent in the next block; a coinbase output has to age first.
    pub spendable: bool,
}

/// The unspent outputs of a transparent address and what is needed to spend them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxos {
    /// The height a transaction sent now would be mined at.
    pub next_height: u32,
    /// How many chain steps a coinbase output must age.
    pub maturity: u32,
    pub outputs: Vec<UtxoInfo>,
}

pub fn utxos(service: &str, address: &str) -> Result<Utxos, String> {
    let ok = call(service, &format!("UTXOS {address}"), BALANCE_TIMEOUT)?;
    let mut parts = ok.splitn(3, ' ');
    let bad = || "unexpected output list".to_owned();
    let next_height = parts.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
    let maturity = parts.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
    let mut outputs = Vec::new();
    for o in parts
        .next()
        .unwrap_or("")
        .split(';')
        .filter(|o| !o.is_empty())
    {
        let f: Vec<&str> = o.split(':').collect();
        let [txid, index, zats, spendable] = f.as_slice() else {
            return Err(bad());
        };
        outputs.push(UtxoInfo {
            txid: unhex32(txid)?,
            index: index.parse().map_err(|_| bad())?,
            zats: zats.parse().map_err(|_| bad())?,
            spendable: *spendable == "1",
        });
    }
    Ok(Utxos {
        next_height,
        maturity,
        outputs,
    })
}

/// Hands a signed transaction to the node. Returns the transaction id the node reports.
pub fn send_raw(service: &str, raw: &[u8]) -> Result<String, String> {
    call(service, &format!("SENDRAW {}", tohex(raw)), SEND_TIMEOUT)
}

/// Asks the node to mine `count` blocks now (devnet only), paying the reward to `reward_to`, or
/// to the node's own addresses when that is `None`.
pub fn mine(service: &str, count: u32, reward_to: Option<&str>) -> Result<(), String> {
    let command = match reward_to {
        Some(address) => format!("MINE {count} {address}"),
        None => format!("MINE {count}"),
    };
    call(service, &command, SEND_TIMEOUT).map(|_| ())
}

/// What the node reports about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    /// Blocks accepted into the ledger state.
    pub accepted: u64,
    /// Blocks in the DAG, genesis included.
    pub dag: u64,
    pub utxos: u64,
    pub mempool: u64,
    pub peers: u64,
}

/// The node's chain status.
pub fn status(service: &str) -> Result<NodeInfo, String> {
    let ok = call(service, "STATUS", BALANCE_TIMEOUT)?;
    let n: Vec<u64> = ok
        .split_whitespace()
        .filter_map(|v| v.parse().ok())
        .collect();
    match n.as_slice() {
        [accepted, dag, utxos, mempool, peers] => Ok(NodeInfo {
            accepted: *accepted,
            dag: *dag,
            utxos: *utxos,
            mempool: *mempool,
            peers: *peers,
        }),
        _ => Err("unexpected status answer".to_owned()),
    }
}

/// One line of the block list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRow {
    /// Position in the order this node received blocks (genesis is 0).
    pub index: u64,
    pub hash: String,
    pub timestamp_ms: u64,
    pub parents: u64,
    pub txs: u64,
    /// Total coinbase payouts to miners, in zats.
    pub reward: u64,
}

/// The newest blocks, newest first, and the total number of blocks.
pub fn blocks(service: &str, count: usize) -> Result<(u64, Vec<BlockRow>), String> {
    let ok = call(service, &format!("BLOCKS {count}"), BALANCE_TIMEOUT)?;
    let (total, rest) = ok.split_once(' ').unwrap_or((ok.as_str(), ""));
    let total = total
        .parse()
        .map_err(|_| "unexpected block list".to_owned())?;
    let mut rows = Vec::new();
    for record in rest.split(';').filter(|r| !r.is_empty()) {
        let f: Vec<&str> = record.split(',').collect();
        let num = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok());
        match (num(0), f.get(1), num(2), num(3), num(4), num(5)) {
            (
                Some(index),
                Some(hash),
                Some(timestamp_ms),
                Some(parents),
                Some(txs),
                Some(reward),
            ) => {
                rows.push(BlockRow {
                    index,
                    hash: (*hash).to_owned(),
                    timestamp_ms,
                    parents,
                    txs,
                    reward,
                });
            }
            _ => return Err("unexpected block record".to_owned()),
        }
    }
    Ok((total, rows))
}

/// Everything the explorer shows about one block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDetail {
    pub hash: String,
    pub index: u64,
    pub timestamp_ms: u64,
    pub bits: u64,
    pub nonce: u64,
    pub parents: Vec<String>,
    /// The part of the reward locked as protocol-owned liquidity, in zats.
    pub pol: u64,
    /// Miner payouts as (address, zats).
    pub payouts: Vec<(String, u64)>,
    /// Transactions as (id, direction), where direction is t-t, t-z, z-z or z-t.
    pub txs: Vec<(String, String)>,
}

fn list(field: &str) -> Vec<String> {
    if field == "-" {
        Vec::new()
    } else {
        field.split(',').map(str::to_owned).collect()
    }
}

/// Looks a block up by its 64-character hex hash.
pub fn block(service: &str, hash: &str) -> Result<BlockDetail, String> {
    let ok = call(service, &format!("BLOCK {hash}"), BALANCE_TIMEOUT)?;
    let f: Vec<&str> = ok.split_whitespace().collect();
    let [index, timestamp_ms, bits, nonce, parents, pol, payouts, txids] = f.as_slice() else {
        return Err("unexpected block answer".to_owned());
    };
    let num = |v: &str| {
        v.parse::<u64>()
            .map_err(|_| "unexpected block answer".to_owned())
    };
    let payouts = list(payouts)
        .into_iter()
        .filter_map(|p| {
            let (address, zats) = p.split_once(':')?;
            Some((address.to_owned(), zats.parse().ok()?))
        })
        .collect();
    Ok(BlockDetail {
        hash: hash.to_owned(),
        index: num(index)?,
        timestamp_ms: num(timestamp_ms)?,
        bits: num(bits)?,
        nonce: num(nonce)?,
        parents: list(parents),
        pol: num(pol)?,
        payouts,
        txs: list(txids)
            .into_iter()
            .filter_map(|t| {
                let (id, kind) = t.split_once(':')?;
                Some((id.to_owned(), kind.to_owned()))
            })
            .collect(),
    })
}

/// Everything the explorer shows about one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxDetail {
    pub txid: String,
    pub block: String,
    /// t-t, t-z, z-z or z-t.
    pub kind: String,
    pub fee: u64,
    pub inputs: u64,
    /// Transparent outputs as (address, zats).
    pub outputs: Vec<(String, u64)>,
    pub nullifiers: u64,
    /// Value moved out of the shielded pool by this transaction. Negative when it shields.
    pub pool_out: i64,
    /// One entry per shielded note created: `hidden`, or the amount on a proof-less devnet.
    pub notes: Vec<String>,
}

/// Looks a transaction up by its 64-character hex id.
pub fn tx(service: &str, txid: &str) -> Result<TxDetail, String> {
    let ok = call(service, &format!("TX {txid}"), BALANCE_TIMEOUT)?;
    let f: Vec<&str> = ok.split_whitespace().collect();
    let [block, kind, fee, inputs, outputs, nullifiers, pool_out, notes] = f.as_slice() else {
        return Err("unexpected transaction answer".to_owned());
    };
    let bad = || "unexpected transaction answer".to_owned();
    Ok(TxDetail {
        txid: txid.to_owned(),
        block: (*block).to_owned(),
        kind: (*kind).to_owned(),
        fee: fee.parse().map_err(|_| bad())?,
        inputs: inputs.parse().map_err(|_| bad())?,
        outputs: list(outputs)
            .into_iter()
            .filter_map(|o| {
                let (address, zats) = o.split_once(':')?;
                Some((address.to_owned(), zats.parse().ok()?))
            })
            .collect(),
        nullifiers: nullifiers.parse().map_err(|_| bad())?,
        pool_out: pool_out.parse().map_err(|_| bad())?,
        notes: list(notes),
    })
}

/// Polls the balances of one wallet, and the node's status, in the background.
pub struct BalanceMonitor {
    service: Arc<Mutex<String>>,
    state: Arc<Mutex<Option<Result<u64, String>>>>,
    shielded: Arc<Mutex<Option<Result<u64, String>>>>,
    scanner: Arc<Mutex<Scanner>>,
    info: Arc<Mutex<Option<NodeInfo>>>,
    recent: Arc<Mutex<(u64, Vec<BlockRow>)>>,
    refresh: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl BalanceMonitor {
    pub fn start(
        service: String,
        address: String,
        dfvk: &DiversifiableFullViewingKey,
        cache: Option<std::path::PathBuf>,
        ctx: eframe::egui::Context,
    ) -> Self {
        let service = Arc::new(Mutex::new(service));
        let state = Arc::new(Mutex::new(None));
        let shielded = Arc::new(Mutex::new(None));
        // Pick up where the last run stopped, if its saved scan is still good.
        let scanner = cache
            .as_deref()
            .and_then(|path| scancache::load(path, dfvk))
            .unwrap_or_else(|| Scanner::new(dfvk));
        let scanner = Arc::new(Mutex::new(scanner));
        let dfvk = dfvk.clone();
        let info = Arc::new(Mutex::new(None));
        let recent = Arc::new(Mutex::new((0, Vec::new())));
        let refresh = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (t_service, t_state, t_shielded, t_scanner, t_info, t_recent, t_refresh, t_stop) = (
            service.clone(),
            state.clone(),
            shielded.clone(),
            scanner.clone(),
            info.clone(),
            recent.clone(),
            refresh.clone(),
            stop.clone(),
        );
        std::thread::spawn(move || {
            let mut unsaved = false;
            let mut last_save = std::time::Instant::now();
            while !t_stop.load(Ordering::Relaxed) {
                let service = t_service.lock().expect("service lock").clone();
                let next = balance(&service, &address);
                let next_z = chain::sync(&t_scanner, &service).map(|report| {
                    unsaved |= report.applied > 0 || report.rescanned;
                    t_scanner.lock().expect("scanner lock").balance()
                });
                // Save what was learned, but not more than every few seconds.
                if unsaved && last_save.elapsed() >= Duration::from_secs(3) {
                    if let Some(path) = &cache {
                        let scanner = t_scanner.lock().expect("scanner lock");
                        let _ = scancache::save(path, &dfvk, &scanner);
                    }
                    unsaved = false;
                    last_save = std::time::Instant::now();
                }
                let node_info = status(&service).ok();
                let list = blocks(&service, 25).unwrap_or_default();
                let mut changed = false;
                {
                    let mut current = t_recent.lock().expect("blocks lock");
                    changed |= *current != list;
                    *current = list;
                }
                {
                    let mut current = t_state.lock().expect("balance lock");
                    changed |= current.as_ref() != Some(&next);
                    *current = Some(next);
                }
                {
                    let mut current = t_shielded.lock().expect("balance lock");
                    changed |= current.as_ref() != Some(&next_z);
                    *current = Some(next_z);
                }
                {
                    let mut current = t_info.lock().expect("info lock");
                    changed |= *current != node_info;
                    *current = node_info;
                }
                if changed {
                    ctx.request_repaint();
                }
                // Wait up to three seconds, but wake early for a refresh request or shutdown.
                for _ in 0..30 {
                    if t_stop.load(Ordering::Relaxed) {
                        return;
                    }
                    if t_refresh.swap(false, Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        });
        Self {
            service,
            state,
            shielded,
            scanner,
            info,
            recent,
            refresh,
            stop,
        }
    }

    /// Points the monitor at a different node.
    pub fn set_service(&self, service: String) {
        *self.service.lock().expect("service lock") = service;
        *self.state.lock().expect("balance lock") = None;
        *self.shielded.lock().expect("balance lock") = None;
        self.refresh();
    }

    /// The transparent balance.
    pub fn latest(&self) -> Option<Result<u64, String>> {
        self.state.lock().expect("balance lock").clone()
    }

    /// The wallet's one balance: public and private coins together, in zats.
    ///
    /// `None` while the first reading is still on its way, and an error if either part cannot
    /// be read, because a total that silently leaves out a part would be wrong.
    pub fn total(&self) -> Option<Result<u64, String>> {
        let public = self.latest()?;
        let private = self.latest_shielded()?;
        Some(match (public, private) {
            (Ok(t), Ok(z)) => Ok(t.saturating_add(z)),
            (Err(e), _) => Err(e),
            (_, Err(e)) => Err(format!("could not scan for your private coins: {e}")),
        })
    }

    /// The wallet's view of the shielded pool: its notes and their witnesses.
    pub fn scanner(&self) -> Arc<Mutex<Scanner>> {
        self.scanner.clone()
    }

    /// The shielded balance.
    pub fn latest_shielded(&self) -> Option<Result<u64, String>> {
        self.shielded.lock().expect("balance lock").clone()
    }

    /// The total block count and the newest blocks, newest first.
    pub fn recent(&self) -> (u64, Vec<BlockRow>) {
        self.recent.lock().expect("blocks lock").clone()
    }

    pub fn info(&self) -> Option<NodeInfo> {
        self.info.lock().expect("info lock").clone()
    }

    /// Asks for a fresh reading soon, for example right after a payment.
    pub fn refresh(&self) {
        self.refresh.store(true, Ordering::Relaxed);
    }
}

impl Drop for BalanceMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;

    /// A one-shot fake service that answers the first line with `reply`.
    fn fake(reply: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            writeln!(stream, "{reply}").unwrap();
            let _ = stream.read(&mut [0u8; 1]);
        });
        addr
    }

    #[test]
    fn parses_balance_and_errors() {
        assert_eq!(balance(&fake("OK 123456 2"), "tvX"), Ok(123_456));
        assert_eq!(
            balance(&fake("ERR bad address"), "tvX"),
            Err("bad address".to_owned())
        );
        assert!(balance(&fake("garbage"), "tvX").is_err());
    }

    #[test]
    fn parses_status() {
        assert_eq!(
            status(&fake("OK 20 22 20 0 1")),
            Ok(NodeInfo {
                accepted: 20,
                dag: 22,
                utxos: 20,
                mempool: 0,
                peers: 1
            })
        );
        assert!(status(&fake("OK 1 2")).is_err());
    }

    #[test]
    fn parses_block_lists_and_details() {
        let (total, rows) = blocks(&fake("OK 7 6,aa,1000,2,3,5000;5,bb,900,1,0,0"), 2).unwrap();
        assert_eq!(total, 7);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].hash, "aa");
        assert_eq!((rows[0].txs, rows[0].reward), (3, 5000));
        assert_eq!(blocks(&fake("OK 1 "), 1).unwrap().1, Vec::new());
        assert!(blocks(&fake("OK 1 x,y"), 1).is_err());

        let d = block(
            &fake("OK 4 1000 33 9 p1,p2 50 tvA:60,tvB:70 t1:t-t,t2:z-z"),
            "h",
        )
        .unwrap();
        assert_eq!((d.index, d.nonce, d.pol), (4, 9, 50));
        assert_eq!(d.parents, ["p1", "p2"]);
        assert_eq!(d.payouts, [("tvA".to_owned(), 60), ("tvB".to_owned(), 70)]);
        assert_eq!(
            d.txs,
            [
                ("t1".to_owned(), "t-t".to_owned()),
                ("t2".to_owned(), "z-z".to_owned())
            ]
        );
        let empty = block(&fake("OK 0 1 2 3 - 0 - -"), "h").unwrap();
        assert!(empty.parents.is_empty() && empty.payouts.is_empty() && empty.txs.is_empty());
    }

    #[test]
    fn parses_transactions() {
        let t = tx(
            &fake("OK bb z-t 20000 0 tvA:2500000000 1 2520000000 hidden"),
            "aa",
        )
        .unwrap();
        assert_eq!((t.kind.as_str(), t.fee, t.nullifiers), ("z-t", 20_000, 1));
        assert_eq!(t.outputs, [("tvA".to_owned(), 2_500_000_000)]);
        assert_eq!(t.pool_out, 2_520_000_000);
        assert_eq!(t.notes, ["hidden"]);
        let shielding = tx(&fake("OK bb t-z 20000 1 - 0 -100 hidden,hidden"), "aa").unwrap();
        assert_eq!(shielding.pool_out, -100);
        assert_eq!(shielding.notes.len(), 2);
    }

    #[test]
    fn an_unreachable_service_is_an_error_not_a_hang() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        assert!(balance(&addr, "tvX").is_err());
    }
}
