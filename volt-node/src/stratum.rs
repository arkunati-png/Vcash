//! A Monero-style stratum server, so XMRig and other standard RandomX miners can mine Voltcash.
//!
//! The protocol is line-delimited JSON-RPC over TCP:
//!
//! - the miner sends `login` with its Voltcash `tv...` address as the login name; the node
//!   answers with the first job. The block reward is paid to that address;
//! - the node pushes a new `job` whenever the best tip changes;
//! - the miner sends `submit` with the job id and the 4-byte nonce it found.
//!
//! A job's blob is the proof-of-work blob of the block template (see
//! [`volt_core::VoltHeader::pow_blob`]): the 4-byte nonce goes at offset 39, exactly where XMRig
//! writes it, and each connection gets its own 4-byte extra nonce in the bytes before it, so two
//! miners never search the same space. The job's target is the block target, so this is solo
//! mining: a miner only reports a share when it has found a block.
//!
//! The server verifies every submitted nonce itself and ignores the miner's claimed hash.
//! Whether it is reachable from outside this computer is decided by the address it listens on.

use std::{
    collections::{HashMap, VecDeque},
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tracing::{info, warn};
use volt_core::{pow_blob_for, VoltBlock, VoltHash, POW_NONCE_OFFSET};
use volt_crypto::{meets_target, target_top64};
use zebra_chain::{parameters::NetworkKind, transparent::Address};

use crate::node::Node;

/// The most miners connected at once.
const MAX_SESSIONS: usize = 256;
/// The longest request line accepted, in bytes.
const MAX_LINE: u64 = 8 * 1024;
/// How many recent jobs a miner may still submit against.
const JOBS_KEPT: usize = 8;
/// A fresh job at least this often, so block timestamps and mempool contents do not go stale.
const REFRESH: Duration = Duration::from_secs(30);

struct Job {
    block: VoltBlock,
    seed: [u8; 32],
    commitment: [u8; 32],
}

struct Session {
    id: String,
    extra_nonce: u32,
    miners: Vec<Address>,
    jobs: HashMap<String, Job>,
    order: VecDeque<String>,
    last_sink: VoltHash,
    last_job_at: Instant,
}

static SESSIONS: AtomicU32 = AtomicU32::new(0);
static NEXT_EXTRA_NONCE: AtomicU32 = AtomicU32::new(1);
static NEXT_JOB: AtomicU64 = AtomicU64::new(1);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Builds a job for this session from a fresh template, and remembers it.
fn new_job(node: &Node, session: &mut Session) -> Result<Value> {
    let (block, seed) = node.mining_template(&session.miners)?;
    let commitment = block.header.pow_commitment();
    let blob = pow_blob_for(&commitment, u64::from(session.extra_nonce) << 32);
    let target = target_top64(block.header.bits).context("the template has an invalid target")?;
    let job_id = format!("{:x}", NEXT_JOB.fetch_add(1, Ordering::Relaxed));

    session.last_sink = node.status().sink;
    session.last_job_at = Instant::now();
    session.order.push_back(job_id.clone());
    while session.order.len() > JOBS_KEPT {
        if let Some(old) = session.order.pop_front() {
            session.jobs.remove(&old);
        }
    }
    let height = node.status().accepted_blocks;
    session.jobs.insert(
        job_id.clone(),
        Job {
            block,
            seed,
            commitment,
        },
    );
    Ok(json!({
        "blob": hex(&blob),
        "job_id": job_id,
        // The top 64 bits of the target, little-endian: XMRig reports a share when the top 64
        // bits of its hash are below this.
        "target": hex(&target.to_le_bytes()),
        "algo": "rx/0",
        "seed_hash": hex(&seed),
        "height": height,
    }))
}

fn send(stream: &Mutex<TcpStream>, value: &Value) -> bool {
    let mut stream = stream.lock().expect("stratum writer");
    writeln!(stream, "{value}").is_ok()
}

fn error(id: &Value, message: &str) -> Value {
    json!({"id": id, "jsonrpc": "2.0", "error": {"code": -1, "message": message}, "result": null})
}

fn ok(id: &Value, result: Value) -> Value {
    json!({"id": id, "jsonrpc": "2.0", "error": null, "result": result})
}

/// Checks a submitted nonce and, if it solves the block, hands the block to the node.
fn submit(node: &Node, session: &Session, params: &Value) -> Result<(), String> {
    let job_id = params["job_id"].as_str().ok_or("missing job_id")?;
    let job = session.jobs.get(job_id).ok_or("Invalid job id")?;
    let nonce: [u8; 4] = unhex(params["nonce"].as_str().ok_or("missing nonce")?)
        .and_then(|b| b.try_into().ok())
        .ok_or("the nonce must be 4 bytes of hex")?;
    let full = (u64::from(session.extra_nonce) << 32) | u64::from(u32::from_le_bytes(nonce));

    let blob = pow_blob_for(&job.commitment, full);
    debug_assert_eq!(
        blob[POW_NONCE_OFFSET..POW_NONCE_OFFSET + 4],
        nonce,
        "the miner's nonce lands where XMRig writes it"
    );
    let hash = node
        .pow()
        .pow_hash(&job.seed, &blob)
        .map_err(|e| format!("could not hash: {e}"))?;
    if !meets_target(&hash, job.block.header.bits) {
        return Err("Low difficulty share".to_owned());
    }
    let mut block = job.block.clone();
    block.header.nonce = full;
    let hash = node
        .submit_found_block(block)
        .map_err(|e| format!("Block rejected: {e}"))?;
    info!(%hash, "a stratum miner found a block");
    Ok(())
}

fn serve(node: Arc<Node>, stream: TcpStream) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let writer = Arc::new(Mutex::new(stream));
    let session: Arc<Mutex<Option<Session>>> = Arc::new(Mutex::new(None));
    let closed = Arc::new(AtomicBool::new(false));

    // Pushes a new job when the chain moves on, and now and then anyway.
    {
        let (node, writer, session, closed) = (
            node.clone(),
            writer.clone(),
            session.clone(),
            closed.clone(),
        );
        thread::spawn(move || {
            while !closed.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(300));
                let mut guard = session.lock().expect("stratum session");
                let Some(s) = guard.as_mut() else { continue };
                if node.status().sink == s.last_sink && s.last_job_at.elapsed() < REFRESH {
                    continue;
                }
                match new_job(&node, s) {
                    Ok(job) => {
                        drop(guard);
                        if !send(
                            &writer,
                            &json!({"jsonrpc": "2.0", "method": "job", "params": job}),
                        ) {
                            return;
                        }
                    }
                    Err(e) => warn!(%e, "could not build a stratum job"),
                }
            }
        });
    }

    let mut lines = BufReader::new(read_half.take(MAX_LINE));
    loop {
        let mut line = String::new();
        // Each request gets a fresh allowance, so one huge line cannot be sent in pieces.
        lines.get_mut().set_limit(MAX_LINE);
        match lines.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let Ok(request) = serde_json::from_str::<Value>(line.trim()) else {
            break;
        };
        let id = request["id"].clone();
        let params = &request["params"];
        let reply = match request["method"].as_str() {
            Some("login") => {
                let login = params["login"].as_str().unwrap_or_default().trim();
                match volt_params::transparent::decode_p2pkh(login) {
                    Err(_) => error(&id, "login must be a Voltcash tv... address"),
                    Ok(hash) => {
                        let mut guard = session.lock().expect("stratum session");
                        let mut s = Session {
                            id: format!("{:x}", rand_id()),
                            extra_nonce: NEXT_EXTRA_NONCE.fetch_add(1, Ordering::Relaxed),
                            miners: vec![Address::from_pub_key_hash(NetworkKind::Regtest, hash)],
                            jobs: HashMap::new(),
                            order: VecDeque::new(),
                            last_sink: VoltHash::ZERO,
                            last_job_at: Instant::now(),
                        };
                        match new_job(&node, &mut s) {
                            Ok(job) => {
                                let reply =
                                    ok(&id, json!({"id": s.id, "status": "OK", "job": job}));
                                *guard = Some(s);
                                reply
                            }
                            Err(e) => error(&id, &format!("no work available: {e}")),
                        }
                    }
                }
            }
            Some("submit") => {
                let guard = session.lock().expect("stratum session");
                match guard.as_ref() {
                    None => error(&id, "Unauthenticated"),
                    Some(s) if params["id"].as_str() != Some(&s.id) => {
                        error(&id, "Unauthenticated")
                    }
                    Some(s) => match submit(&node, s, params) {
                        Ok(()) => ok(&id, json!({"status": "OK"})),
                        Err(message) => error(&id, &message),
                    },
                }
            }
            Some("keepalived") => ok(&id, json!({"status": "KEEPALIVED"})),
            _ => error(&id, "Unknown method"),
        };
        if !send(&writer, &reply) {
            break;
        }
    }
    closed.store(true, Ordering::Relaxed);
    SESSIONS.fetch_sub(1, Ordering::Relaxed);
}

fn rand_id() -> u64 {
    NEXT_JOB.fetch_add(1, Ordering::Relaxed) ^ 0x5eed_0000_0000
}

/// Starts the stratum server. Returns the address it is listening on.
pub fn start(node: Arc<Node>, addr: SocketAddr) -> Result<SocketAddr> {
    let listener = TcpListener::bind(addr).with_context(|| format!("cannot listen on {addr}"))?;
    let bound = listener.local_addr()?;
    info!(addr = %bound, "stratum server listening: point XMRig at this address, login = your tv... address");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            if SESSIONS.fetch_add(1, Ordering::Relaxed) as usize >= MAX_SESSIONS {
                SESSIONS.fetch_sub(1, Ordering::Relaxed);
                continue;
            }
            let node = node.clone();
            thread::spawn(move || serve(node, stream));
        }
    });
    Ok(bound)
}
