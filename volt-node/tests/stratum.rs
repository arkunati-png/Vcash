//! The stratum server, driven the way XMRig drives it: log in with an address, get a job, search
//! 4-byte nonces at the blob's nonce offset, submit a share, receive a fresh job.

use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

use serde_json::{json, Value};
use volt_core::{Economics, POW_BLOB_LEN, POW_NONCE_OFFSET};
use volt_crypto::{PowHasher, RandomXEngine};
use volt_node::{
    node::{Node, NodeConfig},
    stratum,
};
use zebra_chain::{parameters::NetworkKind, transparent::Address};

const MINER: [u8; 20] = [0x42; 20];

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Client {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl Client {
    fn connect(addr: std::net::SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        Self { stream, reader }
    }

    fn call(&mut self, request: Value) -> Value {
        writeln!(self.stream, "{request}").unwrap();
        self.read()
    }

    fn read(&mut self) -> Value {
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("a reply in time");
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON: {line:?}"))
    }
}

/// What an XMRig thread does: try nonces until the top 64 bits of the hash are under the target.
fn search(job: &Value, hasher: &dyn PowHasher, skip_solutions: bool) -> [u8; 4] {
    let blob = unhex(job["blob"].as_str().unwrap());
    assert_eq!(blob.len(), POW_BLOB_LEN);
    let seed: [u8; 32] = unhex(job["seed_hash"].as_str().unwrap())
        .try_into()
        .unwrap();
    let target = u64::from_le_bytes(unhex(job["target"].as_str().unwrap()).try_into().unwrap());
    assert_eq!(job["algo"], "rx/0");
    for nonce in 0u32.. {
        let mut candidate = blob.clone();
        candidate[POW_NONCE_OFFSET..POW_NONCE_OFFSET + 4].copy_from_slice(&nonce.to_le_bytes());
        let hash = hasher.pow_hash(&seed, &candidate).unwrap();
        let value = u64::from_le_bytes(hash[24..32].try_into().unwrap());
        if (value < target) != skip_solutions {
            return nonce.to_le_bytes();
        }
    }
    unreachable!()
}

async fn drive(pow: Arc<dyn PowHasher>) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::devnet(
        dir.path().to_path_buf(),
        pow.clone(),
        vec![Address::from_pub_key_hash(NetworkKind::Regtest, [1; 20])],
    )
    .with_easy_pow();
    config.economics = Economics::faucet();
    let node = Arc::new(Node::start(config).await.unwrap());
    let addr = stratum::start(node.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();

    let miner_address = volt_params::transparent::encode_p2pkh(&MINER);
    let node2 = node.clone();
    let hasher = pow;
    tokio::task::spawn_blocking(move || {
        let mut client = Client::connect(addr);

        // A login that is not a Voltcash address is refused.
        let refused = client.call(json!({
            "id": 1, "jsonrpc": "2.0", "method": "login",
            "params": {"login": "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs", "pass": "x", "agent": "XMRig/6", "algo": ["rx/0"]}
        }));
        assert!(refused["error"]["message"].as_str().unwrap().contains("tv..."), "{refused}");

        // A real login gets a session and a job.
        let login = client.call(json!({
            "id": 2, "jsonrpc": "2.0", "method": "login",
            "params": {"login": miner_address, "pass": "x", "agent": "XMRig/6", "algo": ["rx/0"]}
        }));
        assert_eq!(login["result"]["status"], "OK", "{login}");
        let session = login["result"]["id"].as_str().unwrap().to_owned();
        let job = login["result"]["job"].clone();

        // A nonce that does not solve the block is a low-difficulty share.
        let bad = search(&job, &*hasher, true);
        let low = client.call(json!({
            "id": 3, "jsonrpc": "2.0", "method": "submit",
            "params": {"id": session, "job_id": job["job_id"], "nonce": hex(&bad), "result": hex(&[0; 32])}
        }));
        assert_eq!(low["error"]["message"], "Low difficulty share", "{low}");
        // An unknown job id is refused.
        let stale = client.call(json!({
            "id": 4, "jsonrpc": "2.0", "method": "submit",
            "params": {"id": session, "job_id": "nope", "nonce": "00000000", "result": hex(&[0; 32])}
        }));
        assert_eq!(stale["error"]["message"], "Invalid job id");

        // The real thing: find a nonce, submit it, and the node has a new block.
        let before = node2.status().dag_blocks;
        let good = search(&job, &*hasher, false);
        let accepted = client.call(json!({
            "id": 5, "jsonrpc": "2.0", "method": "submit",
            "params": {"id": session, "job_id": job["job_id"], "nonce": hex(&good), "result": hex(&[0; 32])}
        }));
        assert_eq!(accepted["result"]["status"], "OK", "{accepted}");
        assert_eq!(node2.status().dag_blocks, before + 1);

        // The reward goes to the miner's address.
        let (_, newest) = node2.recent_blocks(1);
        let paid: Vec<_> = newest[0].1.coinbase.payouts.iter().map(|p| p.address.hash_bytes()).collect();
        assert_eq!(paid, [MINER]);

        // The tip moved, so the node pushes a new job.
        let pushed = client.read();
        assert_eq!(pushed["method"], "job", "{pushed}");
        assert_ne!(pushed["params"]["job_id"], job["job_id"]);
        assert_ne!(pushed["params"]["blob"], job["blob"]);

        // A second miner gets its own extra nonce, so they never search the same space.
        let mut other = Client::connect(addr);
        let second = other.call(json!({
            "id": 1, "jsonrpc": "2.0", "method": "login",
            "params": {"login": miner_address, "pass": "x", "agent": "XMRig/6", "algo": ["rx/0"]}
        }));
        let (a, b) = (job["blob"].as_str().unwrap(), second["result"]["job"]["blob"].as_str().unwrap());
        assert_ne!(&a[64..72], &b[64..72], "different extra nonces");

        // Keepalive is answered.
        let alive = client.call(json!({"id": 9, "jsonrpc": "2.0", "method": "keepalived", "params": {"id": session}}));
        assert_eq!(alive["result"]["status"], "KEEPALIVED");
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stratum_miner_logs_in_finds_a_block_and_gets_the_next_job() {
    drive(RandomXEngine::shared()).await;
}
