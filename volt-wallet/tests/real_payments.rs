//! End to end with real transactions: a real `volt-node` (with proof and signature checking on)
//! and the wallet's own scanner and transaction builder, paying in all four directions.
//!
//! These tests need the node built with `--features zebra-proofs`:
//! `cargo build --release -p volt-node --features zebra-proofs` in the repository root.
//! Without that binary they say so and pass, so a plain `cargo test` still works.

use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

use voltcash_core::{
    chain::{self, Scanner},
    keys, pay, rpc,
};
use zcash_keys::keys::UnifiedSpendingKey;

const VOLT: u64 = 100_000_000;

const PHRASE_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const PHRASE_C: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
const PHRASE_B: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";

fn node_exe() -> Option<PathBuf> {
    let exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join("release")
        .join(if cfg!(windows) {
            "volt-node.exe"
        } else {
            "volt-node"
        });
    exe.is_file().then_some(exe)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Node {
    child: Child,
    rpc: String,
    peer: String,
    _dir: tempfile::TempDir,
}

impl Node {
    /// Starts a real-transaction node that pays its mining rewards to `payout`.
    fn start(exe: &PathBuf, payout: &str, seed: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (peer, rpc) = (
            format!("127.0.0.1:{}", free_port()),
            format!("127.0.0.1:{}", free_port()),
        );
        let log = std::fs::File::create(dir.path().join("node.log")).unwrap();
        let mut command = Command::new(exe);
        command
            .args(["run", "--data-dir"])
            .arg(dir.path().join("chain"))
            .args(["--listen", &peer, "--rpc", &rpc])
            .args([
                "--real-txs",
                "--easy-pow",
                "--economics",
                "faucet",
                "--maturity",
                "3",
            ])
            .args(["--payout", payout])
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        if let Some(seed) = seed {
            command.args(["--seed", seed]);
        }
        let child = command.spawn().expect("the node starts");
        let node = Self {
            child,
            rpc,
            peer,
            _dir: dir,
        };
        let started = Instant::now();
        while rpc::status(&node.rpc).is_err() {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "the node did not come up: {}",
                std::fs::read_to_string(node._dir.path().join("node.log")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        node
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Wallet {
    usk: UnifiedSpendingKey,
    scanner: Mutex<Scanner>,
    addresses: keys::Addresses,
}

impl Wallet {
    fn new(phrase: &str) -> Self {
        let usk = keys::spending_key(phrase).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();
        let addresses = keys::addresses(&ufvk).unwrap();
        let scanner = Mutex::new(Scanner::new(ufvk.sapling().expect("a Sapling component")));
        Self {
            usk,
            scanner,
            addresses,
        }
    }

    fn sync(&mut self, service: &str) {
        chain::sync(&self.scanner, service).expect("the wallet syncs");
    }

    fn transparent(&self, service: &str) -> u64 {
        rpc::balance(service, &self.addresses.transparent).unwrap()
    }

    /// The wallet's one balance: public and private together.
    fn balance(&self, service: &str) -> u64 {
        self.transparent(service) + self.scanner.lock().unwrap().balance()
    }

    fn private(&self) -> u64 {
        self.scanner.lock().unwrap().balance()
    }

    /// Builds a payment, hands it to the node and mines it. The wallet chooses what to spend.
    fn pay(&mut self, service: &str, to: &str, zats: u64, memo: &str) -> String {
        self.sync(service);
        let utxos = rpc::utxos(service, &self.addresses.transparent).unwrap();
        let built = pay::build(
            &self.usk,
            &self.scanner.lock().unwrap(),
            &utxos,
            &pay::Payment {
                to: to.to_owned(),
                zats,
                memo: memo.to_owned(),
            },
        )
        .unwrap_or_else(|e| panic!("paying {zats}: {e}"));
        let txid = rpc::send_raw(service, &built.raw)
            .unwrap_or_else(|e| panic!("the node refused the transaction: {e}"));
        // Confirming blocks must not pay the sender, or its balance would not fall.
        rpc::mine(
            service,
            2,
            Some(&voltcash_core::network::dev_sink_address()),
        )
        .unwrap();
        self.sync(service);
        txid
    }
}

/// Mines blocks that pay nobody, so earlier rewards land and become spendable.
fn settle(service: &str, blocks: u32) {
    rpc::mine(
        service,
        blocks,
        Some(&voltcash_core::network::dev_sink_address()),
    )
    .unwrap();
}

#[test]
fn one_balance_pays_any_address_and_the_wallet_picks_what_to_spend() {
    let Some(exe) = node_exe() else {
        eprintln!("skipped: build volt-node with --features zebra-proofs first");
        return;
    };
    let mut a = Wallet::new(PHRASE_A);
    let mut b = Wallet::new(PHRASE_B);
    let mut c = Wallet::new(PHRASE_C);
    assert_ne!(a.addresses.shielded, b.addresses.shielded);

    let node = Node::start(&exe, &a.addresses.transparent, None);
    let service = node.rpc.clone();

    // Fund A (public coins) and C (a second miner, also public coins).
    rpc::mine(&service, 8, None).unwrap();
    rpc::mine(&service, 3, Some(&c.addresses.transparent)).unwrap();
    settle(&service, 6);
    assert!(a.balance(&service) >= 100 * VOLT);
    assert_eq!(b.balance(&service), 0);

    // 1. A pays its own private address: only public coins exist, so this shields them.
    //    The balance is one number, and moving money between its parts costs only the fee.
    a.sync(&service);
    let total_before = a.balance(&service);
    let to_self = a.addresses.shielded.clone();
    let first = a.pay(&service, &to_self, 100 * VOLT, "");
    assert_eq!(
        a.private(),
        100 * VOLT,
        "the 100 VOLT arrived as a private note"
    );
    assert_eq!(
        a.balance(&service),
        total_before - 20_000,
        "the one balance fell by the fee and nothing else"
    );

    // 2. A pays B privately. A has a private note, so it is spent first.
    let to_b = b.addresses.shielded.clone();
    let second = a.pay(&service, &to_b, 40 * VOLT, "hello from A");
    b.sync(&service);
    assert_eq!(b.private(), 40 * VOLT, "B received the private payment");
    assert_eq!(
        b.scanner.lock().unwrap().unspent()[0]
            .memo_text()
            .as_deref(),
        Some("hello from A")
    );
    assert_eq!(
        a.private(),
        60 * VOLT - 20_000,
        "A keeps the change, privately"
    );

    // 3. B pays a public address. B has only a private note, so it is spent.
    let to_b_public = b.addresses.transparent.clone();
    let third = b.pay(&service, &to_b_public, 25 * VOLT, "");
    assert_eq!(b.transparent(&service), 25 * VOLT);
    assert_eq!(
        b.private(),
        15 * VOLT - 20_000,
        "B's change came back private"
    );

    // 4. B pays C privately an amount bigger than its private part, so the wallet has to use
    //    both its private note and its public coins in one payment.
    let to_c = c.addresses.shielded.clone();
    let b_total = b.balance(&service);
    let fourth = b.pay(&service, &to_c, 30 * VOLT, "");
    c.sync(&service);
    assert_eq!(c.private(), 30 * VOLT);
    assert_eq!(
        b.balance(&service),
        b_total - 30 * VOLT - 20_000,
        "B's one balance fell by the payment and the fee"
    );

    // 5. C pays a public address. C also has a private note now (the 30), so use a fresh
    //    wallet D that holds only public coins to see a purely public payment.
    let d = Wallet::new(
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
    );
    let mut d = d;
    rpc::mine(&service, 3, Some(&d.addresses.transparent)).unwrap();
    settle(&service, 6);
    let a_public = a.addresses.transparent.clone();
    let d_before = d.balance(&service);
    let fifth = d.pay(&service, &a_public, VOLT, "");
    assert_eq!(
        d.balance(&service),
        d_before - VOLT - 10_000,
        "a purely public payment costs the lower fee"
    );

    // A saved scan restores to exactly the same wallet, picks up with nothing to redo, and its
    // witnesses still spend: the node accepts a payment built from the restored scanner.
    {
        // Catch up with the blocks mined for the other wallets first, then save.
        b.sync(&service);
        let dfvk = b
            .usk
            .to_unified_full_viewing_key()
            .sapling()
            .unwrap()
            .clone();
        let saved = b.scanner.lock().unwrap().to_bytes();
        let restored = Scanner::from_bytes(&dfvk, &saved).expect("the saved scan loads");
        assert_eq!(restored.balance(), b.private());
        assert_eq!(restored.root(), b.scanner.lock().unwrap().root());
        assert_eq!(restored.next_step(), b.scanner.lock().unwrap().next_step());
        assert!(
            Scanner::from_bytes(&dfvk, &saved[..saved.len() - 1]).is_err(),
            "a cut-off save is refused"
        );
        let other = c
            .usk
            .to_unified_full_viewing_key()
            .sapling()
            .unwrap()
            .clone();
        let strangers = Scanner::from_bytes(&other, &saved);
        assert!(
            b.private() == 0 || strangers.is_err(),
            "another account cannot restore this wallet's notes"
        );

        b.scanner = Mutex::new(restored);
        let report = chain::sync(&b.scanner, &service).unwrap();
        assert_eq!(report.applied, 0, "nothing new to scan after the restore");
        assert!(!report.rescanned);
        let a_public = a.addresses.transparent.clone();
        let before = b.balance(&service);
        b.pay(&service, &a_public, VOLT, "");
        assert_eq!(b.balance(&service), before - VOLT - 20_000);
    }

    // The explorer sees what each one was.
    for (txid, kind) in [
        (&first, "t-z"),
        (&second, "z-z"),
        (&third, "z-t"),
        (&fourth, "mixed"),
        (&fifth, "t-t"),
    ] {
        let tx = rpc::tx(&service, txid).unwrap();
        assert_eq!(tx.kind, kind, "{txid}");
    }

    // The whole feed can be rescanned from nothing to the same answer.
    let mut fresh = Wallet::new(PHRASE_B);
    fresh.sync(&service);
    assert_eq!(fresh.private(), b.private());
    assert_eq!(
        fresh.scanner.lock().unwrap().root(),
        b.scanner.lock().unwrap().root()
    );
}

#[test]
fn a_second_node_follows_and_the_wallet_reads_either() {
    let Some(exe) = node_exe() else {
        eprintln!("skipped: build volt-node with --features zebra-proofs first");
        return;
    };
    let mut a = Wallet::new(PHRASE_A);
    let mut b = Wallet::new(PHRASE_B);
    let first = Node::start(&exe, &a.addresses.transparent, None);
    let other_miner = volt_params::transparent::encode_p2pkh(&[9; 20]);
    let second = Node::start(&exe, &other_miner, Some(&first.peer));

    rpc::mine(&first.rpc, 8, None).unwrap();
    a.pay(&first.rpc, &a.addresses.shielded.clone(), 50 * VOLT, "");
    a.pay(
        &first.rpc,
        &b.addresses.shielded.clone(),
        10 * VOLT,
        "over two nodes",
    );

    // Wait for the second node to catch up, then read B's note from it.
    let started = Instant::now();
    loop {
        b.sync(&second.rpc);
        if b.scanner.lock().unwrap().balance() == 10 * VOLT {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the second node never showed B's payment"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    let a_seen_by_first = {
        a.sync(&first.rpc);
        a.scanner.lock().unwrap().root()
    };
    a.sync(&second.rpc);
    assert_eq!(a.scanner.lock().unwrap().root(), a_seen_by_first);
}

#[test]
fn forged_and_repeated_transactions_are_refused_by_the_node() {
    let Some(exe) = node_exe() else {
        eprintln!("skipped: build volt-node with --features zebra-proofs first");
        return;
    };
    let mut a = Wallet::new(PHRASE_A);
    let b = Wallet::new(PHRASE_B);
    let node = Node::start(&exe, &a.addresses.transparent, None);
    let service = node.rpc.clone();
    rpc::mine(&service, 8, None).unwrap();
    a.pay(&service, &a.addresses.shielded.clone(), 100 * VOLT, "");
    a.sync(&service);

    let build = |a: &Wallet, zats: u64| {
        let utxos = rpc::utxos(&service, &a.addresses.transparent).unwrap();
        pay::build(
            &a.usk,
            &a.scanner.lock().unwrap(),
            &utxos,
            &pay::Payment {
                to: b.addresses.shielded.clone(),
                zats,
                memo: String::new(),
            },
        )
        .unwrap()
    };

    // A transaction with one flipped byte (inside the proofs and signatures) is refused.
    let good = build(&a, 10 * VOLT);
    let mut forged = good.raw.clone();
    let middle = forged.len() / 2;
    forged[middle] ^= 0x01;
    assert!(
        rpc::send_raw(&service, &forged).is_err(),
        "a damaged transaction must not be accepted"
    );
    assert_eq!(
        rpc::status(&service).unwrap().mempool,
        0,
        "nothing forged reached the mempool"
    );

    // The genuine one goes through and is mined.
    rpc::send_raw(&service, &good.raw).unwrap();
    rpc::mine(
        &service,
        2,
        Some(&voltcash_core::network::dev_sink_address()),
    )
    .unwrap();

    // Spending the same note again is refused. The wallet has not re-scanned, so it still
    // believes the note is unspent and builds a second spend of it.
    let again = build(&a, 20 * VOLT);
    let refused = rpc::send_raw(&service, &again.raw);
    assert!(
        refused.is_err(),
        "a second spend of the same note must be refused, got {refused:?}"
    );
    // After a rescan the wallet knows better and spends the change instead.
    a.sync(&service);
    let change = a.scanner.lock().unwrap().balance();
    assert!(change < 90 * VOLT && change > 89 * VOLT, "{change}");
}
