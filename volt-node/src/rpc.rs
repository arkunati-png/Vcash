//! A tiny wallet service for the proof-less devnet.
//!
//! One command per line over loopback TCP:
//!
//! - `BALANCE <t-address>` answers `OK <zatoshis> <outputs>`;
//! - `BALANCEZ <z-address>` answers `OK <zatoshis> <notes>`;
//! - `SEND <from-t> <to-t> <zatoshis>` (t-t), `SHIELD <from-t> <to-z> <zatoshis>` (t-z),
//!   `ZSEND <from-z> <to-z> <zatoshis>` (z-z) and `UNSHIELD <from-z> <to-t> <zatoshis>` (z-t)
//!   answer `OK <txid>` or `ERR <reason>`;
//! - `STATUS` answers `OK <accepted blocks> <dag blocks> <utxos> <mempool> <peers>`;
//! - `BLOCKS <n>` answers `OK <total> <block>;<block>;...`, newest first, where a block is
//!   `index,hash,timestamp_ms,parents,transactions,reward_zats`;
//! - `BLOCK <hash>` answers `OK <index> <timestamp_ms> <bits> <nonce> <parents> <pol_zats>
//!   <payouts> <transactions>`, with comma lists (`address:zats`, `txid:kind`, `-` when empty);
//! - `TX <txid>` answers `OK <block> <kind> <fee> <inputs> <outputs> <nullifiers> <pool_out>
//!   <notes>`;
//! - `STEPS <from> <max>` answers `OK <total> <step>;<step>;...` where a step is
//!   `index,chain_block,sapling_root,sapling_notes,<tx>|<tx>|...` (`-` when it has no shielded
//!   transactions) and a tx is `txid/nullifiers/commitments/outputs`, each list joined with `+`, all in hex, where an
//!   output is `ephemeral_key:encrypted_note` aligned with the commitments (`-` for devnet
//!   transactions). This is
//!   what a light wallet scans;
//! - `UTXOS <t-address>` answers `OK <next_height> <maturity> <txid>:<index>:<zats>:<spendable>;...`;
//! - `SENDRAW <hex>` submits a signed transaction and answers `OK <txid>`;
//! - `MINE <n> [address]` mines `n` blocks on this node (devnet convenience), paying the reward
//!   to `address` when given and to the node's own addresses otherwise, and answers `OK <n>`;
//! - `POOL` answers `OK <sapling pool zats> <nullifiers>`.
//!
//! The payment-building commands are devnet only, and **not private**. A node started with
//! `--real-txs` answers only the commands that read the chain, `SENDRAW` and `MINE`.
//!
//! Devnet payments: Devnet transactions carry no signatures and no
//! zero-knowledge proofs, so this service builds each payment for the wallet and mines it
//! straight away. The node's shielded accounting is real (note commitment tree, anchors,
//! nullifiers and the per-pool turnstile all run on these transactions), but a "note" here is a
//! commitment that spells out its owner and value in the clear. A real network needs the wallet
//! to scan, sign and prove on its own, and this does none of that.
//!
//! A shielded address is not decoded here. Its owner id is a hash of the address text, which is
//! enough for a devnet to tell whose note is whose.
//!
//! Rollups take ten transactions per batch, so one payment is padded with nine tiny self-spends
//! of the node's own mining rewards (never the outputs the payment itself spends). Those cost a few fees and move nobody else's coins.

use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
};

use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use tracing::{info, warn};
use volt_core::{calculate_tx_fee, BatchableTx, DevTx, VoltBlock, VoltHash};
use zebra_chain::{
    amount::Amount,
    parameters::NetworkKind,
    transparent::{Address, OutPoint, Output, Script},
};

use crate::node::Node;

/// How many blocks a payment may take to be mined before the service gives up.
const MAX_BLOCKS: usize = 8;

fn script_to_address(address: &str) -> Result<Address> {
    let hash = volt_params::transparent::decode_p2pkh(address)
        .map_err(|e| anyhow::anyhow!("{address}: {e}"))?;
    Ok(Address::from_pub_key_hash(NetworkKind::Regtest, hash))
}

fn script_of(address: &str) -> Result<Script> {
    let hash = volt_params::transparent::decode_p2pkh(address)
        .map_err(|e| anyhow::anyhow!("{address}: {e}"))?;
    Ok(Address::from_pub_key_hash(NetworkKind::Regtest, hash).script())
}

/// The address a standard pay-to-public-key-hash script pays, if it is one.
fn address_of(script: &Script) -> Option<String> {
    let bytes = script.as_raw_bytes();
    // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if bytes.len() == 25 && bytes[..3] == [0x76, 0xa9, 0x14] && bytes[23..] == [0x88, 0xac] {
        let hash: [u8; 20] = bytes[3..23].try_into().ok()?;
        Some(volt_params::transparent::encode_p2pkh(&hash))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------------------------
// Devnet notes

/// A shielded address, as far as the devnet can tell: it must at least look like one.
fn check_z(address: &str) -> Result<()> {
    if address.starts_with('z') && address.len() >= 20 && address.is_ascii() {
        Ok(())
    } else {
        bail!("{address} is not a shielded (z) address")
    }
}

/// Identifies a note's owner: the first 20 bytes of a hash of the address text.
fn owner_of(address: &str) -> [u8; 20] {
    let hash = VoltHash::digest(b"VoltDevOwner____", address.as_bytes());
    hash.0[..20].try_into().expect("20 of 32 bytes")
}

/// A note commitment that spells out its value and owner. 8 bytes of value, 20 of owner, 3 of
/// uniqueness and a zero top byte, which keeps it a canonical field element.
fn commitment(owner: &[u8; 20], value: i64, unique: u32) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[..8].copy_from_slice(&value.to_le_bytes());
    c[8..28].copy_from_slice(owner);
    c[28..31].copy_from_slice(&unique.to_le_bytes()[..3]);
    c
}

fn nullifier(commitment: &[u8; 32]) -> [u8; 32] {
    VoltHash::digest(b"VoltDevNullifier", commitment).0
}

/// A note: its commitment and what that spells out.
struct Note {
    commitment: [u8; 32],
    value: i64,
}

/// The unspent notes of one owner.
fn notes_of(node: &Node, owner: &[u8; 20]) -> Vec<Note> {
    node.sapling_commitments()
        .into_iter()
        .filter(|c| c[8..28] == owner[..] && c[31] == 0)
        .map(|c| Note {
            value: i64::from_le_bytes(c[..8].try_into().expect("8 bytes")),
            commitment: c,
        })
        .filter(|note| note.value > 0 && !node.has_nullifier(&nullifier(&note.commitment)))
        .collect()
}

fn unique_nonce() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |d| d.as_nanos() as u64)
}

// ---------------------------------------------------------------------------------------------
// Building and mining payments

/// The fee a transaction of this shape must pay. It depends on the shape, not on the amounts.
fn fee_of(tx: &DevTx) -> i64 {
    calculate_tx_fee(tx).zatoshis()
}

fn output(value: i64, script: &Script) -> Output {
    Output::new(Amount::new(value), script.clone())
}

/// Mines until `done` holds, at most [`MAX_BLOCKS`] blocks.
fn mine_until(node: &Node, mut done: impl FnMut(&Node) -> bool) -> Result<()> {
    for _ in 0..MAX_BLOCKS {
        if done(node) {
            return Ok(());
        }
        node.mine_one(u64::MAX)?;
    }
    if done(node) {
        Ok(())
    } else {
        bail!("the payment was not mined in {MAX_BLOCKS} blocks")
    }
}

/// The unspent total and output count for a transparent address.
pub fn balance(node: &Node, address: &str) -> Result<(i64, usize)> {
    let outputs = node.unspent_for(&script_of(address)?);
    Ok((outputs.iter().map(|(_, v)| v).sum(), outputs.len()))
}

/// The unspent total and note count for a shielded address.
pub fn balance_z(node: &Node, address: &str) -> Result<(i64, usize)> {
    check_z(address)?;
    let notes = notes_of(node, &owner_of(address));
    Ok((notes.iter().map(|n| n.value).sum(), notes.len()))
}

/// Picks the sender's biggest transparent outputs until `enough` holds.
fn pick_utxos(
    node: &Node,
    script: &Script,
    mut enough: impl FnMut(&[OutPoint], i64) -> bool,
) -> (Vec<OutPoint>, i64) {
    let mut owned = node.unspent_for(script);
    owned.sort_by_key(|(_, value)| std::cmp::Reverse(*value));
    let (mut inputs, mut total) = (Vec::new(), 0i64);
    for (outpoint, value) in owned {
        inputs.push(outpoint);
        total += value;
        if enough(&inputs, total) {
            break;
        }
    }
    (inputs, total)
}

/// Picks the owner's biggest notes until `enough` holds.
fn pick_notes(
    node: &Node,
    owner: &[u8; 20],
    mut enough: impl FnMut(&[Note], i64) -> bool,
) -> (Vec<Note>, i64) {
    let mut owned = notes_of(node, owner);
    owned.sort_by_key(|n| std::cmp::Reverse(n.value));
    let (mut picked, mut total) = (Vec::new(), 0i64);
    for note in owned {
        total += note.value;
        picked.push(note);
        if enough(&picked, total) {
            break;
        }
    }
    (picked, total)
}

/// Builds a transaction with an optional change part, and finds the exact fee it must pay.
///
/// `build(change, fee)` returns the transaction with `change` zats returned to the sender, or no
/// change. The fee comes from the transaction's shape, so it is found with a probe first.
fn with_fee(total: i64, spend: i64, build: impl Fn(Option<i64>, i64) -> DevTx) -> Result<DevTx> {
    let fee = fee_of(&build(Some(1), 0));
    let change = total - spend - fee;
    if change < 0 {
        bail!(
            "not enough funds: have {total} zats, need {} (amount plus fee)",
            spend + fee
        );
    }
    let tx = build((change > 0).then_some(change), fee);
    // Dropping the change part makes the transaction smaller. If that moved the fee, redo it.
    let exact = fee_of(&tx);
    if exact == fee {
        return Ok(tx);
    }
    let change = total - spend - exact;
    if change < 0 {
        bail!("not enough funds for the amount plus the fee");
    }
    Ok(build((change > 0).then_some(change), exact))
}

/// Submits `main`, then mines until it is spendable.
fn submit_and_mine(node: &Node, main: DevTx) -> Result<String> {
    let txid = main.txid();
    node.submit_tx(main.to_bytes())
        .map_err(|e| anyhow::anyhow!("the node refused the payment: {e:?}"))?;
    // One block to include the payment, one more so its effects reach the spendable state.
    mine_until(node, |node| node.status().mempool == 0)?;
    node.mine_one(u64::MAX)?;
    Ok(txid.to_string())
}

/// t-t: pays `zats` from a transparent address to another.
pub fn send(node: &Node, from: &str, to: &str, zats: i64) -> Result<String> {
    if zats <= 0 {
        bail!("the amount must be positive");
    }
    let (from_script, to_script) = (script_of(from)?, script_of(to)?);
    let nonce = unique_nonce();
    let build = |inputs: &[OutPoint], change: Option<i64>| {
        let mut outputs = vec![output(zats, &to_script)];
        outputs.extend(change.map(|c| output(c, &from_script)));
        DevTx::new(inputs.to_vec(), outputs, Vec::new(), false, nonce)
    };
    let (inputs, total) = pick_utxos(node, &from_script, |inputs, total| {
        total >= zats + fee_of(&build(inputs, Some(1)))
    });
    let tx = with_fee(total, zats, |change, _| build(&inputs, change))?;
    submit_and_mine(node, tx)
}

/// t-z: moves `zats` from a transparent address into a shielded address.
pub fn shield(node: &Node, from_t: &str, to_z: &str, zats: i64) -> Result<String> {
    if zats <= 0 {
        bail!("the amount must be positive");
    }
    check_z(to_z)?;
    let from_script = script_of(from_t)?;
    let (owner, nonce) = (owner_of(to_z), unique_nonce());
    let note = commitment(&owner, zats, nonce as u32);
    let build = |inputs: &[OutPoint], change: Option<i64>| {
        DevTx::new(
            inputs.to_vec(),
            change
                .map(|c| output(c, &from_script))
                .into_iter()
                .collect(),
            Vec::new(),
            true,
            nonce,
        )
        .with_sapling(-zats, Vec::new(), vec![note])
    };
    let (inputs, total) = pick_utxos(node, &from_script, |inputs, total| {
        total >= zats + fee_of(&build(inputs, Some(1)))
    });
    let tx = with_fee(total, zats, |change, _| build(&inputs, change))?;
    submit_and_mine(node, tx)
}

/// z-z: moves `zats` between shielded addresses.
pub fn zsend(node: &Node, from_z: &str, to_z: &str, zats: i64) -> Result<String> {
    if zats <= 0 {
        bail!("the amount must be positive");
    }
    check_z(from_z)?;
    check_z(to_z)?;
    let (from_owner, to_owner) = (owner_of(from_z), owner_of(to_z));
    let (nonce, anchor) = (unique_nonce(), node.status().sapling_root);
    let build = |notes: &[Note], change: Option<i64>, fee: i64| {
        let mut created = vec![commitment(&to_owner, zats, nonce as u32)];
        created.extend(change.map(|c| commitment(&from_owner, c, (nonce >> 24) as u32)));
        DevTx::new(
            Vec::new(),
            Vec::new(),
            notes.iter().map(|n| nullifier(&n.commitment)).collect(),
            true,
            nonce,
        )
        // Notes in minus notes out is the fee, and that is what leaves the pool.
        .with_sapling(fee, vec![anchor], created)
    };
    let (notes, total) = pick_notes(node, &from_owner, |notes, total| {
        total >= zats + fee_of(&build(notes, Some(1), 0))
    });
    if notes.is_empty() {
        bail!("not enough funds: you have no shielded notes");
    }
    let tx = with_fee(total, zats, |change, fee| build(&notes, change, fee))?;
    submit_and_mine(node, tx)
}

/// z-t: moves `zats` from a shielded address to a transparent one.
pub fn unshield(node: &Node, from_z: &str, to_t: &str, zats: i64) -> Result<String> {
    if zats <= 0 {
        bail!("the amount must be positive");
    }
    check_z(from_z)?;
    let to_script = script_of(to_t)?;
    let from_owner = owner_of(from_z);
    let (nonce, anchor) = (unique_nonce(), node.status().sapling_root);
    let build = |notes: &[Note], change: Option<i64>, fee: i64| {
        let created: Vec<[u8; 32]> = change
            .map(|c| commitment(&from_owner, c, nonce as u32))
            .into_iter()
            .collect();
        DevTx::new(
            Vec::new(),
            vec![output(zats, &to_script)],
            notes.iter().map(|n| nullifier(&n.commitment)).collect(),
            true,
            nonce,
        )
        // What leaves the pool pays the transparent output and the fee.
        .with_sapling(zats + fee, vec![anchor], created)
    };
    let (notes, total) = pick_notes(node, &from_owner, |notes, total| {
        total >= zats + fee_of(&build(notes, Some(1), 0))
    });
    if notes.is_empty() {
        bail!("not enough funds: you have no shielded notes");
    }
    let tx = with_fee(total, zats, |change, fee| build(&notes, change, fee))?;
    submit_and_mine(node, tx)
}

// ---------------------------------------------------------------------------------------------
// Reading the chain

fn tx_count(block: &VoltBlock) -> usize {
    block.batches.iter().map(|b| b.raw_txs().len()).sum()
}

fn reward(block: &VoltBlock) -> i64 {
    block
        .coinbase
        .payouts
        .iter()
        .map(|p| p.amount.zatoshis())
        .sum()
}

/// Which way a transaction moves value: `t-t`, `t-z`, `z-z`, `z-t` or `mixed` (it spent both
/// public coins and private notes).
///
/// It goes by the value balance, not by counting spends: a real shielding transaction carries a
/// dummy spend for padding, so nullifiers alone would misread it.
fn kind_of(tx: &dyn BatchableTx) -> &'static str {
    let t_in = !tx.spent_outpoints().is_empty();
    let t_out = !tx.outputs().is_empty();
    let touches_pool = !tx.nullifiers().is_empty() || !tx.sapling_commitment_bytes().is_empty();
    // Public coins and private notes spent together: neither pure kind describes it.
    if t_in && !tx.nullifiers().is_empty() {
        "mixed"
    } else if tx.shielded_value_out() < 0 {
        "t-z"
    } else if touches_pool && !t_in && t_out {
        "z-t"
    } else if touches_pool && !t_in {
        "z-z"
    } else {
        "t-t"
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The chain steps a light wallet scans, as one text line.
pub fn steps_line(node: &Node, from: usize, max: usize) -> String {
    let dash = |items: Vec<String>| {
        if items.is_empty() {
            "-".to_owned()
        } else {
            items.join("+")
        }
    };
    let (total, steps) = node.chain_steps(from, max);
    let steps: Vec<String> = steps
        .iter()
        .map(|step| {
            let txs: Vec<String> = step
                .txs
                .iter()
                .map(|tx| {
                    format!(
                        "{}/{}/{}/{}",
                        tx.txid,
                        dash(tx.nullifiers.iter().map(|n| hex(n)).collect()),
                        dash(tx.sapling_commitments.iter().map(|c| hex(c)).collect()),
                        dash(
                            tx.sapling_outputs
                                .iter()
                                .map(|o| format!(
                                    "{}:{}",
                                    hex(&o.ephemeral_key),
                                    hex(&o.enc_ciphertext)
                                ))
                                .collect()
                        ),
                    )
                })
                .collect();
            format!(
                "{},{},{},{},{}",
                step.index,
                step.block,
                hex(&step.sapling_root),
                step.sapling_notes,
                if txs.is_empty() {
                    "-".to_owned()
                } else {
                    txs.join("|")
                }
            )
        })
        .collect();
    format!("OK {total} {}", steps.join(";"))
}

fn blocks(node: &Node, count: usize) -> String {
    let (total, recent) = node.recent_blocks(count);
    let rows: Vec<String> = recent
        .iter()
        .map(|(index, block)| {
            format!(
                "{index},{},{},{},{},{}",
                block.hash(),
                block.header.timestamp_ms,
                block.header.parents.len(),
                tx_count(block),
                reward(block)
            )
        })
        .collect();
    format!("OK {total} {}", rows.join(";"))
}

fn parse_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        bail!("not hex");
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).context("not hex"))
        .collect()
}

fn parse_hash(text: &str) -> Result<VoltHash> {
    let bytes = (text.len() == 64)
        .then(|| {
            (0..32)
                .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok())
                .collect::<Option<Vec<u8>>>()
        })
        .flatten()
        .context("a hash is 64 hex characters")?;
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    Ok(VoltHash(raw))
}

fn list(items: Vec<String>) -> String {
    if items.is_empty() {
        "-".to_owned()
    } else {
        items.join(",")
    }
}

fn block(node: &Node, hash: &str) -> Result<String> {
    let (index, block) = node
        .block_with_index(&parse_hash(hash)?)
        .context("no block with that hash")?;
    let parents = list(block.header.parents.iter().map(|p| p.to_string()).collect());
    let payouts = list(
        block
            .coinbase
            .payouts
            .iter()
            .map(|p| {
                format!(
                    "{}:{}",
                    volt_params::transparent::encode_p2pkh(&p.address.hash_bytes()),
                    p.amount.zatoshis()
                )
            })
            .collect(),
    );
    let txs = list(
        block
            .batches
            .iter()
            .flat_map(|b| b.raw_txs())
            .filter_map(|raw| node.decode_tx(raw))
            .map(|tx| format!("{}:{}", tx.txid(), kind_of(tx.as_ref())))
            .collect(),
    );
    Ok(format!(
        "OK {index} {} {} {} {parents} {} {payouts} {txs}",
        block.header.timestamp_ms,
        block.header.bits,
        block.header.nonce,
        block.coinbase.pol_contribution.zatoshis(),
    ))
}

/// What one transaction did, for the explorer.
fn tx_info(node: &Node, txid: &str) -> Result<String> {
    let (block_hash, raw) = node
        .find_tx(&parse_hash(txid)?)
        .context("no transaction with that id")?;
    let tx = node
        .decode_tx(&raw)
        .context("the node cannot decode that transaction")?;
    let outputs = list(
        tx.outputs()
            .iter()
            .map(|o| {
                format!(
                    "{}:{}",
                    address_of(&o.lock_script).unwrap_or_else(|| "script".to_owned()),
                    o.value().zatoshis()
                )
            })
            .collect(),
    );
    // Real notes are encrypted, so all the chain shows is how many were created. A devnet note
    // spells out its value in the clear.
    let devnet = tx.sapling_output_data().is_empty();
    let notes = list(
        tx.sapling_commitment_bytes()
            .iter()
            .map(|c| {
                if devnet {
                    i64::from_le_bytes(c[..8].try_into().expect("8 bytes")).to_string()
                } else {
                    "hidden".to_owned()
                }
            })
            .collect(),
    );
    Ok(format!(
        "OK {block_hash} {} {} {} {outputs} {} {} {notes}",
        kind_of(tx.as_ref()),
        calculate_tx_fee(tx.as_ref()).zatoshis(),
        tx.spent_outpoints().len(),
        tx.nullifiers().len(),
        tx.sapling_value_out(),
    ))
}

fn handle(node: &Node, lock: &Mutex<()>, devnet: bool, line: &str) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let amount = |text: &str| text.parse::<i64>().context("the amount is not a number");
    // The commands that build a payment for the wallet, and read shielded balances from notes
    // that name their owner, only make sense for the proof-less devnet.
    if !devnet
        && matches!(
            parts.first().copied(),
            Some("SEND" | "SHIELD" | "ZSEND" | "UNSHIELD" | "BALANCEZ")
        )
    {
        return "ERR this node checks real transactions: build and sign them in the wallet and use SENDRAW".to_owned();
    }
    let result: Result<String> = match parts.as_slice() {
        ["BALANCE", address] => {
            balance(node, address).map(|(zats, count)| format!("OK {zats} {count}"))
        }
        ["BALANCEZ", address] => {
            balance_z(node, address).map(|(zats, count)| format!("OK {zats} {count}"))
        }
        ["STATUS"] => {
            let s = node.status();
            Ok(format!(
                "OK {} {} {} {} {}",
                s.accepted_blocks, s.dag_blocks, s.utxos, s.mempool, s.peers
            ))
        }
        ["STEPS", from, max] => from
            .parse::<usize>()
            .ok()
            .zip(max.parse::<usize>().ok())
            .map(|(from, max)| steps_line(node, from, max.min(500)))
            .context("STEPS needs two numbers: from and max"),
        ["UTXOS", address] => script_of(address).map(|script| {
            let (next, maturity) = node.spend_context();
            let outputs: Vec<String> = node
                .spendable_for(&script)
                .into_iter()
                .map(|(o, value, spendable)| {
                    format!(
                        "{}:{}:{value}:{}",
                        hex(&o.hash.0),
                        o.index,
                        u8::from(spendable)
                    )
                })
                .collect();
            format!("OK {next} {maturity} {}", outputs.join(";"))
        }),
        ["SENDRAW", raw] => parse_hex(raw)
            .and_then(|bytes| {
                node.submit_tx(bytes)
                    .map_err(|e| anyhow::anyhow!("the node refused the transaction: {e:?}"))
            })
            .map(|txid| format!("OK {txid}")),
        ["MINE", count] | ["MINE", count, _] => {
            let _one_at_a_time = lock.lock();
            let to = match parts.get(2) {
                Some(address) => script_to_address(address).map(|a| vec![a]),
                None => Ok(Vec::new()),
            };
            count
                .parse::<usize>()
                .context("the count is not a number")
                .and_then(|n| {
                    let to = to?;
                    for _ in 0..n.min(500) {
                        node.mine_one_to((!to.is_empty()).then_some(to.as_slice()), u64::MAX)?;
                    }
                    Ok(format!("OK {}", n.min(500)))
                })
        }
        ["POOL"] => {
            let s = node.status();
            Ok(format!("OK {} {}", s.sapling_pool, s.nullifiers))
        }
        ["BLOCKS", count] => count
            .parse::<usize>()
            .context("the count is not a number")
            .map(|n| blocks(node, n.min(100))),
        ["BLOCK", hash] => block(node, hash),
        ["TX", txid] => tx_info(node, txid),
        [command @ ("SEND" | "SHIELD" | "ZSEND" | "UNSHIELD"), from, to, zats] => {
            let _one_at_a_time = lock.lock();
            amount(zats)
                .and_then(|zats| match *command {
                    "SEND" => send(node, from, to, zats),
                    "SHIELD" => shield(node, from, to, zats),
                    "ZSEND" => zsend(node, from, to, zats),
                    _ => unshield(node, from, to, zats),
                })
                .map(|txid| format!("OK {txid}"))
        }
        _ => Err(anyhow::anyhow!("unknown command")),
    };
    match result {
        Ok(reply) => reply,
        Err(e) => format!("ERR {e}"),
    }
}

fn serve_connection(node: Arc<Node>, lock: Arc<Mutex<()>>, devnet: bool, stream: TcpStream) {
    let Ok(reader) = stream.try_clone() else {
        return;
    };
    let mut writer = stream;
    for line in BufReader::new(reader).lines() {
        let Ok(line) = line else { break };
        let reply = handle(&node, &lock, devnet, &line);
        if writeln!(writer, "{reply}").is_err() {
            break;
        }
    }
}

/// Starts the service on a loopback address. Anything else is refused: it can spend coins.
pub fn start(node: Arc<Node>, addr: SocketAddr, devnet: bool) -> Result<()> {
    if !addr.ip().is_loopback() {
        bail!("--rpc must be a loopback address: the service spends coins without a password");
    }
    let listener = TcpListener::bind(addr).with_context(|| format!("cannot listen on {addr}"))?;
    info!(%addr, "devnet wallet service listening (balance and send, no signatures, no proofs)");
    let lock = Arc::new(Mutex::new(()));
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let (node, lock) = (node.clone(), lock.clone());
                    thread::spawn(move || serve_connection(node, lock, devnet, stream));
                }
                Err(e) => warn!(%e, "wallet service accept failed"),
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitments_spell_out_their_owner_and_value() {
        let owner = owner_of("z1exampleexampleexampleexample");
        let c = commitment(&owner, 12_345, 7);
        assert_eq!(i64::from_le_bytes(c[..8].try_into().unwrap()), 12_345);
        assert_eq!(c[8..28], owner[..]);
        assert_eq!(
            c[31], 0,
            "a zero top byte keeps it a canonical field element"
        );
        assert_ne!(owner_of("z1other"), owner);
        assert_ne!(nullifier(&c), nullifier(&commitment(&owner, 12_345, 8)));
    }

    #[test]
    fn only_shielded_looking_addresses_are_accepted() {
        assert!(check_z("z1pzuxhr0g8e9430gxxaxyy9lkwgmypea3g8467k3s26").is_ok());
        assert!(check_z("tv4wDzjsuGiN3wtf1eezdA5iwVK6SgNMr8i").is_err());
        assert!(check_z("z1short").is_err());
    }

    #[test]
    fn transactions_are_classified_by_direction() {
        let script = Script::new(&[1]);
        let out = || vec![Output::new(Amount::new(1), script.clone())];
        let input = || {
            vec![OutPoint {
                hash: zebra_chain::transaction::Hash([1; 32]),
                index: 0,
            }]
        };
        let c = commitment(&[1; 20], 5, 1);
        let tt = DevTx::new(input(), out(), Vec::new(), false, 1);
        let tz =
            DevTx::new(input(), Vec::new(), Vec::new(), true, 2).with_sapling(-5, vec![], vec![c]);
        let zz = DevTx::new(Vec::new(), Vec::new(), vec![[9; 32]], true, 3).with_sapling(
            1,
            vec![],
            vec![c],
        );
        let zt =
            DevTx::new(Vec::new(), out(), vec![[9; 32]], true, 4).with_sapling(5, vec![], vec![]);
        assert_eq!(
            [kind_of(&tt), kind_of(&tz), kind_of(&zz), kind_of(&zt)],
            ["t-t", "t-z", "z-z", "z-t"]
        );
    }
}
