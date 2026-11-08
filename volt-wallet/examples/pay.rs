//! A tiny command-line wallet for scripts and demos, using the same code as the app.
//!
//! ```text
//! VOLT_WALLET_DIR=<wallet folder> VOLT_PASSWORD=<password> \
//!   pay <node wallet service> addresses
//!   pay <node wallet service> balance
//!   pay <node wallet service> send <to address> <VOLT> [memo]
//! ```
//!
//! It opens the wallet's encrypted file with the password, scans the node's chain feed, and for
//! `send` builds, signs and proves the transaction locally, then hands it to the node.

use voltcash_core::{
    chain::{self, Scanner},
    keys,
    network::{format_volt, parse_volt},
    pay, rpc, settings, vault,
};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [service, command, rest @ ..] = args.as_slice() else {
        return Err("usage: pay <service> addresses|balance|send ...".to_owned());
    };
    let password = std::env::var("VOLT_PASSWORD").map_err(|_| "set VOLT_PASSWORD")?;
    let phrase = vault::open(&settings::vault_path(), &password).map_err(|e| e.to_string())?;
    let usk = keys::spending_key(&phrase)?;
    let ufvk = usk.to_unified_full_viewing_key();
    let addresses = keys::addresses(&ufvk)?;
    let scanner = std::sync::Mutex::new(Scanner::new(
        ufvk.sapling().ok_or("the key has no Sapling part")?,
    ));

    match command.as_str() {
        "addresses" => {
            println!("shielded:    {}", addresses.shielded);
            println!("transparent: {}", addresses.transparent);
        }
        "balance" => {
            chain::sync(&scanner, service)?;
            let t = rpc::balance(service, &addresses.transparent)?;
            let z = scanner.lock().unwrap().balance();
            println!("balance: {} VOLT", format_volt(t + z));
            if std::env::var_os("VOLT_DETAILS").is_some() {
                println!("  public  {} VOLT", format_volt(t));
                println!("  private {} VOLT", format_volt(z));
                for note in scanner.lock().unwrap().unspent() {
                    println!(
                        "    note {} VOLT, memo {:?}",
                        format_volt(note.value()),
                        note.memo_text()
                    );
                }
            }
        }
        "send" => {
            let [to, amount, memo @ ..] = rest else {
                return Err("send <to> <VOLT> [memo]".to_owned());
            };
            chain::sync(&scanner, service)?;
            let utxos = rpc::utxos(service, &addresses.transparent)?;
            let built = pay::build(
                &usk,
                &scanner.lock().unwrap(),
                &utxos,
                &pay::Payment {
                    to: to.clone(),
                    zats: parse_volt(amount).map_err(str::to_owned)?,
                    memo: memo.join(" "),
                },
            )?;
            let txid = rpc::send_raw(service, &built.raw)?;
            rpc::mine(
                service,
                2,
                Some(&voltcash_core::network::dev_sink_address()),
            )?;
            println!(
                "sent {txid} (fee {} VOLT, {} bytes)",
                format_volt(built.fee),
                built.raw.len()
            );
        }
        other => return Err(format!("unknown command {other}")),
    }
    Ok(())
}
