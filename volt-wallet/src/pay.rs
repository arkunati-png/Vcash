//! Building signed, proven transactions from one balance.
//!
//! The wallet has one balance. A payment names a recipient and an amount, and this module works
//! out the rest:
//!
//! - **what to spend**: private (shielded) notes first, largest first, then public coins if the
//!   private ones do not cover it;
//! - **what kind of payment it is**: the recipient's address decides. A `z1...` address gets a
//!   shielded output, a `tv...` address gets a public one;
//! - **where the change goes**: back to the private balance whenever a private note was spent,
//!   and to the public balance when only public coins were.
//!
//! Spending both kinds in one payment links the two on the chain, so the private coins are
//! always used first and the public ones only as far as needed.
//!
//! Everything cryptographic is librustzcash: `zcash_primitives`' transaction builder, the
//! Sapling prover from `zcash_proofs`, and the keys from `zcash_keys`. This module chooses what
//! to spend, adds change, and works out the exact fee the Voltcash node demands.
//!
//! Voltcash accepts Sapling and Orchard version 5 transactions and refuses Ironwood, while the
//! current builder proposes version 6 for the newest network upgrade, so the version is pinned
//! to 5.

use std::{convert::Infallible, sync::OnceLock};

use sapling_crypto::{zip32::ExtendedSpendingKey, Anchor, PaymentAddress};
use zcash_keys::{address::Address, keys::UnifiedSpendingKey};
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder},
    fees::fixed::FeeRule,
    Transaction, TxVersion,
};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes, value::Zatoshis};
use zcash_transparent::{
    address::TransparentAddress,
    builder::TransparentSigningSet,
    bundle::{OutPoint, TxOut},
    keys::NonHardenedChildIndex,
};
use zip32::Scope;

use crate::chain::Scanner;
use crate::network::VoltNetwork;
use crate::rpc::Utxos;

/// A payment to build.
#[derive(Clone, Debug)]
pub struct Payment {
    pub to: String,
    pub zats: u64,
    /// An encrypted note for the recipient. Only a shielded recipient can receive one.
    pub memo: String,
}

/// A transaction ready to hand to the node.
#[derive(Debug)]
pub struct Built {
    pub raw: Vec<u8>,
    pub fee: u64,
}

fn prover() -> &'static LocalTxProver {
    static PROVER: OnceLock<LocalTxProver> = OnceLock::new();
    PROVER.get_or_init(LocalTxProver::bundled)
}

fn zats(value: u64) -> Result<Zatoshis, String> {
    Zatoshis::from_u64(value).map_err(|_| "that amount is out of range".to_owned())
}

/// The fee the node will demand for this transaction: the larger of the kind's tier, 2,000 per
/// logical action and 2,000 per started kilobyte, rounded down to an even number.
/// This mirrors `volt-core`'s `fee_for`; an end-to-end test keeps the two in step.
fn required_fee(tx: &Transaction, raw_len: usize) -> u64 {
    let transparent = tx
        .transparent_bundle()
        .map_or((0, 0), |b| (b.vin.len(), b.vout.len()));
    let (spends, outputs) = tx.sapling_bundle().map_or((0, 0), |b| {
        (b.shielded_spends().len(), b.shielded_outputs().len())
    });
    let shielded = tx.sapling_bundle().is_some();
    let tier = if shielded { 20_000 } else { 10_000 };
    let actions = (transparent.0.max(transparent.1) + spends.max(outputs)) as u64;
    let kilobytes = raw_len.div_ceil(1_000) as u64;
    tier.max(actions * 2_000).max(kilobytes * 2_000) & !1
}

/// Who a payment goes to.
enum Recipient {
    Shielded(PaymentAddress),
    Public(TransparentAddress),
}

fn recipient(text: &str) -> Result<Recipient, String> {
    let address = Address::decode(&VoltNetwork, text.trim())
        .ok_or_else(|| "that is not a Voltcash address".to_owned())?;
    match address {
        Address::Sapling(a) => Ok(Recipient::Shielded(*a)),
        Address::Transparent(a) => Ok(Recipient::Public(a)),
        Address::Unified(ua) => {
            // Prefer the private receiver when the address has one.
            if let Some(a) = ua.sapling() {
                Ok(Recipient::Shielded(*a))
            } else if let Some(a) = ua.transparent() {
                Ok(Recipient::Public(*a))
            } else {
                Err("that address has no receiver this wallet can pay".to_owned())
            }
        }
        _ => Err("that kind of address is not supported".to_owned()),
    }
}

/// Builds, signs and proves a payment. `utxos` and `scanner` say what the wallet owns.
pub fn build(
    usk: &UnifiedSpendingKey,
    scanner: &Scanner,
    utxos: &Utxos,
    payment: &Payment,
) -> Result<Built, String> {
    // The fee depends on the transaction's shape, which depends on the fee through what has to be
    // spent and the change. Start from the shielded tier and let it settle; give up rather than
    // loop.
    let mut fee = 20_000;
    for _ in 0..5 {
        let (tx, raw) = assemble(usk, scanner, utxos, payment, fee)?;
        let needed = required_fee(&tx, raw.len());
        if needed == fee {
            return Ok(Built { raw, fee });
        }
        fee = needed;
    }
    Err("could not settle on a fee".to_owned())
}

fn assemble(
    usk: &UnifiedSpendingKey,
    scanner: &Scanner,
    utxos: &Utxos,
    payment: &Payment,
    fee: u64,
) -> Result<(Transaction, Vec<u8>), String> {
    let params = VoltNetwork;
    let amount = payment.zats;
    if amount == 0 {
        return Err("the amount must be more than zero".to_owned());
    }
    let need = amount
        .checked_add(fee)
        .ok_or_else(|| "that amount is out of range".to_owned())?;
    let to = recipient(&payment.to)?;
    if matches!(to, Recipient::Public(_)) && !payment.memo.is_empty() {
        return Err("a memo can only go to a private (z1...) address".to_owned());
    }

    let extsk: &ExtendedSpendingKey = usk.sapling();
    let dfvk = extsk.to_diversifiable_full_viewing_key();
    let fvk = dfvk.fvk().clone();
    let ovk = dfvk.to_ovk(Scope::External);
    let own_z: PaymentAddress = dfvk.default_address().1;

    let secret = usk
        .transparent()
        .derive_external_secret_key(NonHardenedChildIndex::ZERO)
        .map_err(|e| format!("transparent key: {e:?}"))?;
    let mut signing = TransparentSigningSet::new();
    let pubkey = signing.add_key(secret);
    let own_t = TransparentAddress::from_pubkey(&pubkey);

    // Choose what to spend: private notes first, then public coins, largest first.
    let mut notes = scanner.unspent();
    notes.sort_by_key(|n| std::cmp::Reverse(n.value()));
    let mut coins: Vec<_> = utxos.outputs.iter().filter(|o| o.spendable).collect();
    coins.sort_by_key(|o| std::cmp::Reverse(o.zats));

    let mut total = 0u64;
    let mut chosen_notes = Vec::new();
    for note in notes {
        if total >= need {
            break;
        }
        total += note.value();
        chosen_notes.push(note);
    }
    let mut chosen_coins = Vec::new();
    for coin in coins {
        if total >= need {
            break;
        }
        total += coin.zats;
        chosen_coins.push(coin);
    }
    if total < need {
        let maturing: u64 = utxos
            .outputs
            .iter()
            .filter(|o| !o.spendable)
            .map(|o| o.zats)
            .sum();
        return Err(if maturing > 0 {
            format!(
                "not enough spendable funds: {} zats are ready and {} more are still maturing (mined coins need to age before they can be spent)",
                total, maturing
            )
        } else {
            format!("not enough funds: you need {need} zats (amount plus the {fee} zat fee) and have {total}")
        });
    }
    let change = total - need;

    // Change goes private whenever a private note is involved; otherwise it stays public.
    let change_private = !chosen_notes.is_empty();
    let needs_sapling = !chosen_notes.is_empty()
        || matches!(to, Recipient::Shielded(_))
        || (change > 0 && change_private);

    let anchor = if needs_sapling {
        Some(
            Option::from(Anchor::from_bytes(scanner.root()))
                .ok_or_else(|| "the wallet's note tree root is invalid".to_owned())?,
        )
    } else {
        None
    };
    let mut builder = Builder::new(
        params,
        BlockHeight::from_u32(utxos.next_height),
        BuildConfig::Standard {
            sapling_anchor: anchor,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
            ironwood_padding: zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
        },
    );
    builder
        .propose_version::<Infallible>(TxVersion::V5)
        .map_err(|e| format!("transaction version: {e}"))?;

    for note in &chosen_notes {
        let path = note
            .witness
            .path()
            .ok_or_else(|| "a note has no usable witness yet".to_owned())?;
        builder
            .add_sapling_spend::<Infallible>(fvk.clone(), note.note.clone(), path)
            .map_err(|e| format!("adding a private input: {e}"))?;
    }
    let script = own_t.script();
    for coin in &chosen_coins {
        builder
            .add_transparent_p2pkh_input(
                pubkey,
                OutPoint::new(coin.txid, coin.index),
                TxOut::new(zats(coin.zats)?, script.clone().into()),
            )
            .map_err(|e| format!("adding a public input: {e:?}"))?;
    }

    // Where it goes.
    match &to {
        Recipient::Shielded(address) => {
            let memo = if payment.memo.is_empty() {
                MemoBytes::empty()
            } else {
                MemoBytes::from_bytes(payment.memo.as_bytes())
                    .map_err(|_| "the memo is longer than 512 bytes".to_owned())?
            };
            builder
                .add_sapling_output::<Infallible>(Some(ovk), *address, zats(amount)?, memo)
                .map_err(|e| format!("adding the payment: {e}"))?;
        }
        Recipient::Public(address) => {
            builder
                .add_transparent_output(address, zats(amount)?)
                .map_err(|e| format!("adding the payment: {e:?}"))?;
        }
    }
    if change > 0 {
        if change_private {
            builder
                .add_sapling_output::<Infallible>(
                    Some(ovk),
                    own_z,
                    zats(change)?,
                    MemoBytes::empty(),
                )
                .map_err(|e| format!("adding the change: {e}"))?;
        } else {
            builder
                .add_transparent_output(&own_t, zats(change)?)
                .map_err(|e| format!("adding the change: {e:?}"))?;
        }
    }

    let result = builder
        .build(
            &signing,
            std::slice::from_ref(extsk),
            &[],
            rand10::rng(),
            prover(),
            prover(),
            &FeeRule::non_standard(zats(fee)?),
        )
        .map_err(|e| format!("building the transaction: {e}"))?;
    let tx = result.transaction().clone();
    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| format!("serializing the transaction: {e}"))?;
    Ok((tx, raw))
}
