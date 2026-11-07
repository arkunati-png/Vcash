//! Verification against genuine Zcash transactions.
//!
//! The shielded vectors are real NU5-era mainnet transactions, so a pass means the proofs and
//! signatures really verified under the real circuits. The negative tests tamper with those same
//! transactions and must fail.

use std::sync::Arc;

use volt_core::{BatchableTx, DevTx, TxVerifier, TxVerifyItem};
use volt_verify::{UpgradePolicy, ZebraTxVerifier};
use zebra_chain::{
    amount::Amount,
    block::{Block, Height},
    parameters::{testnet::ConfiguredActivationHeights, Network, NetworkKind, NetworkUpgrade},
    serialization::{ZcashDeserializeInto, ZcashSerialize},
    transaction::{self, Transaction, TransparentSigningKey},
    transparent,
};
use zebra_test::vectors::MAINNET_BLOCKS;

/// Mainnet blocks just after NU5 activation: Sapling-to-Sapling, transparent-to-Sapling,
/// Sapling-to-Orchard and Orchard-to-Orchard transactions.
const NU5_HEIGHTS: [u32; 6] = [
    1_687_106, 1_687_107, 1_687_108, 1_687_113, 1_687_118, 1_687_121,
];

fn transactions(heights: &[u32]) -> Vec<Transaction> {
    heights
        .iter()
        .filter_map(|height| MAINNET_BLOCKS.get(height))
        .flat_map(|bytes| {
            let block: Block = bytes.zcash_deserialize_into().expect("vectors are valid");
            block
                .transactions
                .iter()
                .map(|tx| {
                    tx.zcash_serialize_to_vec()
                        .expect("serializes")
                        .zcash_deserialize_into::<Transaction>()
                        .expect("round-trips")
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// V5 shielded transactions with no transparent inputs, so no spent outputs are needed. Only V5
/// transactions commit to their own network upgrade.
fn shielded_only(tx: &Transaction) -> bool {
    tx.version() >= 5
        && !tx.is_coinbase()
        && !tx.has_transparent_inputs()
        && (tx.has_sapling_shielded_data() || tx.has_orchard_shielded_data())
}

/// Asserts that `result` failed because a proof or signature did not verify, not because of an
/// incidental error such as an unsupported transaction.
fn assert_cryptographic_failure(result: Result<(), volt_core::VerifyError>) {
    let error = result.expect_err("a tampered transaction must not verify");
    assert!(
        error.reason.contains("invalid Sapling bundle")
            || error.reason.contains("invalid Orchard bundle")
            || error.reason.contains("batch verification failed"),
        "rejected for the wrong reason: {error}"
    );
}

fn items(txs: &[Transaction]) -> Vec<TxVerifyItem<'_>> {
    txs.iter()
        .map(|tx| TxVerifyItem {
            tx: tx as &dyn BatchableTx,
            spent_outputs: Vec::new(),
        })
        .collect()
}

/// Flips one bit near the end of the serialization (a signature) until it still parses.
fn tamper(tx: &Transaction) -> Transaction {
    let bytes = tx.zcash_serialize_to_vec().expect("serializes");
    for back in 1..=64 {
        let mut copy = bytes.clone();
        let index = copy.len() - back;
        copy[index] ^= 1;
        if let Ok(parsed) = copy.zcash_deserialize_into::<Transaction>() {
            return parsed;
        }
    }
    panic!("no single-bit change near the end of the transaction still parses");
}

#[test]
fn real_sapling_and_orchard_transactions_verify() {
    let txs = transactions(&NU5_HEIGHTS);
    let shielded: Vec<Transaction> = txs.into_iter().filter(shielded_only).collect();

    assert!(
        shielded.iter().any(|tx| tx.has_sapling_shielded_data()),
        "the vectors contain a Sapling transaction"
    );
    assert!(
        shielded.iter().any(|tx| tx.has_orchard_shielded_data()),
        "the vectors contain an Orchard transaction"
    );

    // NU5-era transactions commit to the NU5 branch id, so use the transaction's own upgrade.
    let verifier = ZebraTxVerifier::new(UpgradePolicy::FromTransaction);
    verifier
        .verify_batch(&items(&shielded))
        .expect("genuine mainnet transactions must verify");

    // A second pass is served from the cache and still succeeds.
    verifier
        .verify_batch(&items(&shielded))
        .expect("cached verification agrees");
}

#[test]
fn a_tampered_sapling_transaction_is_rejected() {
    let sapling = transactions(&NU5_HEIGHTS)
        .into_iter()
        .find(|tx| {
            shielded_only(tx) && tx.has_sapling_shielded_data() && !tx.has_orchard_shielded_data()
        })
        .expect("a Sapling-only transaction exists");

    let verifier = ZebraTxVerifier::new(UpgradePolicy::FromTransaction);
    verifier
        .verify_batch(&items(std::slice::from_ref(&sapling)))
        .expect("the original verifies");

    let bad = tamper(&sapling);
    assert_cryptographic_failure(
        ZebraTxVerifier::new(UpgradePolicy::FromTransaction)
            .verify_batch(&items(std::slice::from_ref(&bad))),
    );
}

#[test]
fn a_tampered_orchard_transaction_is_rejected() {
    let orchard = transactions(&NU5_HEIGHTS)
        .into_iter()
        .find(|tx| shielded_only(tx) && tx.has_orchard_shielded_data())
        .expect("an Orchard transaction exists");

    let bad = tamper(&orchard);
    assert_cryptographic_failure(
        ZebraTxVerifier::new(UpgradePolicy::FromTransaction)
            .verify_batch(&items(std::slice::from_ref(&bad))),
    );
}

#[test]
fn one_bad_transaction_rejects_the_whole_batch() {
    let good: Vec<Transaction> = transactions(&NU5_HEIGHTS)
        .into_iter()
        .filter(shielded_only)
        .collect();
    let mut mixed = good.clone();
    mixed.push(tamper(&good[0]));

    assert_cryptographic_failure(
        ZebraTxVerifier::new(UpgradePolicy::FromTransaction).verify_batch(&items(&mixed)),
    );
}

#[test]
fn sprout_dev_and_unsupported_transactions_are_rejected() {
    let verifier = ZebraTxVerifier::new(UpgradePolicy::FromTransaction);

    // Block 396 holds the first JoinSplit: Sprout is not supported.
    let sprout = transactions(&[396])
        .into_iter()
        .find(|tx| tx.has_sprout_joinsplit_data())
        .expect("block 396 has a JoinSplit transaction");
    let error = verifier
        .verify_batch(&items(std::slice::from_ref(&sprout)))
        .expect_err("Sprout must be rejected");
    assert!(error.reason.contains("Sprout"), "{error}");

    // A proof-less devnet transaction has nothing to verify and must not pass as verified.
    let dev = DevTx::new(vec![], vec![], vec![], false, 1);
    let error = verifier
        .verify_batch(&[TxVerifyItem {
            tx: &dev,
            spent_outputs: vec![],
        }])
        .expect_err("a DevTx is not a Zcash transaction");
    assert!(error.reason.contains("not a Zcash-format"), "{error}");
}

#[test]
fn the_upgrade_policy_selects_the_signature_branch() {
    // The first Sapling-to-Sapling V4 transaction after NU5 has no embedded upgrade, so
    // `FromTransaction` cannot verify it, but a fixed upgrade can.
    let v4 = transactions(&[1_687_106])
        .into_iter()
        .find(|tx| {
            tx.version() == 4
                && !tx.is_coinbase()
                && !tx.has_transparent_inputs()
                && tx.has_sapling_shielded_data()
        })
        .expect("block 1687106 has a V4 Sapling transaction");

    let error = ZebraTxVerifier::new(UpgradePolicy::FromTransaction)
        .verify_batch(&items(std::slice::from_ref(&v4)))
        .expect_err("a V4 transaction does not commit to an upgrade");
    assert!(error.reason.contains("network upgrade"), "{error}");

    ZebraTxVerifier::new(UpgradePolicy::Fixed(NetworkUpgrade::Nu5))
        .verify_batch(&items(std::slice::from_ref(&v4)))
        .expect("verifies under the upgrade it was signed for");

    // Under the wrong branch id the signature hash differs, so the proofs cannot verify.
    assert_cryptographic_failure(
        ZebraTxVerifier::new(UpgradePolicy::Fixed(NetworkUpgrade::Sapling))
            .verify_batch(&items(std::slice::from_ref(&v4))),
    );
}

fn regtest() -> Network {
    Network::new_regtest(
        ConfiguredActivationHeights {
            nu5: Some(1),
            ..Default::default()
        }
        .into(),
    )
}

#[test]
fn transparent_scripts_are_checked_against_the_spent_output() {
    let network = regtest();
    let key = TransparentSigningKey::random();
    let other = TransparentSigningKey::random();
    let recipient = other.address(NetworkKind::Regtest);

    let outpoint = transparent::OutPoint {
        hash: transaction::Hash([1; 32]),
        index: 3,
    };
    let coin = transparent::Output {
        value: Amount::try_from(100_000_000).expect("valid amount"),
        lock_script: key.address(NetworkKind::Regtest).script(),
    };
    let tx = Transaction::signed_transparent(
        &network,
        Height(10),
        &key,
        &[(outpoint, coin.clone())],
        &[(
            recipient,
            Amount::try_from(30_000_000).expect("valid amount"),
        )],
    )
    .expect("a funded transparent spend builds");
    assert_eq!(tx.network_upgrade(), Some(NetworkUpgrade::Nu5));

    let verifier = ZebraTxVerifier::new(UpgradePolicy::FromTransaction);
    let item = |spent: transparent::Output| {
        vec![TxVerifyItem {
            tx: &tx as &dyn BatchableTx,
            spent_outputs: vec![spent],
        }]
    };

    verifier
        .verify_batch(&item(coin.clone()))
        .expect("the signature matches the spent output");

    // Spending an output locked to a different key: the script fails.
    let not_yours = transparent::Output {
        value: coin.value,
        lock_script: other.address(NetworkKind::Regtest).script(),
    };
    let fresh = ZebraTxVerifier::new(UpgradePolicy::FromTransaction);
    assert!(fresh.verify_batch(&item(not_yours)).is_err());

    // A v5 signature hash commits to the spent amount, so a different value fails too.
    let wrong_amount = transparent::Output {
        value: Amount::try_from(100_000_001).expect("valid amount"),
        lock_script: coin.lock_script.clone(),
    };
    let fresh = ZebraTxVerifier::new(UpgradePolicy::FromTransaction);
    assert!(fresh.verify_batch(&item(wrong_amount)).is_err());

    // Supplying no spent outputs for a transaction with inputs is an error, not a pass.
    let fresh = ZebraTxVerifier::new(UpgradePolicy::FromTransaction);
    assert!(fresh
        .verify_batch(&[TxVerifyItem {
            tx: &tx,
            spent_outputs: vec![],
        }])
        .is_err());

    // The adapter reports value balance through the same trait the state uses.
    assert_eq!(Arc::new(tx).inputs().len(), 1);
}
