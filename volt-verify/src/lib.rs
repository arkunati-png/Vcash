//! Proof and signature verification for Zcash-format transactions.
//!
//! [`ZebraTxVerifier`] implements [`volt_core::TxVerifier`] for real
//! [`zebra_chain::transaction::Transaction`]s. It checks, for every transaction:
//!
//! - **Sapling**: the Groth16 spend and output proofs, the spend-authorization signatures and the
//!   binding signature, batched across the whole input;
//! - **Orchard** (and **Ironwood**): the aggregated Halo2 proof and the signatures, batched per
//!   circuit era;
//! - **transparent inputs**: the script of every input against the output it spends, through
//!   `zebra-script` (zcashd's script interpreter).
//!
//! It uses the same cryptography as Zebra (`sapling-crypto`, `orchard`, `zcash_proofs` with the
//! bundled Sapling parameters), but drives it synchronously. It does not depend on
//! `zebra-consensus`, whose verifiers are private, async, and tied to `zebra-state`.
//!
//! Sprout is rejected outright: Voltcash has no use for the legacy JoinSplit pool.

use std::{collections::HashSet, sync::Arc, sync::LazyLock};

use orchard::{
    bundle::BatchValidator as OrchardBatch,
    circuit::{OrchardCircuitVersion, VerifyingKey as OrchardVerifyingKey},
};
use parking_lot::Mutex;
use rayon::prelude::*;
use sapling_crypto::BatchValidator as SaplingBatch;
use volt_core::{BatchableTx, TxVerifier, TxVerifyItem, VerifyError};
use zcash_proofs::prover::LocalTxProver;
use zebra_chain::{
    parameters::NetworkUpgrade,
    serialization::{ZcashDeserializeInto, ZcashSerialize},
    transaction::{HashType, Transaction, UnminedTxId},
};
use zebra_script::CachedFfiTransaction;

/// How many verified transactions to remember before the cache is cleared.
const CACHE_CAPACITY: usize = 100_000;

/// Sapling has one set of spend and output verifying keys for all of history. The bundled
/// parameters are parsed once, on first use.
static SAPLING: LazyLock<LocalTxProver> = LazyLock::new(LocalTxProver::bundled);

/// The Orchard Action verifying key for each circuit era. Building one takes a few seconds, so
/// each is built once, and only if a transaction needs it.
static ORCHARD_PRE_NU6_2: LazyLock<OrchardVerifyingKey> =
    LazyLock::new(|| OrchardVerifyingKey::build(OrchardCircuitVersion::InsecurePreNu6_2));
static ORCHARD_NU6_2: LazyLock<OrchardVerifyingKey> =
    LazyLock::new(|| OrchardVerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2));
static ORCHARD_NU6_3_ONWARD: LazyLock<OrchardVerifyingKey> =
    LazyLock::new(|| OrchardVerifyingKey::build(OrchardCircuitVersion::PostNu6_3));

/// The Orchard circuit era that `network_upgrade` commits to.
///
/// This mirrors Zebra's exhaustive mapping: the Orchard Action circuit changed in NU6.2 (a fix)
/// and NU6.3 (the cross-address restriction), and a proof only verifies under its own era's key.
fn orchard_era(network_upgrade: NetworkUpgrade) -> Era {
    use NetworkUpgrade::*;
    match network_upgrade {
        Genesis | BeforeOverwinter | Overwinter | Sapling | Blossom | Heartwood | Canopy | Nu5
        | Nu6 | Nu6_1 => Era::PreNu6_2,
        Nu6_2 => Era::Nu6_2,
        Nu6_3 | Nu7 => Era::Nu6_3Onward,
        #[cfg(zcash_unstable = "zfuture")]
        ZFuture => Era::Nu6_3Onward,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Era {
    PreNu6_2,
    Nu6_2,
    Nu6_3Onward,
}

impl Era {
    fn key(self) -> &'static OrchardVerifyingKey {
        match self {
            Era::PreNu6_2 => &ORCHARD_PRE_NU6_2,
            Era::Nu6_2 => &ORCHARD_NU6_2,
            Era::Nu6_3Onward => &ORCHARD_NU6_3_ONWARD,
        }
    }
}

/// Which network upgrade a transaction is verified under.
///
/// The upgrade selects the consensus branch the signature hash commits to and the Orchard
/// circuit era.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradePolicy {
    /// Every transaction is verified under this upgrade. Voltcash uses this: it is a new
    /// network with one rule set, so every transaction must commit to the same branch id.
    Fixed(NetworkUpgrade),
    /// Use the upgrade the transaction commits to. Only v5 and later transactions carry one.
    /// For verifying historical Zcash transactions, e.g. in tests.
    FromTransaction,
}

/// Verifies the proofs and signatures of Zcash-format transactions.
#[derive(Debug)]
pub struct ZebraTxVerifier {
    policy: UpgradePolicy,
    /// Witnessed ids of transactions that already verified, so a block re-applied after a
    /// reorg is not verified again. The witnessed id commits to the proofs and signatures too.
    verified: Mutex<HashSet<UnminedTxId>>,
}

impl ZebraTxVerifier {
    /// Creates a verifier with the given upgrade policy.
    pub fn new(policy: UpgradePolicy) -> Self {
        Self {
            policy,
            verified: Mutex::new(HashSet::new()),
        }
    }

    /// The verifier a Voltcash node uses: every transaction is verified under NU6.3.
    pub fn voltcash() -> Self {
        Self::new(UpgradePolicy::Fixed(NetworkUpgrade::Nu6_3))
    }

    fn upgrade_for(&self, tx: &Transaction) -> Result<NetworkUpgrade, String> {
        match self.policy {
            UpgradePolicy::Fixed(nu) => Ok(nu),
            UpgradePolicy::FromTransaction => tx
                .network_upgrade()
                .ok_or_else(|| "the transaction does not commit to a network upgrade".to_owned()),
        }
    }

    fn is_cached(&self, id: &UnminedTxId) -> bool {
        self.verified.lock().contains(id)
    }

    fn remember(&self, ids: impl IntoIterator<Item = UnminedTxId>) {
        let mut cache = self.verified.lock();
        if cache.len() >= CACHE_CAPACITY {
            cache.clear();
        }
        cache.extend(ids);
    }
}

/// A transparent-script check to run once the batched proofs have passed.
struct ScriptJob {
    txid: volt_core::VoltHash,
    ffi: Arc<CachedFfiTransaction>,
    inputs: usize,
}

impl TxVerifier for ZebraTxVerifier {
    fn verify_batch(&self, items: &[TxVerifyItem<'_>]) -> Result<(), VerifyError> {
        let fail = |tx: &dyn BatchableTx, reason: String| VerifyError {
            txid: tx.txid(),
            reason,
        };

        let mut sapling = SaplingBatch::new();
        let mut sapling_used = false;
        let mut orchard: Vec<(Era, OrchardBatch<'static>)> = Vec::new();
        let mut scripts: Vec<ScriptJob> = Vec::new();
        let mut fresh: Vec<UnminedTxId> = Vec::new();

        for item in items {
            let tx = item
                .tx
                .as_any()
                .downcast_ref::<Transaction>()
                .ok_or_else(|| {
                    fail(
                        item.tx,
                        "not a Zcash-format transaction: no proofs to verify".into(),
                    )
                })?;
            let id = tx.unmined_id();
            if self.is_cached(&id) {
                continue;
            }

            if tx.is_coinbase() {
                return Err(fail(
                    item.tx,
                    "coinbase transactions cannot be batched".into(),
                ));
            }
            if tx.has_sprout_joinsplit_data() {
                return Err(fail(item.tx, "Sprout JoinSplits are not supported".into()));
            }
            // The node tracks no Ironwood pool, so value could be created there without limit.
            if tx.has_ironwood_shielded_data() {
                return Err(fail(item.tx, "Ironwood is not supported".into()));
            }

            let nu = self.upgrade_for(tx).map_err(|e| fail(item.tx, e))?;
            let spent = Arc::new(item.spent_outputs.clone());
            let hasher = tx
                .sighasher(nu, spent.clone())
                .map_err(|e| fail(item.tx, format!("cannot compute the signature hash: {e}")))?;
            let sighash = hasher.sighash(HashType::ALL, None);

            // Sapling: proofs, spend-auth signatures and the binding signature.
            if let Some(bundle) = hasher.sapling_bundle() {
                if !sapling.check_bundle(bundle, sighash.0) {
                    return Err(fail(item.tx, "invalid Sapling bundle".into()));
                }
                sapling_used = true;
            }

            // Orchard bundles verify against the Action circuit of the era.
            let era = orchard_era(nu);
            if let Some(bundle) = hasher.orchard_bundle() {
                let batch = match orchard.iter().position(|(e, _)| *e == era) {
                    Some(i) => &mut orchard[i].1,
                    None => {
                        orchard.push((era, OrchardBatch::new(era.key())));
                        &mut orchard.last_mut().expect("an element was just pushed").1
                    }
                };
                batch
                    .add_bundle(&bundle, sighash.0)
                    .map_err(|e| fail(item.tx, format!("invalid Orchard bundle: {e:?}")))?;
            }

            // Transparent inputs: scripts are checked after the (cheaper to batch) proofs.
            let inputs = tx.inputs().len();
            if inputs > 0 {
                let bytes = tx
                    .zcash_serialize_to_vec()
                    .map_err(|e| fail(item.tx, e.to_string()))?;
                let owned: Transaction = bytes
                    .zcash_deserialize_into()
                    .map_err(|e| fail(item.tx, format!("cannot re-parse the transaction: {e}")))?;
                let ffi = CachedFfiTransaction::new(Arc::new(owned), spent, nu)
                    .map_err(|e| fail(item.tx, format!("cannot prepare script checks: {e}")))?;
                scripts.push(ScriptJob {
                    txid: item.tx.txid(),
                    ffi: Arc::new(ffi),
                    inputs,
                });
            }

            fresh.push(id);
        }

        // The batches are all-or-nothing, so a failure cannot be pinned on one transaction. The
        // block is rejected as a whole either way.
        let batch_failure = |what: &str| VerifyError {
            txid: items
                .first()
                .map_or(volt_core::VoltHash::ZERO, |i| i.tx.txid()),
            reason: format!("{what} batch verification failed"),
        };

        if sapling_used {
            let (spend_vk, output_vk) = SAPLING.verifying_keys();
            if !sapling.validate(&spend_vk, &output_vk, rand::rng()) {
                return Err(batch_failure("Sapling"));
            }
        }
        for (_, batch) in orchard {
            if !batch.validate(rand::rng()) {
                return Err(batch_failure("Orchard"));
            }
        }

        scripts.par_iter().try_for_each(|job| {
            (0..job.inputs).try_for_each(|index| {
                job.ffi.is_valid(index).map_err(|e| VerifyError {
                    txid: job.txid,
                    reason: format!("script check failed on input {index}: {e}"),
                })
            })
        })?;

        self.remember(fresh);
        Ok(())
    }
}
