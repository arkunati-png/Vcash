//! Robustness of every decoder that reads untrusted bytes.
//!
//! Each decoder must, for any input: never panic, never allocate unboundedly, and, when it
//! accepts an input, produce a value that re-encodes to something that decodes to the same
//! value. These run as ordinary property tests; `cargo-fuzz` would explore further but needs a
//! nightly toolchain.

use std::{io::Write, sync::Arc, time::Instant};

use flate2::{write::ZlibEncoder, Compression};
use proptest::prelude::*;
use volt_core::{
    codec::{Reader, Writer},
    BatchableTx, Coinbase, DevTx, DevTxDecoder, Payout, RollupBatch, TxDecoder, VoltBlock,
    VoltHash, VoltHeader,
};
use zebra_chain::{
    amount::Amount,
    parameters::NetworkKind,
    transaction,
    transparent::{Address, OutPoint, Output, Script},
};

fn arb_outpoint() -> impl Strategy<Value = OutPoint> {
    (any::<[u8; 32]>(), any::<u32>()).prop_map(|(hash, index)| OutPoint {
        hash: transaction::Hash(hash),
        index,
    })
}

fn arb_output() -> impl Strategy<Value = Output> {
    (
        0i64..2_100_000_000_000_000,
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(value, script)| Output::new(Amount::new(value), Script::new(&script)))
}

fn arb_dev_tx() -> impl Strategy<Value = DevTx> {
    (
        prop::collection::vec(arb_outpoint(), 0..4),
        prop::collection::vec(arb_output(), 0..4),
        prop::collection::vec(any::<[u8; 32]>(), 0..3),
        any::<bool>(),
        any::<u64>(),
        -1_000_000i64..1_000_000,
    )
        .prop_map(|(inputs, outputs, nullifiers, shielded, nonce, out)| {
            DevTx::new(inputs, outputs, nullifiers, shielded, nonce).with_shielded_value_out(out)
        })
}

fn arb_block() -> impl Strategy<Value = VoltBlock> {
    (
        prop::collection::btree_set(any::<[u8; 32]>(), 0..5),
        any::<u64>(),
        any::<u32>(),
        any::<u64>(),
        prop::collection::vec((any::<[u8; 20]>(), 10_000i64..1_000_000), 0..6),
        prop::collection::vec(any::<u8>(), 0..32),
        prop::collection::vec(prop::collection::vec(arb_dev_tx(), 10..=10), 0..3),
    )
        .prop_map(
            |(parents, timestamp_ms, bits, nonce, payouts, extra, batches)| {
                let coinbase = Coinbase {
                    payouts: payouts
                        .into_iter()
                        .map(|(hash, amount)| Payout {
                            address: Address::from_pub_key_hash(NetworkKind::Regtest, hash),
                            amount: Amount::new(amount),
                        })
                        .collect(),
                    pol_contribution: Amount::new(1_000),
                    extra,
                };
                // Distinct nonces keep the ten transactions in a batch distinct.
                let batches: Vec<RollupBatch> = batches
                    .into_iter()
                    .enumerate()
                    .filter_map(|(b, txs)| {
                        let txs: Vec<Arc<dyn BatchableTx>> = txs
                            .into_iter()
                            .enumerate()
                            .map(|(i, tx)| {
                                let tagged = DevTx::new(
                                    tx.spent_outpoints(),
                                    tx.outputs(),
                                    tx.nullifiers(),
                                    tx.kind() == volt_core::TxKind::Shielded,
                                    (b * 10 + i) as u64,
                                );
                                Arc::new(tagged) as Arc<dyn BatchableTx>
                            })
                            .collect();
                        RollupBatch::pack(&txs).ok()
                    })
                    .collect();
                VoltBlock {
                    header: VoltHeader {
                        version: 1,
                        parents: parents.into_iter().map(VoltHash).collect(),
                        timestamp_ms,
                        bits,
                        nonce,
                        batches_root: VoltBlock::compute_batches_root(&batches),
                        coinbase_root: coinbase.hash(),
                    },
                    coinbase,
                    batches,
                }
            },
        )
}

/// Flips a few bits of `bytes`, chosen by `seeds`.
fn mutate(mut bytes: Vec<u8>, seeds: &[u16]) -> Vec<u8> {
    if bytes.is_empty() {
        return bytes;
    }
    for seed in seeds {
        let index = usize::from(*seed) % bytes.len();
        bytes[index] ^= 1 << (seed % 8);
    }
    bytes
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn dev_tx_round_trips(tx in arb_dev_tx()) {
        let decoded = DevTx::decode(&tx.to_bytes()).unwrap();
        prop_assert_eq!(&decoded, &tx);
        prop_assert_eq!(decoded.txid(), tx.txid());
    }

    #[test]
    fn dev_tx_decoding_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        if let Ok(tx) = DevTx::decode(&bytes) {
            prop_assert_eq!(DevTx::decode(&tx.to_bytes()).unwrap(), tx);
        }
    }

    #[test]
    fn dev_tx_decoding_mutated_valid_bytes_never_panics(
        tx in arb_dev_tx(),
        seeds in prop::collection::vec(any::<u16>(), 1..6),
    ) {
        let mutated = mutate(tx.to_bytes(), &seeds);
        if let Ok(parsed) = DevTxDecoder.decode(&mutated) {
            // Whatever it accepted must be self-consistent.
            prop_assert!(DevTx::decode(&parsed.to_bytes()).is_ok());
        }
    }

    #[test]
    fn blocks_round_trip(block in arb_block()) {
        let decoded = VoltBlock::decode(&block.encode()).unwrap();
        prop_assert_eq!(decoded.hash(), block.hash());
        prop_assert_eq!(&decoded, &block);
    }

    #[test]
    fn block_decoding_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        let _ = VoltBlock::decode(&bytes);
    }

    #[test]
    fn block_decoding_mutated_valid_bytes_never_panics(
        block in arb_block(),
        seeds in prop::collection::vec(any::<u16>(), 1..8),
    ) {
        let mutated = mutate(block.encode(), &seeds);
        if let Ok(parsed) = VoltBlock::decode(&mutated) {
            // Accepted input re-encodes to something that decodes to the same block.
            prop_assert_eq!(VoltBlock::decode(&parsed.encode()).unwrap(), parsed);
        }
    }

    #[test]
    fn batch_decompression_of_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        let _ = RollupBatch::decompress(&bytes);
    }

    #[test]
    fn batch_decompression_of_valid_zlib_around_garbage_never_panics(
        garbage in prop::collection::vec(any::<u8>(), 0..400),
    ) {
        // A well-formed compression stream whose contents are nonsense reaches the parser.
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&garbage).unwrap();
        let _ = RollupBatch::decompress(&encoder.finish().unwrap());
    }

    #[test]
    fn the_raw_codec_never_panics_and_respects_its_bounds(
        bytes in prop::collection::vec(any::<u8>(), 0..64),
        max in 0usize..32,
    ) {
        let mut r = Reader::new(&bytes);
        let _ = r.u8();
        let _ = r.u32();
        let _ = r.count("x", max);
        let _ = r.bytes("y", max);
        let _ = r.array20();
        let _ = r.array32();

        let mut w = Writer::new();
        w.bytes(&bytes);
        let encoded = w.finish();
        let mut r = Reader::new(&encoded);
        prop_assert_eq!(r.bytes("z", 64).unwrap(), bytes.as_slice());
        r.finish().unwrap();
    }
}

#[test]
fn a_decompression_bomb_is_refused_quickly_without_exhausting_memory() {
    // 200 MiB of zeros compresses to about 200 KiB, but the decoder's limit is ~20 MiB.
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    let zeros = vec![0u8; 1024 * 1024];
    for _ in 0..200 {
        encoder.write_all(&zeros).unwrap();
    }
    let bomb = encoder.finish().unwrap();
    assert!(
        bomb.len() < 2_000_000,
        "the bomb is small on the wire: {}",
        bomb.len()
    );

    let started = Instant::now();
    assert!(RollupBatch::decompress(&bomb).is_err());
    assert!(
        started.elapsed().as_secs() < 5,
        "refusing the bomb took {:?}",
        started.elapsed()
    );
}

#[test]
fn a_block_claiming_huge_collections_is_refused_before_allocating() {
    // Hand-built encodings that declare enormous counts with almost no data behind them.
    for count in [u32::MAX, 1 << 30, 100_000] {
        let mut w = Writer::new();
        // header: version, a parent count that is too large.
        let mut header = Writer::new();
        header.u32(1).u32(count);
        w.bytes(&header.finish()).bytes(&[]).count(0);
        assert!(VoltBlock::decode(&w.finish()).is_err(), "parents = {count}");
    }
}
