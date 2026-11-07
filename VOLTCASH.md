# Voltcash ($VOLT) L1 core

Eight crates added to this Zebra workspace. They reuse `zebra-chain` types (`Transaction`,
`Amount`, `transparent::{Address, OutPoint, Output, Utxo}`, `work::difficulty`) and leave `zebrad`,
`zebra-consensus` and `zebra-state` unchanged.

| Crate | Responsibility |
| --- | --- |
| `volt-core` | Constants, `Economics` (emission, miner share), size-aware fees, `RollupBatch` (10-to-1), DAG block types, bounded codec |
| `volt-crypto` | `PowHasher` trait, `Blake2bPowHasher` (tests/devnet), `RandomXEngine` (`randomx` feature) |
| `volt-state` | `RamUtxoStore` (DashMap-sharded, in RAM), coinbase maturity, proof-verification hook, append-only `PolReserve` |
| `volt-consensus` | GHOSTDAG (`k = 32`), reachability index, difficulty, coinbase rules, epochs, mempool, block validation, chain state, `Consensus` engine |
| `volt-verify` | Sapling / Orchard proof and transparent-script verification for real Zcash-format transactions |
| `volt-storage` | Checksummed append-only block log with torn-write recovery and deterministic replay |
| `volt-network` | Wire messages, framing, and a TCP peer-to-peer runtime (plus an in-process hub for simulations) |
| `volt-node` | A full node (`run`) and a multi-miner simulation (`sim`) |

## Rules and where they are enforced

| Rule | Where |
| --- | --- |
| GHOSTDAG, `k = 32`, blue/red coloring | `volt-consensus/src/ghostdag.rs` |
| Fast "is it in the past of" queries | `volt-consensus/src/reachability.rs` (jump pointers + covering sets) |
| 500 ms target interval | `difficulty::next_bits` (adjusts per blue block) |
| 10 txs per `RollupBatch`, compressed payload | `volt-core/src/batch.rs` |
| Fees: tier floor **and** per-action **and** per-KB | `volt-core/src/fee.rs`; exact balance in `RamUtxoStore` |
| Block caps (bytes, actions) | `BlockValidator::validate` |
| RandomX replaces Equihash | `BlockValidator::validate` calls `PowHasher` |
| Emission halving + tail; miner share tapering 70% → 50% | `volt-core/src/economics.rs` |
| At most 100 unique payout addresses, each at least the minimum payout | `coinbase::check_coinbase` |
| Scheduled miner / POL split | `check_coinbase` per block; `EpochAccumulator::settle` per 200-block epoch |
| POL permanently locked | `PolReserve` has no withdraw API |
| Coinbase maturity | `RamUtxoStore::plan` |
| Sapling / Orchard proofs, signatures, transparent scripts | `volt-verify`, invoked by `RamUtxoStore` at acceptance |
| Sharded RAM UTXO store | `volt-state/src/utxo.rs` |

## Build and run

`rust-toolchain.toml` pins 1.91.0. On Windows without Visual Studio Build Tools, use the GNU
toolchain: `cargo +1.91.0-x86_64-pc-windows-gnu ...`.

```bash
CRATES="-p volt-core -p volt-crypto -p volt-state -p volt-consensus -p volt-network \
        -p volt-node -p volt-verify -p volt-storage"
cargo test   $CRATES
cargo clippy $CRATES --all-targets -- -D warnings
```

`volt-verify` binds zcashd's script interpreter with `bindgen`, so it needs **libclang**
(`LIBCLANG_PATH`). On `windows-gnu` also point bindgen at the MinGW headers with
`BINDGEN_EXTRA_CLANG_ARGS="--target=x86_64-w64-mingw32 -I<mingw>/x86_64-w64-mingw32/include -I<mingw>/lib/gcc/x86_64-w64-mingw32/<ver>/include"`.

Run a node, or the simulation:

```bash
# Two nodes, in two terminals: one mines, one follows it over TCP.
volt-node run --data-dir a --listen 127.0.0.1:8445 --mine
volt-node run --data-dir b --listen 127.0.0.1:8446 --seed 127.0.0.1:8445

# A multi-miner simulation in one process.
volt-node sim --blocks 300 --miners 3 --batches 2
```

Options: `--economics mainnet|fifty-fifty`, `--maturity STEPS`, `--pow blake2b|randomx`,
`--real-txs` (needs `--features zebra-proofs`). RandomX needs CMake and a C++ compiler
(`--features randomx`); on `windows-gnu` also set `RUSTFLAGS='-C link-arg=-lstdc++'`.

## How state and finality work

State follows the selected-parent chain. Moving from chain block `P` to its child `C` merges `C`'s
mergeset in consensus order:

- **red** blocks are skipped entirely;
- **blue** blocks apply atomically (coinbase, then batches). A blue block that conflicts with an
  earlier block in the order is *rejected*, which does not make it invalid in the DAG;
- the 200th accepted block *completes* an epoch.

A block's own transactions therefore take effect one chain step after it is mined.

Tips of equal blue work swap places constantly, so the newest steps stay revertible. A completed
epoch's POL part is locked into the reserve only once its step is `FINALITY_DEPTH` (50) steps deep,
and state that deep is never reverted.

Proofs and signatures are verified when a block is *accepted into state*, not when it is
validated, because a transparent signature hash commits to the spent outputs, which only the
consensus order determines. They are checked after the cheap state rules, and results are cached
by witnessed transaction id.

## Economics

`Economics::mainnet()`: 0.05 VOLT per block, halving yearly, 0.001 VOLT tail; miners keep 70% of
each reward, falling 5 points about every 36 days to 50%; the rest is locked as
protocol-owned liquidity. `Economics::fifty_fifty()` is a flat, exact 50/50 from the first block.

Fees are **exact**: a transaction's value must balance to `inputs = outputs + fee`, where
`fee = max(tier, 2,000 zats per action, 2,000 zats per KB)` and the tier is 10,000 zats
(transparent) or 20,000 (shielded). Because the fee is exact there is no fee market: spam is
priced by size and verification work, not by auction. The mempool still ranks by fee per weight,
which favours transactions that are cheap to verify.

## What this is not

Read this before trusting any of it with value.

- **The POL reserve is locked issuance and nothing more.** It is not paired with any asset and
  has no AMM or swap logic, so nothing can trade against it yet. What it should hold alongside VOLT
  is an open design decision.
- **No external audit.** The consensus rules, fee and reward arithmetic and finality logic were
  tested heavily (property tests, differential tests against a slow oracle, mutation-checked) and
  self-reviewed, but not audited. A fuzzing campaign with `cargo-fuzz` has not been run; the
  decoders are covered by `proptest` only.
- **The real-transaction path is not exercised in a live node.** `volt-verify` is tested against
  genuine mainnet Sapling and Orchard transactions and a signed transparent spend, and the state
  layer is tested against its hook. But no wallet exists that builds Voltcash-fee shielded
  transactions, so `--real-txs` has never run end to end. The devnet uses proof-less `DevTx` and
  says so loudly.
- **The 100-address cap does not limit mining concentration.** Anyone can make addresses. The
  minimum payout makes splitting cost something; RandomX is the actual anti-concentration measure.
- **Networking is minimal.** Peers come from a configured seed list: no discovery, no address
  gossip, no encryption or authentication, no NAT traversal. Bans and limits are per IP address,
  so an attacker with many addresses sidesteps them. A peer can request bulk catch-up repeatedly,
  which costs the node bandwidth. Run it behind a firewall or VPN.
- **Storage replays.** A restart re-validates the whole log, so it is O(chain). There are no UTXO
  snapshots and no pruning. It is not RocksDB.
- **The reachability index is verified, not proven.** It matches the slow walk on random DAGs, but
  the worst-case size of covering sets on adversarially built DAGs has not been analysed.
- **Chain parameters are placeholders.** Emission, taper, finality depth, caps and fee constants
  are reasoned defaults, not the output of a modelling exercise.
- **Header and genesis are Voltcash-specific**, not Zcash's Equihash header, so `zebrad` cannot
  sync a Voltcash chain.
- **RandomX hashing is serialized** through one worker thread per engine.
