# Voltcash ($VOLT) L1 core

Six crates added to this Zebra workspace. They reuse `zebra-chain` types
(`Transaction`, `Amount`, `transparent::{Address, OutPoint, Output, Utxo}`,
`work::difficulty`) and leave `zebrad`, `zebra-consensus` and `zebra-state` unchanged.

| Crate | Responsibility |
| --- | --- |
| `volt-core` | Constants, dual-tier fees (`calculate_tx_fee`), `RollupBatch` (10-to-1), DAG block types, bounded codec |
| `volt-crypto` | `PowHasher` trait, `Blake2bPowHasher` (tests/devnet), `RandomXEngine` (`randomx` feature) |
| `volt-state` | `RamUtxoStore` (DashMap-sharded, in-RAM), `PolReserve` (append-only) |
| `volt-consensus` | GHOSTDAG (`k = 32`), difficulty, coinbase rules, epoch settlement, block validation, chain state, `Consensus` engine |
| `volt-network` | Bounded wire messages and an in-process gossip hub (not a TCP stack) |
| `volt-node` | Multi-miner devnet that wires everything together |

## Rules and where they are enforced

| Rule | Where |
| --- | --- |
| GHOSTDAG, `k = 32`, blue/red coloring | `volt-consensus/src/ghostdag.rs` |
| 500 ms target interval | `difficulty::next_bits` (adjusts per blue block) |
| 10 txs per `RollupBatch`, compressed payload | `volt-core/src/batch.rs` (`pack`, `compress`, `unpack`) |
| Fees: transparent 0.0001 VOLT, shielded 0.0002 VOLT | `volt-core/src/fee.rs`; exact value balance in `RamUtxoStore` |
| RandomX replaces Equihash | `BlockValidator::validate` calls `PowHasher` |
| At most 100 unique coinbase payout addresses | `coinbase::check_coinbase` |
| Exact 50/50: half to miners, half to POL | `check_coinbase` per block; `EpochAccumulator::settle` per 200-block epoch |
| POL permanently locked | `PolReserve` has no withdraw API |
| Sharded RAM UTXO store | `volt-state/src/utxo.rs` |

## Build and run

`rust-toolchain.toml` pins 1.91.0. On Windows without Visual Studio Build Tools, use the GNU
toolchain: `cargo +1.91.0-x86_64-pc-windows-gnu ...`.

```bash
CRATES="-p volt-core -p volt-crypto -p volt-state -p volt-consensus -p volt-network -p volt-node"
cargo check  $CRATES --all-targets
cargo test   $CRATES
cargo clippy $CRATES --all-targets -- -D warnings
cargo run -p volt-node --release -- --blocks 300 --miners 3 --batches 2
```

RandomX needs CMake and a C++ compiler: `cargo run -p volt-node --release --features randomx -- --pow randomx`.
On `windows-gnu` also set `RUSTFLAGS='-C link-arg=-lstdc++'` (`randomx-rs` does not link the C++ runtime there).

## How state and finality work

State follows the selected-parent chain. Moving from chain block `P` to its child `C` merges `C`'s
mergeset in consensus order:

- **red** blocks are skipped entirely;
- **blue** blocks apply atomically (coinbase, then batches). A blue block that conflicts with an
  earlier block in the order is *rejected*, which does not make it invalid in the DAG;
- the 200th accepted block *completes* an epoch.

A block's own transactions therefore take effect one chain step after it is mined.

Tips of equal blue work swap places constantly, so the newest steps stay revertible. A completed
epoch's POL half is locked into the reserve only once its step is `FINALITY_DEPTH` (50) steps deep,
and state that deep is never reverted.

## What this is not (yet)

- **Shielded proofs and signatures are not verified.** Transactions are classified (Sapling, Orchard
  or Sprout makes a tx shielded), fee-checked, and their nullifiers are tracked. The devnet uses
  proof-less `DevTx`. Full verification would reuse the `zebra-consensus` verifiers.
- **No transparent signature checks** in `DevTx`, and no coinbase maturity.
- **`volt-network` is in-process only**: no peer discovery, handshake, sync, or DoS scoring.
- **No persistence.** The UTXO store lives in RAM and is rebuilt from the DAG.
- **The 100-address cap can be sybiled.** One pool can use 100 addresses per block, or many blocks.
  The cap limits a single block's coinbase, not pool concentration.
- **Reachability is a pruned BFS**, which is fine for a devnet but needs an interval-tree index for
  production DAG widths. Mergeset size is bounded (`MAX_MERGESET_SIZE`).
- **The reward schedule is flat** (`BASE_EMISSION_PER_BLOCK`); a real emission curve is a design decision.
- **Header and genesis are Voltcash-specific.** They do not use Zcash's Equihash header, so
  `zebrad` cannot sync a Voltcash chain.
- **RandomX hashing is serialized** through one worker thread per engine.
