# Voltcash ($VOLT) L1 core

Eight crates added to this Zebra workspace. They reuse `zebra-chain` types (`Transaction`,
`Amount`, `transparent::{Address, OutPoint, Output, Utxo}`, `work::difficulty`) and leave `zebrad`,
`zebra-consensus` and `zebra-state` unchanged.

| Crate | Responsibility |
| --- | --- |
| `volt-core` | Constants, `Economics` (emission, miner share), size-aware fees, `RollupBatch` (10-to-1), DAG block types, bounded codec |
| `volt-crypto` | `PowHasher` trait and `RandomXEngine` (the only proof of work) |
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
| 850 ms target interval | `difficulty::next_bits` (adjusts per blue block) |
| Up to 10 txs per `RollupBatch` (a quiet chain closes a smaller batch), compressed payload | `volt-core/src/batch.rs` |
| Fees: tier floor **and** per-action **and** per-KB | `volt-core/src/fee.rs`; exact balance in `RamUtxoStore` |
| Block caps (bytes, actions) | `BlockValidator::validate` |
| RandomX replaces Equihash | `BlockValidator::validate` calls `PowHasher` |
| Emission halving + tail; flat 80% miner / 20% POL split (a taper is supported) | `volt-core/src/economics.rs` |
| At most 100 unique payout addresses, each at least the minimum payout | `coinbase::check_coinbase` |
| Scheduled miner / POL split | `check_coinbase` per block; `EpochAccumulator::settle` per 200-block epoch |
| POL permanently locked | `PolReserve` has no withdraw API |
| Coinbase maturity | `RamUtxoStore::plan` |
| Sapling / Orchard proofs, signatures, transparent scripts | `volt-verify`, invoked by `RamUtxoStore` at acceptance |
| Shielded anchors, note commitment trees, pool balances (turnstile) | `volt-state/src/shielded.rs`, applied by `ChainState` |
| Sprout and Ironwood refused | `ShieldedState::check_anchors`, and `volt-verify` |
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
volt-node run --data-dir b --listen 127.0.0.1:8446 --seed 127.0.0.1:8445 --easy-pow

# A multi-miner simulation in one process.
volt-node sim --blocks 300 --miners 3 --batches 2
```

Options: `--economics mainnet|tapered|fifty-fifty`, `--maturity STEPS`, `--easy-pow`,
`--real-txs` (needs `--features zebra-proofs`). `--easy-pow` makes blocks about 64 times easier
to find (still RandomX) for a local test chain. RandomX needs CMake and a C++ compiler.

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

## Shielded transactions

Verifying a shielded proof is not enough. A proof is checked against whatever *anchor* (note
commitment tree root) the transaction names, so without more it could be made against a tree the
spender invented and **mint shielded coins**. `ShieldedState` closes that with three rules taken
from Zcash:

1. **Anchors.** A spend must name the root of the real tree at the end of an *earlier* chain step.
   Roots become valid anchors only when their step is sealed, so a transaction can never anchor
   to its own step. The empty-tree roots are valid from genesis. A reorg unseals and restores
   exactly, and wallets should anchor a few steps back, because an anchor from a step that is later
   reverted makes the transaction invalid.
2. **Commitments.** Every note commitment is appended to its pool's tree in consensus order, so all
   nodes build identical trees. It uses Zebra's own `NoteCommitmentTree` types.
3. **The turnstile.** Each pool's value may never go negative, checked per block. Even a flaw in a
   proof system could not let someone take out more than was put in.

A block that breaks these is rejected whole at acceptance, atomically (its UTXO changes are undone
too), exactly like any other state conflict. The mempool refuses such transactions up front.
Sprout and Ironwood are refused outright, because nothing tracks their pools.

Shielded values are carried as wide integers end to end, so adding the Sapling and Orchard
balances can never overflow or be silently clamped.

### How a wallet follows the chain

The node lists its accepted chain steps in the order they were applied (`STEPS` on the wallet
service, `Consensus::step_views`). Each step carries the shielded transactions in application order
with their nullifiers, note commitments and encrypted notes, plus the Sapling tree root and size
after the step. A wallet appends the commitments in that order and must arrive at exactly the
node's root after every step; `volt-consensus/tests/step_feed.rs` checks this with parallel blocks
and across a reorg, and the wallet's own tests check it against a real node. A changed closing
block at a step the wallet already has means a reorg, and the wallet rescans.

Real payments (Sapling, version 5 transactions, Nu6.3 branch) are built and proven by the wallet
with librustzcash, and verified by `volt-verify` when the node runs with `--real-txs`
(`cargo build --release -p volt-node --features zebra-proofs`). Rollup batches may hold fewer than
ten transactions, so a lone payment on a quiet chain is not left waiting for nine others.

## Mining

Proof of work is RandomX. A block's hash is `RandomX(seed, blob)` where the 76-byte `blob` is built
from a commitment to the header and the 64-bit nonce (`VoltHeader::pow_blob`), laid out like a
Monero hashing blob: the low 32 bits of the nonce sit at offset 39, where XMRig writes its nonce, and
the high 32 bits (the stratum extra nonce, different for every connection) just before them.

The RandomX key (`seed`) changes every `POW_KEY_EPOCH_LENGTH` blue blocks (2^18, about 62 hours at
850 ms) and lags by one period, so a miner knows the next key a full period ahead and rebuilds its
2 GB dataset rarely. It is separate from the 200-block reward epoch.

`volt-node run --stratum ADDR` serves a Monero-style stratum protocol (login, job,
submit, keepalive; algorithm `rx/0`). Point XMRig at it with your Voltcash address as the user:

```text
xmrig -o 127.0.0.1:3333 -a rx/0 -u tv...your address... -p x
```

The job target is the block target, so this is solo mining: a share is a block. The server
verifies every nonce itself.

There is no other proof of work. The old Blake2b stand-in is gone, and tests, simulations and local
chains use RandomX too, with an easy target: `--easy-pow` on the node, `Consensus::test_genesis_block`
and `RandomXEngine::shared()` in code. The easy limit (`TEST_POW_LIMIT_BITS`, 2^253, about 8 hashes
per block) is committed in the genesis block, so an easy-pow chain is a different network from the
production one and the two cannot be mixed up. RandomX needs CMake and a C++ compiler; on the
GNU Windows toolchain `.cargo/config.toml` links the C++ runtime.

The production limit is `POW_LIMIT_BITS` (about 512 expected hashes), so a single light-mode
RandomX thread (about 70 H/s) finds a block roughly every 7 to 10 seconds, and difficulty rises as
hash power joins. The genesis start difficulty is that limit.

## Economics

`Economics::mainnet()`: 0.05 VOLT per block, halving yearly, 0.001 VOLT tail; miners keep a flat
80% of each reward and the other 20% is locked as protocol-owned liquidity, from the first block.
`Economics::tapered()` is the same emission with miners starting at 70% and falling to 50%;
`Economics::fifty_fifty()` is a flat, exact 50/50.

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
  genuine mainnet Sapling and Orchard transactions and a signed transparent spend, and the shielded
  rules against both `DevTx` and real transactions. But no wallet exists that builds Voltcash-fee
  shielded transactions, so `--real-txs` has never run end to end, and no real shielded spend has
  ever been accepted by a Voltcash node. The devnet uses proof-less `DevTx` and says so loudly.
- **The commitment trees are not checked against a real chain's roots.** The vectors are sparse, so
  a full replay is impossible. What *is* checked against real data: real Orchard anchors equal the
  empty-tree root byte for byte, real commitments are accepted as tree leaves, and real Sapling
  spends are refused as unknown anchors.
- **One nullifier set is shared by both pools.** A Sapling and an Orchard nullifier with identical
  bytes would collide. That is cryptographically negligible, but separate sets would be cleaner.
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
