# Voltcash Wallet

Desktop wallet for Voltcash ($VOLT). Native Rust (egui), one executable.

All key derivation and address encoding is librustzcash (`zcash_keys`, ZIP 32 / ZIP 316).
Nothing cryptographic is hand-written here; the recovery phrase is stored with Argon2id and
ChaCha20-Poly1305 from RustCrypto.

## What works today

- Create a wallet (24-word BIP-39 phrase, backup quiz) or restore from a phrase.
- Password-encrypted phrase on disk (`%APPDATA%\Voltcash\wallet.vault`), lock/unlock.
- Sapling, Orchard and transparent keys; unified, shielded-only, Sapling and transparent
  receive addresses with QR codes.
- Recipient and amount validation. Zcash addresses (main or test) are refused as "not Voltcash".
- Node reachability check (plain TCP connect to `volt-node`).

## What does not work yet

- **Balance, history and sending.** The wallet has to scan the chain for its notes, and
  `volt-node` does not serve wallet data yet (see roadmap item 2 in the handoff notes). The Send
  screen is deliberately disabled rather than faking it.

## Voltcash prefixes (vendored librustzcash patch)

librustzcash's `NetworkType` is a closed enum, so Voltcash occupies the `Regtest` slot and
`vendor/zcash_address` and `vendor/zcash_protocol` replace that slot's constants:

| | Voltcash | 
| --- | --- |
| Unified address | `volt1...` |
| Sapling address | `volts1...` |
| Transparent P2PKH | `Vo...` (prefix `0x10 0x37`) |
| ZIP 32 coin type | `22083` |

Patches are marked `VOLTCASH PATCH`. Two behaviours differ from upstream on purpose: transparent
Regtest addresses keep their own prefixes (upstream folds them into testnet), and Zcash testnet
addresses are not accepted as Voltcash ones. These crates are only used by this wallet, which is
its own Cargo workspace, so Zebra's crates keep Zcash's real prefixes. Do not use the vendored
crates for real Zcash regtest work. The prefixes and coin type are placeholders until the
network parameters are final.

Keys exported through `zcash_keys` (extended spending/viewing key strings) still carry Zcash
regtest prefixes; the wallet never exports them, the recovery phrase is the backup.

## Build and run (Windows, GNU toolchain)

```powershell
cd volt-wallet
cargo +1.91.0-x86_64-pc-windows-gnu test
cargo +1.91.0-x86_64-pc-windows-gnu clippy --all-targets -- -D warnings
cargo +1.91.0-x86_64-pc-windows-gnu build --release
.\target\release\volt-wallet.exe
```

`VOLT_WALLET_DIR` overrides the wallet folder (useful for testing with a throwaway wallet).
The rendering backend is wgpu/DX12; the OpenGL backend showed a blank window on the dev machine.
