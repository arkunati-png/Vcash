# Voltcash Core

The Voltcash ($VOLT) desktop app: wallet, node and miner in one. Native Rust (egui), one executable
(`voltcash-core.exe`). The node and miner run on localhost only for now; they are the separate
`volt-node` program, started and stopped from the **Node & mining** tab.

All key derivation and address encoding is librustzcash (`zcash_keys`, ZIP 32 / ZIP 316).
Nothing cryptographic is hand-written here; the recovery phrase is stored with Argon2id and
ChaCha20-Poly1305 from RustCrypto.

## What works today

- Create a wallet (24-word BIP-39 phrase, backup quiz) or restore from a phrase.
- Password-encrypted phrase on disk (`%APPDATA%\Voltcash\wallet.vault`), lock/unlock.
- A shielded address (`z1...`, Sapling) and a transparent one (`tv...`), with QR codes.
- **One balance.** The wallet shows a single number. A payment names a recipient and an amount;
  the recipient's address decides whether it is private (`z1...`) or public (`tv...`), and the
  wallet spends private coins first and public ones only as far as needed, returning change to the
  private part when a private note was used. Payments are built, signed and proven by this wallet
  on your computer with librustzcash, and checked by the node (Groth16
  proofs, spend signatures, binding signature, transparent scripts, exact fees):
  - the wallet scans the node's chain feed with its viewing key, keeps a witness for every note
    it owns, and checks after every chain step that its note tree equals the node's;
  - a reorg is noticed (the closing block of the last step changed) and the wallet rescans;
  - memos are encrypted to the recipient and shown by the receiving wallet;
  - spending needs the wallet password: the spending key is derived for the length of one
    payment and then dropped.
- Node and miner controls (localhost only), a block and transaction explorer.
- Recipient and amount validation. Zcash addresses (main or test) are refused as "not Voltcash".

`examples/pay.rs` is a small command-line wallet over the same code
(`pay <node wallet service> addresses|balance|send <to> <VOLT> [memo]`; `VOLT_DETAILS=1` shows the public/private split), used for scripted demos.

## Limits

- Only Sapling is scanned and spent. Funds sent to an Orchard receiver would not be seen, so the
  shown shielded address has a Sapling receiver only.
- Rescanning starts from the first chain step every time the app starts. Fine for a young chain,
  not for a long one.
- The wallet talks to the node through a plain loopback TCP service (`volt-node --rpc`). It has
  no password, so it must stay on localhost.
- After a send, the app asks the node to mine two blocks. That is a convenience for a local
  development chain; on a real network the payment waits for someone else's block.
- Not audited. A wallet and a node written for a chain that has never run outside one computer.

## Voltcash prefixes (vendored librustzcash patch)

librustzcash's `NetworkType` is a closed enum, so Voltcash occupies the `Regtest` slot and
`vendor/zcash_address` and `vendor/zcash_protocol` replace that slot's constants:

| | Voltcash | 
| --- | --- |
| Shielded address (Sapling receiver) | `z1...` |
| Sapling-only address (accepted, not shown) | `zv1...` |
| Transparent P2PKH | `tv...` (prefix `0x1d 0x3b`) |
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
