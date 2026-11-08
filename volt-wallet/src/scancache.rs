//! The saved scan on disk.
//!
//! Scanning the chain from the first step is slow once the chain is long, so the app saves the
//! scanner's state and loads it on the next start. The file holds the wallet's notes and their
//! witnesses, which say how much it owns and when, so it is encrypted. The key comes from the
//! account's viewing key, which is never stored on disk: only an unlocked wallet can read the
//! cache, and a cache made by a different account simply fails to open.
//!
//! A cache that is missing, damaged or stale is never an error. The wallet scans from the start,
//! which is always correct, only slower. If the node's chain has moved on from the saved scan,
//! the next sync notices and rescans.

use std::{fs, io, path::Path};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use sapling_crypto::zip32::DiversifiableFullViewingKey;

use crate::chain::Scanner;

const MAGIC: &[u8; 5] = b"VSCC1";
const NONCE_LEN: usize = 12;

fn cipher(dfvk: &DiversifiableFullViewingKey) -> ChaCha20Poly1305 {
    let key = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"VoltScanCache___")
        .hash(&dfvk.to_bytes());
    ChaCha20Poly1305::new(key.as_bytes().into())
}

/// Encrypts the scanner's state and writes it to `path`, replacing any earlier file atomically.
pub fn save(path: &Path, dfvk: &DiversifiableFullViewingKey, scanner: &Scanner) -> io::Result<()> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let sealed = cipher(dfvk)
        .encrypt(Nonce::from_slice(&nonce), scanner.to_bytes().as_slice())
        .map_err(|_| io::Error::other("could not encrypt the scan"))?;

    let mut file = Vec::with_capacity(MAGIC.len() + NONCE_LEN + sealed.len());
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&sealed);

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, file)?;
    fs::rename(&tmp, path)
}

/// Loads a saved scan for this account, or `None` if there is none or it cannot be trusted.
pub fn load(path: &Path, dfvk: &DiversifiableFullViewingKey) -> Option<Scanner> {
    let file = fs::read(path).ok()?;
    let body = file.strip_prefix(MAGIC.as_slice())?;
    if body.len() < NONCE_LEN {
        return None;
    }
    let (nonce, sealed) = body.split_at(NONCE_LEN);
    let plain = cipher(dfvk)
        .decrypt(Nonce::from_slice(nonce), sealed)
        .ok()?;
    Scanner::from_bytes(dfvk, &plain).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;

    const PHRASE_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const PHRASE_B: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";

    fn dfvk(phrase: &str) -> DiversifiableFullViewingKey {
        keys::viewing_key(phrase)
            .unwrap()
            .sapling()
            .unwrap()
            .clone()
    }

    #[test]
    fn an_empty_scan_round_trips_and_only_its_own_account_can_open_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.cache");
        let (a, b) = (dfvk(PHRASE_A), dfvk(PHRASE_B));

        save(&path, &a, &Scanner::new(&a)).unwrap();
        assert!(load(&path, &a).is_some());
        assert!(load(&path, &b).is_none(), "another account cannot read it");

        // Damage anywhere makes it unreadable rather than wrong.
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert!(load(&path, &a).is_none());
        assert!(load(&dir.path().join("missing"), &a).is_none());
        fs::write(&path, b"not a cache").unwrap();
        assert!(load(&path, &a).is_none());
    }
}
