//! The encrypted recovery phrase on disk.
//!
//! Standard, audited primitives only: Argon2id derives a key from the password and
//! ChaCha20-Poly1305 encrypts the phrase. The whole header is authenticated.
//!
//! File layout: `MAGIC | m_kib u32 | t u32 | p u32 | salt[16] | nonce[12] | ciphertext+tag`.

use std::fs;
use std::io::Write;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"VOLTWLT1";
const HEADER_LEN: usize = 8 + 12 + 16 + 12;

/// Argon2id cost: 64 MiB, 3 passes, 1 lane.
const M_KIB: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    WrongPasswordOrCorrupt,
    Unsupported,
    Io(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongPasswordOrCorrupt => {
                write!(f, "wrong password (or the wallet file is damaged)")
            }
            Self::Unsupported => write!(f, "unsupported wallet file"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

fn derive_key(
    password: &str,
    salt: &[u8],
    m: u32,
    t: u32,
    p: u32,
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let params = Params::new(m, t, p, Some(32)).map_err(|_| VaultError::Unsupported)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| VaultError::Unsupported)?;
    Ok(key)
}

fn seal_with(phrase: &str, password: &str, m: u32, t: u32, p: u32) -> Result<Vec<u8>, VaultError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let mut out = Vec::with_capacity(HEADER_LEN + phrase.len() + 16);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&m.to_le_bytes());
    out.extend_from_slice(&t.to_le_bytes());
    out.extend_from_slice(&p.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);

    let key = derive_key(password, &salt, m, t, p)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: phrase.as_bytes(),
                aad: &out,
            },
        )
        .map_err(|_| VaultError::Unsupported)?;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open_bytes(data: &[u8], password: &str) -> Result<Zeroizing<String>, VaultError> {
    if data.len() < HEADER_LEN + 16 || &data[..8] != MAGIC {
        return Err(VaultError::Unsupported);
    }
    let word = |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"));
    let (m, t, p) = (word(8), word(12), word(16));
    // A tampered header must not make us allocate gigabytes before the MAC check.
    if m > 1024 * 1024 || t > 100 || p > 16 {
        return Err(VaultError::Unsupported);
    }
    let salt = &data[20..36];
    let nonce = &data[36..48];
    let (header, ciphertext) = data.split_at(HEADER_LEN);

    let key = derive_key(password, salt, m, t, p)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let plain = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)?;
    let plain = Zeroizing::new(plain);
    String::from_utf8(plain.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| VaultError::WrongPasswordOrCorrupt)
}

/// Encrypts `phrase` under `password` and writes it atomically to `path`.
pub fn create(path: &Path, phrase: &str, password: &str) -> Result<(), VaultError> {
    let bytes = seal_with(phrase, password, M_KIB, T_COST, P_COST)?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| VaultError::Io(e.to_string()))?;
    }
    let tmp = path.with_extension("tmp");
    let mut file = fs::File::create(&tmp).map_err(|e| VaultError::Io(e.to_string()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| VaultError::Io(e.to_string()))?;
    drop(file);
    fs::rename(&tmp, path).map_err(|e| VaultError::Io(e.to_string()))
}

/// Decrypts the recovery phrase stored at `path`.
pub fn open(path: &Path, password: &str) -> Result<Zeroizing<String>, VaultError> {
    let data = fs::read(path).map_err(|e| VaultError::Io(e.to_string()))?;
    open_bytes(&data, password)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Light Argon2 settings keep the tests fast; production uses the constants above.
    fn seal(phrase: &str, password: &str) -> Vec<u8> {
        seal_with(phrase, password, 8, 1, 1).unwrap()
    }

    #[test]
    fn round_trips() {
        let blob = seal("alpha beta gamma", "hunter2");
        assert_eq!(
            open_bytes(&blob, "hunter2").unwrap().as_str(),
            "alpha beta gamma"
        );
    }

    #[test]
    fn rejects_wrong_password_and_tampering() {
        let blob = seal("alpha beta gamma", "hunter2");
        assert_eq!(
            open_bytes(&blob, "hunter3"),
            Err(VaultError::WrongPasswordOrCorrupt)
        );

        // Flipping any single bit anywhere (header or ciphertext) must fail.
        for i in 8..blob.len() {
            let mut bad = blob.clone();
            bad[i] ^= 1;
            assert!(open_bytes(&bad, "hunter2").is_err(), "byte {i}");
        }
    }

    #[test]
    fn rejects_foreign_and_truncated_files() {
        assert_eq!(
            open_bytes(b"not a wallet", "x"),
            Err(VaultError::Unsupported)
        );
        let blob = seal("a b c", "pw");
        assert!(open_bytes(&blob[..blob.len() - 1], "pw").is_err());
    }

    #[test]
    fn nonces_and_salts_are_fresh() {
        assert_ne!(seal("a b c", "pw"), seal("a b c", "pw"));
    }
}
