//! The encrypted file an aut-ct server reads a proving key from.
//!
//! The server takes a file path and a password, not a key: it decrypts the file and parses a WIF from it.
//! The format is aut-ct's `encryption.rs`: the key is Argon2i (version 0x13, 4096 KiB, 3 passes, 1 lane,
//! 32 bytes) of the password and a 32-byte salt, the data is sealed with AES-256-GCM-SIV under a 12-byte
//! nonce, and the file is bincode: an 8-byte little-endian length, the ciphertext, the nonce, the salt.
//!
//! The file exists only for one proving call: it is created with mode 0600 under a random name, with a
//! password made for that call, and removed when the [`KeyFile`] is dropped.

use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, Key, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use vortex_ng_core::tx::random_u64;

use crate::AutctError;

fn kdf(password: &[u8], salt: &[u8; 32]) -> Result<[u8; 32], AutctError> {
    let params =
        Params::new(4096, 3, 1, Some(32)).map_err(|e| AutctError::KeyFile(e.to_string()))?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2i, Version::V0x13, params)
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| AutctError::KeyFile(e.to_string()))?;
    Ok(key)
}

/// `data` sealed for `password` in aut-ct's file format, with the given salt and nonce.
pub fn seal(
    data: &[u8],
    password: &[u8],
    salt: [u8; 32],
    nonce: [u8; 12],
) -> Result<Vec<u8>, AutctError> {
    let cipher = Aes256GcmSiv::new(&Key::<Aes256GcmSiv>::from(kdf(password, &salt)?));
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), data)
        .map_err(|_| AutctError::KeyFile("encryption failed".into()))?;
    let mut out = Vec::with_capacity(8 + ciphertext.len() + 12 + 32);
    out.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&salt);
    Ok(out)
}

/// What [`seal`] wrote, opened again (for tests and for checking a file before it is handed over).
pub fn open(file: &[u8], password: &[u8]) -> Result<Vec<u8>, AutctError> {
    let bad = || AutctError::KeyFile("not a key file".into());
    let len = file
        .get(..8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
        .ok_or_else(bad)?;
    let len = usize::try_from(len).map_err(|_| bad())?;
    if file.len() != 8usize.saturating_add(len).saturating_add(44) {
        return Err(bad());
    }
    let (ciphertext, tail) = file[8..].split_at(len);
    let nonce: [u8; 12] = tail[..12].try_into().map_err(|_| bad())?;
    let salt: [u8; 32] = tail[12..].try_into().map_err(|_| bad())?;
    let cipher = Aes256GcmSiv::new(&Key::<Aes256GcmSiv>::from(kdf(password, &salt)?));
    cipher
        .decrypt(&Nonce::from(nonce), ciphertext)
        .map_err(|_| AutctError::KeyFile("wrong password".into()))
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    for chunk in out.chunks_mut(8) {
        let word = random_u64().to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    out
}

/// A proving key on disk for one proving call, and the password that opens it.
pub struct KeyFile {
    path: PathBuf,
    password: String,
}

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFile").finish_non_exhaustive()
    }
}

impl KeyFile {
    /// Write `wif` (the proving UTXO's private key) under `dir`, sealed with a fresh password.
    pub fn create(dir: &Path, wif: &str) -> Result<KeyFile, AutctError> {
        let io = |e: std::io::Error| AutctError::KeyFile(e.to_string());
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let password = hex(&random_bytes::<16>());
        let sealed = seal(
            wif.as_bytes(),
            password.as_bytes(),
            random_bytes(),
            random_bytes(),
        )?;
        let path = dir.join(format!("autct-{}.enc", hex(&random_bytes::<8>())));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = KeyFile { path, password };
        options
            .open(&file.path)
            .and_then(|mut f| f.write_all(&sealed))
            .map_err(io)?;
        Ok(file)
    }

    /// Where the file is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The password that opens it.
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_layout_is_aut_cts_and_round_trips() {
        let wif = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
        let file = seal(wif.as_bytes(), b"hunter2", [7; 32], [9; 12]).unwrap();
        // u64 length, ciphertext (plaintext + 16-byte tag), nonce, salt.
        assert_eq!(&file[..8], &(wif.len() as u64 + 16).to_le_bytes());
        assert_eq!(file.len(), 8 + wif.len() + 16 + 12 + 32);
        assert_eq!(&file[file.len() - 44..file.len() - 32], &[9; 12]);
        assert_eq!(&file[file.len() - 32..], &[7; 32]);
        assert_eq!(open(&file, b"hunter2").unwrap(), wif.as_bytes());
        assert!(open(&file, b"hunter3").is_err());
        assert!(open(&file[..file.len() - 1], b"hunter2").is_err());
        // Deterministic for fixed salt and nonce, different for another salt.
        assert_eq!(
            seal(wif.as_bytes(), b"hunter2", [7; 32], [9; 12]).unwrap(),
            file
        );
        assert_ne!(
            seal(wif.as_bytes(), b"hunter2", [8; 32], [9; 12]).unwrap(),
            file
        );
    }

    #[test]
    fn a_key_file_is_private_and_removed_when_dropped() {
        let dir = std::env::temp_dir();
        let file =
            KeyFile::create(&dir, "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        let path = file.path().to_path_buf();
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(
            open(&on_disk, file.password().as_bytes()).unwrap().len(),
            52
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(file.password().len(), 32);
        let other = KeyFile::create(&dir, "x").unwrap();
        assert_ne!(other.password(), file.password());
        drop(file);
        assert!(!path.exists());
    }
}
