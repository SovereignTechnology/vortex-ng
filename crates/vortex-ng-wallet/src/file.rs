//! The wallet file: a BIP39 seed encrypted at rest.
//!
//! A small JSON object. Everything but `ciphertext` is readable without the password and is authenticated
//! with it:
//!
//! ```json
//! {
//!   "format": "vortex-ng-wallet",
//!   "version": 1,
//!   "network": "regtest",
//!   "birthday": 0,
//!   "kdf": "argon2id",
//!   "memory_kib": 65536,
//!   "passes": 3,
//!   "lanes": 1,
//!   "salt": "<16 bytes, hex>",
//!   "nonce": "<12 bytes, hex>",
//!   "ciphertext": "<hex>"
//! }
//! ```
//!
//! The key is Argon2id (version 0x13, 32 bytes) of the password and the salt at the cost the file names. The
//! ciphertext is AES-256-GCM-SIV over the mnemonic and the BIP39 passphrase (each with a 2-byte big-endian
//! length, then zero padding to a multiple of 512 bytes, so the file's size does not tell 12 words from 24 or
//! whether there is a passphrase), with the other fields as associated data: changing the network, the
//! birthday or the cost of a file makes it fail to open.
//!
//! A file is only ever created ([`write_new`]): mode 0600, and never over an existing file.

use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm_siv::aead::{Aead, Payload};
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use bdk_wallet::bitcoin::Network;
use bdk_wallet::bitcoin::hex::{DisplayHex, FromHex};
use bdk_wallet::keys::bip39::{Language, Mnemonic};
use vortex_ng_core::tx::random_bytes;
use zeroize::Zeroizing;

use crate::{Seed, WalletError};

const FORMAT: &str = "vortex-ng-wallet";
const VERSION: u64 = 1;
const KDF: &str = "argon2id";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
/// The plaintext is padded to a multiple of this.
const PAD: usize = 512;
/// The plaintext never exceeds this (a 24-word mnemonic is at most 215 bytes).
const MAX_PLAINTEXT: usize = 4 * PAD;
/// AES-GCM-SIV's tag.
const TAG_LEN: usize = 16;
/// A wallet file is never larger than this; [`read`] refuses to load more.
pub const MAX_FILE_BYTES: u64 = 64 * 1024;

fn bad(what: impl Into<String>) -> WalletError {
    WalletError::File(what.into())
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The cost of deriving the file's key from the password (Argon2id).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory, in KiB.
    pub memory_kib: u32,
    /// Passes over the memory.
    pub passes: u32,
    /// Lanes.
    pub lanes: u32,
}

impl KdfParams {
    /// What new files are written with: 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT: KdfParams = KdfParams {
        memory_kib: 65_536,
        passes: 3,
        lanes: 1,
    };
    /// A file that asks for less memory than this is refused (19 MiB, OWASP's floor for Argon2id).
    pub const MIN_MEMORY_KIB: u32 = 19_456;
    /// A file that asks for more memory than this is refused (1 GiB): opening a file must not be a way to
    /// exhaust the machine.
    pub const MAX_MEMORY_KIB: u32 = 1_048_576;
    /// Fewest passes accepted.
    pub const MIN_PASSES: u32 = 2;
    /// Most passes accepted.
    pub const MAX_PASSES: u32 = 16;
    /// Most lanes accepted.
    pub const MAX_LANES: u32 = 4;

    fn check(self) -> Result<(), WalletError> {
        let ok = (Self::MIN_MEMORY_KIB..=Self::MAX_MEMORY_KIB).contains(&self.memory_kib)
            && (Self::MIN_PASSES..=Self::MAX_PASSES).contains(&self.passes)
            && (1..=Self::MAX_LANES).contains(&self.lanes);
        if ok {
            Ok(())
        } else {
            Err(bad("key derivation cost out of range"))
        }
    }

    fn key(
        self,
        password: &str,
        salt: &[u8; SALT_LEN],
    ) -> Result<Zeroizing<[u8; 32]>, WalletError> {
        self.check()?;
        let params = Params::new(self.memory_kib, self.passes, self.lanes, Some(32))
            .map_err(|e| bad(e.to_string()))?;
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password.as_bytes(), salt, &mut key[..])
            .map_err(|e| bad(e.to_string()))?;
        Ok(key)
    }
}

/// What a wallet file says without its password. All of it is authenticated when the file is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The network the wallet's keys are for.
    pub network: Network,
    /// The block height the wallet's history starts at: nothing below it is scanned.
    pub birthday: u32,
    /// The cost of deriving the key.
    pub kdf: KdfParams,
    salt: [u8; SALT_LEN],
}

impl Header {
    /// The associated data: every field in a fixed order.
    fn aad(&self) -> String {
        format!(
            "{FORMAT}\n{VERSION}\n{}\n{}\n{KDF}\n{}\n{}\n{}\n{}",
            self.network.to_core_arg(),
            self.birthday,
            self.kdf.memory_kib,
            self.kdf.passes,
            self.kdf.lanes,
            self.salt[..].to_lower_hex_string()
        )
    }
}

fn cipher(key: &[u8; 32]) -> Result<Aes256GcmSiv, WalletError> {
    Aes256GcmSiv::new_from_slice(key).map_err(|_| bad("cipher key"))
}

/// A wallet's seed words with what is needed to use them. Holds the mnemonic; never printed by `Debug`.
pub struct WalletFile {
    network: Network,
    birthday: u32,
    mnemonic: Zeroizing<String>,
    passphrase: Zeroizing<String>,
}

impl std::fmt::Debug for WalletFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletFile")
            .field("network", &self.network)
            .field("birthday", &self.birthday)
            .finish_non_exhaustive()
    }
}

impl WalletFile {
    /// From a BIP39 English mnemonic (any spacing; stored in its canonical form) and passphrase (empty for
    /// none).
    pub fn new(
        network: Network,
        mnemonic: &str,
        passphrase: &str,
        birthday: u32,
    ) -> Result<WalletFile, WalletError> {
        let parsed = Mnemonic::parse_in(Language::English, mnemonic)
            .map_err(|e| WalletError::Mnemonic(e.to_string()))?;
        Ok(WalletFile {
            network,
            birthday,
            mnemonic: Zeroizing::new(parsed.to_string()),
            passphrase: Zeroizing::new(passphrase.to_string()),
        })
    }

    /// A new wallet: `words` (12 or 24) from the operating system's randomness, no passphrase.
    pub fn generate(
        network: Network,
        words: usize,
        birthday: u32,
    ) -> Result<WalletFile, WalletError> {
        let bytes = match words {
            12 => 16,
            24 => 32,
            _ => return Err(WalletError::Mnemonic("12 or 24 words".into())),
        };
        let entropy = Zeroizing::new(random_bytes::<32>());
        let mnemonic = Mnemonic::from_entropy(&entropy[..bytes])
            .map_err(|e| WalletError::Mnemonic(e.to_string()))?;
        let text = Zeroizing::new(mnemonic.to_string());
        WalletFile::new(network, &text, "", birthday)
    }

    /// The network the wallet's keys are for.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The block height the wallet's history starts at.
    pub fn birthday(&self) -> u32 {
        self.birthday
    }

    /// The seed words. Whoever has them has the coins: show them once, to the owner, and nowhere else.
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Whether the seed has a BIP39 passphrase.
    pub fn has_passphrase(&self) -> bool {
        !self.passphrase.is_empty()
    }

    /// The seed, for building wallets.
    pub fn seed(&self) -> Result<Seed, WalletError> {
        Seed::from_mnemonic(&self.mnemonic, &self.passphrase, self.network)
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, WalletError> {
        let (words, phrase) = (self.mnemonic.as_bytes(), self.passphrase.as_bytes());
        let len = 4 + words.len() + phrase.len();
        let (Ok(words_len), Ok(phrase_len)) =
            (u16::try_from(words.len()), u16::try_from(phrase.len()))
        else {
            return Err(bad("the passphrase is too long"));
        };
        let padded = len.div_ceil(PAD) * PAD;
        if padded > MAX_PLAINTEXT {
            return Err(bad("the passphrase is too long"));
        }
        // Allocated once at its final size: no copy of the words is left behind by a reallocation.
        let mut out = Zeroizing::new(Vec::with_capacity(padded));
        out.extend_from_slice(&words_len.to_be_bytes());
        out.extend_from_slice(words);
        out.extend_from_slice(&phrase_len.to_be_bytes());
        out.extend_from_slice(phrase);
        out.resize(padded, 0);
        Ok(out)
    }

    /// The file's contents, sealed for `password` with a fresh salt and nonce at [`KdfParams::DEFAULT`].
    pub fn seal(&self, password: &str) -> Result<String, WalletError> {
        self.seal_with(password, KdfParams::DEFAULT, random_bytes(), random_bytes())
    }

    fn seal_with(
        &self,
        password: &str,
        kdf: KdfParams,
        salt: [u8; SALT_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> Result<String, WalletError> {
        if password.is_empty() {
            return Err(bad("the wallet password is empty"));
        }
        let header = Header {
            network: self.network,
            birthday: self.birthday,
            kdf,
            salt,
        };
        let key = kdf.key(password, &salt)?;
        let plain = self.encode()?;
        let aad = header.aad();
        let ciphertext = cipher(&key)?
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &plain[..],
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| bad("encryption failed"))?;
        Ok(format!(
            "{{\n  \"format\": \"{FORMAT}\",\n  \"version\": {VERSION},\n  \"network\": \"{}\",\n  \
             \"birthday\": {},\n  \"kdf\": \"{KDF}\",\n  \"memory_kib\": {},\n  \"passes\": {},\n  \
             \"lanes\": {},\n  \"salt\": \"{}\",\n  \"nonce\": \"{}\",\n  \"ciphertext\": \"{}\"\n}}\n",
            header.network.to_core_arg(),
            header.birthday,
            kdf.memory_kib,
            kdf.passes,
            kdf.lanes,
            salt[..].to_lower_hex_string(),
            nonce[..].to_lower_hex_string(),
            ciphertext[..].to_lower_hex_string()
        ))
    }

    /// What the file `text` says without its password. Nothing here is authenticated until [`Self::open`]
    /// succeeds.
    pub fn header(text: &str) -> Result<Header, WalletError> {
        Ok(parse(text)?.0)
    }

    /// Open the file `text` with `password`. [`WalletError::Password`] when the password is wrong or any
    /// part of the file was changed.
    pub fn open(password: &str, text: &str) -> Result<WalletFile, WalletError> {
        let (header, nonce, ciphertext) = parse(text)?;
        let key = header.kdf.key(password, &header.salt)?;
        let aad = header.aad();
        let plain = Zeroizing::new(
            cipher(&key)?
                .decrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: &ciphertext[..],
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| WalletError::Password)?,
        );
        let (mnemonic, passphrase) = decode(&plain)?;
        WalletFile::new(header.network, &mnemonic, &passphrase, header.birthday)
    }
}

/// The mnemonic and passphrase out of a decrypted, padded plaintext.
fn decode(plain: &[u8]) -> Result<(Zeroizing<String>, Zeroizing<String>), WalletError> {
    fn damaged() -> WalletError {
        bad("the decrypted contents are not a wallet")
    }
    /// The length-prefixed field at `at`, and where the next one starts.
    fn field(plain: &[u8], at: usize) -> Result<(&[u8], usize), WalletError> {
        let len = plain.get(at..at + 2).ok_or_else(damaged)?;
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        let end = at + 2 + len;
        Ok((plain.get(at + 2..end).ok_or_else(damaged)?, end))
    }
    fn text(bytes: &[u8]) -> Result<Zeroizing<String>, WalletError> {
        std::str::from_utf8(bytes)
            .map(|s| Zeroizing::new(s.to_string()))
            .map_err(|_| damaged())
    }
    let (words, next) = field(plain, 0)?;
    let (phrase, end) = field(plain, next)?;
    if !plain.len().is_multiple_of(PAD) || plain[end..].iter().any(|&b| b != 0) {
        return Err(damaged());
    }
    Ok((text(words)?, text(phrase)?))
}

type Object = serde_json::Map<String, serde_json::Value>;

fn string<'a>(object: &'a Object, name: &str) -> Result<&'a str, WalletError> {
    object
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| bad(format!("no \"{name}\"")))
}

fn number(object: &Object, name: &str) -> Result<u64, WalletError> {
    object
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| bad(format!("no \"{name}\"")))
}

fn small(object: &Object, name: &str) -> Result<u32, WalletError> {
    u32::try_from(number(object, name)?).map_err(|_| bad(format!("\"{name}\" out of range")))
}

/// The field `name` as bytes: lowercase hex, its length within `bytes`.
fn hex(
    object: &Object,
    name: &str,
    bytes: std::ops::RangeInclusive<usize>,
) -> Result<Vec<u8>, WalletError> {
    let text = string(object, name)?;
    let wrong = || {
        bad(format!(
            "\"{name}\" is not lowercase hex of the right length"
        ))
    };
    if !is_lower_hex(text) || !text.len().is_multiple_of(2) || !bytes.contains(&(text.len() / 2)) {
        return Err(wrong());
    }
    Vec::<u8>::from_hex(text).map_err(|_| wrong())
}

fn parse(text: &str) -> Result<(Header, [u8; NONCE_LEN], Vec<u8>), WalletError> {
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(bad("too large to be a wallet file"));
    }
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| bad("not a wallet file"))?;
    let object = value.as_object().ok_or_else(|| bad("not a wallet file"))?;
    if object.get("format").and_then(serde_json::Value::as_str) != Some(FORMAT) {
        return Err(bad("not a wallet file"));
    }
    let version = number(object, "version")?;
    if version != VERSION {
        return Err(bad(format!(
            "wallet file version {version}: this build reads version {VERSION}"
        )));
    }
    let network =
        Network::from_core_arg(string(object, "network")?).map_err(|_| bad("unknown network"))?;
    if string(object, "kdf")? != KDF {
        return Err(bad("unknown key derivation"));
    }
    let kdf = KdfParams {
        memory_kib: small(object, "memory_kib")?,
        passes: small(object, "passes")?,
        lanes: small(object, "lanes")?,
    };
    kdf.check()?;
    let salt: [u8; SALT_LEN] = hex(object, "salt", SALT_LEN..=SALT_LEN)?
        .try_into()
        .map_err(|_| bad("salt"))?;
    let nonce: [u8; NONCE_LEN] = hex(object, "nonce", NONCE_LEN..=NONCE_LEN)?
        .try_into()
        .map_err(|_| bad("nonce"))?;
    let ciphertext = hex(
        object,
        "ciphertext",
        PAD + TAG_LEN..=MAX_PLAINTEXT + TAG_LEN,
    )?;
    let header = Header {
        network,
        birthday: small(object, "birthday")?,
        kdf,
        salt,
    };
    Ok((header, nonce, ciphertext))
}

/// Create the wallet file `path` holding `contents`: mode 0600, synced to disk, and never over an existing
/// file (`AlreadyExists`). The contents are written beside it first (`<path>.tmp`), so `path` either does not
/// exist or is complete.
pub fn write_new(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut beside = path.as_os_str().to_owned();
    beside.push(".tmp");
    let beside = PathBuf::from(beside);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&beside)?;
    let placed = file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        // A hard link fails if `path` exists: nothing is ever replaced.
        .and_then(|()| std::fs::hard_link(&beside, path));
    let _ = std::fs::remove_file(&beside);
    placed?;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    if let Ok(dir) = std::fs::File::open(dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// The contents of the wallet file `path`, refusing anything larger than [`MAX_FILE_BYTES`].
pub fn read(path: &Path) -> std::io::Result<String> {
    use std::io::Read;

    let mut text = String::new();
    std::fs::File::open(path)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "too large to be a wallet file",
        ));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use vortex_ng_core::offer::Pit;

    use super::*;
    use crate::PitWallet;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// The cheapest cost a file may name.
    const FLOOR: KdfParams = KdfParams {
        memory_kib: KdfParams::MIN_MEMORY_KIB,
        passes: KdfParams::MIN_PASSES,
        lanes: 1,
    };

    fn sealed(wallet: &WalletFile, password: &str) -> String {
        wallet
            .seal_with(password, FLOOR, [7; SALT_LEN], [9; NONCE_LEN])
            .unwrap()
    }

    fn first_address(wallet: &WalletFile) -> String {
        PitWallet::new(&wallet.seed().unwrap(), Pit::Sw0)
            .unwrap()
            .peek_address(0, false, 0)
            .unwrap()
            .to_string()
    }

    #[test]
    fn round_trip() {
        let wallet = WalletFile::new(Network::Regtest, WORDS, "extra words", 1234).unwrap();
        let text = sealed(&wallet, "correct horse");
        assert!(!text.contains("abandon") && !text.contains("extra"));

        let header = WalletFile::header(&text).unwrap();
        assert_eq!(
            (header.network, header.birthday, header.kdf),
            (Network::Regtest, 1234, FLOOR)
        );

        let opened = WalletFile::open("correct horse", &text).unwrap();
        assert_eq!(opened.mnemonic(), WORDS);
        assert!(opened.has_passphrase());
        assert_eq!(
            (opened.network(), opened.birthday()),
            (Network::Regtest, 1234)
        );
        assert_eq!(first_address(&opened), first_address(&wallet));
        // The passphrase is part of the seed.
        let plain = WalletFile::new(Network::Regtest, WORDS, "", 1234).unwrap();
        assert_ne!(first_address(&opened), first_address(&plain));
        // Nothing secret in Debug.
        assert!(!format!("{opened:?}").contains("abandon"));
    }

    #[test]
    fn mnemonic_is_stored_canonically() {
        let spaced = format!("  {}  ", WORDS.replace(' ', "   "));
        let wallet = WalletFile::new(Network::Regtest, &spaced, "", 0).unwrap();
        assert_eq!(wallet.mnemonic(), WORDS);
        assert!(matches!(
            WalletFile::new(Network::Regtest, "abandon abandon", "", 0),
            Err(WalletError::Mnemonic(_))
        ));
    }

    #[test]
    fn wrong_password_and_tampering_fail_alike() {
        let wallet = WalletFile::new(Network::Regtest, WORDS, "", 5).unwrap();
        let text = sealed(&wallet, "right");
        assert_eq!(
            WalletFile::open("wrong", &text).unwrap_err(),
            WalletError::Password
        );
        // Every readable field is authenticated.
        for (from, to) in [
            ("\"network\": \"regtest\"", "\"network\": \"signet\""),
            ("\"birthday\": 5", "\"birthday\": 6"),
            ("\"passes\": 2", "\"passes\": 3"),
            ("\"salt\": \"07", "\"salt\": \"08"),
            ("\"nonce\": \"09", "\"nonce\": \"0a"),
        ] {
            assert!(text.contains(from), "{from}");
            let changed = text.replace(from, to);
            assert_eq!(
                WalletFile::open("right", &changed).unwrap_err(),
                WalletError::Password,
                "{from}"
            );
        }
        // A flipped ciphertext bit.
        let at = text.find("\"ciphertext\": \"").unwrap() + 15;
        let mut bytes = text.clone().into_bytes();
        bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
        let changed = String::from_utf8(bytes).unwrap();
        assert_eq!(
            WalletFile::open("right", &changed).unwrap_err(),
            WalletError::Password
        );
    }

    #[test]
    fn hostile_files_are_refused_before_any_work() {
        let wallet = WalletFile::new(Network::Regtest, WORDS, "", 0).unwrap();
        let text = sealed(&wallet, "pw");
        let file_error = |changed: String| {
            assert!(
                matches!(WalletFile::open("pw", &changed), Err(WalletError::File(_))),
                "{changed}"
            );
        };
        let memory = format!("\"memory_kib\": {}", FLOOR.memory_kib);
        assert!(text.contains(&memory));
        // Too cheap, too costly (4 TiB), too many passes, no lanes.
        file_error(text.replace(&memory, "\"memory_kib\": 8"));
        file_error(text.replace(&memory, "\"memory_kib\": 4294967295"));
        file_error(text.replace("\"passes\": 2", "\"passes\": 4000000"));
        file_error(text.replace("\"lanes\": 1", "\"lanes\": 0"));
        // Another version, another format, another KDF, an unknown network.
        file_error(text.replace("\"version\": 1", "\"version\": 2"));
        file_error(text.replace("vortex-ng-wallet", "another-wallet"));
        file_error(text.replace("argon2id", "pbkdf2"));
        file_error(text.replace("\"regtest\"", "\"moon\""));
        // Uppercase hex, a short salt, a ciphertext too short to hold a wallet.
        file_error(text.replace("\"salt\": \"07", "\"salt\": \"0A"));
        file_error(text.replace("\"salt\": \"0707", "\"salt\": \"07"));
        let start = text.find("\"ciphertext\": \"").unwrap() + 15;
        file_error(format!("{}00\"\n}}\n", &text[..start]));
        // Not JSON, not an object, too large.
        file_error("seed words".to_string());
        file_error("[1, 2]".to_string());
        file_error(" ".repeat(MAX_FILE_BYTES as usize + 1));
    }

    #[test]
    fn size_does_not_tell_what_is_inside() {
        let short = WalletFile::new(Network::Regtest, WORDS, "", 0).unwrap();
        let long = WalletFile::generate(Network::Regtest, 24, 0).unwrap();
        let with_phrase = WalletFile::new(Network::Regtest, WORDS, "a passphrase", 0).unwrap();
        assert_eq!(long.mnemonic().split(' ').count(), 24);
        let len = sealed(&short, "pw").len();
        assert_eq!(sealed(&long, "pw").len(), len);
        assert_eq!(sealed(&with_phrase, "pw").len(), len);
    }

    #[test]
    fn generated_wallets_are_new_each_time() {
        let a = WalletFile::generate(Network::Signet, 12, 0).unwrap();
        let b = WalletFile::generate(Network::Signet, 12, 0).unwrap();
        assert_eq!(a.mnemonic().split(' ').count(), 12);
        assert_ne!(a.mnemonic(), b.mnemonic());
        assert!(!a.has_passphrase());
        assert!(WalletFile::generate(Network::Signet, 13, 0).is_err());
    }

    #[test]
    fn sealing_is_salted_and_refuses_an_empty_password() {
        let wallet = WalletFile::new(Network::Regtest, WORDS, "", 0).unwrap();
        assert!(matches!(wallet.seal(""), Err(WalletError::File(_))));
        // The public path: default cost, fresh salt and nonce each time.
        let (one, two) = (wallet.seal("pw").unwrap(), wallet.seal("pw").unwrap());
        assert_ne!(one, two);
        assert_eq!(WalletFile::header(&one).unwrap().kdf, KdfParams::DEFAULT);
        assert_eq!(WalletFile::open("pw", &two).unwrap().mnemonic(), WORDS);
    }

    #[test]
    fn a_wallet_file_is_private_and_never_replaced() {
        let dir = std::env::temp_dir().join(format!(
            "vortex-ng-wallet-file-{}-{:016x}",
            std::process::id(),
            vortex_ng_core::tx::random_u64()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("wallet.json");

        write_new(&path, "first").unwrap();
        assert_eq!(read(&path).unwrap(), "first");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!dir.join("wallet.json.tmp").exists());

        let again = write_new(&path, "second").unwrap_err();
        assert_eq!(again.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(read(&path).unwrap(), "first");
        assert!(!dir.join("wallet.json.tmp").exists());

        std::fs::write(dir.join("big"), vec![b' '; MAX_FILE_BYTES as usize + 1]).unwrap();
        assert!(read(&dir.join("big")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
