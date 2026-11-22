//! The addresses `coinjoin` has handed out, kept beside the wallet file as `<wallet>.issued`.
//!
//! The wallet lives in memory and learns which addresses are used from the chain. An address given to a
//! round that failed, or whose transaction is not confirmed yet, looks unused, so the next round would get
//! the same one: two transactions paying one script, which links them for good. Makers that saw a failed
//! round could also pick out the taker's outputs in the retry. So each address is written here, and synced
//! to disk, before it leaves this process, and every wallet opened from the file starts past them.
//!
//! One line per address: `<pit> <mixdepth> receive|change <index>`. Indices, nothing that could spend.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use vortex_ng_wallet::{MIXDEPTHS, PitWallet};

/// A log is never this large.
const MAX_BYTES: u64 = 4 * 1024 * 1024;
/// BIP32's first hardened index: the chains here are unhardened.
const MAX_INDEX: u32 = (1 << 31) - 1;

/// The highest index issued, per pit, mixdepth and chain.
pub(crate) struct IssuedLog {
    path: PathBuf,
    highest: HashMap<(String, u32, bool), u32>,
}

impl IssuedLog {
    /// The log of the wallet file `wallet`: empty when there is none yet. A file that is not a log is an
    /// error, never an empty log, because an empty one would reuse addresses.
    pub(crate) fn open(wallet: &Path) -> Result<IssuedLog, String> {
        let mut path = wallet.as_os_str().to_owned();
        path.push(".issued");
        let path = PathBuf::from(path);
        let text = match std::fs::metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
            Ok(meta) if meta.len() > MAX_BYTES => {
                return Err(format!(
                    "{}: too large to be an address log",
                    path.display()
                ));
            }
            Ok(_) => {
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?
            }
        };
        let mut highest: HashMap<(String, u32, bool), u32> = HashMap::new();
        for (number, line) in text.lines().enumerate() {
            let (key, index) = parse_line(line).ok_or_else(|| {
                format!(
                    "{}: line {} is not an address record",
                    path.display(),
                    number + 1
                )
            })?;
            let entry = highest.entry(key).or_insert(index);
            *entry = (*entry).max(index);
        }
        Ok(IssuedLog { path, highest })
    }

    /// Move `wallet` (of pit `pit`) past every address issued. Done before it syncs, so that the chain scan
    /// also watches them.
    pub(crate) fn apply(&self, wallet: &mut PitWallet, pit: &str) -> Result<(), String> {
        for ((logged, mixdepth, internal), index) in &self.highest {
            if logged == pit {
                wallet
                    .reveal_through(*mixdepth, *internal, *index)
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    /// Note an address as issued, on disk before returning.
    pub(crate) fn record(
        &mut self,
        pit: &str,
        mixdepth: u32,
        internal: bool,
        index: u32,
    ) -> Result<(), String> {
        let chain = if internal { "change" } else { "receive" };
        let written = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.path)
            .and_then(|mut file| {
                file.write_all(format!("{pit} {mixdepth} {chain} {index}\n").as_bytes())?;
                file.sync_all()
            });
        written.map_err(|e| format!("{}: {e}", self.path.display()))?;
        let entry = self
            .highest
            .entry((pit.to_string(), mixdepth, internal))
            .or_insert(index);
        *entry = (*entry).max(index);
        Ok(())
    }
}

fn digits(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn parse_line(line: &str) -> Option<((String, u32, bool), u32)> {
    let mut words = line.split(' ');
    let (pit, mixdepth, chain, index) =
        (words.next()?, words.next()?, words.next()?, words.next()?);
    if words.next().is_some() || !matches!(pit, "sw0" | "tr0" | "wsh0") {
        return None;
    }
    let mixdepth = digits(mixdepth).filter(|m| *m < MIXDEPTHS)?;
    let internal = match chain {
        "receive" => false,
        "change" => true,
        _ => return None,
    };
    let index = digits(index).filter(|i| *i <= MAX_INDEX)?;
    Some(((pit.to_string(), mixdepth, internal), index))
}

#[cfg(test)]
mod tests {
    use vortex_ng_core::bitcoin::Network;
    use vortex_ng_core::offer::Pit;
    use vortex_ng_core::tx::random_u64;
    use vortex_ng_wallet::Seed;

    use super::*;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn wallet() -> PitWallet {
        PitWallet::new(
            &Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap(),
            Pit::Sw0,
        )
        .unwrap()
    }

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vortex-ng-issued-{}-{:016x}",
            std::process::id(),
            random_u64()
        ));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    /// The bug this exists for: a fresh wallet hands out the same address every time.
    #[test]
    fn a_new_process_never_gets_an_address_again() {
        let dir = scratch();
        let path = dir.join("w.json");

        let mut first = wallet();
        let mut log = IssuedLog::open(&path).unwrap();
        log.apply(&mut first, "sw0").unwrap();
        let (index, address) = first.next_address_indexed(1, false).unwrap();
        assert_eq!(index, 0);
        log.record("sw0", 1, false, index).unwrap();
        let (change_index, change) = first.next_address_indexed(0, true).unwrap();
        log.record("sw0", 0, true, change_index).unwrap();

        // Without the log the next process would repeat it.
        assert_eq!(wallet().next_address_indexed(1, false).unwrap().1, address);

        let mut second = wallet();
        IssuedLog::open(&path)
            .unwrap()
            .apply(&mut second, "sw0")
            .unwrap();
        let (index, next) = second.next_address_indexed(1, false).unwrap();
        assert_eq!(index, 1);
        assert_ne!(next, address);
        assert_ne!(second.next_address_indexed(0, true).unwrap().1, change);

        // Another pit's record moves nothing here.
        let mut other = wallet();
        let mut log = IssuedLog::open(&path).unwrap();
        log.record("tr0", 2, false, 9).unwrap();
        log.apply(&mut other, "sw0").unwrap();
        assert_eq!(other.next_address_indexed(2, false).unwrap().0, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_is_not_a_log_is_an_error() {
        let dir = scratch();
        let path = dir.join("w.json");
        let log = dir.join("w.json.issued");
        for bad in [
            "sw0 0 receive\n",
            "sw0 0 receive 1 2\n",
            "xx0 0 receive 1\n",
            "sw0 5 receive 1\n",
            "sw0 0 sideways 1\n",
            "sw0 0 change -1\n",
            "sw0 0 change 2147483648\n",
            "sw0  0 change 1\n",
        ] {
            std::fs::write(&log, bad).unwrap();
            assert!(IssuedLog::open(&path).is_err(), "{bad:?}");
        }
        std::fs::write(&log, "sw0 0 receive 3\nsw0 0 receive 1\n").unwrap();
        let read = IssuedLog::open(&path).unwrap();
        assert_eq!(read.highest[&("sw0".to_string(), 0, false)], 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
