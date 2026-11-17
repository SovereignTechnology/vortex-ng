//! The PoDLE commitments a wallet has used, kept beside the wallet file as `<wallet>.podle`.
//!
//! A commitment is spent the moment it is sent: makers broadcast it (`!hp2`) and refuse it from then on,
//! whether or not the round completes. A taker that forgot would offer the same commitment again and be
//! refused by every maker that saw it. So each commitment is written here, and synced to disk, before it is
//! sent.
//!
//! One commitment per line, as makers broadcast it (the SHA-256 of the PoDLE's second point, lowercase hex):
//! the file says nothing the relays have not seen, and nothing about which coin a commitment was made from.

use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use vortex_ng_core::bitcoin::hex::DisplayHex;

/// A log is never this large (each coin has three commitments).
const MAX_BYTES: u64 = 4 * 1024 * 1024;

/// The commitments used so far, and where they are kept.
pub(crate) struct PodleLog {
    path: PathBuf,
    used: HashSet<String>,
}

impl PodleLog {
    /// The log of the wallet file `wallet`: empty when there is none yet. A file that is not a log is an
    /// error, never an empty log.
    pub(crate) fn open(wallet: &Path) -> Result<PodleLog, String> {
        let mut path = wallet.as_os_str().to_owned();
        path.push(".podle");
        let path = PathBuf::from(path);
        let text = match std::fs::metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
            Ok(meta) if meta.len() > MAX_BYTES => {
                return Err(format!(
                    "{}: too large to be a commitment log",
                    path.display()
                ));
            }
            Ok(_) => {
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?
            }
        };
        let mut used = HashSet::new();
        for (number, line) in text.lines().enumerate() {
            let ok =
                line.len() == 64 && line.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            if !ok {
                return Err(format!(
                    "{}: line {} is not a commitment",
                    path.display(),
                    number + 1
                ));
            }
            used.insert(line.to_string());
        }
        Ok(PodleLog { path, used })
    }

    /// Whether `commitment` was used before.
    pub(crate) fn contains(&self, commitment: &[u8; 32]) -> bool {
        self.used.contains(&commitment.to_lower_hex_string())
    }

    /// Note `commitment` as used, on disk before returning.
    pub(crate) fn record(&mut self, commitment: &[u8; 32]) -> Result<(), String> {
        let line = commitment.to_lower_hex_string();
        let written = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.path)
            .and_then(|mut file| {
                file.write_all(format!("{line}\n").as_bytes())?;
                file.sync_all()
            });
        written.map_err(|e| format!("{}: {e}", self.path.display()))?;
        self.used.insert(line);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn commitments_are_remembered_across_runs() {
        let dir = std::env::temp_dir().join(format!(
            "vortex-ng-podle-log-{}-{:016x}",
            std::process::id(),
            vortex_ng_core::tx::random_u64()
        ));
        std::fs::create_dir(&dir).unwrap();
        let wallet = dir.join("wallet.json");
        let (a, b) = ([0xab; 32], [0x01; 32]);

        let mut log = PodleLog::open(&wallet).unwrap();
        assert!(!log.contains(&a));
        log.record(&a).unwrap();
        assert!(log.contains(&a) && !log.contains(&b));

        // Another run sees it, and adds to it.
        let mut log = PodleLog::open(&wallet).unwrap();
        assert!(log.contains(&a) && !log.contains(&b));
        log.record(&b).unwrap();
        let file = dir.join("wallet.json.podle");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("{}\n{}\n", "ab".repeat(32), "01".repeat(32))
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // A damaged log is an error: read as empty, it would hand out used commitments again.
        std::fs::write(&file, format!("{}\nnot a commitment\n", "ab".repeat(32))).unwrap();
        let damaged = PodleLog::open(&wallet).err().unwrap();
        assert!(damaged.contains("line 2"), "{damaged}");
        std::fs::write(&file, "AB".repeat(32)).unwrap();
        assert!(PodleLog::open(&wallet).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
