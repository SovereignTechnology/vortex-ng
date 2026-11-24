//! The PoDLE commitments a maker has seen used, kept beside the wallet file as `<wallet>.commitments`, so that
//! a restarted maker still refuses them (issue #52).
//!
//! One commitment per line, lowercase hex as makers broadcast it: `v <hex>` for one this maker verified
//! before it showed its coins, `a <hex>` for one announced by others (`!hp2`). A verified one is written and
//! synced to disk before the coins go out; an announced one is written without waiting for the disk. The
//! file is rewritten from what the maker remembers once it reaches [`REWRITE_AT`] lines, so a flood of
//! announcements, which cost nothing to send, cannot grow it without end.
//!
//! A last line cut short (a crash while writing it) is dropped when the file is opened, and a write that fails
//! is cut back off. Any other line that is not a commitment is an error: read as empty, the file would let
//! used commitments see the coins again.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use vortex_ng_core::bitcoin::hex::{DisplayHex, FromHex};
use vortex_ng_maker::{CommitmentKeeper, MAX_COMMITMENTS, Seen};

/// Lines at which the file is rewritten: what the maker remembers is at most twice [`MAX_COMMITMENTS`].
const REWRITE_AT: usize = 3 * MAX_COMMITMENTS;
/// Bytes past which announced commitments are no longer written, should rewriting keep failing (a line is
/// 67 bytes, so a rewritten file is under 14 MB, and one due for rewriting under 21 MB).
const ANNOUNCED_UP_TO: u64 = 32 * 1024 * 1024;
/// A file this large is not one this program wrote.
const MAX_BYTES: u64 = 2 * ANNOUNCED_UP_TO;

/// What a commitments file holds, oldest first.
pub(crate) type Remembered = Vec<(Seen, [u8; 32])>;

/// The commitments file of one maker.
pub(crate) struct SeenLog {
    path: PathBuf,
    file: File,
    /// The file's length after the last whole line.
    size: u64,
    lines: usize,
    rewrite_at: usize,
}

fn tag(seen: Seen) -> char {
    match seen {
        Seen::Verified => 'v',
        Seen::Announced => 'a',
    }
}

fn line(seen: Seen, commitment: &[u8; 32]) -> String {
    format!("{} {}\n", tag(seen), commitment.to_lower_hex_string())
}

fn parse(line: &str) -> Option<(Seen, [u8; 32])> {
    let (seen, hex) = match line.split_once(' ')? {
        ("v", hex) => (Seen::Verified, hex),
        ("a", hex) => (Seen::Announced, hex),
        _ => return None,
    };
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    <[u8; 32]>::from_hex(hex)
        .ok()
        .map(|commitment| (seen, commitment))
}

/// Write `text` to `fresh`, durably, and put it in `path`'s place: the new file, open to append.
fn replace(fresh: &Path, path: &Path, text: &str) -> std::io::Result<File> {
    // A new file, never one already there (nor where a link there points).
    match std::fs::remove_file(fresh) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(fresh)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(fresh, path)?;
    sync_dir(path)?;
    OpenOptions::new().append(true).open(path)
}

/// Make a new or renamed file's directory entry durable.
fn sync_dir(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => File::open(dir)?.sync_all(),
        _ => File::open(".")?.sync_all(),
    }
}

impl SeenLog {
    /// The log of the wallet file `wallet`, and what it holds, oldest first: nothing when there is no file yet.
    pub(crate) fn open(wallet: &Path) -> Result<(SeenLog, Remembered), String> {
        let mut path = wallet.as_os_str().to_owned();
        path.push(".commitments");
        let path = PathBuf::from(path);
        let shown = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
        // A symbolic link is not followed: it is not a file this program wrote.
        let existed = match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(shown(&e)),
            Ok(meta) if !meta.is_file() => return Err(shown(&"not a file")),
            Ok(meta) if meta.len() > MAX_BYTES => {
                return Err(shown(&"too large to be a commitments file"));
            }
            Ok(_) => true,
        };
        let text = if existed {
            std::fs::read_to_string(&path).map_err(|e| shown(&e))?
        } else {
            String::new()
        };
        // A last line without its newline was cut short: drop it, on disk too, so the next line starts clean.
        let whole = text.rfind('\n').map_or(0, |at| at + 1);
        if whole < text.len() {
            OpenOptions::new()
                .write(true)
                .open(&path)
                .and_then(|file| {
                    file.set_len(whole as u64)?;
                    file.sync_all()
                })
                .map_err(|e| shown(&e))?;
        }
        let mut remembered = Vec::new();
        for (number, text) in text[..whole].lines().enumerate() {
            let entry = parse(text)
                .ok_or_else(|| shown(&format!("line {} is not a commitment", number + 1)))?;
            remembered.push(entry);
        }
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| shown(&e))?;
        if !existed {
            sync_dir(&path).map_err(|e| shown(&e))?;
        }
        let log = SeenLog {
            path,
            file,
            size: whole as u64,
            lines: remembered.len(),
            rewrite_at: REWRITE_AT,
        };
        Ok((log, remembered))
    }

    #[cfg(test)]
    fn rewrite_at(mut self, lines: usize) -> SeenLog {
        self.rewrite_at = lines;
        self
    }

    #[cfg(test)]
    fn fail_writes(&mut self) -> std::io::Result<()> {
        self.file = OpenOptions::new().append(true).open("/dev/full")?;
        Ok(())
    }
}

impl CommitmentKeeper for SeenLog {
    fn keep(&mut self, seen: Seen, commitment: &[u8; 32]) -> Result<(), String> {
        if seen == Seen::Announced && self.size >= ANNOUNCED_UP_TO {
            return Ok(());
        }
        let text = line(seen, commitment);
        let written = self
            .file
            .write_all(text.as_bytes())
            .and_then(|()| match seen {
                Seen::Verified => self.file.sync_data(),
                Seen::Announced => Ok(()),
            });
        match written {
            Ok(()) => {
                self.size += text.len() as u64;
                self.lines += 1;
                Ok(())
            }
            Err(e) => {
                // Whatever part of the line went out would run into the next one.
                let _ = self.file.set_len(self.size);
                Err(format!("{}: {e}", self.path.display()))
            }
        }
    }

    fn wants_rewrite(&self) -> bool {
        self.lines >= self.rewrite_at
    }

    fn rewrite(&mut self, remembered: &[(Seen, [u8; 32])]) -> Result<(), String> {
        let mut fresh = self.path.as_os_str().to_owned();
        fresh.push(".new");
        let fresh = PathBuf::from(fresh);
        let mut text = String::with_capacity(remembered.len() * 67);
        for (seen, commitment) in remembered {
            text.push_str(&line(*seen, commitment));
        }
        match replace(&fresh, &self.path, &text) {
            Ok(file) => {
                self.file = file;
                self.size = text.len() as u64;
                self.lines = remembered.len();
                self.rewrite_at = REWRITE_AT.max(remembered.len() + MAX_COMMITMENTS);
                Ok(())
            }
            Err(e) => {
                // The old file stands, with the old handle; try again after a good many more lines.
                let _ = std::fs::remove_file(&fresh);
                self.rewrite_at = self.lines + MAX_COMMITMENTS;
                Err(format!("{}: {e}", self.path.display()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn wallet_in_new_dir(name: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "vortex-ng-seen-log-{name}-{}-{:016x}",
            std::process::id(),
            vortex_ng_core::tx::random_u64()
        ));
        std::fs::create_dir(&dir).unwrap();
        let wallet = dir.join("wallet.json");
        (dir, wallet)
    }

    #[test]
    fn what_was_seen_is_read_back_in_order() {
        let (dir, wallet) = wallet_in_new_dir("order");
        let (mut log, remembered) = SeenLog::open(&wallet).unwrap();
        assert!(remembered.is_empty());
        log.keep(Seen::Announced, &[0xab; 32]).unwrap();
        log.keep(Seen::Verified, &[0x01; 32]).unwrap();
        drop(log);

        let (mut log, remembered) = SeenLog::open(&wallet).unwrap();
        assert_eq!(
            remembered,
            vec![(Seen::Announced, [0xab; 32]), (Seen::Verified, [0x01; 32])]
        );
        log.keep(Seen::Announced, &[0x02; 32]).unwrap();
        let file = dir.join("wallet.json.commitments");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!(
                "a {}\nv {}\na {}\n",
                "ab".repeat(32),
                "01".repeat(32),
                "02".repeat(32)
            )
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_line_cut_short_is_dropped_and_any_other_damage_refused() {
        let (dir, wallet) = wallet_in_new_dir("damage");
        let file = dir.join("wallet.json.commitments");
        let good = format!("v {}\n", "ab".repeat(32));

        // A crash while writing the last line: it goes, the rest stays, and the file is whole again.
        std::fs::write(&file, format!("{good}a {}", "cd".repeat(20))).unwrap();
        let (mut log, remembered) = SeenLog::open(&wallet).unwrap();
        assert_eq!(remembered, vec![(Seen::Verified, [0xab; 32])]);
        log.keep(Seen::Announced, &[0xcd; 32]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("{good}a {}\n", "cd".repeat(32))
        );

        for damaged in [
            format!("{good}not a commitment\n"),
            format!("{good}v {}\n", "AB".repeat(32)),
            format!("{good}x {}\n", "ab".repeat(32)),
            format!("{good}v {}\n", "ab".repeat(31)),
            format!("{good}v  {}\n", "ab".repeat(32)),
        ] {
            std::fs::write(&file, &damaged).unwrap();
            let refused = SeenLog::open(&wallet).err().unwrap();
            assert!(refused.contains("line 2 is not a commitment"), "{refused}");
        }
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        assert!(SeenLog::open(&wallet).err().unwrap().contains("not a file"));
        std::fs::remove_dir(&file).unwrap();
        let elsewhere = dir.join("elsewhere");
        std::fs::write(&elsewhere, &good).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &file).unwrap();
        assert!(SeenLog::open(&wallet).err().unwrap().contains("not a file"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_file_is_rewritten_from_what_is_remembered() {
        let (dir, wallet) = wallet_in_new_dir("rewrite");
        let (log, _) = SeenLog::open(&wallet).unwrap();
        let mut log = log.rewrite_at(4);
        // A link left where the new file goes is replaced, not written through.
        let elsewhere = dir.join("elsewhere");
        std::fs::write(&elsewhere, "untouched").unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join("wallet.json.commitments.new")).unwrap();
        for byte in 1..=3u8 {
            log.keep(Seen::Announced, &[byte; 32]).unwrap();
            assert!(!log.wants_rewrite());
        }
        log.keep(Seen::Verified, &[9; 32]).unwrap();
        assert!(log.wants_rewrite());
        let kept = [(Seen::Verified, [9; 32]), (Seen::Announced, [3; 32])];
        log.rewrite(&kept).unwrap();
        assert!(!log.wants_rewrite());
        log.keep(Seen::Announced, &[4; 32]).unwrap();
        drop(log);
        let (_, remembered) = SeenLog::open(&wallet).unwrap();
        assert_eq!(
            remembered,
            vec![
                (Seen::Verified, [9; 32]),
                (Seen::Announced, [3; 32]),
                (Seen::Announced, [4; 32])
            ]
        );
        assert!(!dir.join("wallet.json.commitments.new").exists());
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "untouched");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_write_that_fails_is_an_error() {
        let (dir, wallet) = wallet_in_new_dir("full");
        let (mut log, _) = SeenLog::open(&wallet).unwrap();
        log.fail_writes().unwrap();
        assert!(log.keep(Seen::Verified, &[1; 32]).is_err());
        assert!(log.keep(Seen::Announced, &[2; 32]).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
