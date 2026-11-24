//! What the commands using one wallet share, kept beside the wallet file as `<wallet>.claims` (issue #51): the
//! coins each holds, so that `maker`, `coinjoin` and a joinstr `pool` round never put one coin into two
//! transactions, and every address handed out, so that no two rounds pay the same address.
//!
//! One claim per line: `coin <txid>:<vout> <holder> <until>`, held by the process whose random token is
//! `holder` until the unix time `until`; `address <address>`, taken for good. Every read and write happens
//! under an exclusive lock on the file, so commands in different processes see each other's claims at once.
//! Expired coin claims are dropped whenever the file is rewritten. A line that is not a claim is an error:
//! read as empty, the file would let a coin into two rounds.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use vortex_ng_core::bitcoin::hex::DisplayHex;
use vortex_ng_core::bitcoin::{Address, OutPoint};
use vortex_ng_core::tx::random_bytes;
use vortex_ng_maker::WalletClaims;
use vortex_ng_nostr::client::unix_now;
use vortex_ng_wallet::PitWallet;

/// A claims file this large is not one this program wrote.
const MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Most addresses passed over in a row because another command took them.
const MAX_TAKEN_IN_A_ROW: usize = 1_000;

/// One process's view of the claims file of a wallet.
pub(crate) struct Claims {
    path: PathBuf,
    /// This process's token: which coin claims are its own.
    holder: String,
}

#[derive(Default)]
struct State {
    coins: Vec<(OutPoint, String, u64)>,
    addresses: Vec<String>,
}

impl State {
    fn parse(text: &str, path: &Path) -> Result<State, String> {
        let mut state = State::default();
        for (number, line) in text.lines().enumerate() {
            let fields: Vec<&str> = line.split(' ').collect();
            let parsed = match fields.as_slice() {
                ["coin", coin, holder, until] => OutPoint::from_str(coin)
                    .ok()
                    .zip(until.parse::<u64>().ok())
                    .filter(|_| !holder.is_empty() && holder.bytes().all(|b| b.is_ascii_hexdigit()))
                    .map(|(coin, until)| state.coins.push((coin, holder.to_string(), until))),
                ["address", address]
                    if !address.is_empty()
                        && address.bytes().all(|b| b.is_ascii_alphanumeric()) =>
                {
                    state.addresses.push(address.to_string());
                    Some(())
                }
                _ => None,
            };
            if parsed.is_none() {
                return Err(format!(
                    "{}: line {} is not a claim",
                    path.display(),
                    number + 1
                ));
            }
        }
        Ok(state)
    }

    fn text(&self, now: u64) -> String {
        let mut text = String::new();
        for (coin, holder, until) in &self.coins {
            if *until > now {
                text.push_str(&format!("coin {coin} {holder} {until}\n"));
            }
        }
        for address in &self.addresses {
            text.push_str(&format!("address {address}\n"));
        }
        text
    }

    fn held_elsewhere(&self, holder: &str, now: u64) -> HashSet<OutPoint> {
        self.coins
            .iter()
            .filter(|(_, who, until)| who != holder && *until > now)
            .map(|(coin, _, _)| *coin)
            .collect()
    }
}

impl Claims {
    /// The claims file of the wallet file `wallet`, created (empty, mode 0600) if there is none yet.
    pub(crate) fn open(wallet: &Path) -> Result<Claims, String> {
        let mut path = wallet.as_os_str().to_owned();
        path.push(".claims");
        let claims = Claims {
            path: PathBuf::from(path),
            holder: random_bytes::<8>().to_lower_hex_string(),
        };
        claims.with_lock(|_, _| ((), false))?;
        Ok(claims)
    }

    /// Run `change` on the claims as they stand, under the file's lock. It returns its result and whether the
    /// file is to be rewritten (expired claims go then too).
    fn with_lock<T>(&self, change: impl FnOnce(&mut State, u64) -> (T, bool)) -> Result<T, String> {
        let shown = |e: &dyn std::fmt::Display| format!("{}: {e}", self.path.display());
        match std::fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(shown(&e)),
            // A symbolic link is not followed: it is not a file this program wrote.
            Ok(meta) if !meta.is_file() => return Err(shown(&"not a file")),
            Ok(_) => {}
        }
        let mut file: File = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&self.path)
            .map_err(|e| shown(&e))?;
        file.lock().map_err(|e| shown(&e))?;
        if file.metadata().map_err(|e| shown(&e))?.len() > MAX_BYTES {
            return Err(shown(&"too large to be a claims file"));
        }
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(|e| shown(&e))?;
        let mut state = State::parse(&text, &self.path)?;
        let now = unix_now();
        let (result, rewrite) = change(&mut state, now);
        if rewrite {
            let fresh = state.text(now);
            file.seek(SeekFrom::Start(0)).map_err(|e| shown(&e))?;
            file.set_len(0).map_err(|e| shown(&e))?;
            file.write_all(fresh.as_bytes()).map_err(|e| shown(&e))?;
            file.sync_data().map_err(|e| shown(&e))?;
        }
        // The lock goes with the file.
        Ok(result)
    }

    /// Hold `coins` until `until` (unix time) for this process, unless another holds one of them now.
    pub(crate) fn hold_until(&self, coins: &[OutPoint], until: u64) -> Result<bool, String> {
        let holder = self.holder.clone();
        self.with_lock(|state, now| {
            let elsewhere = state.held_elsewhere(&holder, now);
            if coins.iter().any(|coin| elsewhere.contains(coin)) {
                return (false, false);
            }
            state
                .coins
                .retain(|(coin, who, _)| !(who == &holder && coins.contains(coin)));
            state
                .coins
                .extend(coins.iter().map(|coin| (*coin, holder.clone(), until)));
            (true, true)
        })
    }

    /// Let go of this process's hold on `coins`.
    pub(crate) fn release(&self, coins: &[OutPoint]) -> Result<(), String> {
        let holder = self.holder.clone();
        self.with_lock(|state, _| {
            state
                .coins
                .retain(|(coin, who, _)| !(who == &holder && coins.contains(coin)));
            ((), true)
        })
    }

    /// The next address of `mixdepth`'s receiving or change chain that no command has taken, now taken.
    pub(crate) fn fresh_address(
        &self,
        wallet: &mut PitWallet,
        mixdepth: u32,
        change: bool,
    ) -> Result<Address, String> {
        for _ in 0..MAX_TAKEN_IN_A_ROW {
            let address = if change {
                wallet.next_change_address(mixdepth)
            } else {
                wallet.next_receive_address(mixdepth)
            }
            .map_err(|e| e.to_string())?;
            if self.take(&address)? {
                return Ok(address);
            }
        }
        Err("no address left that another command has not taken".into())
    }

    fn take(&self, address: &Address) -> Result<bool, String> {
        let text = address.to_string();
        self.with_lock(|state, _| {
            if state.addresses.contains(&text) {
                return (false, false);
            }
            state.addresses.push(text);
            (true, true)
        })
    }

    /// The coins other processes hold now.
    pub(crate) fn held_by_others(&self) -> Result<HashSet<OutPoint>, String> {
        let holder = self.holder.clone();
        self.with_lock(|state, now| (state.held_elsewhere(&holder, now), false))
    }
}

impl WalletClaims for Claims {
    fn held_elsewhere(&self) -> Result<HashSet<OutPoint>, String> {
        self.held_by_others()
    }

    fn hold(&self, coins: &[OutPoint], seconds: u64) -> Result<bool, String> {
        self.hold_until(coins, unix_now().saturating_add(seconds))
    }

    fn take_address(&self, address: &Address) -> Result<bool, String> {
        self.take(address)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use vortex_ng_core::bitcoin::Txid;
    use vortex_ng_core::bitcoin::hashes::Hash;

    use super::*;

    fn wallet_in_new_dir(name: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "vortex-ng-claims-{name}-{}-{:016x}",
            std::process::id(),
            vortex_ng_core::tx::random_u64()
        ));
        std::fs::create_dir(&dir).unwrap();
        let wallet = dir.join("wallet.json");
        (dir, wallet)
    }

    fn coin(byte: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([byte; 32]),
            vout: u32::from(byte),
        }
    }

    #[test]
    fn a_coin_one_command_holds_is_refused_to_another_until_released_or_expired() {
        let (dir, wallet) = wallet_in_new_dir("coins");
        // Two commands on one wallet, as two processes would open it.
        let (maker, pool) = (
            Claims::open(&wallet).unwrap(),
            Claims::open(&wallet).unwrap(),
        );
        let now = unix_now();
        assert!(pool.hold_until(&[coin(1)], now + 600).unwrap());
        assert_eq!(maker.held_by_others().unwrap(), HashSet::from([coin(1)]));
        assert!(
            pool.held_by_others().unwrap().is_empty(),
            "its own hold is not another's"
        );
        // The maker cannot hold it, nor a set with it in, and holds nothing of that set.
        assert!(!maker.hold_until(&[coin(2), coin(1)], now + 300).unwrap());
        assert!(pool.held_by_others().unwrap().is_empty());
        assert!(maker.hold_until(&[coin(2)], now + 300).unwrap());
        assert_eq!(pool.held_by_others().unwrap(), HashSet::from([coin(2)]));
        // Released, it is free again.
        pool.release(&[coin(1)]).unwrap();
        assert!(maker.hold_until(&[coin(1)], now + 300).unwrap());
        // An expired hold counts for nothing, and goes when the file is next written.
        assert!(pool.hold_until(&[coin(3)], now.saturating_sub(1)).unwrap());
        assert!(!maker.held_by_others().unwrap().contains(&coin(3)));
        let file = dir.join("wallet.json.claims");
        assert!(
            !std::fs::read_to_string(&file)
                .unwrap()
                .contains(&coin(3).to_string())
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_address_is_handed_out_once_across_commands() {
        let (dir, wallet) = wallet_in_new_dir("addresses");
        let seed = vortex_ng_wallet::Seed::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
            vortex_ng_core::bitcoin::Network::Regtest,
        )
        .unwrap();
        let pit = vortex_ng_core::offer::Pit::Sw0;
        // Each process derives the wallet anew, so both would start at the same index.
        let mut first = PitWallet::new(&seed, pit).unwrap();
        let mut second = PitWallet::new(&seed, pit).unwrap();
        let (a, b) = (
            Claims::open(&wallet).unwrap(),
            Claims::open(&wallet).unwrap(),
        );
        let one = a.fresh_address(&mut first, 1, false).unwrap();
        let two = b.fresh_address(&mut second, 1, false).unwrap();
        assert_ne!(one, two);
        assert_eq!(
            two,
            PitWallet::new(&seed, pit)
                .unwrap()
                .peek_address(1, false, 1)
                .unwrap()
        );
        // The change chain is its own.
        let change = a.fresh_address(&mut first, 1, true).unwrap();
        assert_eq!(
            change,
            PitWallet::new(&seed, pit)
                .unwrap()
                .peek_address(1, true, 0)
                .unwrap()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_or_linked_claims_file_is_refused() {
        let (dir, wallet) = wallet_in_new_dir("damage");
        let file = dir.join("wallet.json.claims");
        for damaged in [
            "coin nonsense ab 1\n".to_string(),
            format!("coin {} xyz 1\n", coin(1)),
            format!("coin {} ab soon\n", coin(1)),
            "address\n".to_string(),
            "address bc1q!\n".to_string(),
            "hold it\n".to_string(),
        ] {
            std::fs::write(&file, &damaged).unwrap();
            let refused = Claims::open(&wallet).err().unwrap();
            assert!(
                refused.contains("line 1 is not a claim"),
                "{damaged}: {refused}"
            );
        }
        std::fs::remove_file(&file).unwrap();
        let elsewhere = dir.join("elsewhere");
        std::fs::write(&elsewhere, "").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &file).unwrap();
        assert!(Claims::open(&wallet).err().unwrap().contains("not a file"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
