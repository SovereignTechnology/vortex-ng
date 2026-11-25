//! What the commands using one wallet share, kept beside the wallet file as `<wallet>.claims` (issue #51): the
//! coins each holds, so that `maker`, `coinjoin` and a joinstr `pool` round never put one coin into two
//! transactions, and the addresses handed out, so that no two rounds pay one address.
//!
//! One claim per line:
//!
//! - `coin <txid>:<vout> <holder> <until>`: held by the process whose random token is `holder` until the unix
//!   time `until`;
//! - `address <pit> <mixdepth> receive|change <index>`: the highest address index handed out on that chain,
//!   for good. The wallet lives in memory and learns which addresses are used from the chain, so an address
//!   given to a round that failed, or whose transaction is not confirmed yet, looks unused, and the next round
//!   would get it again: two transactions paying one script, which links them for good, and makers that saw a
//!   failed round could pick out the taker's outputs in the retry. Every wallet opened from the file starts
//!   past what is recorded here, whichever command handed it out.
//!
//! Every read and write happens under an exclusive lock on the file, so commands in different processes see
//! each other's claims at once. Expired coin claims are dropped whenever the file is rewritten. A line that is
//! not a claim is an error: read as empty, the file would let a coin into two rounds and an address into two
//! transactions. Indices and outpoints only: nothing here could spend.

use std::collections::{HashMap, HashSet};
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
use vortex_ng_wallet::{MIXDEPTHS, PitWallet};

/// A claims file this large is not one this program wrote.
const MAX_BYTES: u64 = 16 * 1024 * 1024;
/// BIP32's first hardened index: the chains here are unhardened.
const MAX_INDEX: u32 = (1 << 31) - 1;

/// One process's view of the claims file of a wallet.
pub(crate) struct Claims {
    path: PathBuf,
    /// This process's token: which coin claims are its own.
    holder: String,
}

/// A pit, a mixdepth and a chain (`true`: change).
type Chain = (String, u32, bool);

#[derive(Default)]
struct State {
    coins: Vec<(OutPoint, String, u64)>,
    /// The highest address index handed out, per chain.
    issued: HashMap<Chain, u32>,
}

fn digits(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
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
                ["address", pit, mixdepth, chain, index] => {
                    let internal = match *chain {
                        "receive" => Some(false),
                        "change" => Some(true),
                        _ => None,
                    };
                    match (
                        matches!(*pit, "sw0" | "tr0" | "wsh0"),
                        digits(mixdepth).filter(|m| *m < MIXDEPTHS),
                        internal,
                        digits(index).filter(|i| *i <= MAX_INDEX),
                    ) {
                        (true, Some(mixdepth), Some(internal), Some(index)) => {
                            let entry = state
                                .issued
                                .entry((pit.to_string(), mixdepth, internal))
                                .or_insert(index);
                            *entry = (*entry).max(index);
                            Some(())
                        }
                        _ => None,
                    }
                }
                // An earlier version of this file named the addresses themselves: they only ever stood for
                // addresses the wallet could be handed again, which the indices now do better.
                ["address", address]
                    if !address.is_empty()
                        && address.bytes().all(|b| b.is_ascii_alphanumeric()) =>
                {
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
        let mut chains: Vec<_> = self.issued.iter().collect();
        chains.sort();
        for ((pit, mixdepth, internal), index) in chains {
            let chain = if *internal { "change" } else { "receive" };
            text.push_str(&format!("address {pit} {mixdepth} {chain} {index}\n"));
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
    /// The claims file of the wallet file `wallet`. Nothing is created until a claim is made, so a command
    /// that only reads (`balance`, `coins`) works from a directory it cannot write to.
    pub(crate) fn open(wallet: &Path) -> Result<Claims, String> {
        let mut path = wallet.as_os_str().to_owned();
        path.push(".claims");
        let claims = Claims {
            path: PathBuf::from(path),
            holder: random_bytes::<8>().to_lower_hex_string(),
        };
        // A file that is not a claims file is an error now, not at the first claim.
        claims.with_lock(false, |_, _| ((), false))?;
        Ok(claims)
    }

    /// Run `change` on the claims as they stand, under the file's lock. It returns its result and whether the
    /// file is to be rewritten (expired claims go then too). With `create`, a missing file is made; without,
    /// it is taken as empty and never written.
    fn with_lock<T>(
        &self,
        create: bool,
        change: impl FnOnce(&mut State, u64) -> (T, bool),
    ) -> Result<T, String> {
        let shown = |e: &dyn std::fmt::Display| format!("{}: {e}", self.path.display());
        match std::fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !create {
                    return Ok(change(&mut State::default(), unix_now()).0);
                }
            }
            Err(e) => return Err(shown(&e)),
            // A symbolic link is not followed: it is not a file this program wrote.
            Ok(meta) if !meta.is_file() => return Err(shown(&"not a file")),
            Ok(_) => {}
        }
        let mut file: File = OpenOptions::new()
            .read(true)
            .write(create)
            .create(create)
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
            if !create {
                return Err(shown(&"a write on a file opened to read"));
            }
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
        self.with_lock(true, |state, now| {
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
        self.with_lock(true, |state, _| {
            state
                .coins
                .retain(|(coin, who, _)| !(who == &holder && coins.contains(coin)));
            ((), true)
        })
    }

    /// The coins other processes hold now.
    pub(crate) fn held_by_others(&self) -> Result<HashSet<OutPoint>, String> {
        let holder = self.holder.clone();
        self.with_lock(false, |state, now| {
            (state.held_elsewhere(&holder, now), false)
        })
    }

    /// Move `wallet` past every address any command has handed out, before it syncs, so that the scan watches
    /// them too.
    pub(crate) fn apply(&self, wallet: &mut PitWallet) -> Result<(), String> {
        let pit = wallet.pit().prefix();
        self.with_lock(false, |state, _| {
            let done = state
                .issued
                .iter()
                .filter(|((logged, _, _), _)| logged == pit)
                .try_for_each(|((_, mixdepth, internal), index)| {
                    wallet
                        .reveal_through(*mixdepth, *internal, *index)
                        .map_err(|e| e.to_string())
                });
            (done, false)
        })?
    }

    /// The next address of `mixdepth`'s receiving or change chain that no command has handed out, written
    /// down on disk before it is returned.
    pub(crate) fn fresh_address(
        &self,
        wallet: &mut PitWallet,
        mixdepth: u32,
        internal: bool,
    ) -> Result<Address, String> {
        let key: Chain = (wallet.pit().prefix().to_string(), mixdepth, internal);
        self.with_lock(true, |state, _| {
            // Another process may have handed out more since this wallet was opened.
            if let Some(highest) = state.issued.get(&key)
                && let Err(e) = wallet.reveal_through(mixdepth, internal, *highest)
            {
                return (Err(e.to_string()), false);
            }
            match wallet.next_address_indexed(mixdepth, internal) {
                Ok((index, address)) => {
                    let entry = state.issued.entry(key).or_insert(index);
                    *entry = (*entry).max(index);
                    (Ok(address), true)
                }
                Err(e) => (Err(e.to_string()), false),
            }
        })?
    }
}

impl WalletClaims for Claims {
    fn held_elsewhere(&self) -> Result<HashSet<OutPoint>, String> {
        self.held_by_others()
    }

    fn hold(&self, coins: &[OutPoint], seconds: u64) -> Result<bool, String> {
        self.hold_until(coins, unix_now().saturating_add(seconds))
    }

    fn fresh_address(
        &self,
        wallet: &mut PitWallet,
        mixdepth: u32,
        change: bool,
    ) -> Result<Address, String> {
        Claims::fresh_address(self, wallet, mixdepth, change)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use vortex_ng_core::bitcoin::Network;
    use vortex_ng_core::bitcoin::Txid;
    use vortex_ng_core::bitcoin::hashes::Hash;
    use vortex_ng_core::offer::Pit;
    use vortex_ng_wallet::Seed;

    use super::*;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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

    /// The wallet as a process derives it anew: from the seed, knowing nothing of what others handed out.
    fn fresh_wallet() -> PitWallet {
        let seed = Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap();
        PitWallet::new(&seed, Pit::Sw0).unwrap()
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
        assert!(maker.hold_until(&[coin(4)], now + 300).unwrap());
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
    fn an_address_is_handed_out_once_across_commands_and_runs() {
        let (dir, wallet) = wallet_in_new_dir("addresses");
        // Each process derives the wallet anew, so both would start at the same index.
        let (mut first, mut second) = (fresh_wallet(), fresh_wallet());
        let (a, b) = (
            Claims::open(&wallet).unwrap(),
            Claims::open(&wallet).unwrap(),
        );
        let one = a.fresh_address(&mut first, 1, false).unwrap();
        let two = b.fresh_address(&mut second, 1, false).unwrap();
        let reference = fresh_wallet();
        assert_eq!(one, reference.peek_address(1, false, 0).unwrap());
        assert_eq!(
            two,
            reference.peek_address(1, false, 1).unwrap(),
            "the second process was moved past what the first handed out"
        );
        // The change chain and another mixdepth are their own.
        assert_eq!(
            a.fresh_address(&mut first, 1, true).unwrap(),
            reference.peek_address(1, true, 0).unwrap()
        );
        assert_eq!(
            b.fresh_address(&mut second, 2, false).unwrap(),
            reference.peek_address(2, false, 0).unwrap()
        );

        // A later run starts past all of it, and so does the wallet `apply` moves before it syncs.
        let mut later = fresh_wallet();
        Claims::open(&wallet).unwrap().apply(&mut later).unwrap();
        assert_eq!(
            later.next_receive_address(1).unwrap(),
            reference.peek_address(1, false, 2).unwrap()
        );
        // The file keeps one line per chain, however many addresses were handed out.
        let lines = std::fs::read_to_string(dir.join("wallet.json.claims"))
            .unwrap()
            .lines()
            .count();
        assert_eq!(lines, 3, "receive 1, change 1, receive 2");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn what_has_been_handed_out_costs_nothing_to_skip() {
        let (dir, wallet) = wallet_in_new_dir("many");
        let claims = Claims::open(&wallet).unwrap();
        let mut busy = fresh_wallet();
        for _ in 0..3_000 {
            claims.fresh_address(&mut busy, 0, false).unwrap();
        }
        // A new process, which knows none of it: one call, one address, past the 3,000.
        let mut restarted = fresh_wallet();
        let next = Claims::open(&wallet)
            .unwrap()
            .fresh_address(&mut restarted, 0, false)
            .unwrap();
        assert_eq!(next, fresh_wallet().peek_address(0, false, 3_000).unwrap());
        assert_eq!(
            std::fs::read_to_string(dir.join("wallet.json.claims"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_command_that_only_reads_creates_nothing() {
        let (dir, wallet) = wallet_in_new_dir("reads");
        let claims = Claims::open(&wallet).unwrap();
        let mut reader = fresh_wallet();
        claims.apply(&mut reader).unwrap();
        assert!(claims.held_by_others().unwrap().is_empty());
        assert!(!dir.join("wallet.json.claims").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_or_linked_claims_file_is_refused_and_an_old_one_is_read() {
        let (dir, wallet) = wallet_in_new_dir("damage");
        let file = dir.join("wallet.json.claims");
        for damaged in [
            "coin nonsense ab 1\n".to_string(),
            format!("coin {} xyz 1\n", coin(1)),
            format!("coin {} ab soon\n", coin(1)),
            "address\n".to_string(),
            "address bc1q!\n".to_string(),
            "address sw0 9 receive 1\n".to_string(),
            "address sw0 0 sideways 1\n".to_string(),
            "address xx0 0 receive 1\n".to_string(),
            "address sw0 0 receive 2147483648\n".to_string(),
            "address sw0 0 receive -1\n".to_string(),
            "hold it\n".to_string(),
        ] {
            std::fs::write(&file, &damaged).unwrap();
            let refused = Claims::open(&wallet).err().unwrap();
            assert!(
                refused.contains("line 1 is not a claim"),
                "{damaged}: {refused}"
            );
        }
        // Addresses named outright, as an earlier version wrote them, are read and let go.
        std::fs::write(&file, "address bcrt1qexample\naddress sw0 0 receive 4\n").unwrap();
        let mut moved = fresh_wallet();
        Claims::open(&wallet).unwrap().apply(&mut moved).unwrap();
        assert_eq!(
            moved.next_receive_address(0).unwrap(),
            fresh_wallet().peek_address(0, false, 5).unwrap()
        );
        std::fs::remove_file(&file).unwrap();
        let elsewhere = dir.join("elsewhere");
        std::fs::write(&elsewhere, "").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &file).unwrap();
        assert!(Claims::open(&wallet).err().unwrap().contains("not a file"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
