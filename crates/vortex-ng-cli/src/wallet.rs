//! `vortex-ng wallet …`: create, restore and read a wallet file.

use std::path::Path;

use vortex_ng_core::bitcoin::Network;
use vortex_ng_core::bond::{timenumber_locktime, timenumber_of};
use vortex_ng_core::offer::Pit;
use vortex_ng_wallet::file::{self, WalletFile};
use vortex_ng_wallet::{MIXDEPTHS, PitWallet};
use zeroize::Zeroizing;

use crate::args::Args;
use crate::{Failure, secret};

pub(crate) fn failed(why: impl std::fmt::Display) -> Failure {
    Failure::Failed(why.to_string())
}

pub(crate) fn parse(
    rest: &[String],
    valued: &[&'static str],
    flags: &[&'static str],
) -> Result<Args, Failure> {
    Args::parse(rest, valued, flags).map_err(Failure::Usage)
}

/// Run `vortex-ng wallet <command> <rest>`.
pub(crate) fn run(command: &str, rest: &[String]) -> Result<(), Failure> {
    match command {
        "new" => new(rest),
        "restore" => restore(rest),
        "info" => info(rest),
        "addresses" => addresses(rest),
        "bond-address" => bond_address(rest),
        other => Err(Failure::Usage(format!("unknown wallet command `{other}`"))),
    }
}

/// The network as people name it.
pub(crate) fn network_name(network: Network) -> &'static str {
    match network.to_core_arg() {
        "main" => "mainnet",
        "test" => "testnet",
        other => other,
    }
}

/// The network `--network` names. Mainnet is refused: this is a pre-release.
pub(crate) fn network(args: &Args) -> Result<Network, Failure> {
    let core = match args.required("network").map_err(Failure::Usage)? {
        "mainnet" | "bitcoin" => "main",
        "testnet" | "testnet3" => "test",
        other => other,
    };
    let network = Network::from_core_arg(core).map_err(|_| {
        Failure::Usage("`--network` is one of regtest, signet, testnet4, testnet".into())
    })?;
    if network == Network::Bitcoin {
        return Err(failed(
            "mainnet wallets are disabled in this pre-release: vortex-ng is unaudited",
        ));
    }
    Ok(network)
}

fn exists_error(path: &Path) -> Failure {
    failed(format!(
        "{0} (or {0}.tmp) already exists: a wallet file is never overwritten",
        path.display()
    ))
}

/// Where the new wallet goes, refused before anything is asked when something is already there.
fn new_path(args: &Args) -> Result<&Path, Failure> {
    let path = Path::new(args.required("wallet").map_err(Failure::Usage)?);
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(exists_error(path));
    }
    Ok(path)
}

/// Seal `wallet` for `password` into the new file `path`.
fn create(path: &Path, wallet: &WalletFile, password: &str) -> Result<(), Failure> {
    let sealed = wallet.seal(password).map_err(failed)?;
    file::write_new(path, &sealed).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            exists_error(path)
        } else {
            failed(format!("{}: {e}", path.display()))
        }
    })
}

/// Open the wallet `--wallet` names, asking for its password only once the file looks like a wallet.
pub(crate) fn open(args: &Args) -> Result<WalletFile, Failure> {
    let path = args.required("wallet").map_err(Failure::Usage)?;
    let here = |e: &dyn std::fmt::Display| failed(format!("{path}: {e}"));
    let text = file::read(Path::new(path)).map_err(|e| here(&e))?;
    WalletFile::header(&text).map_err(|e| here(&e))?;
    let password =
        secret::obtain("wallet password", args.get("password-file"), false).map_err(failed)?;
    WalletFile::open(&password, &text).map_err(|e| here(&e))
}

fn new(rest: &[String]) -> Result<(), Failure> {
    let args = parse(
        rest,
        &["wallet", "network", "words", "birthday", "password-file"],
        &[],
    )?;
    let path = new_path(&args)?;
    let network = network(&args)?;
    let words = args.number("words", 12, 12..=24).map_err(Failure::Usage)?;
    if words != 12 && words != 24 {
        return Err(Failure::Usage("`--words` is 12 or 24".into()));
    }
    let birthday = args
        .number("birthday", 0, 0..=u32::MAX)
        .map_err(Failure::Usage)?;
    let password =
        secret::obtain("wallet password", args.get("password-file"), true).map_err(failed)?;
    let wallet = WalletFile::generate(network, words as usize, birthday).map_err(failed)?;
    create(path, &wallet, &password)?;
    println!(
        "Wallet written to {} ({}).",
        path.display(),
        network_name(network)
    );
    println!();
    println!(
        "Write these {words} words down and keep them offline. Anyone who has them has the coins,"
    );
    println!(
        "and if the file or its password is lost they are the only way back. They are not shown again."
    );
    println!();
    println!("  {}", wallet.mnemonic());
    Ok(())
}

fn restore(rest: &[String]) -> Result<(), Failure> {
    let args = parse(
        rest,
        &[
            "wallet",
            "network",
            "mnemonic-file",
            "bip39-passphrase-file",
            "birthday",
            "password-file",
        ],
        &["bip39-passphrase"],
    )?;
    let path = new_path(&args)?;
    let network = network(&args)?;
    let birthday = args
        .number("birthday", 0, 0..=u32::MAX)
        .map_err(Failure::Usage)?;
    let mnemonic =
        secret::obtain("seed words", args.get("mnemonic-file"), false).map_err(failed)?;
    let passphrase = match args.get("bip39-passphrase-file") {
        Some(path) => secret::from_file(path).map_err(failed)?,
        None if args.flag("bip39-passphrase") => {
            secret::obtain("BIP39 passphrase", None, true).map_err(failed)?
        }
        None => Zeroizing::new(String::new()),
    };
    let wallet = WalletFile::new(network, &mnemonic, &passphrase, birthday).map_err(failed)?;
    let password =
        secret::obtain("wallet password", args.get("password-file"), true).map_err(failed)?;
    create(path, &wallet, &password)?;
    let first = PitWallet::new(&wallet.seed().map_err(failed)?, Pit::Sw0)
        .and_then(|w| w.peek_address(0, false, 0))
        .map_err(failed)?;
    println!(
        "Wallet written to {} ({}).",
        path.display(),
        network_name(network)
    );
    println!("Its first sw0 address is {first}: check it against your records.");
    Ok(())
}

fn info(rest: &[String]) -> Result<(), Failure> {
    let args = parse(rest, &["wallet"], &[])?;
    let path = args.required("wallet").map_err(Failure::Usage)?;
    let here = |e: &dyn std::fmt::Display| failed(format!("{path}: {e}"));
    let text = file::read(Path::new(path)).map_err(|e| here(&e))?;
    let header = WalletFile::header(&text).map_err(|e| here(&e))?;
    println!("network:  {}", network_name(header.network));
    println!("birthday: block {}", header.birthday);
    println!(
        "key:      argon2id, {} MiB, {} passes, {} lane(s)",
        header.kdf.memory_kib / 1024,
        header.kdf.passes,
        header.kdf.lanes
    );
    println!("Read without the password: none of this is verified until the wallet is opened.");
    Ok(())
}

/// The pit `--pit` names (`sw0` when not given), with its name.
pub(crate) fn pit(args: &Args) -> Result<(Pit, &'static str), Failure> {
    match args.get("pit").unwrap_or("sw0") {
        "sw0" => Ok((Pit::Sw0, "sw0")),
        "tr0" => Ok((Pit::Tr0, "tr0")),
        "wsh0" => Ok((Pit::Wsh0, "wsh0")),
        _ => Err(Failure::Usage("`--pit` is sw0, tr0 or wsh0".into())),
    }
}

fn addresses(rest: &[String]) -> Result<(), Failure> {
    let args = parse(
        rest,
        &["wallet", "pit", "mixdepth", "count", "password-file"],
        &["change"],
    )?;
    let (pit, pit_name) = pit(&args)?;
    let mixdepth = args
        .number("mixdepth", 0, 0..=MIXDEPTHS - 1)
        .map_err(Failure::Usage)?;
    let count = args.number("count", 5, 1..=1000).map_err(Failure::Usage)?;
    let change = args.flag("change");
    let wallet = open(&args)?;
    let pit_wallet = PitWallet::new(&wallet.seed().map_err(failed)?, pit).map_err(failed)?;
    println!(
        "{pit_name} mixdepth {mixdepth}, {} addresses from index 0 ({})",
        if change { "change" } else { "receive" },
        network_name(wallet.network())
    );
    for index in 0..count {
        let address = pit_wallet
            .peek_address(mixdepth, change, index)
            .map_err(failed)?;
        println!("{index:>4}  {address}");
    }
    Ok(())
}

/// `YYYY-MM` as (year, month).
fn month(text: &str) -> Option<(u32, u32)> {
    let (year, month) = text.split_once('-')?;
    let digits = |s: &str, len: usize| s.len() == len && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(year, 4) || !digits(month, 2) {
        return None;
    }
    Some((year.parse().ok()?, month.parse().ok()?))
}

fn bond_address(rest: &[String]) -> Result<(), Failure> {
    let args = parse(rest, &["wallet", "locktime", "password-file"], &[])?;
    let wrong =
        || Failure::Usage("`--locktime` is a month from 2020-01 to 2099-12, as YYYY-MM".into());
    let (year, month) =
        month(args.required("locktime").map_err(Failure::Usage)?).ok_or_else(wrong)?;
    let timenumber = timenumber_of(year, month).ok_or_else(wrong)?;
    let locktime = timenumber_locktime(timenumber).ok_or_else(wrong)?;
    let wallet = open(&args)?;
    let address = PitWallet::new(&wallet.seed().map_err(failed)?, Pit::Sw0)
        .and_then(|w| w.bond_address(timenumber))
        .map_err(failed)?;
    println!("{address}");
    eprintln!(
        "Coins sent to this address cannot be moved before {year}-{month:02}-01 00:00 UTC ({}).",
        network_name(wallet.network())
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let locktime = u64::from(locktime);
    if locktime <= now {
        eprintln!("That date has passed: a bond locked until then has no value.");
    } else {
        // Said in plain words, so a mistyped year is seen before coins are sent.
        let months = (locktime - now) / (30 * 86_400);
        if months >= 24 {
            eprintln!("That is about {} years from now.", months / 12);
        } else {
            eprintln!("That is about {months} months from now.");
        }
    }
    Ok(())
}
