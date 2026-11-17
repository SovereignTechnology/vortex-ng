//! The `vortex-ng wallet` commands, run as a user would run them: the built binary, files on disk, no
//! terminal.

// A test: a failed step should panic with its error.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use vortex_ng_core::bitcoin::Network;
use vortex_ng_core::offer::Pit;
use vortex_ng_core::tx::random_u64;
use vortex_ng_wallet::{PitWallet, Seed};

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// A directory of this test's own, removed afterwards.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!(
            "vortex-ng-cli-{name}-{}-{:016x}",
            std::process::id(),
            random_u64()
        ));
        std::fs::create_dir(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_string()
    }

    /// A file only we can read, as secrets must be.
    fn secret(&self, name: &str, contents: &str) -> String {
        let path = self.path(name);
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `vortex-ng` with no terminal on its standard input.
fn vortex(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vortex-ng"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn out(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn err(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

/// The addresses a listing printed (`<index>  <address>` lines).
fn listed(output: &Output) -> Vec<String> {
    assert!(output.status.success(), "{}", err(output));
    out(output)
        .lines()
        .skip(1)
        .map(|line| line.split_whitespace().nth(1).unwrap().to_string())
        .collect()
}

fn derived(
    words: &str,
    passphrase: &str,
    pit: Pit,
    mixdepth: u32,
    change: bool,
    count: u32,
) -> Vec<String> {
    let seed = Seed::from_mnemonic(words, passphrase, Network::Regtest).unwrap();
    let wallet = PitWallet::new(&seed, pit).unwrap();
    (0..count)
        .map(|i| {
            wallet
                .peek_address(mixdepth, change, i)
                .unwrap()
                .to_string()
        })
        .collect()
}

#[test]
fn a_new_wallet_is_written_once_and_read_back() {
    let scratch = Scratch::new("new");
    let (wallet, password) = (
        scratch.path("wallet.json"),
        scratch.secret("pw", "hunter2 hunter2\n"),
    );

    let made = vortex(&[
        "wallet",
        "new",
        "--wallet",
        &wallet,
        "--network",
        "regtest",
        "--password-file",
        &password,
    ]);
    assert!(made.status.success(), "{}", err(&made));
    let printed = out(&made);
    let words = printed
        .lines()
        .find(|line| line.starts_with("  "))
        .expect("the seed words")
        .trim()
        .to_string();
    assert_eq!(words.split(' ').count(), 12);

    // The file: private, and without the words.
    assert_eq!(
        std::fs::metadata(&wallet).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let on_disk = std::fs::read_to_string(&wallet).unwrap();
    assert!(on_disk.contains("\"format\": \"vortex-ng-wallet\""));
    assert!(!on_disk.contains(&words));

    let info = vortex(&["wallet", "info", "--wallet", &wallet]);
    assert!(info.status.success(), "{}", err(&info));
    assert!(out(&info).contains("network:  regtest"));
    assert!(out(&info).contains("argon2id, 64 MiB, 3 passes"));

    // Its addresses are the ones the words derive, in every pit.
    let listing = vortex(&[
        "wallet",
        "addresses",
        "--wallet",
        &wallet,
        "--count",
        "3",
        "--password-file",
        &password,
    ]);
    assert_eq!(listed(&listing), derived(&words, "", Pit::Sw0, 0, false, 3));
    assert!(out(&listing).starts_with("sw0 mixdepth 0, receive addresses"));
    for (name, pit) in [("tr0", Pit::Tr0), ("wsh0", Pit::Wsh0)] {
        let listing = vortex(&[
            "wallet",
            "addresses",
            "--wallet",
            &wallet,
            "--pit",
            name,
            "--mixdepth",
            "2",
            "--change",
            "--count=2",
            "--password-file",
            &password,
        ]);
        assert_eq!(
            listed(&listing),
            derived(&words, "", pit, 2, true, 2),
            "{name}"
        );
    }

    // A second `new` or `restore` on the same path changes nothing.
    let mnemonic = scratch.secret("words", WORDS);
    for again in [
        vortex(&[
            "wallet",
            "new",
            "--wallet",
            &wallet,
            "--network",
            "regtest",
            "--password-file",
            &password,
        ]),
        vortex(&[
            "wallet",
            "restore",
            "--wallet",
            &wallet,
            "--network",
            "regtest",
            "--mnemonic-file",
            &mnemonic,
            "--password-file",
            &password,
        ]),
    ] {
        assert_eq!(again.status.code(), Some(1));
        assert!(err(&again).contains("never overwritten"), "{}", err(&again));
        assert_eq!(out(&again), "");
    }
    assert_eq!(std::fs::read_to_string(&wallet).unwrap(), on_disk);
}

#[test]
fn restoring_gives_the_same_wallet() {
    let scratch = Scratch::new("restore");
    let password = scratch.secret("pw", "a password");
    let mnemonic = scratch.secret("words", &format!("{WORDS}\n"));
    let phrase = scratch.secret("phrase", "TREZOR\n");

    let plain = scratch.path("plain.json");
    let made = vortex(&[
        "wallet",
        "restore",
        "--wallet",
        &plain,
        "--network",
        "regtest",
        "--mnemonic-file",
        &mnemonic,
        "--birthday",
        "150",
        "--password-file",
        &password,
    ]);
    assert!(made.status.success(), "{}", err(&made));
    let expected = derived(WORDS, "", Pit::Sw0, 0, false, 2);
    assert!(out(&made).contains(&expected[0]), "{}", out(&made));
    assert!(!out(&made).contains("abandon"));
    let listing = vortex(&[
        "wallet",
        "addresses",
        "--wallet",
        &plain,
        "--count",
        "2",
        "--password-file",
        &password,
    ]);
    assert_eq!(listed(&listing), expected);
    assert!(out(&vortex(&["wallet", "info", "--wallet", &plain])).contains("birthday: block 150"));

    // With a BIP39 passphrase it is another wallet.
    let extended = scratch.path("extended.json");
    let made = vortex(&[
        "wallet",
        "restore",
        "--wallet",
        &extended,
        "--network",
        "regtest",
        "--mnemonic-file",
        &mnemonic,
        "--bip39-passphrase-file",
        &phrase,
        "--password-file",
        &password,
    ]);
    assert!(made.status.success(), "{}", err(&made));
    let listing = vortex(&[
        "wallet",
        "addresses",
        "--wallet",
        &extended,
        "--count",
        "2",
        "--password-file",
        &password,
    ]);
    assert_eq!(
        listed(&listing),
        derived(WORDS, "TREZOR", Pit::Sw0, 0, false, 2)
    );
    assert_ne!(listed(&listing), expected);

    // Words that are not a mnemonic make no wallet.
    let wrong = scratch.secret("wrong", "abandon abandon abandon");
    let none = scratch.path("none.json");
    let made = vortex(&[
        "wallet",
        "restore",
        "--wallet",
        &none,
        "--network",
        "regtest",
        "--mnemonic-file",
        &wrong,
        "--password-file",
        &password,
    ]);
    assert_eq!(made.status.code(), Some(1));
    assert!(!std::path::Path::new(&none).exists());
}

#[test]
fn a_bond_address_is_the_wallets() {
    let scratch = Scratch::new("bond");
    let (wallet, password) = (
        scratch.path("wallet.json"),
        scratch.secret("pw", "a password"),
    );
    let mnemonic = scratch.secret("words", WORDS);
    let made = vortex(&[
        "wallet",
        "restore",
        "--wallet",
        &wallet,
        "--network",
        "regtest",
        "--mnemonic-file",
        &mnemonic,
        "--password-file",
        &password,
    ]);
    assert!(made.status.success(), "{}", err(&made));

    let seed = Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap();
    let expected = PitWallet::new(&seed, Pit::Sw0)
        .unwrap()
        .bond_address(959)
        .unwrap()
        .to_string();
    let bond = vortex(&[
        "wallet",
        "bond-address",
        "--wallet",
        &wallet,
        "--locktime",
        "2099-12",
        "--password-file",
        &password,
    ]);
    assert!(bond.status.success(), "{}", err(&bond));
    // Only the address on standard output; the warning beside it.
    assert_eq!(out(&bond).trim_end(), expected);
    assert!(err(&bond).contains("cannot be moved before 2099-12-01"));
    assert!(!err(&bond).contains("has passed"));
    assert!(err(&bond).contains("years from now"), "{}", err(&bond));

    let past = vortex(&[
        "wallet",
        "bond-address",
        "--wallet",
        &wallet,
        "--locktime",
        "2020-01",
        "--password-file",
        &password,
    ]);
    assert!(past.status.success());
    assert!(err(&past).contains("has passed"));

    for locktime in ["2019-12", "2100-01", "2030-13", "2030-1", "30-01", "2030"] {
        let refused = vortex(&[
            "wallet",
            "bond-address",
            "--wallet",
            &wallet,
            "--locktime",
            locktime,
            "--password-file",
            &password,
        ]);
        assert_eq!(refused.status.code(), Some(2), "{locktime}");
        assert_eq!(out(&refused), "");
    }
}

#[test]
fn secrets_are_guarded() {
    let scratch = Scratch::new("guard");
    let (wallet, password) = (
        scratch.path("wallet.json"),
        scratch.secret("pw", "the password"),
    );
    let made = vortex(&[
        "wallet",
        "new",
        "--wallet",
        &wallet,
        "--network",
        "regtest",
        "--password-file",
        &password,
    ]);
    assert!(made.status.success(), "{}", err(&made));

    // The wrong password opens nothing and prints nothing.
    let other = scratch.secret("other", "another password");
    let refused = vortex(&[
        "wallet",
        "addresses",
        "--wallet",
        &wallet,
        "--password-file",
        &other,
    ]);
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(out(&refused), "");
    assert!(
        err(&refused).contains("wrong password"),
        "{}",
        err(&refused)
    );

    // A password file others can read is refused, before any wallet is made.
    let loose = scratch.secret("loose", "the password");
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    let unmade = scratch.path("unmade.json");
    let refused = vortex(&[
        "wallet",
        "new",
        "--wallet",
        &unmade,
        "--network",
        "regtest",
        "--password-file",
        &loose,
    ]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        err(&refused).contains("readable by others"),
        "{}",
        err(&refused)
    );
    assert!(!std::path::Path::new(&unmade).exists());
    let empty = scratch.secret("empty", "\n");
    let refused = vortex(&[
        "wallet",
        "new",
        "--wallet",
        &unmade,
        "--network",
        "regtest",
        "--password-file",
        &empty,
    ]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(!std::path::Path::new(&unmade).exists());

    // Without a terminal and without a file there is no password: nothing is made, nothing is read from a pipe.
    let refused = vortex(&["wallet", "new", "--wallet", &unmade, "--network", "regtest"]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(err(&refused).contains("no terminal"), "{}", err(&refused));
    assert!(!std::path::Path::new(&unmade).exists());

    // Mainnet is off in this pre-release.
    for name in ["main", "mainnet", "bitcoin"] {
        let refused = vortex(&[
            "wallet",
            "new",
            "--wallet",
            &unmade,
            "--network",
            name,
            "--password-file",
            &password,
        ]);
        assert_eq!(refused.status.code(), Some(1), "{name}");
        assert!(
            err(&refused).contains("mainnet wallets are disabled"),
            "{}",
            err(&refused)
        );
        assert!(!std::path::Path::new(&unmade).exists());
    }

    // Something that is not a wallet file is said to be so, without asking for a password.
    let not_wallet = scratch.secret("notes", "just some notes");
    let refused = vortex(&["wallet", "addresses", "--wallet", &not_wallet]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        err(&refused).contains("not a wallet file"),
        "{}",
        err(&refused)
    );
}

#[test]
fn a_command_that_is_not_understood_shows_the_usage() {
    let scratch = Scratch::new("usage");
    let wallet = scratch.path("wallet.json");
    let cases: [&[&str]; 9] = [
        &[],
        &["walet"],
        &["wallet"],
        &["wallet", "burn"],
        &["wallet", "new", "--network", "regtest"],
        &["wallet", "new", "--wallet", &wallet],
        &["wallet", "new", "--wallet", &wallet, "--network", "moon"],
        &[
            "wallet",
            "new",
            "--wallet",
            &wallet,
            "--network",
            "regtest",
            "--words",
            "13",
        ],
        &[
            "wallet",
            "new",
            "--wallet",
            &wallet,
            "--network",
            "regtest",
            "--mnemonic",
            WORDS,
        ],
    ];
    for args in cases {
        let refused = vortex(args);
        assert_eq!(
            refused.status.code(),
            Some(2),
            "{args:?}: {}",
            err(&refused)
        );
        assert!(err(&refused).contains("Usage:"), "{args:?}");
        assert!(!std::path::Path::new(&wallet).exists());
    }
    let version = vortex(&["--version"]);
    assert!(version.status.success() && out(&version).starts_with("vortex-ng "));
    assert!(out(&vortex(&["--help"])).contains("wallet bond-address"));
}
