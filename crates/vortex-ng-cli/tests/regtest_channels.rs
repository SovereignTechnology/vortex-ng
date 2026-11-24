//! The commands on each message channel, chosen with `--relays`, `--directories` and `--irc`.
//!
//! Two `vortex-ng maker` processes serve a Nostr relay, an onion directory node and an IRC server at once.
//! `vortex-ng orderbook` finds them on each channel and says which, and `vortex-ng coinjoin` takes one round
//! on each channel and one on all three.
//!
//! Nobody reaches a server directly: each is known by a name only the test's SOCKS proxy resolves.
//!
//! The round test is skipped unless `VORTEX_NG_REGTEST_RPC` and `VORTEX_NG_REGTEST_COOKIE` are set
//! (`tools/itest/run.sh` sets them). The refusals outside regtest need no node.

// A test: a failed step should panic with its error.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::MockRelay;
use vortex_ng_chain::{Auth, CoreRpc};
use vortex_ng_core::bitcoin::{Address, Network, OutPoint, Txid};
use vortex_ng_core::tx::random_u64;
use vortex_ng_irc::testing::TestIrc;
use vortex_ng_nostr::testing::AuthSocks;
use vortex_ng_onion::testing::TestDirectory;

const AMOUNT: u64 = 500_000;
const MAKERS: usize = 2;
/// One round on each channel, and one on all three.
const ROUNDS: usize = 4;

/// The maker processes: stopped when the test ends, however it ends.
struct Makers(Vec<Child>);

impl Drop for Makers {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vortex-ng"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn vortex(args: &[&str]) -> Output {
    let output = run(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// A directory of its own, with a password file only its owner can read.
fn workspace(name: &str) -> (PathBuf, String) {
    let dir = std::env::temp_dir().join(format!(
        "vortex-ng-cli-{name}-{}-{:016x}",
        std::process::id(),
        random_u64()
    ));
    std::fs::create_dir(&dir).unwrap();
    let password = dir.join("password");
    std::fs::write(&password, "a test password").unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
    let password = password.to_str().unwrap().to_string();
    (dir, password)
}

fn new_wallet(wallet: &str, network: &str, password: &str) {
    vortex(&[
        "wallet",
        "new",
        "--wallet",
        wallet,
        "--network",
        network,
        "--password-file",
        password,
    ]);
}

/// The wallet's first `count` receiving addresses.
fn addresses(wallet: &str, password: &str, count: usize) -> Vec<Address> {
    let how_many = count.to_string();
    let listing = vortex(&[
        "wallet",
        "addresses",
        "--wallet",
        wallet,
        "--count",
        &how_many,
        "--password-file",
        password,
    ]);
    let listing = String::from_utf8(listing.stdout).unwrap();
    let found: Vec<Address> = listing
        .lines()
        .skip(1)
        .take(count)
        .map(|line| {
            Address::from_str(line.split_whitespace().nth(1).unwrap())
                .unwrap()
                .require_network(Network::Regtest)
                .unwrap()
        })
        .collect();
    assert_eq!(found.len(), count);
    found
}

fn first_address(wallet: &str, password: &str) -> Address {
    addresses(wallet, password, 1).remove(0)
}

/// The height of a maker's latest report, if that report is an offer.
fn offering_at(log: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let last = text
        .lines()
        .rev()
        .find(|line| line.contains(": offering ") || line.contains(": nothing to offer"))?;
    if !last.contains(": offering sw0absoffer ") {
        return None;
    }
    last.strip_prefix("height ")?
        .split(':')
        .next()?
        .parse()
        .ok()
}

async fn wait_for(what: &str, limit: Duration, done: impl Fn() -> bool) {
    let until = Instant::now() + limit;
    while !done() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn show(logs: &[PathBuf]) -> String {
    logs.iter()
        .map(|log| {
            format!(
                "{}\n{}",
                std::fs::read_to_string(log).unwrap_or_default(),
                std::fs::read_to_string(log.with_extension("err")).unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n---\n")
}

/// Off regtest, every command refuses the legacy channels, naming `--proxy` when it is missing, and before
/// connecting to anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_legacy_channels_are_refused_outside_regtest() {
    let proxy = AuthSocks::start().await.unwrap();
    let proxy_addr = proxy.addr().to_string();
    let (dir, password) = workspace("refused");
    let wallet = dir.join("signet.json").to_str().unwrap().to_string();
    new_wallet(&wallet, "signet", &password);

    let orderbook = vec!["orderbook", "--network", "signet"];
    let node = [
        "--rpc-url",
        "http://127.0.0.1:1",
        "--rpc-cookie-file",
        "/nonexistent",
    ];
    let mut maker = vec!["maker", "--wallet", &wallet, "--password-file", &password];
    maker.extend(node);
    maker.extend(["--fee-abs", "500"]);
    let mut coinjoin = vec![
        "coinjoin",
        "--wallet",
        &wallet,
        "--password-file",
        &password,
    ];
    coinjoin.extend(node);
    coinjoin.extend(["--amount", "500000"]);

    for command in [&orderbook, &maker, &coinjoin] {
        for channel in [
            ["--directories", "directory.test:5222"],
            ["--irc", "irc.test:6697"],
        ] {
            let mut args = command.clone();
            args.extend(channel);
            let bare = run(&args);
            let said = String::from_utf8_lossy(&bare.stderr);
            assert_eq!(bare.status.code(), Some(1), "{args:?}: {said}");
            assert!(said.contains("need `--proxy"), "{args:?}: {said}");

            args.extend(["--proxy", &proxy_addr]);
            let proxied = run(&args);
            let said = String::from_utf8_lossy(&proxied.stderr);
            assert_eq!(proxied.status.code(), Some(1), "{args:?}: {said}");
            assert!(said.contains("on regtest only"), "{args:?}: {said}");
            assert!(!said.contains("need `--proxy"), "{args:?}: {said}");
        }
    }
    assert!(proxy.seen().is_empty(), "{:?}", proxy.seen());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_commands_work_on_each_channel_through_the_proxy() {
    let (Ok(url), Ok(cookie)) = (
        std::env::var("VORTEX_NG_REGTEST_RPC"),
        std::env::var("VORTEX_NG_REGTEST_COOKIE"),
    ) else {
        println!(
            "skipped: tools/itest/run.sh sets VORTEX_NG_REGTEST_RPC and VORTEX_NG_REGTEST_COOKIE"
        );
        return;
    };
    let rpc = CoreRpc::new(
        &url,
        &Auth::CookieFile(PathBuf::from(&cookie)),
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(rpc.network().unwrap(), Network::Regtest, "regtest only");

    // The three servers, as everyone knows them: names only the proxy resolves.
    let relay = MockRelay::run().await.unwrap();
    let listening = relay.url().await.to_string();
    let relay_port = listening
        .trim_end_matches('/')
        .rsplit(':')
        .next()
        .unwrap()
        .to_string();
    let directory = TestDirectory::start("regtest", None).await;
    let irc = TestIrc::start(Some("TestNet")).await;
    let proxy = AuthSocks::start().await.unwrap();
    let proxy_addr = proxy.addr().to_string();
    let relay_at = format!("relay.test:{relay_port}");
    let directory_at = format!("directory.test:{}", directory.directory().port);
    let irc_at = format!("irc.test:{}", irc.server().port);
    let relay_url = format!("ws://{relay_at}");
    let irc_url = format!("irc://{irc_at}");
    let irc_label = format!("irc {irc_at}");

    let on_nostr = ["--relays", relay_url.as_str()];
    let on_onion = ["--directories", directory_at.as_str()];
    let on_irc = ["--irc", irc_url.as_str()];
    let on_all: Vec<&str> = [on_nostr, on_onion, on_irc].concat();
    let each = [
        ("Nostr", on_nostr, "nostr"),
        ("onion", on_onion, "onion"),
        ("IRC", on_irc, irc_label.as_str()),
    ];

    // Wallet files made by the command line: each maker with one coin, the taker with one per round.
    let (dir, password) = workspace("channels");
    let file = |name: &str| dir.join(name).to_str().unwrap().to_string();
    let wallets: Vec<String> = (0..MAKERS)
        .map(|i| file(&format!("maker{i}.json")))
        .collect();
    for wallet in &wallets {
        new_wallet(wallet, "regtest", &password);
        rpc.generate_to_address(1, &first_address(wallet, &password))
            .unwrap();
    }
    let taker = file("taker.json");
    new_wallet(&taker, "regtest", &password);
    // Each coin at an address of its own: a commitment belongs to a key, so coins on one address share
    // their three.
    for to_taker in addresses(&taker, &password, ROUNDS) {
        rpc.generate_to_address(1, &to_taker).unwrap();
    }
    let sink = file("sink.json");
    new_wallet(&sink, "regtest", &password);
    let sink = first_address(&sink, &password);
    rpc.generate_to_address(100, &sink).unwrap();

    // The maker processes, on all three channels at once.
    let logs: Vec<PathBuf> = (0..MAKERS)
        .map(|i| dir.join(format!("maker{i}.log")))
        .collect();
    let mut makers = Makers(Vec::new());
    for (wallet, log) in wallets.iter().zip(&logs) {
        let out = std::fs::File::create(log).unwrap();
        let err = std::fs::File::create(log.with_extension("err")).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_vortex-ng"))
            .args([
                "maker",
                "--wallet",
                wallet,
                "--password-file",
                &password,
                "--rpc-url",
                &url,
                "--rpc-cookie-file",
                &cookie,
                "--fee-abs",
                "500",
                "--min-size",
                "10000",
                "--upkeep",
                "2",
                "--proxy",
                &proxy_addr,
            ])
            .args(&on_all)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .spawn()
            .unwrap();
        makers.0.push(child);
    }
    wait_for(
        "both makers' first offers",
        Duration::from_secs(120),
        || logs.iter().all(|log| offering_at(log).is_some()),
    )
    .await;

    // `orderbook` finds both makers on each channel, and says which channel.
    for (name, channel, label) in &each {
        let mut args = vec![
            "orderbook",
            "--proxy",
            &proxy_addr,
            "--network",
            "regtest",
            "--wait",
            "8",
        ];
        args.extend(channel);
        let listing = String::from_utf8(vortex(&args).stdout).unwrap();
        let ending = format!(" {label}");
        assert_eq!(
            listing
                .lines()
                .filter(|line| line.contains(" sw0absoffer ") && line.trim_end().ends_with(&ending))
                .count(),
            MAKERS,
            "{name}: {listing}\n{}",
            show(&logs)
        );
    }
    // On all three at once, a maker is listed once: it is one nick.
    let mut args = vec![
        "orderbook",
        "--proxy",
        &proxy_addr,
        "--network",
        "regtest",
        "--wait",
        "8",
    ];
    args.extend(&on_all);
    let listing = String::from_utf8(vortex(&args).stdout).unwrap();
    assert_eq!(
        listing
            .lines()
            .filter(|line| line.contains(" sw0absoffer "))
            .count(),
        MAKERS,
        "{listing}"
    );
    println!("orderbook found both makers on each channel");

    // A round on each channel, then one on all three.
    let amount = AMOUNT.to_string();
    let rounds: Vec<(&str, Vec<&str>)> = each
        .iter()
        .map(|(name, channel, _)| (*name, channel.to_vec()))
        .chain([("all three", on_all.clone())])
        .collect();
    assert_eq!(rounds.len(), ROUNDS);
    for (name, channels) in &rounds {
        let mut args = vec![
            "coinjoin",
            "--proxy",
            &proxy_addr,
            "--wallet",
            &taker,
            "--password-file",
            &password,
            "--amount",
            &amount,
            "--makers",
            "2",
            "--fee-rate",
            "2",
            "--wait",
            "8",
            "--rpc-url",
            &url,
            "--rpc-cookie-file",
            &cookie,
            "--yes",
            "--allow-bondless-fees",
        ];
        args.extend(channels);
        let round = run(&args);
        assert!(
            round.status.success(),
            "{name}: {}\n{}",
            String::from_utf8_lossy(&round.stderr),
            show(&logs)
        );
        let said = String::from_utf8(round.stdout).unwrap();
        let txid = said
            .lines()
            .find_map(|line| line.strip_prefix("Broadcast "))
            .expect("the broadcast txid");
        let txid = Txid::from_str(txid).unwrap();
        rpc.generate_to_address(1, &sink).unwrap();
        let confirmed = rpc
            .utxo(&OutPoint { txid, vout: 0 })
            .unwrap()
            .expect("the round's first output, unspent");
        assert_eq!(confirmed.confirmations, 1);
        println!("{name}: `vortex-ng coinjoin` confirmed {txid}");

        // Each maker's only coin is now one this round paid it: wait until it offers that one, then let the
        // taker's change age enough to commit to.
        let tip = rpc.tip_height().unwrap();
        wait_for(
            "both makers' offers after the round",
            Duration::from_secs(120),
            || {
                logs.iter()
                    .all(|log| offering_at(log).is_some_and(|height| height >= tip))
            },
        )
        .await;
        rpc.generate_to_address(5, &sink).unwrap();
    }

    // The wallet's view: every round's amount in the next mixdepth.
    let balance = vortex(&[
        "balance",
        "--wallet",
        &taker,
        "--password-file",
        &password,
        "--rpc-url",
        &url,
        "--rpc-cookie-file",
        &cookie,
    ]);
    let balance = String::from_utf8(balance.stdout).unwrap();
    let mixed = balance
        .lines()
        .find(|line| line.starts_with("mixdepth 1:"))
        .unwrap_or_else(|| panic!("mixdepth 1 in\n{balance}"));
    let total = AMOUNT * ROUNDS as u64;
    assert!(
        mixed.contains(&format!(" {total} sat in {ROUNDS} coin(s)")),
        "{balance}"
    );

    // Everything went through the proxy, to the three servers by name, and no maker connected directly.
    let reached: BTreeSet<String> = proxy.seen().into_iter().map(|(_, to)| to).collect();
    let expected: BTreeSet<String> = [relay_at, directory_at.clone(), irc_at.clone()]
        .into_iter()
        .collect();
    assert_eq!(reached, expected);
    assert!(!show(&logs).contains("connecting directly"));

    for child in &mut makers.0 {
        assert!(
            child.try_wait().unwrap().is_none(),
            "a maker exited\n{}",
            show(&logs)
        );
    }
    drop(makers);
    let _ = std::fs::remove_dir_all(&dir);
    println!("The commands: {ROUNDS} CoinJoins confirmed across Nostr, onion and IRC");
}
