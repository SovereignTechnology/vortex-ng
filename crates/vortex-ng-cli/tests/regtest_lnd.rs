//! A CoinJoin spending what real channel closes left in a real LND node's wallet.
//!
//! `tools/lnd-itest/drive.py` gives LND a mutual close, a force close it has swept, and the change of its
//! channel opens. Here `vortex-ng lnd-coins` must tell them apart by the node's own records, and `vortex-ng
//! coinjoin --from-lnd` must spend close coins and nothing else: LND signs, two `vortex-ng maker` processes
//! join, the outputs land in a vortex-ng wallet, and the commitment comes from a coin of that wallet which is
//! not an input of the round.
//!
//! Also here: a certificate that is not the node's is refused, so is a macaroon other users can read, and
//! so is a node on another network. A macaroon that may only read lists coins and cannot start a round, and
//! the attempt spends no commitment.
//!
//! Skipped unless `tools/lnd-itest/run.sh` set the environment.

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
use vortex_ng_core::offer::Pit;
use vortex_ng_core::tx::random_u64;
use vortex_ng_wallet::{PitWallet, Seed};

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const AMOUNT: u64 = 1_000_000;

/// The maker processes: stopped when they go out of scope, however the test ends.
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

fn ok(args: &[&str]) -> String {
    let output = run(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// A command that must fail (exit 1) saying `why`.
fn refused(args: &[&str], why: &str) {
    let output = run(args);
    let said = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{args:?}: {said}");
    assert!(said.contains(why), "{args:?} should say {why:?}: {said}");
}

fn address(text: &str) -> Address {
    Address::from_str(text)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
}

/// A coin as `lnd-coins --outpoints` prints it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Listed {
    sats: u64,
    pit: String,
    origin: String,
    outpoint: OutPoint,
}

fn listed(stdout: &str) -> Vec<Listed> {
    stdout
        .lines()
        .filter(|line| line.starts_with("  "))
        .map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            assert!(
                words.len() >= 6 && words[1] == "sat" && words[3] == "conf",
                "{line}"
            );
            Listed {
                sats: words[0].parse().unwrap(),
                pit: words[4].to_string(),
                origin: words[5..words.len() - 1].join(" "),
                outpoint: OutPoint::from_str(words[words.len() - 1]).unwrap(),
            }
        })
        .collect()
}

/// How many coins a `coins` listing shows.
fn listing_coins(stdout: &str) -> usize {
    stdout.lines().filter(|line| line.starts_with("  ")).count()
}

fn first_address(wallet: &str, password: &str, pit: &str, mixdepth: &str) -> Address {
    let listing = ok(&[
        "wallet",
        "addresses",
        "--wallet",
        wallet,
        "--pit",
        pit,
        "--mixdepth",
        mixdepth,
        "--count",
        "1",
        "--password-file",
        password,
    ]);
    address(
        listing
            .lines()
            .nth(1)
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap(),
    )
}

fn new_wallet(wallet: &str, password: &str) {
    ok(&[
        "wallet",
        "new",
        "--wallet",
        wallet,
        "--network",
        "regtest",
        "--password-file",
        password,
    ]);
}

async fn wait_for(what: &str, limit: Duration, done: impl Fn() -> bool) {
    let until = Instant::now() + limit;
    while !done() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn offered(log: &Path) -> bool {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .contains(": offering ")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_coinjoin_spends_what_a_close_left_in_an_lnd_wallet() {
    let env = |name: &str| std::env::var(name).ok();
    let (
        Some(url),
        Some(cookie),
        Some(rest),
        Some(cert),
        Some(macaroon),
        Some(read_macaroon),
        Some(no_sign_macaroon),
        Some(other_cert),
    ) = (
        env("VORTEX_NG_REGTEST_RPC"),
        env("VORTEX_NG_REGTEST_COOKIE"),
        env("VORTEX_NG_LND_REST"),
        env("VORTEX_NG_LND_CERT"),
        env("VORTEX_NG_LND_MACAROON"),
        env("VORTEX_NG_LND_READ_MACAROON"),
        env("VORTEX_NG_LND_NOSIGN_MACAROON"),
        env("VORTEX_NG_LND_OTHER_CERT"),
    )
    else {
        println!("skipped: tools/lnd-itest/run.sh sets the environment");
        return;
    };
    let rpc = CoreRpc::new(
        &url,
        &Auth::CookieFile(PathBuf::from(&cookie)),
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(rpc.network().unwrap(), Network::Regtest, "regtest only");
    let node = [
        "--rpc-url",
        url.as_str(),
        "--rpc-cookie-file",
        cookie.as_str(),
    ];
    let lnd_with = |tls: &'_ str, mac: &'_ str| -> Vec<String> {
        [
            "--lnd-rest",
            &rest,
            "--lnd-tls-cert",
            tls,
            "--lnd-macaroon",
            mac,
        ]
        .map(str::to_string)
        .to_vec()
    };
    let lnd_coins = |network: &str, tls: &str, mac: &str| -> Vec<String> {
        let mut args: Vec<String> = ["lnd-coins", "--network", network, "--outpoints"]
            .map(str::to_string)
            .to_vec();
        args.extend(lnd_with(tls, mac));
        args
    };
    let list = || {
        let args = lnd_coins("regtest", &cert, &read_macaroon);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        listed(&ok(&args))
    };

    let dir = std::env::temp_dir().join(format!(
        "vortex-ng-cli-lnd-{}-{:016x}",
        std::process::id(),
        random_u64()
    ));
    std::fs::create_dir(&dir).unwrap();
    let file = |name: &str| dir.join(name).to_str().unwrap().to_string();
    let password = file("password");
    std::fs::write(&password, "a regtest password").unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();

    // What the node holds, told apart by its own records.
    let mut before = list();
    println!("LND holds {} coins:", before.len());
    for coin in &before {
        println!("  {} sat, {}, {:?}", coin.sats, coin.pit, coin.origin);
    }
    let has = |coins: &[Listed], origin: &str| coins.iter().any(|coin| coin.origin == origin);
    assert!(has(&before, "channel close: mutual close"), "{before:?}");
    assert!(
        has(&before, "channel close: force-close sweep"),
        "{before:?}"
    );
    assert!(
        before.iter().any(|coin| coin.origin.is_empty()),
        "the change of the channel opens is the control: {before:?}"
    );

    // The channel still open makes the node keep funds to fee-bump its force close, and the figure is read.
    let args = lnd_coins("regtest", &cert, &read_macaroon);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let said = ok(&args);
    assert!(
        said.contains("The node keeps 10000 sat for its anchor channels"),
        "{said}"
    );

    // Who may talk to the node.
    let check_refused = |args: Vec<String>, why: &str| {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        refused(&args, why);
    };
    check_refused(
        lnd_coins("regtest", &other_cert, &read_macaroon),
        "certificate",
    );
    check_refused(lnd_coins("signet", &cert, &read_macaroon), "is on regtest");
    let open_macaroon = file("open.macaroon");
    std::fs::copy(&read_macaroon, &open_macaroon).unwrap();
    std::fs::set_permissions(&open_macaroon, std::fs::Permissions::from_mode(0o644)).unwrap();
    check_refused(lnd_coins("regtest", &cert, &open_macaroon), "other users");

    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let sink = PitWallet::new(
        &Seed::from_mnemonic(WORDS, "lnd-sink", Network::Regtest).unwrap(),
        Pit::Sw0,
    )
    .unwrap()
    .next_receive_address(0)
    .unwrap();
    let taker = file("taker.json");
    new_wallet(&taker, &password);
    let podle_log = format!("{taker}.podle");

    // One round per pit the close coins are in: LND pays its closes to whichever script it prefers.
    let pits: BTreeSet<String> = before
        .iter()
        .filter(|coin| !coin.origin.is_empty() && coin.pit != "-")
        .map(|coin| coin.pit.clone())
        .collect();
    assert!(!pits.is_empty(), "{before:?}");
    for pit in &pits {
        println!("--- a round in {pit}");
        // A coin for the commitment, in the mixdepth named for the round.
        let commit_to = first_address(&taker, &password, pit, "3");
        rpc.generate_to_address(1, &commit_to).unwrap();
        // Two makers, a coinbase each.
        let wallets: Vec<String> = (0..2)
            .map(|i| file(&format!("maker-{pit}-{i}.json")))
            .collect();
        for wallet in &wallets {
            new_wallet(wallet, &password);
            rpc.generate_to_address(1, &first_address(wallet, &password, pit, "0"))
                .unwrap();
        }
        rpc.generate_to_address(100, &sink).unwrap();

        let logs: Vec<PathBuf> = (0..2)
            .map(|i| dir.join(format!("maker-{pit}-{i}.log")))
            .collect();
        let mut makers = Makers(Vec::new());
        for (wallet, log) in wallets.iter().zip(&logs) {
            let out = std::fs::File::create(log).unwrap();
            let err = std::fs::File::create(log.with_extension("err")).unwrap();
            makers.0.push(
                Command::new(env!("CARGO_BIN_EXE_vortex-ng"))
                    .args([
                        "maker",
                        "--wallet",
                        wallet,
                        "--password-file",
                        &password,
                        "--pit",
                        pit,
                        "--relays",
                        &relay_url,
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
                    ])
                    .stdin(Stdio::null())
                    .stdout(out)
                    .stderr(err)
                    .spawn()
                    .unwrap(),
            );
        }
        wait_for("both makers' offers", Duration::from_secs(120), || {
            logs.iter().all(|log| offered(log))
        })
        .await;

        let round = |mac: &str, extra: &[&str]| -> Vec<String> {
            let mut args: Vec<String> = [
                "coinjoin",
                "--wallet",
                &taker,
                "--password-file",
                &password,
                "--relays",
                &relay_url,
                "--pit",
                pit,
                "--mixdepth",
                "3",
                "--amount",
                "1000000",
                "--makers",
                "2",
                "--fee-rate",
                "2",
                "--wait",
                "8",
                "--allow-bondless-fees",
                "--from-lnd",
                "--yes",
            ]
            .map(str::to_string)
            .to_vec();
            args.extend(node.map(str::to_string));
            args.extend(lnd_with(&cert, mac));
            args.extend(extra.iter().map(|a| a.to_string()));
            args
        };
        // A macaroon that may only read cannot hold the coins, and the attempt costs no commitment.
        let commitments =
            || std::fs::read_to_string(&podle_log).map_or(0, |text| text.lines().count());
        let spent_before = commitments();
        check_refused(round(&read_macaroon, &[]), "permission");
        assert_eq!(commitments(), spent_before);
        // One that may hold the coins but not sign is caught before any maker hears of them, and the
        // coins it held are given back.
        check_refused(round(&no_sign_macaroon, &[]), "permission");
        assert_eq!(commitments(), spent_before);
        wait_for("LND to get its coins back", Duration::from_secs(30), || {
            let now = list();
            before
                .iter()
                .all(|coin| now.iter().any(|other| other.outpoint == coin.outpoint))
        })
        .await;

        let args = round(&macaroon, &[]);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = run(&args);
        let show_logs = || {
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
        };
        assert!(
            output.status.success(),
            "{}\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            show_logs()
        );
        let said = String::from_utf8(output.stdout).unwrap();
        print!("{said}");
        assert_eq!(commitments(), spent_before + 1);
        let txid = said
            .lines()
            .find_map(|line| line.strip_prefix("Broadcast "))
            .expect("the broadcast txid");
        let txid = Txid::from_str(txid).unwrap();
        rpc.generate_to_address(1, &sink).unwrap();
        let tx = rpc.raw_transaction(&txid).unwrap().expect("the round");

        // LND's coins in the round are close coins of this pit, and that is all of its coins there.
        let inputs: Vec<OutPoint> = tx.input.iter().map(|input| input.previous_output).collect();
        let spent: Vec<&Listed> = before
            .iter()
            .filter(|coin| inputs.contains(&coin.outpoint))
            .collect();
        assert!(!spent.is_empty(), "no coin of LND's in the round");
        assert!(
            spent
                .iter()
                .all(|coin| !coin.origin.is_empty() && coin.pit == *pit),
            "{spent:?}"
        );
        assert_eq!(inputs.len(), spent.len() + 2, "one input per maker");
        assert_eq!(
            tx.output
                .iter()
                .filter(|out| out.value.to_sat() == AMOUNT)
                .count(),
            3,
            "three equal outputs"
        );

        // The coin committed to is still there: it was shown to the makers, not spent.
        let mut listing = vec![
            "coins",
            "--wallet",
            &taker,
            "--password-file",
            &password,
            "--pit",
            pit,
            "--mixdepth",
            "3",
            "--outpoints",
        ];
        listing.extend(node);
        let committed = ok(&listing);
        // Mixdepth 3 holds it and nothing else: the change went back to the node.
        let committed = committed
            .lines()
            .filter(|line| line.starts_with("  "))
            .map(|line| OutPoint::from_str(line.split_whitespace().last().unwrap()).unwrap())
            .find(|outpoint| outpoint.txid != txid)
            .expect("the committed coin");
        assert!(!inputs.contains(&committed));
        assert!(rpc.utxo(&committed).unwrap().is_some());

        assert_eq!(
            listing_coins(&ok(&listing)),
            1,
            "the round's change must not land in the wallet"
        );

        // The amount is in the vortex-ng wallet's next mixdepth.
        let mut args = vec![
            "balance",
            "--wallet",
            &taker,
            "--password-file",
            &password,
            "--pit",
            pit,
        ];
        args.extend(node);
        let balance = ok(&args);
        let next_mixdepth = balance
            .lines()
            .find(|line| line.starts_with("mixdepth 4:"))
            .unwrap();
        assert!(
            next_mixdepth.contains(" 1000000 sat in 1 coin(s)"),
            "{balance}"
        );

        // The node saw its coins go, and only those.
        let gone: BTreeSet<OutPoint> = spent.iter().map(|coin| coin.outpoint).collect();
        wait_for(
            "LND to hold the round's change",
            Duration::from_secs(60),
            || {
                let now = list();
                now.iter().all(|coin| !gone.contains(&coin.outpoint))
                    && now.iter().any(|coin| coin.outpoint.txid == txid)
            },
        )
        .await;
        let after = list();
        for coin in before.iter().filter(|coin| !gone.contains(&coin.outpoint)) {
            assert!(
                after.iter().any(|other| other.outpoint == coin.outpoint),
                "{coin:?} was not in the round and should still be in the wallet"
            );
        }
        before = after;
        for child in &mut makers.0 {
            assert!(
                child.try_wait().unwrap().is_none(),
                "a maker exited\n{}",
                show_logs()
            );
        }
        println!("round in {pit} confirmed: {txid}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
