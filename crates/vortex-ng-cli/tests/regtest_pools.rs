//! A JoinMarket maker and a joinstr pool on one wallet at once (issue #51), through the command line.
//!
//! Wallet A runs `vortex-ng maker` and `vortex-ng pool join` at the same time. Its pool coin is the larger of
//! its two coins, so a maker that did not see the pool's hold would put it into the JoinMarket round first.
//! Wallet B creates a pool of three, C joins it too, and a taker's `vortex-ng coinjoin` does a round with A's
//! maker while A is in the pool. Both transactions must confirm, with no coin in both and no output script in
//! both.
//!
//! Skipped unless `VORTEX_NG_REGTEST_RPC` and `VORTEX_NG_REGTEST_COOKIE` are set (`tools/itest/run.sh` sets
//! them).

// A test: a failed step should panic with its error.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::MockRelay;
use vortex_ng_chain::{Auth, CoreRpc};
use vortex_ng_core::bitcoin::{Address, Network, OutPoint, Txid};
use vortex_ng_core::tx::random_u64;

/// Regtest halves the subsidy every 150 blocks.
const HALVING: u32 = 150;
/// How far above the pool's denomination its coins sit (the window is 500 to 5000 sats).
const SLACK: u64 = 2_500;
/// The JoinMarket round's amount.
const AMOUNT: u64 = 50_000;

/// Processes stopped when the test ends, however it ends.
struct Running(Vec<Child>);

impl Drop for Running {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run<S: AsRef<std::ffi::OsStr>>(args: &[S]) -> Output {
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

/// Start `vortex-ng args`, its output to `log` and `log.err`.
fn spawn<S: AsRef<std::ffi::OsStr>>(args: &[S], log: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_vortex-ng"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(log).unwrap())
        .stderr(std::fs::File::create(log.with_extension("err")).unwrap())
        .spawn()
        .unwrap()
}

fn read(log: &Path) -> String {
    format!(
        "{}{}",
        std::fs::read_to_string(log).unwrap_or_default(),
        std::fs::read_to_string(log.with_extension("err")).unwrap_or_default()
    )
}

fn show(logs: &[&Path]) -> String {
    logs.iter()
        .map(|log| format!("== {}\n{}", log.display(), read(log)))
        .collect::<Vec<_>>()
        .join("\n")
}

async fn wait_for(what: &str, limit: Duration, done: impl Fn() -> bool) {
    let until = Instant::now() + limit;
    while !done() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// The wallet's first `count` receiving addresses of mixdepth 0.
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
    String::from_utf8(listing.stdout)
        .unwrap()
        .lines()
        .skip(1)
        .take(count)
        .map(|line| {
            Address::from_str(line.split_whitespace().nth(1).unwrap())
                .unwrap()
                .require_network(Network::Regtest)
                .unwrap()
        })
        .collect()
}

/// The txid a command printed as `Broadcast <txid>…`.
fn broadcast(log: &Path) -> Option<Txid> {
    read(log).lines().find_map(|line| {
        let rest = line.strip_prefix("Broadcast ")?;
        Txid::from_str(rest.split(|c: char| c == ':' || c.is_whitespace()).next()?).ok()
    })
}

/// A block's subsidy at `height`, sats.
fn subsidy(height: u32) -> u64 {
    5_000_000_000u64.checked_shr(height / HALVING).unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_maker_and_a_pool_share_one_wallet_without_sharing_a_coin() {
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

    let dir = std::env::temp_dir().join(format!(
        "vortex-ng-cli-pools-{}-{:016x}",
        std::process::id(),
        random_u64()
    ));
    std::fs::create_dir(&dir).unwrap();
    let password = dir.join("password");
    std::fs::write(&password, "a test password").unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
    let password = password.to_str().unwrap().to_string();
    let file = |name: &str| dir.join(name).to_str().unwrap().to_string();
    let [a, b, c, t, sink] = ["a", "b", "c", "t", "sink"].map(|name| {
        let wallet = file(&format!("{name}.json"));
        vortex(&[
            "wallet",
            "new",
            "--wallet",
            &wallet,
            "--network",
            "regtest",
            "--password-file",
            &password,
        ]);
        wallet
    });
    let sink = addresses(&sink, &password, 1).remove(0);

    // The pool's coins: one coinbase each for A, B and C, all of one subsidy era, so all worth V. Then, in the
    // next era, A's other coin and the taker's, worth V / 2: A's pool coin is its larger one.
    let tip = rpc.tip_height().unwrap();
    if HALVING - tip % HALVING <= 3 {
        rpc.generate_to_address(HALVING - tip % HALVING, &sink)
            .unwrap();
    }
    let value = subsidy(rpc.tip_height().unwrap() + 1);
    assert!(
        value >= 400_000,
        "the node is too far along for this test: a coinbase is worth {value} sat"
    );
    let a_coins = addresses(&a, &password, 2);
    for to in [
        &a_coins[0],
        &addresses(&b, &password, 1)[0],
        &addresses(&c, &password, 1)[0],
    ] {
        rpc.generate_to_address(1, to).unwrap();
    }
    let tip = rpc.tip_height().unwrap();
    rpc.generate_to_address(HALVING - tip % HALVING, &sink)
        .unwrap();
    rpc.generate_to_address(1, &a_coins[1]).unwrap();
    rpc.generate_to_address(1, &addresses(&t, &password, 1)[0])
        .unwrap();
    rpc.generate_to_address(100, &sink).unwrap();
    let denomination = (value - SLACK).to_string();

    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let node = [
        "--rpc-url",
        url.as_str(),
        "--rpc-cookie-file",
        cookie.as_str(),
    ];
    let wallet_args = |wallet: &str| -> Vec<String> {
        let mut args = vec![
            "--wallet".to_string(),
            wallet.to_string(),
            "--password-file".to_string(),
            password.clone(),
            "--relays".to_string(),
            relay_url.clone(),
        ];
        args.extend(node.iter().map(|s| s.to_string()));
        args
    };

    // A's maker, on the relay.
    let mut running = Running(Vec::new());
    let maker_log = dir.join("maker.log");
    let mut maker_args = vec!["maker".to_string()];
    maker_args.extend(wallet_args(&a));
    maker_args
        .extend(["--fee-abs", "500", "--min-size", "10000", "--upkeep", "2"].map(String::from));
    running.0.push(spawn(&maker_args, &maker_log));
    wait_for("A's maker's first offer", Duration::from_secs(120), || {
        read(&maker_log).contains(": offering ")
    })
    .await;

    // B creates the pool; A and C join it.
    let creator_log = dir.join("creator.log");
    let mut create = vec!["pool".to_string(), "create".to_string()];
    create.extend(wallet_args(&b));
    create.extend(
        [
            "--denomination",
            &denomination,
            "--peers",
            "3",
            "--fee-rate",
            "1",
            "--expires",
            "900",
            "--yes",
        ]
        .map(String::from),
    );
    running.0.push(spawn(&create, &creator_log));
    wait_for("the pool's announcement", Duration::from_secs(120), || {
        read(&creator_log).contains("announced on ")
    })
    .await;
    let pool_id = read(&creator_log)
        .lines()
        .find_map(|line| {
            line.strip_prefix("pool ")
                .and_then(|rest| rest.split_whitespace().next())
                .map(str::to_string)
        })
        .expect("the pool's id");
    let joiner_logs = [dir.join("join-a.log"), dir.join("join-c.log")];
    for (wallet, log) in [&a, &c].into_iter().zip(&joiner_logs) {
        let mut join = vec!["pool".to_string(), "join".to_string()];
        join.extend(wallet_args(wallet));
        join.extend(["--pool", &pool_id, "--wait", "5", "--yes"].map(String::from));
        running.0.push(spawn(&join, log));
    }
    // A's pool coin is held before the taker asks A's maker for anything.
    let claims = PathBuf::from(format!("{a}.claims"));
    wait_for("A's pool coin held", Duration::from_secs(120), || {
        std::fs::read_to_string(&claims).is_ok_and(|text| text.contains("coin "))
    })
    .await;

    // The taker's round with A's maker, while A is in the pool.
    let taker_log = dir.join("taker.log");
    let mut coinjoin = vec!["coinjoin".to_string()];
    coinjoin.extend(wallet_args(&t));
    coinjoin.extend(
        [
            "--amount",
            &AMOUNT.to_string(),
            "--makers",
            "1",
            "--fee-rate",
            "2",
            "--wait",
            "8",
            "--yes",
            "--allow-bondless-fees",
        ]
        .map(String::from),
    );
    let round = run(&coinjoin);
    std::fs::write(&taker_log, &round.stdout).unwrap();
    std::fs::write(taker_log.with_extension("err"), &round.stderr).unwrap();
    let logs = [
        maker_log.as_path(),
        creator_log.as_path(),
        joiner_logs[0].as_path(),
        joiner_logs[1].as_path(),
        taker_log.as_path(),
    ];
    assert!(
        round.status.success(),
        "the JoinMarket round\n{}",
        show(&logs)
    );
    let jm = broadcast(&taker_log).expect("the round's txid");

    // The pool finishes; every peer broadcasts the same transaction. A pool command that stops without one,
    // or a pool that takes too long, shows every log.
    let pool_logs = [&creator_log, &joiner_logs[0], &joiner_logs[1]];
    let until = Instant::now() + Duration::from_secs(420);
    while !pool_logs.iter().all(|log| broadcast(log).is_some()) {
        for (child, log) in running.0[1..].iter_mut().zip(pool_logs) {
            if let Ok(Some(status)) = child.try_wait() {
                assert!(
                    broadcast(log).is_some(),
                    "{} stopped ({status}) without a transaction\n{}",
                    log.display(),
                    show(&logs)
                );
            }
        }
        assert!(
            Instant::now() < until,
            "timed out waiting for the pool's transaction\n{}",
            show(&logs)
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let pool = broadcast(&creator_log).unwrap();
    for log in &joiner_logs {
        assert_eq!(broadcast(log), Some(pool), "{}", show(&logs));
    }
    // Read from the mempool: this node keeps no transaction index, so a confirmed one cannot be looked up.
    let jm_tx = rpc
        .raw_transaction(&jm)
        .unwrap()
        .expect("the round in the mempool");
    let pool_tx = rpc
        .raw_transaction(&pool)
        .unwrap()
        .expect("the pool in the mempool");
    rpc.generate_to_address(1, &sink).unwrap();
    for (txid, tx) in [(jm, &jm_tx), (pool, &pool_tx)] {
        let out = rpc
            .utxo(&OutPoint { txid, vout: 0 })
            .unwrap()
            .expect("a confirmed output");
        assert_eq!(out.confirmations, 1);
        assert!(!tx.input.is_empty());
    }
    let spent = |tx: &vortex_ng_core::bitcoin::Transaction| -> HashSet<OutPoint> {
        tx.input.iter().map(|i| i.previous_output).collect()
    };
    assert!(
        spent(&jm_tx).is_disjoint(&spent(&pool_tx)),
        "a coin in both\n{}",
        show(&logs)
    );
    let paid = |tx: &vortex_ng_core::bitcoin::Transaction| -> HashSet<Vec<u8>> {
        tx.output
            .iter()
            .map(|o| o.script_pubkey.to_bytes())
            .collect()
    };
    assert!(
        paid(&jm_tx).is_disjoint(&paid(&pool_tx)),
        "an address in both"
    );
    assert_eq!(pool_tx.input.len(), 3, "A, B and C");
    println!(
        "JoinMarket round {jm} with A's maker and joinstr pool {pool} with A in it: both confirmed, no coin \
         and no address in both"
    );
    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
