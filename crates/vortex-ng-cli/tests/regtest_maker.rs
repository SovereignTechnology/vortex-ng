//! `vortex-ng maker` as a service, against a regtest node: two maker processes, started from wallet files
//! the command line made, stay up through two CoinJoins in a row.
//!
//! The second round is the point. A maker that served one round and then went on offering the coins it
//! had just spent, or never noticed the ones it had just received, could not do it: here each maker has a
//! single coin, so round two can only be funded with what round one paid it.
//!
//! A third round is then taken by `vortex-ng coinjoin` itself, from a wallet file of its own, and
//! `vortex-ng balance` shows where the coins went.
//!
//! Nobody reaches the relay directly: it is known to all by a name only the test's SOCKS proxy resolves, a
//! proxy that, like a Tor daemon's, wants a username and password. Each nick must arrive under credentials
//! of its own, the throwaway nicks the makers send `!hp2` from included.
//!
//! Skipped unless `VORTEX_NG_REGTEST_RPC` and `VORTEX_NG_REGTEST_COOKIE` are set (`tools/itest/run.sh`
//! sets them). The taker is the library's, in this process; the relay is nostr-sdk's in-process relay.

// A test: a failed step should panic with its error.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::MockRelay;
use vortex_ng_chain::{Auth, CoreRpc};
use vortex_ng_core::bitcoin::{Address, Network, OutPoint, Transaction};
use vortex_ng_core::offer::Pit;
use vortex_ng_core::tx::random_u64;
use vortex_ng_node::{CONNECT_TIMEOUT, run_taker};
use vortex_ng_nostr::client::NickClient;
use vortex_ng_nostr::keys::NickKeys;
use vortex_ng_nostr::socks::Outbound;
use vortex_ng_nostr::testing::AuthSocks;
use vortex_ng_taker::{DEFAULT_BONDLESS_ALLOWANCE, Taker, TakerConfig, podle_for};
use vortex_ng_wallet::bdk_wallet::LocalOutput;
use vortex_ng_wallet::{PitWallet, Seed};

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const AMOUNT: u64 = 1_000_000;
const MAKERS: usize = 2;

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

fn vortex(args: &[&str]) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_vortex-ng"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn address(text: &str) -> Address {
    Address::from_str(text)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
}

/// How many times a maker's log says it (re)announced an offer.
fn announcements(log: &Path) -> usize {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains(": offering sw0absoffer "))
        .count()
}

async fn wait_for(what: &str, limit: Duration, done: impl Fn() -> bool) {
    let until = Instant::now() + limit;
    while !done() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// One round by the library's taker with `coin`, broadcast and mined into a block.
async fn round(
    rpc: &CoreRpc,
    relay: &str,
    outbound: &Outbound,
    wallet: &mut PitWallet,
    coin: &LocalOutput,
) -> Transaction {
    let cfg = TakerConfig {
        pit: Pit::Sw0,
        network: Network::Regtest,
        amount: AMOUNT,
        makers: MAKERS,
        max_cjfee: 5_000,
        fee_rate_sat_per_kwu: 2_500,
        max_maker_utxos: 20,
        bondless_makers_allowance: DEFAULT_BONDLESS_ALLOWANCE,
        // The makers have no bond and charge a fee.
        bondless_require_zero_fee: false,
        bond_params: Default::default(),
    };
    let podle = podle_for(wallet, 0, coin, 0).unwrap();
    let cj = wallet.next_receive_address(1).unwrap().script_pubkey();
    let change = wallet.next_change_address(0).unwrap().script_pubkey();
    let mut taker = Taker::new(
        cfg.clone(),
        0,
        vec![(coin.outpoint, coin.txout.clone())],
        podle,
        cj,
        change,
    )
    .unwrap();
    let mut client = NickClient::connect_via(
        NickKeys::generate(),
        "regtest",
        &[relay.to_string()],
        outbound,
        CONNECT_TIMEOUT,
    )
    .await
    .unwrap();
    let tx = run_taker(
        &mut taker,
        wallet,
        &mut client,
        rpc,
        &cfg,
        Duration::from_secs(10),
        Instant::now() + Duration::from_secs(120),
    )
    .await
    .unwrap_or_else(|e| panic!("the round with the maker processes failed: {e}"));
    client.shutdown().await;
    rpc.test_accept(&tx)
        .unwrap()
        .unwrap_or_else(|why| panic!("the node refuses the CoinJoin: {why}"));
    rpc.broadcast(&tx).unwrap();
    tx
}

#[tokio::test(flavor = "multi_thread")]
async fn maker_processes_serve_rounds_and_the_command_line_takes_one() {
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
    let relay = MockRelay::run().await.unwrap();
    // The relay as everyone knows it: a name only the proxy resolves. A direct connection, or a name
    // looked up on this machine instead of at the proxy, cannot reach it.
    let listening = relay.url().await.to_string();
    let port = listening
        .trim_end_matches('/')
        .rsplit(':')
        .next()
        .unwrap()
        .to_string();
    let relay_url = format!("ws://relay.test:{port}");
    let proxy = AuthSocks::start().await.unwrap();
    let proxy_addr = proxy.addr().to_string();
    let outbound = Outbound::IsolatingProxy(proxy.addr());

    let dir = std::env::temp_dir().join(format!(
        "vortex-ng-cli-maker-{}-{:016x}",
        std::process::id(),
        random_u64()
    ));
    std::fs::create_dir(&dir).unwrap();
    let file = |name: &str| dir.join(name).to_str().unwrap().to_string();
    let password = file("password");
    std::fs::write(&password, "a regtest password").unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Each maker: a wallet file made by the command line, paid one coinbase at its first address.
    let wallets: Vec<String> = (0..MAKERS)
        .map(|i| file(&format!("maker{i}.json")))
        .collect();
    for wallet in &wallets {
        vortex(&[
            "wallet",
            "new",
            "--wallet",
            wallet,
            "--network",
            "regtest",
            "--password-file",
            &password,
        ]);
        let listing = vortex(&[
            "wallet",
            "addresses",
            "--wallet",
            wallet,
            "--count",
            "1",
            "--password-file",
            &password,
        ]);
        let listing = String::from_utf8(listing.stdout).unwrap();
        let first = listing
            .lines()
            .nth(1)
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        rpc.generate_to_address(1, &address(first)).unwrap();
    }
    // The command line's own taker wallet, for the third round: one coinbase.
    let cli_taker = file("taker.json");
    vortex(&[
        "wallet",
        "new",
        "--wallet",
        &cli_taker,
        "--network",
        "regtest",
        "--password-file",
        &password,
    ]);
    let listing = vortex(&[
        "wallet",
        "addresses",
        "--wallet",
        &cli_taker,
        "--count",
        "1",
        "--password-file",
        &password,
    ]);
    let listing = String::from_utf8(listing.stdout).unwrap();
    let first = listing
        .lines()
        .nth(1)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    rpc.generate_to_address(1, &address(first)).unwrap();
    // The taker: two coinbases, one per round.
    let seed = Seed::from_mnemonic(WORDS, "cli-maker-taker", Network::Regtest).unwrap();
    let mut taker_wallet = PitWallet::new(&seed, Pit::Sw0).unwrap();
    for _ in 0..2 {
        let to = taker_wallet.next_receive_address(0).unwrap();
        rpc.generate_to_address(1, &to).unwrap();
    }
    let sink_seed = Seed::from_mnemonic(WORDS, "cli-maker-sink", Network::Regtest).unwrap();
    let sink = PitWallet::new(&sink_seed, Pit::Sw0)
        .unwrap()
        .next_receive_address(0)
        .unwrap();
    rpc.generate_to_address(100, &sink).unwrap();
    taker_wallet.sync(&rpc, 0).unwrap();
    let coins = taker_wallet.utxos(0).unwrap();
    assert_eq!(coins.len(), 2);

    // The maker processes.
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
                "--proxy",
                &proxy_addr,
            ])
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .spawn()
            .unwrap();
        makers.0.push(child);
    }
    let show = |logs: &[PathBuf]| {
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
    wait_for(
        "both makers' first offers",
        Duration::from_secs(120),
        || logs.iter().all(|log| announcements(log) >= 1),
    )
    .await;
    println!("both maker processes announced their offers");

    // What a taker would see: `vortex-ng orderbook` lists both makers' offers, and none in another pit.
    let listing = vortex(&[
        "orderbook",
        "--proxy",
        &proxy_addr,
        "--network",
        "regtest",
        "--relays",
        &relay_url,
        "--wait",
        "5",
        "--rpc-url",
        &url,
        "--rpc-cookie-file",
        &cookie,
    ]);
    let listing = String::from_utf8(listing.stdout).unwrap();
    assert_eq!(
        listing
            .lines()
            .filter(|line| line.contains(" sw0absoffer ") && line.trim_end().ends_with(" nostr"))
            .count(),
        MAKERS,
        "every offer, and the channel it came on: {listing}"
    );
    let other = vortex(&[
        "orderbook",
        "--proxy",
        &proxy_addr,
        "--network",
        "regtest",
        "--relays",
        &relay_url,
        "--wait",
        "3",
        "--pit",
        "tr0",
    ]);
    assert!(
        String::from_utf8(other.stdout)
            .unwrap()
            .starts_with("No offers")
    );

    // Round one.
    let nicks_before = proxy.usernames().len();
    let first = round(&rpc, &relay_url, &outbound, &mut taker_wallet, &coins[0]).await;
    rpc.generate_to_address(1, &sink).unwrap();
    assert_eq!(first.input.len(), MAKERS + 1);
    println!("round one confirmed: {}", first.compute_txid());
    // The round brought new nicks to the proxy, each under credentials of its own: the taker, and the
    // throwaway nick each maker sent `!hp2` from.
    let nicks = proxy.usernames().len();
    assert!(
        nicks > nicks_before + MAKERS,
        "{nicks_before} nicks before the round, {nicks} after: the makers' throwaway nicks did not come \
         through the proxy under names of their own"
    );

    // Each maker brings its wallet up to the new block and announces what it holds now.
    wait_for(
        "both makers' offers after round one",
        Duration::from_secs(120),
        || logs.iter().all(|log| announcements(log) >= 2),
    )
    .await;

    // Round two: each maker's only coin now is one that round one paid it.
    let second = round(&rpc, &relay_url, &outbound, &mut taker_wallet, &coins[1]).await;
    rpc.generate_to_address(1, &sink).unwrap();
    let from_first = second
        .input
        .iter()
        .filter(|input| input.previous_output.txid == first.compute_txid())
        .count();
    assert_eq!(
        from_first,
        MAKERS,
        "each maker funds round two with an output of round one\n{}",
        show(&logs)
    );
    let confirmed = rpc
        .utxo(&OutPoint {
            txid: second.compute_txid(),
            vout: 0,
        })
        .unwrap()
        .expect("round two's first output, unspent");
    assert_eq!(confirmed.confirmations, 1);
    println!("round two confirmed: {}", second.compute_txid());

    // Round three, by the command line: `vortex-ng coinjoin` from its own wallet file.
    wait_for(
        "both makers' offers after round two",
        Duration::from_secs(120),
        || logs.iter().all(|log| announcements(log) >= 3),
    )
    .await;
    let node = [
        "--rpc-url",
        url.as_str(),
        "--rpc-cookie-file",
        cookie.as_str(),
    ];
    let coinjoin = |extra: &[&str]| {
        let mut args = vec![
            "coinjoin",
            "--proxy",
            &proxy_addr,
            "--wallet",
            &cli_taker,
            "--password-file",
            &password,
            "--relays",
            &relay_url,
            "--amount",
            "500000",
            "--makers",
            "2",
            "--fee-rate",
            "2",
            "--wait",
            "8",
        ];
        args.extend(node);
        args.extend(extra);
        Command::new(env!("CARGO_BIN_EXE_vortex-ng"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    // Without a terminal it will not spend unless told to; and with joinmarket-ng's default policy it
    // finds no maker, for these have no fidelity bond and charge a fee.
    let unconfirmed = coinjoin(&["--allow-bondless-fees"]);
    assert_eq!(unconfirmed.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&unconfirmed.stderr).contains("pass `--yes`"));
    assert!(!Path::new(&format!("{cli_taker}.podle")).exists());
    let strict = coinjoin(&["--yes"]);
    assert_eq!(
        strict.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&strict.stdout)
    );
    assert!(
        String::from_utf8_lossy(&strict.stderr).contains("not enough suitable offers"),
        "{}",
        String::from_utf8_lossy(&strict.stderr)
    );
    // That attempt spent a commitment: the next one must use another.
    let log = format!("{cli_taker}.podle");
    assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 1);

    let third = coinjoin(&["--yes", "--allow-bondless-fees"]);
    assert!(
        third.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&third.stderr),
        show(&logs)
    );
    let said = String::from_utf8(third.stdout).unwrap();
    let txid = said
        .lines()
        .find_map(|line| line.strip_prefix("Broadcast "))
        .expect("the broadcast txid");
    let txid = vortex_ng_core::bitcoin::Txid::from_str(txid).unwrap();
    assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 2);
    rpc.generate_to_address(1, &sink).unwrap();
    let confirmed = rpc
        .utxo(&OutPoint { txid, vout: 0 })
        .unwrap()
        .expect("round three's first output, unspent");
    assert_eq!(confirmed.confirmations, 1);
    println!("round three, by `vortex-ng coinjoin`, confirmed: {txid}");

    // The wallet's view: the amount in mixdepth 1, the change in mixdepth 0.
    let mut args = vec![
        "balance",
        "--wallet",
        &cli_taker,
        "--password-file",
        &password,
    ];
    args.extend(node);
    let balance = String::from_utf8(vortex(&args).stdout).unwrap();
    let line = |start: &str| {
        balance
            .lines()
            .find(|line| line.starts_with(start))
            .unwrap_or_else(|| panic!("{start} in\n{balance}"))
            .to_string()
    };
    assert!(
        line("mixdepth 1:").contains(" 500000 sat in 1 coin(s)"),
        "{balance}"
    );
    assert!(
        line("mixdepth 0:").contains(" sat in 1 coin(s)"),
        "{balance}"
    );
    // A round right away has no coin to commit to: the change is one block old.
    let young = coinjoin(&["--yes", "--allow-bondless-fees"]);
    assert_eq!(young.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&young.stderr).contains("no coin to commit to"),
        "{}",
        String::from_utf8_lossy(&young.stderr)
    );

    // Everything the proxy carried was for the relay, by its name; and no maker said it was connecting
    // directly.
    assert!(
        proxy
            .seen()
            .iter()
            .all(|(_, to)| *to == format!("relay.test:{port}")),
        "{:?}",
        proxy.seen()
    );
    assert!(!show(&logs).contains("connecting to the relays directly"));
    println!(
        "{} nicks came through the proxy, each under its own credentials",
        proxy.usernames().len()
    );

    // Nobody fell over.
    for child in &mut makers.0 {
        assert!(
            child.try_wait().unwrap().is_none(),
            "a maker exited\n{}",
            show(&logs)
        );
    }
    drop(makers);
    let _ = std::fs::remove_dir_all(&dir);
}
