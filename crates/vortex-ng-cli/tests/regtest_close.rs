//! `vortex-ng coins` against a regtest node: the coins a channel close paid the wallet are marked, whatever
//! the close, and a coin that did not come from one is not.
//!
//! Three closes of hand-made channels (`tests/common`) pay one wallet three ways: a mutual close, a force
//! close whose `to_remote` output pays the wallet straight from the commitment transaction, and the sweep of
//! a force close's `to_local` after its 144-block delay (a script Core's interpreter accepts only if it is
//! BOLT 3's). A coinbase paid to the wallet is the control.
//!
//! Skipped unless `VORTEX_NG_REGTEST_RPC` and `VORTEX_NG_REGTEST_COOKIE` are set (`tools/itest/run.sh`).

// A test: a failed step should panic with its error.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::str::FromStr;
use std::time::Duration;

use common::{Channel, ToLocal, mine_to, payout};
use vortex_ng_chain::{Auth, CoreRpc};
use vortex_ng_core::bitcoin::{Address, Amount, Network, OutPoint, TxOut};
use vortex_ng_core::offer::Pit;
use vortex_ng_core::tx::random_u64;
use vortex_ng_wallet::{PitWallet, Seed};

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const FEE: Amount = Amount::from_sat(10_000);

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

/// The `coins` lines that hold a coin (an amount in satoshis), as the command printed them.
fn coin_lines(output: &Output) -> Vec<String> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("  ") && line.contains(" sat "))
        .map(str::to_string)
        .collect()
}

#[test]
fn coins_marks_what_a_channel_close_paid_the_wallet() {
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
        "vortex-ng-cli-close-{}-{:016x}",
        std::process::id(),
        random_u64()
    ));
    std::fs::create_dir(&dir).unwrap();
    let file = |name: &str| dir.join(name).to_str().unwrap().to_string();
    let password = file("password");
    std::fs::write(&password, "a regtest password").unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
    let wallet = file("wallet.json");
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
    let listing = vortex(&[
        "wallet",
        "addresses",
        "--wallet",
        &wallet,
        "--count",
        "4",
        "--password-file",
        &password,
    ]);
    let listing = String::from_utf8(listing.stdout).unwrap();
    let ours: Vec<Address> = listing
        .lines()
        .skip(1)
        .map(|line| address(line.split_whitespace().nth(1).unwrap()))
        .collect();
    assert_eq!(ours.len(), 4);

    // Two channels and a plain payment, each a coinbase (the funding transactions' stand-ins).
    let (mutual_channel, force_channel) = (Channel::new(10), Channel::new(20));
    let (mutual_funding, mutual_value) = mine_to(&rpc, &mutual_channel.funding_address());
    let (force_funding, force_value) = mine_to(&rpc, &force_channel.funding_address());
    let (_, plain_value) = mine_to(&rpc, &ours[3]);
    let sink = PitWallet::new(
        &Seed::from_mnemonic(WORDS, "close-sink", Network::Regtest).unwrap(),
        Pit::Sw0,
    )
    .unwrap()
    .next_receive_address(0)
    .unwrap();
    rpc.generate_to_address(100, &sink).unwrap();

    // 1. A mutual close: the wallet's address is the delivery address, the peer gets the rest.
    // Amounts follow the coinbases: regtest halves the subsidy every 150 blocks, and this node has mined
    // for the other tests first. A quarter, three fifths and the rest keep every coin distinct.
    let to_wallet = Amount::from_sat(mutual_value.to_sat() / 4);
    let mutual = mutual_channel.spend(
        mutual_funding,
        mutual_value,
        0xffff_fffd,
        0,
        vec![
            TxOut {
                value: to_wallet,
                script_pubkey: ours[0].script_pubkey(),
            },
            TxOut {
                value: mutual_value - to_wallet - FEE,
                script_pubkey: payout(1),
            },
        ],
    );
    rpc.test_accept(&mutual).unwrap().unwrap();
    rpc.broadcast(&mutual).unwrap();

    // 2. A force close whose `to_remote` pays the wallet from the commitment transaction itself, and whose
    // `to_local` goes to the peer's side of the chain behind a 144-block delay.
    let to_local = ToLocal::new(30, 144);
    let local_value = Amount::from_sat(force_value.to_sat() * 3 / 5);
    let commitment = force_channel.force_close(
        force_funding,
        force_value,
        &to_local,
        local_value,
        ours[1].script_pubkey(),
        FEE,
    );
    rpc.test_accept(&commitment).unwrap().unwrap();
    rpc.broadcast(&commitment).unwrap();
    rpc.generate_to_address(1, &sink).unwrap();
    let remote_value = force_value - local_value - FEE;

    // 3. The sweep of `to_local` into the wallet, once the delay has passed (and not before: the test
    // proves the delay is real by Core refusing the sweep one block early).
    let delayed = OutPoint {
        txid: commitment.compute_txid(),
        vout: 0,
    };
    let sweep = to_local.sweep(delayed, local_value, ours[2].script_pubkey(), FEE);
    rpc.generate_to_address(142, &sink).unwrap();
    assert!(
        rpc.test_accept(&sweep).unwrap().is_err(),
        "Core accepted the sweep before its delay"
    );
    rpc.generate_to_address(1, &sink).unwrap();
    rpc.test_accept(&sweep).unwrap().unwrap();
    rpc.broadcast(&sweep).unwrap();
    rpc.generate_to_address(6, &sink).unwrap();
    let swept_value = local_value - FEE;

    let node = [
        "--rpc-url",
        url.as_str(),
        "--rpc-cookie-file",
        cookie.as_str(),
    ];
    let coins = |extra: &[&str]| {
        let mut args = vec!["coins", "--wallet", &wallet, "--password-file", &password];
        args.extend(node);
        args.extend(extra);
        vortex(&args)
    };

    // Every coin, marked.
    let all = coins(&[]);
    let lines = coin_lines(&all);
    let text = String::from_utf8(all.stdout.clone()).unwrap();
    assert_eq!(lines.len(), 4, "{text}");
    let find = |sats: Amount| {
        lines
            .iter()
            .find(|line| line.contains(&format!("{:>14} sat", sats.to_sat())))
            .unwrap_or_else(|| panic!("a coin of {sats} in\n{text}"))
    };
    assert!(
        find(to_wallet).contains("channel close: mutual close"),
        "{text}"
    );
    assert!(
        find(remote_value).ends_with("channel close: force close"),
        "{text}"
    );
    assert!(
        find(swept_value).contains("channel close: force-close sweep"),
        "{text}"
    );
    assert!(
        !find(plain_value).contains("channel close"),
        "a coinbase is not a close\n{text}"
    );
    let from_closes = (to_wallet + remote_value + swept_value).to_sat();
    assert!(
        text.contains(&format!(
            "3 coin(s), {from_closes} sat of it from channel closes."
        )),
        "{text}"
    );
    // Outpoints are shown only when asked for.
    assert!(!text.contains(&commitment.compute_txid().to_string()));
    let with = coins(&["--outpoints"]);
    let with = String::from_utf8(with.stdout).unwrap();
    assert!(
        with.contains(&commitment.compute_txid().to_string()),
        "{with}"
    );
    assert!(with.contains(&sweep.compute_txid().to_string()), "{with}");

    // Only the closes, and another mixdepth holds none.
    assert_eq!(coin_lines(&coins(&["--closes-only"])).len(), 3);
    let other = coins(&["--mixdepth", "1"]);
    assert!(coin_lines(&other).is_empty());
    assert!(
        String::from_utf8(other.stdout)
            .unwrap()
            .contains("0 coin(s), 0 sat; 0 coin(s)")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
