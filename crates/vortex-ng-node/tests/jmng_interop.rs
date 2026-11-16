//! A CoinJoin between vortex-ng and joinmarket-ng over the Nostr message channel, on a regtest node.
//!
//! Skipped unless `VORTEX_NG_INTEROP_DIR` is set (`tools/jmng-interop/run.sh` sets it, with
//! `VORTEX_NG_REGTEST_RPC` and `VORTEX_NG_REGTEST_COOKIE`). This side runs the relay (nostr-sdk's
//! in-process relay, on loopback) and writes its URL to `<dir>/relay.url`; the harness then starts
//! joinmarket-ng's makers, built with its Nostr channel, on that relay.
//!
//! `taker_with_joinmarket_ng_makers`: a vortex-ng taker waits until the joinmarket-ng makers have announced
//! their offers, asks them for the orderbook, and runs a `sw0` round with them. The transaction must pass
//! `testmempoolaccept`, confirm, and pay the taker its coinjoin output. Its txid goes to `<dir>/taker.txid`.

// A test harness: a failed step should panic with its error.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::MockRelay;
use vortex_ng_chain::{Auth, CoreRpc};
use vortex_ng_core::bitcoin::{Amount, Network, OutPoint};
use vortex_ng_core::offer::Pit;
use vortex_ng_node::{CONNECT_TIMEOUT, run_taker};
use vortex_ng_nostr::client::{Incoming, NickClient, unix_now};
use vortex_ng_nostr::keys::NickKeys;
use vortex_ng_taker::{DEFAULT_BONDLESS_ALLOWANCE, Taker, TakerConfig, podle_for};
use vortex_ng_wallet::{PitWallet, Seed};

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const AMOUNT: u64 = 1_000_000;

struct Harness {
    dir: PathBuf,
    url: String,
    cookie: PathBuf,
    makers: usize,
}

impl Harness {
    fn from_env() -> Option<Harness> {
        Some(Harness {
            dir: std::env::var("VORTEX_NG_INTEROP_DIR").ok()?.into(),
            url: std::env::var("VORTEX_NG_REGTEST_RPC").ok()?,
            cookie: std::env::var("VORTEX_NG_REGTEST_COOKIE").ok()?.into(),
            makers: std::env::var("VORTEX_NG_INTEROP_MAKERS")
                .ok()
                .and_then(|n| n.parse().ok())
                .unwrap_or(2),
        })
    }

    fn rpc(&self) -> CoreRpc {
        CoreRpc::new(
            &self.url,
            &Auth::CookieFile(self.cookie.clone()),
            Duration::from_secs(60),
        )
        .unwrap()
    }
}

fn wallet(who: &str) -> PitWallet {
    let seed = Seed::from_mnemonic(WORDS, who, Network::Regtest).unwrap();
    PitWallet::new(&seed, Pit::Sw0).unwrap()
}

/// Wait until `count` different nicks have an offer event on the relay.
async fn wait_for_makers(url: &str, count: usize, limit: Duration) {
    let mut observer = NickClient::connect(
        NickKeys::generate(),
        "regtest",
        &[url.to_string()],
        None,
        CONNECT_TIMEOUT,
    )
    .await
    .unwrap();
    observer
        .subscribe(unix_now().saturating_sub(3600), true, false)
        .await
        .unwrap();
    let until = Instant::now() + limit;
    let mut seen = HashSet::new();
    while seen.len() < count {
        let left = until
            .checked_duration_since(Instant::now())
            .unwrap_or_else(|| panic!("only {} of {count} makers announced offers", seen.len()));
        if let Some(Incoming::Offers(author, offers)) = observer.next(left).await
            && seen.insert(author.nick.clone())
        {
            println!("maker {} announced {} offer(s)", author.nick, offers.len());
        }
    }
    observer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn taker_with_joinmarket_ng_makers() {
    let Some(harness) = Harness::from_env() else {
        println!("skipped: set VORTEX_NG_INTEROP_DIR (tools/jmng-interop/run.sh)");
        return;
    };
    let rpc = harness.rpc();
    assert_eq!(rpc.network().unwrap(), Network::Regtest, "regtest only");

    // The relay both sides meet on.
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    std::fs::write(harness.dir.join("relay.url"), &url).unwrap();
    println!("relay at {url}");

    // Our coin: a coinbase, matured.
    let mut taker_wallet = wallet("interop-taker");
    let sink = wallet("interop-sink").next_receive_address(0).unwrap();
    rpc.generate_to_address(1, &taker_wallet.next_receive_address(0).unwrap())
        .unwrap();
    rpc.generate_to_address(100, &sink).unwrap();
    taker_wallet.sync(&rpc, 0).unwrap();

    wait_for_makers(&url, harness.makers, Duration::from_secs(900)).await;

    let utxo = taker_wallet.utxos(0).unwrap().remove(0);
    let podle = podle_for(&taker_wallet, 0, &utxo, 0).unwrap();
    let cfg = TakerConfig {
        pit: Pit::Sw0,
        network: Network::Regtest,
        amount: AMOUNT,
        makers: harness.makers,
        max_cjfee: 5_000,
        fee_rate_sat_per_kwu: 2_500,
        max_maker_utxos: 20,
        bondless_makers_allowance: DEFAULT_BONDLESS_ALLOWANCE,
        // The harness's makers have no fidelity bond and charge a fee.
        bondless_require_zero_fee: false,
        bond_params: Default::default(),
    };
    let cj = taker_wallet
        .next_receive_address(1)
        .unwrap()
        .script_pubkey();
    let change = taker_wallet.next_change_address(0).unwrap().script_pubkey();
    let mut taker = Taker::new(
        cfg.clone(),
        0,
        vec![(utxo.outpoint, utxo.txout.clone())],
        podle,
        cj,
        change,
    )
    .unwrap();
    let mut client = NickClient::connect(
        NickKeys::generate(),
        "regtest",
        std::slice::from_ref(&url),
        None,
        CONNECT_TIMEOUT,
    )
    .await
    .unwrap();
    println!("taker nick {}", client.keys().nick());
    let tx = run_taker(
        &mut taker,
        &taker_wallet,
        &mut client,
        &rpc,
        &cfg,
        Duration::from_secs(15),
        Instant::now() + Duration::from_secs(180),
    )
    .await
    .unwrap_or_else(|e| panic!("the round with joinmarket-ng's makers failed: {e}"));

    rpc.test_accept(&tx)
        .unwrap()
        .unwrap_or_else(|why| panic!("the node refuses the CoinJoin: {why}"));
    let txid = rpc.broadcast(&tx).unwrap();
    rpc.generate_to_address(1, &sink).unwrap();
    for vout in 0..tx.output.len() as u32 {
        let out = rpc
            .utxo(&OutPoint { txid, vout })
            .unwrap()
            .expect("confirmed output");
        assert_eq!(out.confirmations, 1);
    }
    assert!(
        tx.input.len() > harness.makers,
        "every maker and the taker contribute"
    );
    assert_eq!(
        tx.output
            .iter()
            .filter(|o| o.value.to_sat() == AMOUNT)
            .count(),
        harness.makers + 1
    );
    taker_wallet.sync(&rpc, 0).unwrap();
    assert_eq!(
        taker_wallet.confirmed_balance(1).unwrap(),
        Amount::from_sat(AMOUNT)
    );
    std::fs::write(harness.dir.join("taker.txid"), txid.to_string()).unwrap();
    println!(
        "CoinJoin {txid} with {} joinmarket-ng makers confirmed: {} inputs, {} outputs",
        harness.makers,
        tx.input.len(),
        tx.output.len()
    );
}
