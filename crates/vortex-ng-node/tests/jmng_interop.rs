//! A CoinJoin between vortex-ng and joinmarket-ng over the Nostr message channel, on a regtest node.
//!
//! Skipped unless `VORTEX_NG_INTEROP_DIR` is set (`tools/jmng-interop/run.sh` sets it, with
//! `VORTEX_NG_REGTEST_RPC` and `VORTEX_NG_REGTEST_COOKIE`). This side runs the relay (nostr-sdk's
//! in-process relay, on loopback) and writes its URL to `<dir>/relay.url`; the harness then starts
//! joinmarket-ng's makers, built with its Nostr channel, on that relay.
//!
//! `taker_with_joinmarket_ng_makers` (`VORTEX_NG_INTEROP_ROLE=taker`): a vortex-ng taker waits until the
//! joinmarket-ng makers have announced their offers, asks them for the orderbook, and runs a round with them
//! in the pit `VORTEX_NG_INTEROP_PIT` names (`sw0`, the default, or `tr0`). The transaction must pass `testmempoolaccept`, confirm, and pay the taker its coinjoin output. Its
//! txid goes to `<dir>/taker.txid`.
//!
//! `makers_with_joinmarket_ng_taker` (`VORTEX_NG_INTEROP_ROLE=makers`): two vortex-ng makers serve offers on
//! the relay until the harness, having run joinmarket-ng's taker against them and mined a block, writes the
//! round's txid to `<dir>/jmng.txid`. The transaction must be on the node with both makers in it, and each
//! maker's wallet, restored from its seed, must hold what it had plus its fee, less its mining-fee share.

// A test harness: a failed step should panic with its error.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::MockRelay;
use vortex_ng_chain::{Auth, CoreRpc};
use vortex_ng_core::bitcoin::{Amount, Network, OutPoint, Transaction, Txid};
use vortex_ng_core::offer::{Offer, Pit};
use vortex_ng_maker::{Maker, MakerConfig};
use vortex_ng_node::{CONNECT_TIMEOUT, run_maker, run_taker};
use vortex_ng_nostr::client::{Incoming, NickClient, unix_now};
use vortex_ng_nostr::keys::NickKeys;
use vortex_ng_taker::{DEFAULT_BONDLESS_ALLOWANCE, Taker, TakerConfig, podle_for};
use vortex_ng_wallet::{MIXDEPTHS, PitWallet, Seed};

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const AMOUNT: u64 = 1_000_000;
/// What the vortex-ng makers charge and contribute to the mining fee.
const CJFEE: u64 = 500;
const TXFEE: u64 = 100;
/// joinmarket-ng's test bonds are locked until 2099-12-01 (its `--fidelity-bond-locktime 4099766400`):
/// timenumber 959.
const JMNG_BOND_TIMENUMBER: u32 = 959;
/// The vortex-ng makers' bonds are locked until January 2030.
const BOND_TIMENUMBER: u32 = 120;

struct Harness {
    dir: PathBuf,
    url: String,
    cookie: PathBuf,
    makers: usize,
    /// `VORTEX_NG_INTEROP_BONDS=1`: every maker holds a fidelity bond, and takers accept a maker that
    /// charges a fee only if its bond verifies.
    bonds: bool,
    /// `VORTEX_NG_INTEROP_PIT`: the pit both sides trade in.
    pit: Pit,
}

impl Harness {
    /// The harness for `role`, or `None` when this test is not the one being run.
    fn from_env(role: &str) -> Option<Harness> {
        if std::env::var("VORTEX_NG_INTEROP_ROLE").ok()? != role {
            return None;
        }
        Some(Harness {
            dir: std::env::var("VORTEX_NG_INTEROP_DIR").ok()?.into(),
            url: std::env::var("VORTEX_NG_REGTEST_RPC").ok()?,
            cookie: std::env::var("VORTEX_NG_REGTEST_COOKIE").ok()?.into(),
            makers: std::env::var("VORTEX_NG_INTEROP_MAKERS")
                .ok()
                .and_then(|n| n.parse().ok())
                .unwrap_or(2),
            bonds: std::env::var("VORTEX_NG_INTEROP_BONDS").is_ok_and(|v| v == "1"),
            pit: match std::env::var("VORTEX_NG_INTEROP_PIT").as_deref() {
                Ok("sw0") | Err(_) => Pit::Sw0,
                Ok("tr0") => Pit::Tr0,
                Ok(other) => panic!("VORTEX_NG_INTEROP_PIT={other}: sw0 or tr0"),
            },
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

fn wallet(who: &str, pit: Pit) -> PitWallet {
    let seed = Seed::from_mnemonic(WORDS, who, Network::Regtest).unwrap();
    PitWallet::new(&seed, pit).unwrap()
}

/// Where mined coins nobody needs go.
fn sink() -> vortex_ng_core::bitcoin::Address {
    wallet("interop-sink", Pit::Sw0)
        .next_receive_address(0)
        .unwrap()
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
    let Some(harness) = Harness::from_env("taker") else {
        println!("skipped: tools/jmng-interop/run.sh sets VORTEX_NG_INTEROP_ROLE=taker");
        return;
    };
    let rpc = harness.rpc();
    assert_eq!(rpc.network().unwrap(), Network::Regtest, "regtest only");

    // The relay both sides meet on.
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();

    // Our coin: a coinbase. With bonds, a coinbase to each joinmarket-ng maker's bond address too, derived
    // here from its mnemonic (VORTEX_NG_INTEROP_BOND_MNEMONICS, `|`-separated) on joinmarket's bond path
    // (m/84'/coin'/0'/2/timenumber). The maker only has a bond to prove if it derives the same address.
    let mut taker_wallet = wallet("interop-taker", harness.pit);
    let sink = sink();
    rpc.generate_to_address(1, &taker_wallet.next_receive_address(0).unwrap())
        .unwrap();
    if harness.bonds {
        let mnemonics = std::env::var("VORTEX_NG_INTEROP_BOND_MNEMONICS").expect("bond mnemonics");
        for mnemonic in mnemonics.split('|') {
            let seed = Seed::from_mnemonic(mnemonic.trim(), "", Network::Regtest).unwrap();
            let bond = PitWallet::new(&seed, Pit::Sw0)
                .unwrap()
                .bond_address(JMNG_BOND_TIMENUMBER)
                .unwrap();
            rpc.generate_to_address(1, &bond).unwrap();
        }
    }
    rpc.generate_to_address(100, &sink).unwrap();
    taker_wallet.sync(&rpc, 0).unwrap();

    // Everything the makers need is on the chain: tell the harness where to send them.
    std::fs::write(harness.dir.join("relay.url"), &url).unwrap();
    println!("relay at {url}");

    wait_for_makers(&url, harness.makers, Duration::from_secs(900)).await;

    let utxo = taker_wallet.utxos(0).unwrap().remove(0);
    let podle = podle_for(&taker_wallet, 0, &utxo, 0).unwrap();
    let cfg = TakerConfig {
        pit: harness.pit,
        network: Network::Regtest,
        amount: AMOUNT,
        makers: harness.makers,
        max_cjfee: 5_000,
        fee_rate_sat_per_kwu: 2_500,
        max_maker_utxos: 20,
        bondless_makers_allowance: DEFAULT_BONDLESS_ALLOWANCE,
        // The makers charge a fee. With bonds they are chosen only if their `!tbond` proofs verify
        // against the node (joinmarket-ng's default policy); without, the rule is off.
        bondless_require_zero_fee: harness.bonds,
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
    assert_pit_outputs(&tx, harness.pit);
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

/// Every equal-amount output is the pit's kind of output: the round really was in that pit.
fn assert_pit_outputs(tx: &Transaction, pit: Pit) {
    for out in tx.output.iter().filter(|o| o.value.to_sat() == AMOUNT) {
        let script = &out.script_pubkey;
        let ok = match pit {
            Pit::Sw0 => script.is_p2wpkh(),
            Pit::Tr0 => script.is_p2tr(),
            Pit::Wsh0 => script.is_p2wsh(),
        };
        assert!(
            ok,
            "an equal-amount output is not a {pit:?} output: {script:?}"
        );
    }
}

fn total(wallet: &PitWallet) -> Amount {
    (0..MIXDEPTHS)
        .map(|m| wallet.confirmed_balance(m).unwrap())
        .sum()
}

#[tokio::test(flavor = "multi_thread")]
async fn makers_with_joinmarket_ng_taker() {
    let Some(harness) = Harness::from_env("makers") else {
        println!("skipped: tools/jmng-interop/run.sh sets VORTEX_NG_INTEROP_ROLE=makers");
        return;
    };
    let rpc = harness.rpc();
    assert_eq!(rpc.network().unwrap(), Network::Regtest, "regtest only");

    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();

    // Each maker's coin: a coinbase, matured.
    let names: Vec<String> = (0..harness.makers)
        .map(|i| format!("interop-maker{i}"))
        .collect();
    let mut wallets: Vec<PitWallet> = names.iter().map(|n| wallet(n, harness.pit)).collect();
    for w in &mut wallets {
        rpc.generate_to_address(1, &w.next_receive_address(0).unwrap())
            .unwrap();
        if harness.bonds {
            rpc.generate_to_address(1, &w.bond_address(BOND_TIMENUMBER).unwrap())
                .unwrap();
        }
    }
    rpc.generate_to_address(100, &sink()).unwrap();
    let mut before = Vec::new();
    for w in &mut wallets {
        w.sync(&rpc, 0).unwrap();
        assert_eq!(w.bonds().len(), usize::from(harness.bonds));
        before.push(total(w));
    }

    let until = Instant::now() + Duration::from_secs(900);
    let mut handles = Vec::new();
    let offer_type = match harness.pit {
        Pit::Tr0 => "tr0absoffer",
        _ => "sw0absoffer",
    };
    for (i, w) in wallets.into_iter().enumerate() {
        let (url, rpc) = (url.clone(), harness.rpc());
        handles.push(tokio::spawn(async move {
            let offer =
                Offer::parse(offer_type, &format!("{i} 10000 100000000 {TXFEE} {CJFEE}")).unwrap();
            let mut maker = Maker::new(MakerConfig::new(vec![offer]), w).unwrap();
            let mut client = NickClient::connect(
                NickKeys::generate(),
                "regtest",
                &[url],
                None,
                CONNECT_TIMEOUT,
            )
            .await
            .unwrap();
            println!("maker {i} nick {}", client.keys().nick());
            run_maker(&mut maker, &mut client, &rpc, "regtest", until).await
        }));
    }
    // The makers are connecting: tell the harness where.
    std::fs::write(harness.dir.join("relay.url"), &url).unwrap();
    println!("relay at {url}");

    // The harness runs joinmarket-ng's taker, mines a block, then names the transaction.
    let result = harness.dir.join("jmng.txid");
    let txid: Txid = loop {
        if let Ok(text) = std::fs::read_to_string(&result) {
            break text.trim().parse().expect("a txid from the harness");
        }
        assert!(
            Instant::now() < until,
            "joinmarket-ng's taker never finished a round"
        );
        for handle in &handles {
            assert!(!handle.is_finished(), "a maker stopped before the round");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    for handle in handles {
        handle.abort();
    }

    let tx = rpc
        .raw_transaction(&txid)
        .unwrap()
        .expect("the round's transaction on the node");
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
    assert_pit_outputs(&tx, harness.pit);
    for (name, had) in names.iter().zip(before) {
        let mut restored = wallet(name, harness.pit);
        restored.sync(&rpc, 0).unwrap();
        assert_eq!(
            total(&restored),
            had + Amount::from_sat(CJFEE - TXFEE),
            "{name}: its coins, plus its fee, less its mining-fee share"
        );
    }
    println!(
        "CoinJoin {txid} by joinmarket-ng's taker with {} vortex-ng makers confirmed: {} inputs, {} outputs",
        harness.makers,
        tx.input.len(),
        tx.output.len()
    );
}
