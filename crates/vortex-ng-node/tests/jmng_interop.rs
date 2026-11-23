//! A CoinJoin between vortex-ng and another JoinMarket implementation on a regtest node: joinmarket-ng
//! (`tools/jmng-interop/run.sh`) over the Nostr message channel or JoinMarket's onion directory channel, or
//! joinmarket-clientserver (`tools/ref-interop/run.sh`) over the onion directory channel or IRC.
//!
//! Skipped unless `VORTEX_NG_INTEROP_DIR` is set (the harnesses set it, with `VORTEX_NG_REGTEST_RPC` and
//! `VORTEX_NG_REGTEST_COOKIE`). On Nostr this side runs the relay (nostr-sdk's in-process relay, on loopback)
//! and joinmarket-ng's makers, built with its Nostr channel, join it. With
//! `VORTEX_NG_INTEROP_DIRECTORY=<host:port>` (and `VORTEX_NG_INTEROP_DIRECTORY_ID`, its JMP-0005 identity)
//! both sides meet on a directory node the harness runs instead; `VORTEX_NG_INTEROP_ONION_NETWORK` is the
//! network name the directory expects (`regtest`, or `testnet` for joinmarket-clientserver, which runs regtest
//! as testnet). With `VORTEX_NG_INTEROP_IRC=<host:port>` (and `VORTEX_NG_INTEROP_IRC_NETWORK`, the `NETWORK`
//! name the server announces, if any) both sides meet on an IRC server. Either way this side writes where to
//! meet to `<dir>/relay.url` once the chain is ready, and the harness then starts the other side.
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
use vortex_ng_channel::set::ChannelSet;
use vortex_ng_channel::socks::Outbound;
use vortex_ng_channel::{Channel, Incoming as Arrived, Next};
use vortex_ng_core::bitcoin::{Amount, Network, OutPoint, Transaction, Txid};
use vortex_ng_core::nick::NickIdentity;
use vortex_ng_core::offer::{Offer, Pit};
use vortex_ng_irc::{IrcChannel, IrcConfig, IrcServer};
use vortex_ng_maker::{Maker, MakerConfig};
use vortex_ng_node::{CONNECT_TIMEOUT, run_maker, run_taker};
use vortex_ng_nostr::client::{Incoming, NickClient, unix_now};
use vortex_ng_nostr::keys::NickKeys;
use vortex_ng_onion::{Directory, OnionChannel, OnionConfig, PeerPolicy, Serve};
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
    /// `VORTEX_NG_INTEROP_DIRECTORY`: meet on this onion directory node instead of a Nostr relay.
    directory: Option<Directory>,
    /// `VORTEX_NG_INTEROP_ONION_NETWORK`: the network name in the directory handshake.
    onion_network: String,
    /// `VORTEX_NG_INTEROP_IRC`: meet on this IRC server instead.
    irc: Option<IrcServer>,
    /// `VORTEX_NG_INTEROP_SERVE=loopback`: makers on the directory serve on loopback.
    serve_loopback: bool,
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
            directory: std::env::var("VORTEX_NG_INTEROP_DIRECTORY")
                .ok()
                .map(|text| {
                    let mut directory = Directory::parse(&text).expect("a directory host:port");
                    directory.id = std::env::var("VORTEX_NG_INTEROP_DIRECTORY_ID").ok();
                    directory
                }),
            onion_network: std::env::var("VORTEX_NG_INTEROP_ONION_NETWORK")
                .unwrap_or_else(|_| "regtest".into()),
            serve_loopback: std::env::var("VORTEX_NG_INTEROP_SERVE").is_ok_and(|v| v == "loopback"),
            irc: std::env::var("VORTEX_NG_INTEROP_IRC").ok().map(|text| {
                let mut server = IrcServer::parse(&text).expect("an IRC server host:port");
                server.expected_network = std::env::var("VORTEX_NG_INTEROP_IRC_NETWORK").ok();
                server
            }),
        })
    }

    /// Where the sides meet, for the log.
    fn place(&self, url: &str) -> String {
        match (&self.irc, &self.directory) {
            (Some(irc), _) => format!(
                "IRC server at {}:{}{}",
                irc.host,
                irc.port,
                if irc.tls { " over TLS" } else { "" }
            ),
            (None, Some(directory)) => {
                format!("directory at {}:{}", directory.host, directory.port)
            }
            (None, None) => format!("relay at {url}"),
        }
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

/// A channel for a new nick: on the IRC server or the directory when one is given, else on the relay at `url`.
/// A maker (`serve`) on the directory serves on loopback when `VORTEX_NG_INTEROP_SERVE=loopback`, so the
/// other side's taker can connect to it: joinmarket-clientserver's regtest testing mode only, since
/// JoinMarket-NG's directories refuse a location that is not a v3 onion.
async fn meet(harness: &Harness, url: &str, serve: bool) -> ChannelSet {
    let channel: Box<dyn vortex_ng_channel::set::DynChannel> =
        match (&harness.irc, &harness.directory) {
            (Some(server), _) => {
                let config = IrcConfig {
                    server: server.clone(),
                    network: "regtest".into(),
                    timeout: Duration::from_secs(60),
                };
                let identity = NickIdentity::generate();
                // A server with a certificate from the harness's own authority.
                let connected = match std::env::var("VORTEX_NG_INTEROP_IRC_CA") {
                    Ok(path) => {
                        let der = std::fs::read(&path).expect("the CA certificate");
                        let roots = vortex_ng_irc::testing::roots_from_der(&der);
                        IrcChannel::connect_with_roots(identity, config, &Outbound::Direct, roots)
                            .await
                    }
                    Err(_) => IrcChannel::connect(identity, config, &Outbound::Direct).await,
                };
                let channel = connected.unwrap_or_else(|e| panic!("the IRC server: {e}"));
                println!("IRC signature domain {:?}", channel.hostid());
                Box::new(channel)
            }
            (None, Some(directory)) => Box::new(
                OnionChannel::connect(
                    NickIdentity::generate(),
                    OnionConfig {
                        directories: vec![directory.clone()],
                        network: harness.onion_network.clone(),
                        timeout: Duration::from_secs(60),
                        // The reference's makers serve on loopback in its testing mode: a taker reaches
                        // them directly once the directory names them.
                        peers: PeerPolicy::Local,
                        serve: if serve && harness.serve_loopback {
                            Serve::Loopback
                        } else {
                            Serve::None
                        },
                    },
                    &Outbound::Direct,
                )
                .await
                .unwrap_or_else(|e| panic!("the directory: {e}")),
            ),
            (None, None) => Box::new(
                NickClient::connect(
                    NickKeys::generate(),
                    "regtest",
                    &[url.to_string()],
                    None,
                    CONNECT_TIMEOUT,
                )
                .await
                .unwrap(),
            ),
        };
    ChannelSet::new(vec![channel]).unwrap()
}

/// Wait until `count` different makers answer `!orderbook` on the directory or IRC server (asked every five
/// seconds).
async fn wait_for_answering_makers(harness: &Harness, count: usize, limit: Duration) {
    let mut observer = meet(harness, "", false).await;
    observer.listen(true, false).await.unwrap();
    let until = Instant::now() + limit;
    let mut seen = HashSet::new();
    let mut asked: Option<Instant> = None;
    while seen.len() < count {
        assert!(
            Instant::now() < until,
            "only {} of {count} makers answered",
            seen.len()
        );
        if asked.is_none_or(|at| at.elapsed() >= Duration::from_secs(5)) {
            observer.ask_orderbook().await.unwrap();
            asked = Some(Instant::now());
        }
        let nick = match observer.receive(Duration::from_secs(1)).await {
            Next::Message(Arrived::Private { msg, .. }) => msg.from,
            Next::Message(Arrived::Offers { nick, .. }) => nick,
            _ => continue,
        };
        if seen.insert(nick.clone()) {
            println!("maker {nick} answered on the {}", harness.place(""));
        }
    }
    observer.shutdown().await;
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
    println!("{}", harness.place(&url));
    if harness.directory.is_some() || harness.irc.is_some() {
        wait_for_answering_makers(&harness, harness.makers, Duration::from_secs(900)).await;
    } else {
        wait_for_makers(&url, harness.makers, Duration::from_secs(900)).await;
    }

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
    let mut client = meet(&harness, &url, false).await;
    println!("taker nick {}", client.nick());
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
    .unwrap_or_else(|e| panic!("the round with the other side's makers failed: {e}"));

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
        "CoinJoin {txid} with {} makers of the other implementation confirmed: {} inputs, {} outputs",
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
        let rpc = harness.rpc();
        let mut client = meet(&harness, &url, true).await;
        handles.push(tokio::spawn(async move {
            let offer =
                Offer::parse(offer_type, &format!("{i} 10000 100000000 {TXFEE} {CJFEE}")).unwrap();
            let mut maker = Maker::new(MakerConfig::new(vec![offer]), w).unwrap();
            println!("maker {i} nick {}", client.nick());
            run_maker(&mut maker, &mut client, &rpc, "regtest", until).await
        }));
    }
    // The makers are connecting: tell the harness where.
    std::fs::write(harness.dir.join("relay.url"), &url).unwrap();
    println!("{}", harness.place(&url));

    // The harness runs the other implementation's taker, mines a block, then names the transaction.
    let result = harness.dir.join("jmng.txid");
    let txid: Txid = loop {
        if let Ok(text) = std::fs::read_to_string(&result) {
            break text.trim().parse().expect("a txid from the harness");
        }
        assert!(
            Instant::now() < until,
            "the other implementation's taker never finished a round"
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
        "CoinJoin {txid} by the other implementation's taker with {} vortex-ng makers confirmed: {} inputs, {} outputs",
        harness.makers,
        tx.input.len(),
        tx.output.len()
    );
}
