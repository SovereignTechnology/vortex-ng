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
//! name the server announces, if any) both sides meet on an IRC server; with both set, on the two at once,
//! a maker with one nick on both and a taker with a nick of its own on each. Either way this side writes
//! where to meet to `<dir>/relay.url` once the chain is ready, and the harness then starts the other side.
//! With `VORTEX_NG_INTEROP_ONIONS` (comma-separated onion names, possibly none) everyone but a maker reaches
//! the directory through a test SOCKS proxy that stands in for Tor, and a taker connects directly to the
//! makers it chose that serve an onion: the names listed are on this machine, any other onion is refused.
//! With `VORTEX_NG_INTEROP_SERVE` this side's makers serve (`loopback`, or `<onion>:<port>,…`, one per maker);
//! in the makers' run the proxy is then the other side's taker's way out, and its address goes to
//! `<dir>/socks.addr` before `relay.url`.
//!
//! `taker_with_joinmarket_ng_makers` (`VORTEX_NG_INTEROP_ROLE=taker`): a vortex-ng taker waits until the
//! joinmarket-ng makers have announced their offers, asks them for the orderbook, and runs a round with them
//! in the pit `VORTEX_NG_INTEROP_PIT` names (`sw0`, the default, or `tr0`). The transaction must pass `testmempoolaccept`, confirm, and pay the taker its coinjoin output. Its
//! txid goes to `<dir>/taker.txid`. With those makers still up, a vortex-ng maker is then handed a commitment
//! to announce: it must reach the channel from a nick that is not the maker's, and each of the other side's
//! makers must refuse a `!fill` that uses it while still accepting a fresh one.
//!
//! `makers_with_joinmarket_ng_taker` (`VORTEX_NG_INTEROP_ROLE=makers`): two vortex-ng makers serve offers on
//! the relay until the harness, having run joinmarket-ng's taker against them and mined a block, writes the
//! round's txid to `<dir>/jmng.txid`. The transaction must be on the node with both makers in it, and each
//! maker's wallet, restored from its seed, must hold what it had plus its fee, less its mining-fee share.
//!
//! `VORTEX_NG_INTEROP_GRACE_SECS` (the makers' role) is how long, in seconds, a vortex-ng maker still takes a
//! commitment it has heard announced; the default is the maker's own. `tools/mixed-interop/run.sh` sets it to
//! 2 so that the 5 seconds the taker's role waits before probing is past it.
//!
//! `VORTEX_NG_INTEROP_MAKERS` is how many makers this side runs (two by default) and, for the taker, how many
//! it chooses. `VORTEX_NG_INTEROP_ROUND_MAKERS` is how many makers the round has in all, when other
//! implementations' makers are in it too (`tools/mixed-interop/run.sh`).

// A test harness: a failed step should panic with its error.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::MockRelay;
use vortex_ng_chain::{Auth, CoreRpc};
use vortex_ng_channel::set::ChannelSet;
use vortex_ng_channel::socks::Outbound;
use vortex_ng_channel::testing::AuthSocks;
use vortex_ng_channel::{Channel, Incoming as Arrived, Next};
use vortex_ng_core::bitcoin::hex::DisplayHex;
use vortex_ng_core::bitcoin::{Amount, Network, OutPoint, Transaction, Txid};
use vortex_ng_core::command::Command;
use vortex_ng_core::nacl::NaclKeypair;
use vortex_ng_core::nick::NickIdentity;
use vortex_ng_core::offer::{Offer, Pit};
use vortex_ng_core::tx::random_bytes;
use vortex_ng_irc::{IrcChannel, IrcConfig, IrcServer};
use vortex_ng_maker::{Maker, MakerConfig};
use vortex_ng_node::{CONNECT_TIMEOUT, fetch_orderbook, run_maker, run_taker};
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
    /// `VORTEX_NG_INTEROP_ROUND_MAKERS`: the makers in the round, ours and others' (`makers` by default).
    round_makers: usize,
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
    /// `VORTEX_NG_INTEROP_SERVE`: whether and how makers on the directory serve.
    serve: Serving,
    /// `VORTEX_NG_INTEROP_ONIONS`: the onion names on this machine, when the way out is a test proxy.
    onions: Option<HashMap<String, IpAddr>>,
    /// That proxy, once started.
    proxy: Option<AuthSocks>,
}

/// How this side's makers on the directory serve, so that the other side's taker can reach them directly.
#[derive(Clone, Debug)]
enum Serving {
    /// `VORTEX_NG_INTEROP_SERVE` unset: they do not.
    Not,
    /// `loopback`: each on a loopback port that is its location (joinmarket-clientserver's testing mode).
    Loopback,
    /// `<onion>:<port>,…`: maker `i` as the `i`th onion, listening on that port on loopback, as behind a Tor
    /// that forwards the onion there. The test proxy stands in for that Tor.
    Onions(Vec<(String, u16)>),
}

impl Serving {
    fn from_env() -> Serving {
        match std::env::var("VORTEX_NG_INTEROP_SERVE").as_deref() {
            Err(_) => Serving::Not,
            Ok("loopback") => Serving::Loopback,
            Ok(list) => Serving::Onions(
                list.split(',')
                    .map(|entry| {
                        let (host, port) = entry.rsplit_once(':').expect("<onion>:<port>");
                        assert!(
                            vortex_ng_onion::wire::is_v3_onion(host),
                            "{host}: a v3 onion"
                        );
                        (host.to_string(), port.parse().expect("a port"))
                    })
                    .collect(),
            ),
        }
    }

    /// How maker `index` serves; with onions, a maker past those named (the commitment announcer) does not.
    fn serve(&self, index: usize) -> Serve {
        match self {
            Serving::Not => Serve::None,
            Serving::Loopback => Serve::Loopback,
            Serving::Onions(onions) => {
                onions
                    .get(index)
                    .map_or(Serve::None, |(host, port)| Serve::Onion {
                        host: host.clone(),
                        port: *port,
                    })
            }
        }
    }
}

impl Harness {
    /// The harness for `role`, or `None` when this test is not the one being run.
    fn from_env(role: &str) -> Option<Harness> {
        if std::env::var("VORTEX_NG_INTEROP_ROLE").ok()? != role {
            return None;
        }
        let makers = std::env::var("VORTEX_NG_INTEROP_MAKERS")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(2);
        Some(Harness {
            dir: std::env::var("VORTEX_NG_INTEROP_DIR").ok()?.into(),
            url: std::env::var("VORTEX_NG_REGTEST_RPC").ok()?,
            cookie: std::env::var("VORTEX_NG_REGTEST_COOKIE").ok()?.into(),
            makers,
            round_makers: std::env::var("VORTEX_NG_INTEROP_ROUND_MAKERS")
                .ok()
                .and_then(|n| n.parse().ok())
                .unwrap_or(makers),
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
            serve: Serving::from_env(),
            irc: std::env::var("VORTEX_NG_INTEROP_IRC").ok().map(|text| {
                let mut server = IrcServer::parse(&text).expect("an IRC server host:port");
                server.expected_network = std::env::var("VORTEX_NG_INTEROP_IRC_NETWORK").ok();
                server
            }),
            onions: std::env::var("VORTEX_NG_INTEROP_ONIONS").ok().map(|names| {
                names
                    .split(',')
                    .filter(|name| !name.is_empty())
                    .map(|name| {
                        assert!(
                            vortex_ng_onion::wire::is_v3_onion(name),
                            "{name}: a v3 onion"
                        );
                        (name.to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST))
                    })
                    .collect()
            }),
            proxy: None,
        })
    }

    /// Start the test proxy, when this run has one.
    async fn start_proxy(&mut self) {
        if let Some(onions) = &self.onions {
            self.proxy = Some(AuthSocks::start_with_onions(onions.clone()).await.unwrap());
        }
    }

    /// Every onion a direct connection was asked for through the proxy, and whether it is on this machine.
    fn onions_asked(&self) -> Vec<(String, bool)> {
        let (Some(proxy), Some(onions)) = (&self.proxy, &self.onions) else {
            return Vec::new();
        };
        let asked: BTreeSet<String> = proxy
            .seen()
            .into_iter()
            .map(|(_, destination)| destination)
            .filter(|destination| destination.contains(".onion:"))
            .collect();
        asked
            .into_iter()
            .map(|destination| {
                let name = destination.split(':').next().unwrap_or_default();
                let here = onions.contains_key(name);
                (destination, here)
            })
            .collect()
    }

    /// Where the sides meet, for the log.
    fn place(&self, url: &str) -> String {
        let mut places = Vec::new();
        if let Some(directory) = &self.directory {
            places.push(format!(
                "directory at {}:{}",
                directory.host, directory.port
            ));
        }
        if let Some(irc) = &self.irc {
            places.push(format!(
                "IRC server at {}:{}{}",
                irc.host,
                irc.port,
                if irc.tls { " over TLS" } else { "" }
            ));
        }
        if places.is_empty() {
            places.push(format!("relay at {url}"));
        }
        places.join(" and ")
    }

    /// How many legacy channels this run meets on.
    fn legacy_channels(&self) -> usize {
        usize::from(self.directory.is_some()) + usize::from(self.irc.is_some())
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

/// Channels for a new participant: on the directory and the IRC server when they are given (both, with
/// `CHANNEL=both`), else on the relay at `url`. A maker (`Some(index)`) keeps one nick on all of them, anyone
/// else takes a nick of its own on each (ADR 0007). A maker on the directory serves as
/// `VORTEX_NG_INTEROP_SERVE` says ([`Serving`]), so the other side's taker can connect to it: on loopback for
/// joinmarket-clientserver's regtest testing mode, as an onion for JoinMarket-NG, whose directories refuse a
/// location that is not a v3 onion.
async fn meet(harness: &Harness, url: &str, maker_index: Option<usize>) -> ChannelSet {
    let serve = maker_index.is_some();
    let maker = NickIdentity::generate();
    let identity = || {
        if serve {
            maker.clone()
        } else {
            NickIdentity::generate()
        }
    };
    let mut channels: Vec<Box<dyn vortex_ng_channel::set::DynChannel>> = Vec::new();
    if let Some(directory) = &harness.directory {
        // Through the test proxy, a taker reaches makers at their onions, as through Tor. Without it, the
        // reference's makers serve on loopback in its testing mode: a taker reaches them directly once the
        // directory names them.
        let (peers, outbound) = match (&harness.proxy, serve) {
            (Some(proxy), false) => (PeerPolicy::Onion, Outbound::IsolatingProxy(proxy.addr())),
            _ => (PeerPolicy::Local, Outbound::Direct),
        };
        channels.push(Box::new(
            OnionChannel::connect(
                identity(),
                OnionConfig {
                    directories: vec![directory.clone()],
                    network: harness.onion_network.clone(),
                    timeout: Duration::from_secs(60),
                    peers,
                    serve: maker_index.map_or(Serve::None, |index| harness.serve.serve(index)),
                },
                &outbound,
            )
            .await
            .unwrap_or_else(|e| panic!("the directory: {e}")),
        ));
    }
    if let Some(server) = &harness.irc {
        let config = IrcConfig {
            server: server.clone(),
            network: "regtest".into(),
            timeout: Duration::from_secs(60),
        };
        // A server with a certificate from the harness's own authority.
        let connected = match std::env::var("VORTEX_NG_INTEROP_IRC_CA") {
            Ok(path) => {
                let der = std::fs::read(&path).expect("the CA certificate");
                let roots = vortex_ng_irc::testing::roots_from_der(&der);
                IrcChannel::connect_with_roots(identity(), config, &Outbound::Direct, roots).await
            }
            Err(_) => IrcChannel::connect(identity(), config, &Outbound::Direct).await,
        };
        let channel = connected.unwrap_or_else(|e| panic!("the IRC server: {e}"));
        println!("IRC signature domain {:?}", channel.hostid());
        channels.push(Box::new(channel));
    }
    if channels.is_empty() {
        channels.push(Box::new(
            NickClient::connect(
                NickKeys::generate(),
                "regtest",
                &[url.to_string()],
                None,
                CONNECT_TIMEOUT,
            )
            .await
            .unwrap(),
        ));
    }
    ChannelSet::new(channels).unwrap()
}

/// Wait until `count` different makers answer `!orderbook` on every legacy channel of this run (asked every
/// five seconds). Our side has a different nick on each channel, which is checked here too.
async fn wait_for_answering_makers(harness: &Harness, count: usize, limit: Duration) {
    let channels = harness.legacy_channels();
    let mut observer = meet(harness, "", None).await;
    observer.listen(true, false).await.unwrap();
    let until = Instant::now() + limit;
    let mut seen: HashMap<String, HashSet<usize>> = HashMap::new();
    let mut ours = HashSet::new();
    let mut asked: Option<Instant> = None;
    loop {
        let ready = seen.values().filter(|on| on.len() == channels).count();
        if ready >= count {
            break;
        }
        assert!(
            Instant::now() < until,
            "only {ready} of {count} makers answered on all {channels} channel(s)"
        );
        if asked.is_none_or(|at| at.elapsed() >= Duration::from_secs(5)) {
            observer.ask_orderbook().await.unwrap();
            asked = Some(Instant::now());
        }
        let (nick, route) = match observer.receive(Duration::from_secs(1)).await {
            Next::Message(Arrived::Private { msg, route }) => (msg.from, route),
            Next::Message(Arrived::Offers { nick, route, .. }) => (nick, route),
            _ => continue,
        };
        ours.insert(observer.nick_on(&route).to_string());
        let on = seen.entry(nick.clone()).or_default();
        if on.insert(observer.channel_of(&route)) && on.len() == channels {
            println!("maker {nick} answered on the {}", harness.place(""));
        }
    }
    assert_eq!(ours.len(), channels, "our side has one nick per channel");
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
    let Some(mut harness) = Harness::from_env("taker") else {
        println!("skipped: tools/jmng-interop/run.sh sets VORTEX_NG_INTEROP_ROLE=taker");
        return;
    };
    harness.start_proxy().await;
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
    // `VORTEX_NG_INTEROP_COMMIT_ELSEWHERE=1`: the commitment comes from a coin that is not an input of the
    // round, as when a Lightning node's wallet holds the inputs and cannot prove a PoDLE (ADR 0008).
    let commit_elsewhere =
        std::env::var("VORTEX_NG_INTEROP_COMMIT_ELSEWHERE").is_ok_and(|v| v == "1");
    if commit_elsewhere {
        rpc.generate_to_address(1, &taker_wallet.next_receive_address(3).unwrap())
            .unwrap();
    }
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
    let committed = commit_elsewhere.then(|| taker_wallet.utxos(3).unwrap().remove(0));
    let podle = match &committed {
        Some(coin) => podle_for(&taker_wallet, 3, coin, 0).unwrap(),
        None => podle_for(&taker_wallet, 0, &utxo, 0).unwrap(),
    };
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
    let mut client = meet(&harness, &url, None).await;
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
    if let Some(coin) = &committed {
        assert!(
            tx.input
                .iter()
                .all(|input| input.previous_output != coin.outpoint),
            "the coin committed to is not an input"
        );
        assert!(rpc.utxo(&coin.outpoint).unwrap().is_some());
        println!("joinmarket-ng's makers took a commitment to a coin outside the round");
    }
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
    for (destination, here) in harness.onions_asked() {
        if here {
            println!("direct connection asked for {destination}: on this machine");
        } else {
            println!("direct connection asked for {destination}: refused by the proxy");
        }
    }
    announced_commitment_is_refused(&harness, &url).await;
}

/// How long a maker has to answer a `!fill`.
const FILL_ANSWER_TIME: Duration = Duration::from_secs(20);

/// A new nick that has heard the other side's makers and the vortex-ng maker.
struct Prober {
    client: ChannelSet,
    /// The other side's makers: nick, the id of an offer that fits [`AMOUNT`], and the way to reach it.
    makers: Vec<(String, u64, <ChannelSet as Channel>::Route)>,
    /// The way to the vortex-ng maker.
    to_announcer: <ChannelSet as Channel>::Route,
}

impl Prober {
    async fn new(harness: &Harness, url: &str, announcer: &str) -> Prober {
        let mut client = meet(harness, url, None).await;
        let until = Instant::now() + Duration::from_secs(120);
        loop {
            let book = fetch_orderbook(&mut client, "regtest", Duration::from_secs(12))
                .await
                .unwrap();
            let mut makers: Vec<(String, u64, <ChannelSet as Channel>::Route)> = Vec::new();
            for (nick, offer) in &book.offers {
                if nick != announcer
                    && offer.offer_type.pit == harness.pit
                    && (offer.minsize..=offer.maxsize).contains(&AMOUNT)
                    && !makers.iter().any(|(known, ..)| known == nick)
                {
                    let route = book.route(nick).expect("a maker's route").clone();
                    makers.push((nick.clone(), offer.oid, route));
                }
            }
            if makers.len() >= harness.makers
                && let Some(to_announcer) = book.route(announcer).cloned()
            {
                return Prober {
                    client,
                    makers,
                    to_announcer,
                };
            }
            assert!(
                Instant::now() < until,
                "{} of {} makers and the announcer did not answer",
                makers.len(),
                harness.makers
            );
        }
    }

    /// Send each of the other side's makers a `!fill` with `commitment`.
    async fn fill(&self, commitment: &[u8; 32]) {
        let nacl = NaclKeypair::generate().public_hex();
        let commitment = commitment.to_lower_hex_string();
        for (nick, oid, route) in &self.makers {
            self.client
                .send_private(
                    route,
                    nick,
                    "fill",
                    &format!("{oid} {AMOUNT} {nacl} P{commitment}"),
                )
                .await
                .unwrap();
        }
    }

    /// The makers that answered a `!fill` with `!pubkey` within `wait`.
    async fn accepted(&mut self, wait: Duration) -> HashSet<String> {
        let until = Instant::now() + wait;
        let mut accepted = HashSet::new();
        while accepted.len() < self.makers.len() {
            let Some(left) = until.checked_duration_since(Instant::now()) else {
                break;
            };
            match self.client.receive(left).await {
                Next::Message(Arrived::Private { msg, .. })
                    if self.makers.iter().any(|(nick, ..)| *nick == msg.from) =>
                {
                    match msg.command.as_str() {
                        "pubkey" => {
                            accepted.insert(msg.from);
                        }
                        "error" => println!("maker {} answered !error {}", msg.from, msg.body),
                        _ => {}
                    }
                }
                Next::Closed => break,
                _ => {}
            }
        }
        accepted
    }

    /// Every maker takes a commitment nobody has seen. A maker that has just finished a round may not be
    /// taking new ones yet, so it gets a few tries.
    async fn assert_fresh_commitment_accepted(&mut self) {
        let mut accepted = HashSet::new();
        for _ in 0..6 {
            self.fill(&random_bytes::<32>()).await;
            accepted.extend(self.accepted(FILL_ANSWER_TIME).await);
            if accepted.len() == self.makers.len() {
                return;
            }
        }
        panic!(
            "only {} of {} makers accepted a fresh commitment",
            accepted.len(),
            self.makers.len()
        );
    }
}

/// A commitment handed to a vortex-ng maker reaches the channel from a nick that is not the maker's, and the
/// other side's makers then refuse it. A fresh commitment before and after shows that a maker that stays
/// silent has refused this one and is not simply gone.
async fn announced_commitment_is_refused(harness: &Harness, url: &str) {
    let mut channel = meet(harness, url, Some(harness.makers)).await;
    let announcer = channel.nick().to_string();
    let announcer_wallet = wallet("interop-announcer", harness.pit);
    let offer_type = match harness.pit {
        Pit::Tr0 => "tr0absoffer",
        _ => "sw0absoffer",
    };
    let offer = Offer::parse(offer_type, &format!("0 10000 100000000 {TXFEE} {CJFEE}")).unwrap();
    let rpc = harness.rpc();
    let announcing = tokio::spawn(async move {
        let mut maker = Maker::new(MakerConfig::new(vec![offer]), announcer_wallet).unwrap();
        let until = Instant::now() + Duration::from_secs(600);
        run_maker(&mut maker, &mut channel, &rpc, "regtest", until).await
    });
    let mut watcher = meet(harness, url, None).await;
    watcher.listen(false, true).await.unwrap();

    let mut before = Prober::new(harness, url, &announcer).await;
    before.assert_fresh_commitment_accepted().await;

    let commitment = random_bytes::<32>();
    before
        .client
        .send_private(
            &before.to_announcer,
            &announcer,
            "hp2",
            &commitment.to_lower_hex_string(),
        )
        .await
        .unwrap();
    let until = Instant::now() + Duration::from_secs(60);
    let from = loop {
        let left = until
            .checked_duration_since(Instant::now())
            .expect("the commitment handed to the vortex-ng maker reaches the channel");
        match watcher.receive(left).await {
            Next::Message(Arrived::Public { nick, commands, .. })
                if commands.contains(&Command::Hp2(commitment)) =>
            {
                break nick;
            }
            Next::Closed => panic!("the watcher's channel closed"),
            _ => {}
        }
    };
    assert_ne!(
        from, announcer,
        "the announcement is not linked to the maker"
    );
    // It arrived here; give the makers, on the same channel, a moment to act on it.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let mut refused = Prober::new(harness, url, &announcer).await;
    refused.fill(&commitment).await;
    let took = refused.accepted(FILL_ANSWER_TIME).await;
    assert!(took.is_empty(), "these makers took it: {took:?}");

    let mut after = Prober::new(harness, url, &announcer).await;
    after.assert_fresh_commitment_accepted().await;
    let late = refused.accepted(Duration::from_secs(1)).await;
    assert!(late.is_empty(), "these makers took it late: {late:?}");

    println!(
        "Commitment announced by a vortex-ng maker: refused by {} makers of the other implementation, which still accept a fresh one",
        refused.makers.len()
    );
    announcing.abort();
    for client in [&before.client, &refused.client, &after.client, &watcher] {
        client.shutdown().await;
    }
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
    let Some(mut harness) = Harness::from_env("makers") else {
        println!("skipped: tools/jmng-interop/run.sh sets VORTEX_NG_INTEROP_ROLE=makers");
        return;
    };
    let rpc = harness.rpc();
    assert_eq!(rpc.network().unwrap(), Network::Regtest, "regtest only");
    // The other side's taker reaches the makers' onions through this proxy, as through Tor.
    harness.start_proxy().await;

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
        let mut client = meet(&harness, &url, Some(i)).await;
        handles.push(tokio::spawn(async move {
            let offer =
                Offer::parse(offer_type, &format!("{i} 10000 100000000 {TXFEE} {CJFEE}")).unwrap();
            let mut config = MakerConfig::new(vec![offer]);
            // How long this maker still takes a commitment it has heard announced: the harness that checks
            // that every maker refuses one sets it short.
            if let Some(grace) = std::env::var("VORTEX_NG_INTEROP_GRACE_SECS")
                .ok()
                .and_then(|text| text.parse().ok())
            {
                config.announced_grace = grace;
            }
            let mut maker = Maker::new(config, w).unwrap();
            println!("maker {i} nick {}", client.nick());
            run_maker(&mut maker, &mut client, &rpc, "regtest", until).await
        }));
    }
    // The makers are connecting: tell the harness where, and where the proxy is.
    if let Some(proxy) = &harness.proxy {
        std::fs::write(harness.dir.join("socks.addr"), proxy.addr().to_string()).unwrap();
        println!("test proxy at {}", proxy.addr());
    }
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
    for (destination, here) in harness.onions_asked() {
        let answer = if here {
            "on this machine"
        } else {
            "refused by the proxy"
        };
        println!("direct connection asked for {destination}: {answer}");
    }

    let tx = rpc
        .raw_transaction(&txid)
        .unwrap()
        .expect("the round's transaction on the node");
    assert!(
        tx.input.len() > harness.round_makers,
        "every maker and the taker contribute"
    );
    assert_eq!(
        tx.output
            .iter()
            .filter(|o| o.value.to_sat() == AMOUNT)
            .count(),
        harness.round_makers + 1
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
        "CoinJoin {txid} by the other implementation's taker with {} vortex-ng makers of {} confirmed: {} inputs, {} outputs",
        harness.makers,
        harness.round_makers,
        tx.input.len(),
        tx.output.len()
    );
}
