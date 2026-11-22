//! `vortex-ng orderbook` and `vortex-ng maker`: the commands that talk to relays and to a node.

use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};

use vortex_ng_chain::{Auth, CoreRpc};
use vortex_ng_channel::Channel;
use vortex_ng_channel::set::{ChannelSet, DynChannel};
use vortex_ng_core::bitcoin::{Address, Network, OutPoint, TxOut};
use vortex_ng_core::bond::BondValueParams;
use vortex_ng_core::nick::NickIdentity;
use vortex_ng_core::offer::{CjFee, Offer, RelativeFee};
use vortex_ng_core::protocol::{NOSTR_HOSTID, ONION_HOSTID};
use vortex_ng_irc::codec::Hostid;
use vortex_ng_irc::{IrcChannel, IrcConfig, IrcServer};
use vortex_ng_maker::{Maker, MakerConfig};
use vortex_ng_node::{
    CONNECT_TIMEOUT, MAX_BOND_LOOKUPS, MakerReport, MakerService, NodeError, OfferFee, OfferPolicy,
    channel_network, fetch_orderbook_for, run_taker, serve_maker,
};
use vortex_ng_nostr::client::{NickClient, unix_now};
use vortex_ng_nostr::keys::NickKeys;
use vortex_ng_nostr::socks::Outbound;
use vortex_ng_onion::{Directory, OnionChannel, OnionConfig, PeerPolicy, Serve};
use vortex_ng_taker::{
    Coin, DEFAULT_BONDLESS_ALLOWANCE, Taker, TakerConfig, TakerError, choose_coins, podle_for,
    verify_bond,
};
use vortex_ng_wallet::{MIXDEPTHS, PitWallet};

use crate::args::Args;
use crate::podle_log::PodleLog;
use crate::wallet::{failed, network_name, parse};
use crate::{Failure, secret, wallet};

/// Relays a nick connects to at most.
const MAX_RELAYS: usize = 8;
/// The options that say how to reach the node.
const RPC_OPTIONS: [&str; 4] = [
    "rpc-url",
    "rpc-cookie-file",
    "rpc-user",
    "rpc-password-file",
];

fn usage(why: &str) -> Failure {
    Failure::Usage(why.into())
}

/// The relays `--relays` names: one to eight `ws://` or `wss://` URLs, separated by commas.
fn relays(args: &Args) -> Result<Vec<String>, Failure> {
    let wrong = || usage("`--relays` is one to eight ws:// or wss:// URLs, separated by commas");
    let Some(given) = args.get("relays") else {
        return Ok(Vec::new());
    };
    let relays: Vec<String> = given
        .split(',')
        .map(|relay| relay.trim().to_string())
        .collect();
    let valid = |relay: &String| {
        ["ws://", "wss://"]
            .iter()
            .any(|scheme| relay.len() > scheme.len() && relay.starts_with(*scheme))
            && !relay.contains(char::is_whitespace)
    };
    if relays.is_empty() || relays.len() > MAX_RELAYS || !relays.iter().all(valid) {
        return Err(wrong());
    }
    Ok(relays)
}

/// Directory nodes a command may use at most.
const MAX_DIRECTORIES: usize = 16;

/// Where a command meets other peers: Nostr relays, JoinMarket's onion directory nodes, IRC servers.
struct Meeting {
    relays: Vec<String>,
    directories: Vec<Directory>,
    irc: Vec<IrcServer>,
}

impl Meeting {
    fn describe(&self) -> String {
        format!(
            "{} relay(s), {} directory node(s), {} IRC server(s)",
            self.relays.len(),
            self.directories.len(),
            self.irc.len()
        )
    }
}

/// IRC servers a command may use at most.
const MAX_IRC: usize = 4;

/// `--relays`, `--directories` and `--irc`: at least one of them.
fn meeting(args: &Args) -> Result<Meeting, Failure> {
    let relays = relays(args)?;
    let directories = match args.get("directories") {
        None => Vec::new(),
        Some(given) => {
            let parsed: Option<Vec<Directory>> = given.split(',').map(Directory::parse).collect();
            match parsed {
                Some(list) if !list.is_empty() && list.len() <= MAX_DIRECTORIES => list,
                _ => {
                    return Err(usage(
                        "`--directories` is one to sixteen host:port, separated by commas",
                    ));
                }
            }
        }
    };
    let irc = match args.get("irc") {
        None => Vec::new(),
        Some(given) => {
            let parsed: Option<Vec<IrcServer>> = given.split(',').map(IrcServer::parse).collect();
            match parsed {
                Some(list) if !list.is_empty() && list.len() <= MAX_IRC => list,
                _ => {
                    return Err(usage(
                        "`--irc` is one to four host:port, separated by commas",
                    ));
                }
            }
        }
    };
    if relays.is_empty() && directories.is_empty() && irc.is_empty() {
        return Err(usage(
            "give at least one of `--relays`, `--directories`, `--irc`",
        ));
    }
    Ok(Meeting {
        relays,
        directories,
        irc,
    })
}

impl Meeting {
    /// The onion directories are for regtest only in this pre-release (ADR 0007): nothing here has been
    /// tried on a live network.
    fn allowed_on(&self, network: Network) -> Result<(), Failure> {
        if (!self.directories.is_empty() || !self.irc.is_empty()) && network != Network::Regtest {
            return Err(failed(
                "JoinMarket's onion directories and IRC are enabled on regtest only in this pre-release",
            ));
        }
        Ok(())
    }
}

/// The node `--rpc-url` names, authenticated with its cookie file or with a user and password, and checked
/// to be on `network`.
fn node(args: &Args, network: Network) -> Result<CoreRpc, Failure> {
    let url = args.required("rpc-url").map_err(Failure::Usage)?;
    let auth = match (args.get("rpc-cookie-file"), args.get("rpc-user")) {
        (Some(cookie), None) => Auth::CookieFile(cookie.into()),
        (None, Some(user)) => {
            let password = secret::obtain("RPC password", args.get("rpc-password-file"), false)
                .map_err(failed)?;
            Auth::UserPass(user.to_string(), String::clone(&password))
        }
        _ => {
            return Err(usage(
                "give the node's `--rpc-cookie-file <file>`, or `--rpc-user <name>`",
            ));
        }
    };
    let rpc = CoreRpc::new(url, &auth, Duration::from_secs(60)).map_err(failed)?;
    let on = rpc.network().map_err(|e| failed(format!("{url}: {e}")))?;
    if on != network {
        return Err(failed(format!(
            "the node at {url} is on {}, not {}",
            network_name(on),
            network_name(network)
        )));
    }
    Ok(rpc)
}

fn runtime() -> Result<tokio::runtime::Runtime, Failure> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(failed)
}

/// How the command's nicks reach the relays: through `--proxy` when given, each nick under SOCKS
/// credentials of its own; directly otherwise, which is said aloud.
fn outbound(args: &Args) -> Result<Outbound, Failure> {
    match args.get("proxy") {
        Some(text) => {
            let addr = text.parse().map_err(|_| {
                usage("`--proxy` is the address of a SOCKS5 proxy, such as 127.0.0.1:9050")
            })?;
            Ok(Outbound::IsolatingProxy(addr))
        }
        None => {
            eprintln!(
                "vortex-ng: connecting to the relays directly: they see this machine's address. Give \
                 `--proxy <address>` (a Tor daemon's SOCKS port) to hide it."
            );
            Ok(Outbound::Direct)
        }
    }
}

fn fee_text(offer: &Offer) -> String {
    match &offer.cjfee {
        CjFee::Relative(fee) => fee.as_str().to_string(),
        CjFee::Absolute(sats) => sats.to_string(),
    }
}

/// Who the channels speak for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    /// One nick on every channel: takers and bond checks know a maker by its nick.
    Maker,
    /// A different nick on each channel, so the channels cannot be linked through it.
    Taker,
}

/// The command's channels, as one set: Nostr relays and onion directory nodes, as given.
/// The channels a command uses, and a label for each, in the set's order (what `channel_of` indexes).
async fn channels(
    network: &str,
    meeting: &Meeting,
    outbound: &Outbound,
    role: Role,
) -> Result<(ChannelSet, Vec<String>), Failure> {
    let maker = NickIdentity::generate();
    let identity = || match role {
        Role::Maker => maker.clone(),
        Role::Taker => NickIdentity::generate(),
    };
    let mut set: Vec<Box<dyn DynChannel>> = Vec::new();
    let mut labels = Vec::new();
    if !meeting.relays.is_empty() {
        let keys = NickKeys::from_identity(identity()).map_err(failed)?;
        let nostr =
            NickClient::connect_via(keys, network, &meeting.relays, outbound, CONNECT_TIMEOUT)
                .await
                .map_err(failed)?;
        set.push(Box::new(nostr));
        labels.push("nostr".to_string());
    }
    if !meeting.directories.is_empty() {
        let config = OnionConfig {
            directories: meeting.directories.clone(),
            network: network.to_string(),
            timeout: Duration::from_secs(60),
            // A taker connects directly to makers that serve an onion; on regtest, where setups run without
            // Tor, to loopback addresses too.
            peers: if network == "regtest" {
                PeerPolicy::Local
            } else {
                PeerPolicy::Onion
            },
            // Not yet: serving needs an onion published through Tor's control port, which the commands do not
            // take yet. A loopback location is only for joinmarket-clientserver's regtest testing mode:
            // JoinMarket-NG's directories refuse a location that is not a v3 onion.
            serve: Serve::None,
        };
        let onion = OnionChannel::connect(identity(), config, outbound)
            .await
            .map_err(failed)?;
        set.push(Box::new(onion));
        labels.push("onion".to_string());
    }
    // The signature domains of all the channels must stay apart: a line signed for one must never verify on
    // another (IRC's is the server's NETWORK name; see vortex_ng_irc::codec::Hostid).
    let mut domains: Vec<String> = Vec::new();
    if !meeting.relays.is_empty() {
        domains.push(NOSTR_HOSTID.to_string());
    }
    if !meeting.directories.is_empty() {
        domains.push(ONION_HOSTID.to_string());
    }
    for server in &meeting.irc {
        let config = IrcConfig {
            server: server.clone(),
            network: network.to_string(),
            timeout: Duration::from_secs(60),
        };
        let irc = IrcChannel::connect(identity(), config, outbound)
            .await
            .map_err(failed)?;
        let domain = irc.hostid();
        if let Some(other) = domains.iter().find(|d| Hostid::confusable(d, &domain)) {
            return Err(failed(format!(
                "the IRC server {}:{} signs as \"{domain}\", which could be mistaken for \"{other}\"",
                server.host, server.port
            )));
        }
        domains.push(domain);
        set.push(Box::new(irc));
        labels.push(format!("irc {}:{}", server.host, server.port));
    }
    Ok((ChannelSet::new(set).map_err(failed)?, labels))
}

/// `vortex-ng orderbook`: ask the makers on the relays what they offer.
pub(crate) fn orderbook(rest: &[String]) -> Result<(), Failure> {
    let mut valued = vec![
        "network",
        "relays",
        "directories",
        "irc",
        "pit",
        "wait",
        "proxy",
    ];
    valued.extend(RPC_OPTIONS);
    let args = parse(rest, &valued, &[])?;
    let network = wallet::network(&args)?;
    let meeting = meeting(&args)?;
    meeting.allowed_on(network)?;
    let only = match args.get("pit") {
        Some(_) => Some(wallet::pit(&args)?.0),
        None => None,
    };
    let wait = args.number("wait", 15, 1..=600).map_err(Failure::Usage)?;
    // With a node the makers' fidelity bonds are verified; without, they are only counted.
    let chain = match args.get("rpc-url") {
        Some(_) => Some(node(&args, network)?),
        None => None,
    };
    let outbound = outbound(&args)?;
    let channel = channel_network(network);
    let (us, seen_on, book) = runtime()?.block_on(async {
        let (mut client, labels) = channels(channel, &meeting, &outbound, Role::Taker).await?;
        let usable = |offer: &Offer| only.is_none_or(|pit| offer.offer_type.pit == pit);
        let gather = Duration::from_secs(wait.into());
        let book = fetch_orderbook_for(&mut client, channel, gather, usable)
            .await
            .map_err(failed)?;
        // The nick each maker knows us by (a bond proof is made out to it).
        let us: std::collections::HashMap<String, String> = book
            .offers
            .iter()
            .filter_map(|(nick, _)| {
                let route = book.route(nick)?;
                Some((nick.clone(), client.nick_on(route).to_string()))
            })
            .collect();
        // The channel each maker answered on.
        let seen_on: std::collections::HashMap<String, String> = book
            .offers
            .iter()
            .filter_map(|(nick, _)| {
                let route = book.route(nick)?;
                let label = labels.get(client.channel_of(route))?;
                Some((nick.clone(), label.clone()))
            })
            .collect();
        client.shutdown().await;
        Ok::<_, Failure>((us, seen_on, book))
    })?;

    let offers: Vec<&(String, Offer)> = book
        .offers
        .iter()
        .filter(|(_, offer)| only.is_none_or(|pit| offer.offer_type.pit == pit))
        .collect();
    if offers.is_empty() {
        println!(
            "No offers on {} within {wait} s ({}).",
            network_name(network),
            meeting.describe()
        );
        return Ok(());
    }
    // A bond proof is made out to our nick: it is checked once per maker, for at most a bounded number.
    let height = match &chain {
        Some(chain) => Some(chain.tip_height().map_err(failed)?),
        None => None,
    };
    let mut lookups = 0;
    let mut bond_of = |nick: &str| -> String {
        let (Some(proof), Some(me)) = (book.proofs.get(nick), us.get(nick)) else {
            return "-".into();
        };
        let (Some(chain), Some(height)) = (&chain, height) else {
            return "unverified".into();
        };
        if lookups >= MAX_BOND_LOOKUPS {
            return "unchecked".into();
        }
        lookups += 1;
        match verify_bond(
            proof,
            me,
            nick,
            chain,
            height,
            unix_now(),
            BondValueParams::default(),
        ) {
            Ok(bond) => bond.value.to_string(),
            Err(_) => "invalid".into(),
        }
    };
    println!(
        "{:<18} {:<12} {:>12} {:>14} {:>7} {:>10}  {:<12} channel",
        "maker", "offer", "min (sat)", "max (sat)", "txfee", "fee", "bond"
    );
    let mut bonds: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
    for (nick, offer) in offers {
        if !bonds.contains_key(nick.as_str()) {
            let bond = bond_of(nick);
            bonds.insert(nick, bond);
        }
        println!(
            "{:<18} {:<12} {:>12} {:>14} {:>7} {:>10}  {:<12} {}",
            nick,
            offer.offer_type.command(),
            offer.minsize,
            offer.maxsize,
            offer.txfee,
            fee_text(offer),
            bonds.get(nick.as_str()).map_or("-", String::as_str),
            seen_on.get(nick.as_str()).map_or("-", String::as_str)
        );
    }
    Ok(())
}

/// `vortex-ng maker`: offer the wallet's coins for CoinJoins until stopped.
pub(crate) fn maker(rest: &[String]) -> Result<(), Failure> {
    let mut valued = vec![
        "wallet",
        "password-file",
        "relays",
        "directories",
        "irc",
        "pit",
        "fee-rel",
        "fee-abs",
        "txfee",
        "min-size",
        "max-size",
        "upkeep",
        "proxy",
    ];
    valued.extend(RPC_OPTIONS);
    let args = parse(rest, &valued, &[])?;
    let meeting = meeting(&args)?;
    let (pit, pit_name) = wallet::pit(&args)?;
    let fee = match (
        args.get("fee-rel"),
        args.sats("fee-abs").map_err(Failure::Usage)?,
    ) {
        (Some(fraction), None) => {
            if RelativeFee::parse(fraction).is_none() {
                return Err(usage(
                    "`--fee-rel` is a fraction of the amount, such as 0.001",
                ));
            }
            OfferFee::Relative(fraction.to_string())
        }
        (None, Some(sats)) => OfferFee::Absolute(sats),
        _ => {
            return Err(usage(
                "give the fee asked: `--fee-rel <fraction>` or `--fee-abs <sats>`",
            ));
        }
    };
    let policy = OfferPolicy {
        fee,
        txfee: args.sats("txfee").map_err(Failure::Usage)?.unwrap_or(0),
        min_size: args
            .sats("min-size")
            .map_err(Failure::Usage)?
            .unwrap_or(100_000),
        max_size: args.sats("max-size").map_err(Failure::Usage)?,
    };
    if policy.min_size == 0 || policy.max_size.is_some_and(|max| max < policy.min_size) {
        return Err(usage("`--min-size` is at least 1 and at most `--max-size`"));
    }
    let upkeep = args
        .number("upkeep", 30, 1..=3600)
        .map_err(Failure::Usage)?;
    if args.get("rpc-url").is_none() {
        return Err(usage("`--rpc-url` is required: a maker needs a node"));
    }

    let file = wallet::open(&args)?;
    let network = file.network();
    meeting.allowed_on(network)?;
    let chain = node(&args, network)?;
    let pit_wallet = PitWallet::new(&file.seed().map_err(failed)?, pit).map_err(failed)?;
    let mut maker = Maker::new(MakerConfig::new(Vec::new()), pit_wallet).map_err(failed)?;
    let service = MakerService {
        policy,
        birthday: file.birthday(),
        upkeep: Duration::from_secs(upkeep.into()),
    };
    let outbound = outbound(&args)?;
    let channel = channel_network(network);
    runtime()?.block_on(async {
        let (mut client, _) = channels(channel, &meeting, &outbound, Role::Maker).await?;
        println!(
            "maker {} in the {pit_name} pit on {}, {}",
            client.nick(),
            network_name(network),
            meeting.describe()
        );
        let mut report = |report: MakerReport| match report {
            MakerReport::Offering {
                height,
                liquidity,
                offer: Some(offer),
            } => println!(
                "height {height}: offering {} {}-{} sat, fee {}, txfee {} ({liquidity} sat available to one round)",
                offer.offer_type.command(),
                offer.minsize,
                offer.maxsize,
                fee_text(&offer),
                offer.txfee
            ),
            MakerReport::Offering {
                height,
                liquidity,
                offer: None,
            } => println!(
                "height {height}: nothing to offer ({liquidity} sat available to one round is too little)"
            ),
            MakerReport::Trouble(why) => eprintln!("vortex-ng: {why}"),
        };
        serve_maker(
            &mut maker,
            &mut client,
            &chain,
            channel,
            &service,
            None,
            &mut report,
        )
        .await
        .map_err(failed)
    })
}

/// A taker's failure in plain words.
fn taker_failed(error: TakerError) -> Failure {
    match error {
        TakerError::Funds(why) => failed(why),
        TakerError::Maker(nick, why) => failed(format!("maker {nick}: {why}")),
        TakerError::Internal(why) => failed(why),
    }
}

/// The wallet's confirmed coins in `mixdepth`, with their depth at `height`.
fn confirmed_coins(wallet: &PitWallet, mixdepth: u32, height: u32) -> Result<Vec<Coin>, Failure> {
    Ok(wallet
        .utxos(mixdepth)
        .map_err(failed)?
        .into_iter()
        .filter_map(|utxo| {
            let at = utxo.chain_position.confirmation_height_upper_bound()?;
            (at <= height).then(|| Coin {
                confirmations: height - at + 1,
                utxo,
            })
        })
        .collect())
}

/// `vortex-ng balance`: what the wallet holds, confirmed, by mixdepth.
pub(crate) fn balance(rest: &[String]) -> Result<(), Failure> {
    let mut valued = vec!["wallet", "password-file", "pit"];
    valued.extend(RPC_OPTIONS);
    let args = parse(rest, &valued, &[])?;
    let (pit, pit_name) = wallet::pit(&args)?;
    if args.get("rpc-url").is_none() {
        return Err(usage("`--rpc-url` is required: balances come from a node"));
    }
    let file = wallet::open(&args)?;
    let chain = node(&args, file.network())?;
    let mut pit_wallet = PitWallet::new(&file.seed().map_err(failed)?, pit).map_err(failed)?;
    let height = pit_wallet.sync(&chain, file.birthday()).map_err(failed)?;
    println!(
        "{pit_name} wallet at height {height} ({})",
        network_name(file.network())
    );
    let mut total = 0u64;
    for mixdepth in 0..MIXDEPTHS {
        let coins = confirmed_coins(&pit_wallet, mixdepth, height)?;
        let sum: u64 = coins.iter().map(|c| c.utxo.txout.value.to_sat()).sum();
        total += sum;
        println!(
            "mixdepth {mixdepth}: {sum:>16} sat in {} coin(s)",
            coins.len()
        );
    }
    println!("total:      {total:>16} sat confirmed");
    Ok(())
}

/// `vortex-ng coinjoin`: one CoinJoin as the taker.
pub(crate) fn coinjoin(rest: &[String]) -> Result<(), Failure> {
    let mut valued = vec![
        "wallet",
        "password-file",
        "relays",
        "directories",
        "irc",
        "pit",
        "amount",
        "makers",
        "mixdepth",
        "destination",
        "fee-rate",
        "max-maker-fee",
        "wait",
        "proxy",
    ];
    valued.extend(RPC_OPTIONS);
    let args = parse(rest, &valued, &["yes", "allow-bondless-fees"])?;
    let meeting = meeting(&args)?;
    let (pit, pit_name) = wallet::pit(&args)?;
    let amount = match args.sats("amount").map_err(Failure::Usage)? {
        Some(amount) if amount > 0 => amount,
        _ => return Err(usage("`--amount <sats>` is required")),
    };
    let makers = args.number("makers", 3, 1..=20).map_err(Failure::Usage)? as usize;
    let mixdepth = args
        .number("mixdepth", 0, 0..=MIXDEPTHS - 1)
        .map_err(Failure::Usage)?;
    let wait = args.number("wait", 15, 1..=600).map_err(Failure::Usage)?;
    let fee_rate = match args.get("fee-rate") {
        Some(_) => Some(
            args.number("fee-rate", 1, 1..=10_000)
                .map_err(Failure::Usage)?,
        ),
        None => None,
    };
    // Each maker's fee is bounded: 0.1 % of the amount, and no less than 2,000 sat, unless told otherwise.
    let max_maker_fee = args
        .sats("max-maker-fee")
        .map_err(Failure::Usage)?
        .unwrap_or_else(|| (amount / 1000).max(2_000));
    if args.get("rpc-url").is_none() {
        return Err(usage("`--rpc-url` is required: a taker needs a node"));
    }

    let wallet_path = Path::new(args.required("wallet").map_err(Failure::Usage)?);
    let file = wallet::open(&args)?;
    let network = file.network();
    meeting.allowed_on(network)?;
    let chain = node(&args, network)?;
    let mut pit_wallet = PitWallet::new(&file.seed().map_err(failed)?, pit).map_err(failed)?;
    let height = pit_wallet.sync(&chain, file.birthday()).map_err(failed)?;
    let fee_rate_sat_per_kwu = match fee_rate {
        Some(sat_per_vb) => u64::from(sat_per_vb) * 250,
        None => match chain.estimate_fee_rate(3).map_err(failed)? {
            Some(rate) => rate.to_sat_per_kwu().max(250),
            None => {
                return Err(failed(
                    "the node has no fee estimate: give `--fee-rate <sat/vB>`",
                ));
            }
        },
    };
    let cfg = TakerConfig {
        pit,
        network,
        amount,
        makers,
        max_cjfee: max_maker_fee,
        fee_rate_sat_per_kwu,
        max_maker_utxos: 20,
        bondless_makers_allowance: DEFAULT_BONDLESS_ALLOWANCE,
        // joinmarket-ng's default: a maker without a fidelity bond is taken only at a zero fee.
        bondless_require_zero_fee: !args.flag("allow-bondless-fees"),
        bond_params: BondValueParams::default(),
    };

    let chosen = choose_coins(&cfg, confirmed_coins(&pit_wallet, mixdepth, height)?)
        .map_err(taker_failed)?;
    // The first commitment of the chosen coins that was never sent: three per coin (NUMS indices 0-2).
    let mut log = PodleLog::open(wallet_path).map_err(failed)?;
    let mut podle = None;
    'coins: for coin in chosen.iter().filter(|coin| coin.fit_to_commit(amount)) {
        for index in 0..3u8 {
            let candidate =
                podle_for(&pit_wallet, mixdepth, &coin.utxo, index).map_err(taker_failed)?;
            if !log.contains(&candidate.commitment()) {
                podle = Some(candidate);
                break 'coins;
            }
        }
    }
    let Some(podle) = podle else {
        return Err(failed(
            "every commitment of the chosen coins has been used (three per coin, spent even by a round \
             that failed): use another mixdepth, or wait for other coins to reach 5 confirmations",
        ));
    };

    let (cj_script, to) = match args.get("destination") {
        Some(text) => {
            let address = Address::from_str(text)
                .map_err(|_| usage("`--destination` is not an address"))?
                .require_network(network)
                .map_err(|_| {
                    failed(format!("{text} is not a {} address", network_name(network)))
                })?;
            (address.script_pubkey(), text.to_string())
        }
        None => {
            let next = (mixdepth + 1) % MIXDEPTHS;
            let address = pit_wallet.next_receive_address(next).map_err(failed)?;
            (
                address.script_pubkey(),
                format!("mixdepth {next} of this wallet"),
            )
        }
    };
    let change = pit_wallet
        .next_change_address(mixdepth)
        .map_err(failed)?
        .script_pubkey();
    let inputs: Vec<(OutPoint, TxOut)> = chosen
        .iter()
        .map(|coin| (coin.utxo.outpoint, coin.utxo.txout.clone()))
        .collect();
    let total: u64 = inputs.iter().map(|(_, out)| out.value.to_sat()).sum();
    println!(
        "CoinJoin of {amount} sat in the {pit_name} pit with {makers} makers, from mixdepth {mixdepth} \
         ({} coin(s), {total} sat), to {to}.",
        inputs.len()
    );
    println!(
        "Each maker's fee is at most {max_maker_fee} sat; mining fee rate {} sat/vB; makers without a \
         fidelity bond {}.",
        fee_rate_sat_per_kwu.div_ceil(250),
        if cfg.bondless_require_zero_fee {
            "only at a zero fee"
        } else {
            "may charge a fee"
        }
    );
    if !args.flag("yes") && !secret::confirm("Proceed?").map_err(failed)? {
        return Err(failed("not confirmed: nothing was sent"));
    }

    // From here the commitment counts as used, whatever becomes of the round.
    log.record(&podle.commitment()).map_err(failed)?;
    let mut taker = Taker::new(
        cfg.clone(),
        mixdepth,
        inputs,
        podle,
        cj_script,
        change.clone(),
    )
    .map_err(taker_failed)?;
    let outbound = outbound(&args)?;
    let channel = channel_network(network);
    let tx = runtime()?.block_on(async {
        let (mut client, _) = channels(channel, &meeting, &outbound, Role::Taker).await?;
        let gather = Duration::from_secs(wait.into());
        let round = run_taker(
            &mut taker,
            &pit_wallet,
            &mut client,
            &chain,
            &cfg,
            gather,
            Instant::now() + gather + Duration::from_secs(300),
        )
        .await;
        client.shutdown().await;
        round.map_err(|e| match e {
            NodeError::Taker(e) => taker_failed(e),
            NodeError::Timeout => failed("the makers did not finish the round in time"),
            other => failed(other),
        })
    })?;
    if let Err(why) = chain.test_accept(&tx).map_err(failed)? {
        return Err(failed(format!(
            "the node refuses the transaction ({why}): nothing was broadcast"
        )));
    }
    let txid = chain.broadcast(&tx).map_err(failed)?;
    let kept: u64 = tx
        .output
        .iter()
        .filter(|out| out.script_pubkey == change)
        .map(|out| out.value.to_sat())
        .sum();
    println!("Broadcast {txid}");
    println!(
        "{amount} sat to {to}; {} sat in maker and mining fees; {kept} sat change.",
        total.saturating_sub(amount).saturating_sub(kept)
    );
    Ok(())
}
