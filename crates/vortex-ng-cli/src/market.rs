//! `vortex-ng orderbook` and `vortex-ng maker`: the commands that talk to relays and to a node.

use std::time::Duration;

use vortex_ng_chain::{Auth, CoreRpc};
use vortex_ng_core::bitcoin::Network;
use vortex_ng_core::bond::BondValueParams;
use vortex_ng_core::offer::{CjFee, Offer, RelativeFee};
use vortex_ng_maker::{Maker, MakerConfig};
use vortex_ng_node::{
    CONNECT_TIMEOUT, MAX_BOND_LOOKUPS, MakerReport, MakerService, OfferFee, OfferPolicy,
    channel_network, fetch_orderbook, serve_maker,
};
use vortex_ng_nostr::client::{NickClient, unix_now};
use vortex_ng_nostr::keys::NickKeys;
use vortex_ng_taker::verify_bond;
use vortex_ng_wallet::PitWallet;

use crate::args::Args;
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
    let relays: Vec<String> = args
        .required("relays")
        .map_err(Failure::Usage)?
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

/// Said once by every command that connects to relays.
fn warn_direct() {
    eprintln!(
        "vortex-ng: connecting to the relays directly: they see this machine's address. Tor is not wired \
         into this command yet."
    );
}

fn fee_text(offer: &Offer) -> String {
    match &offer.cjfee {
        CjFee::Relative(fee) => fee.as_str().to_string(),
        CjFee::Absolute(sats) => sats.to_string(),
    }
}

/// `vortex-ng orderbook`: ask the makers on the relays what they offer.
pub(crate) fn orderbook(rest: &[String]) -> Result<(), Failure> {
    let mut valued = vec!["network", "relays", "pit", "wait"];
    valued.extend(RPC_OPTIONS);
    let args = parse(rest, &valued, &[])?;
    let network = wallet::network(&args)?;
    let relays = relays(&args)?;
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
    warn_direct();
    let channel = channel_network(network);
    let (me, book) = runtime()?.block_on(async {
        let mut client = NickClient::connect(
            NickKeys::generate(),
            channel,
            &relays,
            None,
            CONNECT_TIMEOUT,
        )
        .await
        .map_err(failed)?;
        let book = fetch_orderbook(&mut client, channel, Duration::from_secs(wait.into()))
            .await
            .map_err(failed)?;
        let me = client.keys().nick().to_string();
        client.shutdown().await;
        Ok::<_, Failure>((me, book))
    })?;

    let offers: Vec<&(String, Offer)> = book
        .offers
        .iter()
        .filter(|(_, offer)| only.is_none_or(|pit| offer.offer_type.pit == pit))
        .collect();
    if offers.is_empty() {
        println!(
            "No offers on {} within {wait} s ({} relay(s)).",
            network_name(network),
            relays.len()
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
        let Some(proof) = book.proofs.get(nick) else {
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
            &me,
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
        "{:<18} {:<12} {:>12} {:>14} {:>7} {:>10}  bond",
        "maker", "offer", "min (sat)", "max (sat)", "txfee", "fee"
    );
    let mut bonds: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
    for (nick, offer) in offers {
        if !bonds.contains_key(nick.as_str()) {
            let bond = bond_of(nick);
            bonds.insert(nick, bond);
        }
        println!(
            "{:<18} {:<12} {:>12} {:>14} {:>7} {:>10}  {}",
            nick,
            offer.offer_type.command(),
            offer.minsize,
            offer.maxsize,
            offer.txfee,
            fee_text(offer),
            bonds.get(nick.as_str()).map_or("-", String::as_str)
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
        "pit",
        "fee-rel",
        "fee-abs",
        "txfee",
        "min-size",
        "max-size",
        "upkeep",
    ];
    valued.extend(RPC_OPTIONS);
    let args = parse(rest, &valued, &[])?;
    let relays = relays(&args)?;
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
    let chain = node(&args, network)?;
    let pit_wallet = PitWallet::new(&file.seed().map_err(failed)?, pit).map_err(failed)?;
    let mut maker = Maker::new(MakerConfig::new(Vec::new()), pit_wallet).map_err(failed)?;
    let service = MakerService {
        policy,
        birthday: file.birthday(),
        upkeep: Duration::from_secs(upkeep.into()),
    };
    warn_direct();
    let channel = channel_network(network);
    runtime()?.block_on(async {
        let mut client = NickClient::connect(
            NickKeys::generate(),
            channel,
            &relays,
            None,
            CONNECT_TIMEOUT,
        )
        .await
        .map_err(failed)?;
        println!(
            "maker {} in the {pit_name} pit on {}, {} relay(s)",
            client.keys().nick(),
            network_name(network),
            relays.len()
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
