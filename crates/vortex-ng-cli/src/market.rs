//! `vortex-ng orderbook` and `vortex-ng maker`: the commands that talk to relays and to a node.

use std::cmp::Reverse;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};

use vortex_ng_chain::{Auth, CoreRpc};
use vortex_ng_core::bitcoin::{Address, Network, OutPoint, TxOut};
use vortex_ng_core::bond::BondValueParams;
use vortex_ng_core::lnclose::CloseEvidence;
use vortex_ng_core::offer::{CjFee, Offer, RelativeFee};
use vortex_ng_maker::{Maker, MakerConfig};
use vortex_ng_node::{
    CONNECT_TIMEOUT, MAX_BOND_LOOKUPS, MakerReport, MakerService, NodeError, OfferFee, OfferPolicy,
    channel_network, fetch_orderbook, run_taker, serve_maker,
};
use vortex_ng_nostr::client::{NickClient, unix_now};
use vortex_ng_nostr::keys::NickKeys;
use vortex_ng_nostr::socks::Outbound;
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

/// `vortex-ng orderbook`: ask the makers on the relays what they offer.
pub(crate) fn orderbook(rest: &[String]) -> Result<(), Failure> {
    let mut valued = vec!["network", "relays", "pit", "wait", "proxy"];
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
    let outbound = outbound(&args)?;
    let channel = channel_network(network);
    let (me, book) = runtime()?.block_on(async {
        let mut client = NickClient::connect_via(
            NickKeys::generate(),
            channel,
            &relays,
            &outbound,
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
        "proxy",
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
    let outbound = outbound(&args)?;
    let channel = channel_network(network);
    runtime()?.block_on(async {
        let mut client = NickClient::connect_via(
            NickKeys::generate(),
            channel,
            &relays,
            &outbound,
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
    Ok(confirmed_coins_with_origin(wallet, mixdepth, height)?
        .into_iter()
        .map(|(coin, _)| coin)
        .collect())
}

/// The wallet's confirmed coins in `mixdepth`, each with the evidence that a channel close made it, if any.
fn confirmed_coins_with_origin(
    wallet: &PitWallet,
    mixdepth: u32,
    height: u32,
) -> Result<Vec<(Coin, Option<CloseEvidence>)>, Failure> {
    Ok(wallet
        .utxos_with_origin(mixdepth)
        .map_err(failed)?
        .into_iter()
        .filter_map(|(utxo, origin)| {
            let at = utxo.chain_position.confirmation_height_upper_bound()?;
            (at <= height).then(|| {
                (
                    Coin {
                        confirmations: height - at + 1,
                        utxo,
                    },
                    origin,
                )
            })
        })
        .collect())
}

/// `vortex-ng coins`: the wallet's coins by mixdepth, with the ones a channel close paid it marked.
pub(crate) fn coins(rest: &[String]) -> Result<(), Failure> {
    let mut valued = vec!["wallet", "password-file", "pit", "mixdepth"];
    valued.extend(RPC_OPTIONS);
    let args = parse(rest, &valued, &["closes-only", "outpoints"])?;
    let (pit, pit_name) = wallet::pit(&args)?;
    if args.get("rpc-url").is_none() {
        return Err(usage("`--rpc-url` is required: coins come from a node"));
    }
    let only = match args.get("mixdepth") {
        Some(_) => Some(
            args.number("mixdepth", 0, 0..=MIXDEPTHS - 1)
                .map_err(Failure::Usage)?,
        ),
        None => None,
    };
    let file = wallet::open(&args)?;
    let chain = node(&args, file.network())?;
    let mut pit_wallet = PitWallet::new(&file.seed().map_err(failed)?, pit).map_err(failed)?;
    let height = pit_wallet.sync(&chain, file.birthday()).map_err(failed)?;
    println!(
        "{pit_name} wallet at height {height} ({})",
        network_name(file.network())
    );
    let (mut count, mut total, mut close_count, mut close_total) = (0usize, 0u64, 0usize, 0u64);
    for mixdepth in (0..MIXDEPTHS).filter(|m| only.is_none_or(|only| only == *m)) {
        let mut coins = pit_wallet.utxos_with_origin(mixdepth).map_err(failed)?;
        if args.flag("closes-only") {
            coins.retain(|(_, origin)| origin.is_some());
        }
        if coins.is_empty() {
            continue;
        }
        coins.sort_by_key(|(utxo, _)| Reverse(utxo.txout.value));
        println!("mixdepth {mixdepth}:");
        for (utxo, origin) in coins {
            let sats = utxo.txout.value.to_sat();
            let depth = match utxo.chain_position.confirmation_height_upper_bound() {
                Some(at) if at <= height => format!("{} conf", height - at + 1),
                _ => "unconfirmed".to_string(),
            };
            let outpoint = if args.flag("outpoints") {
                format!("  {}", utxo.outpoint)
            } else {
                String::new()
            };
            let origin_text = origin.map_or_else(String::new, |e| format!("channel close: {e}"));
            println!("  {sats:>14} sat  {depth:>11}  {origin_text}{outpoint}");
            count += 1;
            total += sats;
            if origin.is_some() {
                close_count += 1;
                close_total += sats;
            }
        }
    }
    println!(
        "{count} coin(s), {total} sat; {close_count} coin(s), {close_total} sat of it from channel closes."
    );
    Ok(())
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
    let args = parse(
        rest,
        &valued,
        &["yes", "allow-bondless-fees", "from-closes"],
    )?;
    let relays = relays(&args)?;
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

    let mut candidates = confirmed_coins_with_origin(&pit_wallet, mixdepth, height)?;
    if args.flag("from-closes") {
        // Only coins a channel close paid the wallet: they are not merged with coins of another history.
        candidates.retain(|(_, origin)| origin.is_some());
        if candidates.is_empty() {
            return Err(failed(format!(
                "no confirmed coin from a channel close in mixdepth {mixdepth}: `vortex-ng coins \
                 --closes-only` lists them (a close needs a wallet address as its delivery address, \
                 and a force close its sweep, to show up here)"
            )));
        }
    }
    let chosen = choose_coins(&cfg, candidates.into_iter().map(|(coin, _)| coin).collect())
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
         ({} coin(s){}, {total} sat), to {to}.",
        inputs.len(),
        if args.flag("from-closes") {
            ", channel closes only"
        } else {
            ""
        }
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
        let mut client = NickClient::connect_via(
            NickKeys::generate(),
            channel,
            &relays,
            &outbound,
            CONNECT_TIMEOUT,
        )
        .await
        .map_err(failed)?;
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
