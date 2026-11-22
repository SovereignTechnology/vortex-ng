//! `vortex-ng lnd-coins`, and the LND half of `vortex-ng coinjoin --from-lnd`: the coins a channel close
//! left in an LND node's own wallet, spent with the node signing (ADR 0008).

use std::path::Path;

use vortex_ng_core::bitcoin::{Network, OutPoint, Script, TxOut};
use vortex_ng_core::offer::Pit;
use vortex_ng_core::podle::Podle;
use vortex_ng_ln::lnd::{Lnd, keeps_reserve};
use vortex_ng_taker::{TakerConfig, choose_external, podle_for};
use vortex_ng_wallet::PitWallet;

use crate::Failure;
use crate::args::Args;
use crate::market::{confirmed_coins, taker_failed};
use crate::podle_log::PodleLog;
use crate::wallet::{self, failed, network_name, parse};

/// The options that say how to reach an LND node.
pub(crate) const OPTIONS: [&str; 3] = ["lnd-rest", "lnd-tls-cert", "lnd-macaroon"];

/// The node the options name, checked to be on `network`.
pub(crate) fn connect(args: &Args, network: Network) -> Result<Lnd, Failure> {
    if network == Network::Bitcoin {
        return Err(failed(
            "mainnet is disabled in this pre-release: vortex-ng is unaudited",
        ));
    }
    let required = |name| args.required(name).map_err(Failure::Usage);
    let lnd = Lnd::open(
        required("lnd-rest")?,
        Path::new(required("lnd-tls-cert")?),
        Path::new(required("lnd-macaroon")?),
    )
    .map_err(failed)?;
    let on = lnd.network().map_err(failed)?;
    if on != network_name(network) {
        return Err(failed(format!(
            "the LND node is on {on}, not {}",
            network_name(network)
        )));
    }
    Ok(lnd)
}

/// The pit a coin of this script can be spent in, if any: an LND wallet holds P2WPKH and P2TR coins.
fn pit_of(script: &Script) -> Option<(Pit, &'static str)> {
    if script.is_p2wpkh() {
        Some((Pit::Sw0, "sw0"))
    } else if script.is_p2tr() {
        Some((Pit::Tr0, "tr0"))
    } else {
        None
    }
}

/// `vortex-ng lnd-coins`: the node's confirmed coins, with the ones a channel close paid it marked by the
/// node's own records.
pub(crate) fn lnd_coins(rest: &[String]) -> Result<(), Failure> {
    let mut valued = vec!["network"];
    valued.extend(OPTIONS);
    let args = parse(rest, &valued, &["closes-only", "outpoints"])?;
    let network = wallet::network(&args)?;
    let lnd = connect(&args, network)?;
    let mut coins = lnd.coins().map_err(failed)?;
    let reserve = lnd.anchor_reserve().map_err(failed)?;
    if args.flag("closes-only") {
        coins.retain(|coin| coin.close.is_some());
    }
    coins.sort_by_key(|coin| std::cmp::Reverse(coin.txout.value));
    println!("LND wallet ({})", network_name(network));
    let (mut total, mut close_count, mut close_total) = (0u64, 0usize, 0u64);
    for coin in &coins {
        let sats = coin.txout.value.to_sat();
        let pit = pit_of(&coin.txout.script_pubkey).map_or("-", |(_, name)| name);
        let depth = format!("{} conf", coin.confirmations);
        let origin = coin.close.map_or_else(String::new, |kind| {
            format!("channel close: {}", kind.describe())
        });
        let outpoint = if args.flag("outpoints") {
            format!("  {}", coin.outpoint)
        } else {
            String::new()
        };
        println!("  {sats:>14} sat  {depth:>11}  {pit:<4} {origin}{outpoint}");
        total += sats;
        if coin.close.is_some() {
            close_count += 1;
            close_total += sats;
        }
    }
    println!(
        "{} coin(s), {total} sat; {close_count} coin(s), {close_total} sat of it from channel closes.",
        coins.len()
    );
    println!(
        "The node keeps {reserve} sat for its anchor channels: a round will not spend into it."
    );
    Ok(())
}

/// What a round from the node spends and commits to.
pub(crate) struct Selection {
    /// The node's coins going in: channel-close coins of the pit, and no others.
    pub(crate) inputs: Vec<(OutPoint, TxOut)>,
    /// The commitment, from a coin of the vortex-ng wallet: the node cannot prove one.
    pub(crate) podle: Podle,
    /// The value of the coin committed to.
    pub(crate) committed_sats: u64,
}

/// Choose the node's close coins for a round in `cfg`'s pit, leaving what the node must keep for its anchor
/// channels, and a commitment from `mixdepth` of `wallet`.
pub(crate) fn select(
    lnd: &Lnd,
    cfg: &TakerConfig,
    wallet: &PitWallet,
    mixdepth: u32,
    height: u32,
    log: &PodleLog,
    merge: bool,
) -> Result<Selection, Failure> {
    let coins = lnd.coins().map_err(failed)?;
    let closes: Vec<_> = coins
        .iter()
        .filter(|coin| coin.close.is_some())
        .cloned()
        .collect();
    if closes.is_empty() {
        return Err(failed(
            "the LND node's wallet holds no confirmed coin from a channel close (a force close counts \
             once the node has resolved all of it)",
        ));
    }
    let other_pit = closes
        .iter()
        .filter(|coin| pit_of(&coin.txout.script_pubkey).is_none_or(|(pit, _)| pit != cfg.pit))
        .count();
    let usable: Vec<(OutPoint, TxOut)> = closes
        .into_iter()
        .filter(|coin| pit_of(&coin.txout.script_pubkey).is_some_and(|(pit, _)| pit == cfg.pit))
        .map(|coin| (coin.outpoint, coin.txout))
        .collect();
    if usable.is_empty() {
        return Err(failed(format!(
            "none of the node's {other_pit} channel-close coin(s) can be spent in this pit: \
             `vortex-ng lnd-coins --closes-only` shows each coin's pit, and `--pit` picks one"
        )));
    }
    let inputs = choose_external(cfg, usable, merge).map_err(taker_failed)?;
    let spending: Vec<OutPoint> = inputs.iter().map(|(outpoint, _)| *outpoint).collect();
    let reserve = lnd.anchor_reserve().map_err(failed)?;
    if !keeps_reserve(&coins, &spending, reserve) {
        return Err(failed(format!(
            "this round would leave the LND wallet under the {reserve} sat it must keep to fee-bump the \
             force close of its open anchor channels: nothing was sent"
        )));
    }
    let (podle, committed_sats) = commitment(wallet, mixdepth, cfg.amount, height, log)?;
    Ok(Selection {
        inputs,
        podle,
        committed_sats,
    })
}

/// A fresh commitment from the smallest suitable coin of `mixdepth`. Makers see this coin and can tie it to
/// the round, so it must not tie anything else: it comes from the round's own mixdepth, never from a
/// CoinJoin (that would show makers whose output it was), and never from a coin already committed to
/// (that would let a maker in both rounds link two channels).
fn commitment(
    wallet: &PitWallet,
    mixdepth: u32,
    amount: u64,
    height: u32,
    log: &PodleLog,
) -> Result<(Podle, u64), Failure> {
    let mut fit = Vec::new();
    for coin in confirmed_coins(wallet, mixdepth, height)? {
        if coin.fit_to_commit(amount)
            && !wallet
                .came_from_coinjoin(mixdepth, &coin.utxo.outpoint)
                .map_err(failed)?
        {
            fit.push(coin);
        }
    }
    fit.sort_by_key(|coin| coin.utxo.txout.value);
    for coin in &fit {
        let podles = (0..3u8)
            .map(|index| podle_for(wallet, mixdepth, &coin.utxo, index))
            .collect::<Result<Vec<_>, _>>()
            .map_err(taker_failed)?;
        if podles
            .iter()
            .all(|podle| !log.contains(&podle.commitment()))
            && let Some(podle) = podles.into_iter().next()
        {
            return Ok((podle, coin.utxo.txout.value.to_sat()));
        }
    }
    Err(failed(format!(
        "the node cannot prove a PoDLE, so mixdepth {mixdepth} of this wallet needs a coin of the pit to \
         commit to: five confirmations, a fifth of the amount, not from a CoinJoin, and never committed to \
         before (each one serves one round, so that no maker can link two)"
    )))
}

/// With the coins leased, and before any maker hears of them: the node still keeps its reserve, and will
/// sign. A commitment spent on a round that cannot finish is lost, and makers would have seen the coins.
pub(crate) fn check_before_round(lnd: &Lnd, inputs: &[(OutPoint, TxOut)]) -> Result<(), Failure> {
    let spending: Vec<OutPoint> = inputs.iter().map(|(outpoint, _)| *outpoint).collect();
    let reserve = lnd.anchor_reserve().map_err(failed)?;
    if !keeps_reserve(&lnd.coins().map_err(failed)?, &spending, reserve) {
        return Err(failed(format!(
            "the LND wallet would fall under the {reserve} sat it must keep for its anchor channels: \
             nothing was sent"
        )));
    }
    lnd.check_can_sign(inputs).map_err(failed)
}
