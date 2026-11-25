//! `vortex-ng pools`, `vortex-ng pool join` and `vortex-ng pool create`: joinstr pools (ADR 0006), from this
//! wallet, beside a `vortex-ng maker` on the same wallet if one runs (issue #51).
//!
//! A pool spends one coin of the wallet worth its denomination plus 500 to 5000 sats, and pays one output of
//! the denomination less a share of the mining fee to the next mixdepth. The coin is held in
//! `<wallet>.claims` for the pool's lifetime, so a maker or a `coinjoin` on the same wallet never puts it into
//! a round of theirs, and the output address is taken there, so no other round pays it.

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use vortex_ng_core::bitcoin::hex::DisplayHex;
use vortex_ng_core::bitcoin::secp256k1::{Secp256k1, SecretKey};
use vortex_ng_core::bitcoin::{Network, OutPoint};
use vortex_ng_core::offer::Pit;
use vortex_ng_core::script::taproot_output_secret;
use vortex_ng_core::tx::random_bytes;
use vortex_ng_joinstr::pool::Pool;
use vortex_ng_joinstr::rules;
use vortex_ng_joinstr::session::Peer;
use vortex_ng_node::joinstr::{Hosting, join_pool, list_pools, pool_client, run_pool};
use vortex_ng_nostr::client::unix_now;
use vortex_ng_wallet::{MIXDEPTHS, PitWallet};

use crate::args::Args;
use crate::claims::Claims;
use crate::market::{node, relays, runtime};
use crate::wallet::{failed, network_name, parse};
use crate::{Failure, secret, wallet};

/// How far back announcements and pool messages are read: a pool open now was announced within this.
const LOOKBACK: u64 = 86_400;
/// How long a joiner waits for the pool's credentials.
const JOIN_WAIT: Duration = Duration::from_secs(60);
/// How long after our registration the recovery round starts if inputs are still missing.
const INPUT_WAIT: Duration = Duration::from_secs(120);
/// How long after a pool closes its round may still finish.
const AFTER_CLOSE: u64 = 600;

fn usage(why: &str) -> Failure {
    Failure::Usage(why.into())
}

/// `--proxy <address>`: the SOCKS5 proxy pools are reached through; said aloud when there is none.
fn proxy(args: &Args) -> Result<Option<SocketAddr>, Failure> {
    match args.get("proxy") {
        Some(text) => text.parse().map(Some).map_err(|_| {
            usage("`--proxy` is the address of a SOCKS5 proxy, such as 127.0.0.1:9050")
        }),
        None => {
            eprintln!(
                "vortex-ng: connecting directly: every relay named sees this machine's address. Give \
                 `--proxy <address>` (a Tor daemon's SOCKS port) to hide it."
            );
            Ok(None)
        }
    }
}

/// The open pools on `relays`, one per pool key.
fn gather_pools(
    relays: &[String],
    proxy: Option<SocketAddr>,
    wait: Duration,
) -> Result<Vec<Pool>, Failure> {
    let since = unix_now().saturating_sub(LOOKBACK);
    runtime()?.block_on(async {
        let mut pools: Vec<Pool> = Vec::new();
        for relay in relays {
            for pool in list_pools(relay, proxy, since, wait, false)
                .await
                .map_err(|e| failed(format!("{relay}: {e}")))?
            {
                if !pools.iter().any(|p| p.public_key == pool.public_key) {
                    pools.push(pool);
                }
            }
        }
        Ok(pools)
    })
}

fn describe(pool: &Pool, now: i64) -> String {
    format!(
        "pool {} ({}): {} sat, {} peers, {} sat/vB, closes in {} min, on {}",
        pool.id,
        &pool.public_key[..16],
        pool.denom_sats(),
        pool.peers,
        pool.fee_rate,
        (pool.timeout - now).max(0) / 60,
        pool.relay
    )
}

fn now() -> i64 {
    i64::try_from(unix_now()).unwrap_or(i64::MAX)
}

/// `vortex-ng pools`: the open joinstr pools on the relays named.
pub(crate) fn pools(rest: &[String]) -> Result<(), Failure> {
    let args = parse(rest, &["relays", "wait", "proxy"], &[])?;
    let relays = relays(&args)?;
    if relays.is_empty() {
        return Err(usage(
            "give the relays to look on: `--relays <url[,url...]>`",
        ));
    }
    let wait = args.number("wait", 10, 1..=600).map_err(Failure::Usage)?;
    let proxy = proxy(&args)?;
    let pools = gather_pools(&relays, proxy, Duration::from_secs(wait.into()))?;
    let now = now();
    for pool in &pools {
        println!("{}", describe(pool, now));
    }
    println!(
        "{} open pool(s) over Tor without an aut-ct requirement",
        pools.len()
    );
    Ok(())
}

/// What both `pool join` and `pool create` start from: the wallet, its node, and a coin to put in.
struct Setup {
    network: Network,
    pit: Pit,
    wallet: PitWallet,
    chain: vortex_ng_chain::CoreRpc,
    claims: Claims,
    mixdepth: u32,
    proxy: Option<SocketAddr>,
}

fn setup(args: &Args) -> Result<Setup, Failure> {
    let (pit, _) = wallet::pit(args)?;
    if pit == Pit::Wsh0 {
        return Err(failed(
            "joinstr pools take P2WPKH and P2TR coins: use the sw0 or tr0 pit",
        ));
    }
    let mixdepth = args
        .number("mixdepth", 0, 0..=MIXDEPTHS - 1)
        .map_err(Failure::Usage)?;
    if args.get("rpc-url").is_none() {
        return Err(usage("`--rpc-url` is required: a pool round needs a node"));
    }
    let wallet_path = Path::new(args.required("wallet").map_err(Failure::Usage)?);
    let file = wallet::open(args)?;
    let network = file.network();
    let chain = node(args, network)?;
    let mut pit_wallet = PitWallet::new(&file.seed().map_err(failed)?, pit).map_err(failed)?;
    // Past every address a command on this wallet handed out, so that the sync watches them too.
    let claims = Claims::open(wallet_path).map_err(failed)?;
    claims.apply(&mut pit_wallet).map_err(failed)?;
    pit_wallet.sync(&chain, file.birthday()).map_err(failed)?;
    Ok(Setup {
        network,
        pit,
        wallet: pit_wallet,
        chain,
        claims,
        mixdepth,
        proxy: proxy(args)?,
    })
}

/// A confirmed coin of `mixdepth` that fits `denomination` (sats) and nobody else holds, the smallest first,
/// with the key a registration signs it with.
fn coin_for(
    setup: &Setup,
    denomination: i64,
) -> Result<(OutPoint, vortex_ng_core::bitcoin::TxOut, SecretKey), Failure> {
    let held = setup.claims.held_by_others().map_err(failed)?;
    let low = denomination.saturating_add(rules::INPUT_SLACK_MIN);
    let high = denomination.saturating_add(rules::INPUT_SLACK_MAX);
    let mut fitting: Vec<_> = setup
        .wallet
        .utxos(setup.mixdepth)
        .map_err(failed)?
        .into_iter()
        .filter(|u| u.chain_position.is_confirmed() && !held.contains(&u.outpoint))
        .filter(|u| {
            let value = i64::try_from(u.txout.value.to_sat()).unwrap_or(i64::MAX);
            (low..=high).contains(&value)
        })
        .collect();
    fitting.sort_by_key(|u| u.txout.value);
    let Some(utxo) = fitting.into_iter().next() else {
        return Err(failed(format!(
            "no confirmed coin of {low} to {high} sat in mixdepth {} that another command does not hold. \
             `vortex-ng coinjoin --amount {} --mixdepth <m>` leaves one in mixdepth m + 1",
            setup.mixdepth,
            denomination.saturating_add((rules::INPUT_SLACK_MIN + rules::INPUT_SLACK_MAX) / 2)
        )));
    };
    let keys = setup
        .wallet
        .utxo_keys(setup.mixdepth, &utxo)
        .map_err(failed)?;
    let key = match setup.pit {
        Pit::Tr0 => taproot_output_secret(&Secp256k1::new(), keys.auth()),
        _ => *keys.auth(),
    };
    Ok((utxo.outpoint, utxo.txout, key))
}

/// Hold `coin` for `pool`'s lifetime, show what is about to happen, and ask.
fn hold_and_confirm(
    setup: &Setup,
    args: &Args,
    pool: &Pool,
    coin: OutPoint,
    value: u64,
    role: &str,
) -> Result<(), Failure> {
    let until = u64::try_from(pool.timeout).unwrap_or(0) + AFTER_CLOSE;
    if !setup.claims.hold_until(&[coin], until).map_err(failed)? {
        return Err(failed(
            "another command on this wallet has just taken that coin",
        ));
    }
    let next = (setup.mixdepth + 1) % MIXDEPTHS;
    println!("{role} {}", describe(pool, now()));
    println!(
        "Puts in {coin} ({value} sat) from mixdepth {}; pays {} sat to mixdepth {next} of this wallet, if the \
         pool fills. Relays see who writes to the pool's key and when; every peer holds the pool's key and can \
         read every pool message; a pool without aut-ct has no defence against one party taking many places.",
        setup.mixdepth,
        rules::output_amount(pool.denomination, pool.fee_rate, pool.peers)
    );
    if !args.flag("yes") && !secret::confirm("Proceed?").map_err(failed)? {
        let _ = setup.claims.release(&[coin]);
        return Err(failed("not confirmed: nothing was sent"));
    }
    Ok(())
}

/// Run our peer in `pool` to the end, check and broadcast the transaction. The coin's hold stays until it runs
/// out when the transaction went out (by then the node shows the coin spent), and goes at once otherwise.
fn run_and_broadcast(
    mut setup: Setup,
    pool: &Pool,
    pool_key: SecretKey,
    hosting: bool,
    coin: (OutPoint, vortex_ng_core::bitcoin::TxOut, SecretKey),
) -> Result<(), Failure> {
    let outpoint = coin.0;
    match round(&mut setup, pool, pool_key, hosting, coin) {
        Ok((txid, outputs)) => {
            println!(
                "Broadcast {txid}: {outputs} peers, {} sat each",
                rules::output_amount(pool.denomination, pool.fee_rate, pool.peers)
            );
            Ok(())
        }
        Err(e) => {
            let _ = setup.claims.release(&[outpoint]);
            Err(e)
        }
    }
}

/// One pool round, from our registration to the broadcast: the txid and the number of outputs.
fn round(
    setup: &mut Setup,
    pool: &Pool,
    pool_key: SecretKey,
    hosting: bool,
    coin: (OutPoint, vortex_ng_core::bitcoin::TxOut, SecretKey),
) -> Result<(vortex_ng_core::bitcoin::Txid, usize), Failure> {
    let (outpoint, txout, key) = coin;
    let next = (setup.mixdepth + 1) % MIXDEPTHS;
    let address = setup
        .claims
        .fresh_address(&mut setup.wallet, next, false)
        .map_err(failed)?;
    let mut peer = Peer::new(pool.clone(), setup.network, address, outpoint, txout, key)
        .map_err(|e| failed(format!("{e:?}")))?;
    let since = unix_now().saturating_sub(LOOKBACK);
    let left = u64::try_from(pool.timeout - now()).unwrap_or(0) + AFTER_CLOSE;
    let until = Instant::now() + Duration::from_secs(left);
    let tx = runtime()?.block_on(async {
        let mut client = pool_client(&pool_key, &pool.relay, setup.proxy)
            .await
            .map_err(failed)?;
        if hosting {
            client
                .announce(&pool.announcement())
                .await
                .map_err(failed)?;
            println!("pool {} announced on {}", pool.id, pool.relay);
        }
        let host = hosting.then_some(Hosting {
            pool,
            key: &pool_key,
            autct: None,
        });
        let round = run_pool(
            &mut peer,
            &mut client,
            host,
            &setup.chain,
            since,
            INPUT_WAIT,
            until,
        )
        .await
        .map_err(failed);
        client.shutdown().await;
        round
    })?;
    // Every peer may broadcast it: another may have done so already, and the node then has it.
    let txid = tx.compute_txid();
    let known = || matches!(setup.chain.utxo(&OutPoint { txid, vout: 0 }), Ok(Some(_)));
    if !known() {
        if let Err(why) = setup.chain.test_accept(&tx).map_err(failed)? {
            if !known() {
                return Err(failed(format!(
                    "the node refuses the pool's transaction ({why}): nothing was broadcast"
                )));
            }
        } else if let Err(e) = setup.chain.broadcast(&tx)
            && !known()
        {
            return Err(failed(e));
        }
    }
    Ok((txid, tx.output.len()))
}

const WALLET_OPTIONS: [&str; 10] = [
    "wallet",
    "password-file",
    "pit",
    "mixdepth",
    "relays",
    "proxy",
    "rpc-url",
    "rpc-cookie-file",
    "rpc-user",
    "rpc-password-file",
];

/// `vortex-ng pool join`: join an open pool with a coin of this wallet.
pub(crate) fn join(rest: &[String]) -> Result<(), Failure> {
    let mut valued = WALLET_OPTIONS.to_vec();
    valued.extend(["pool", "wait"]);
    let args = parse(rest, &valued, &["yes"])?;
    let wanted = args.required("pool").map_err(Failure::Usage)?.to_string();
    let relays = relays(&args)?;
    if relays.is_empty() {
        return Err(usage(
            "give the relays the pool is on: `--relays <url[,url...]>`",
        ));
    }
    let wait = args.number("wait", 10, 1..=600).map_err(Failure::Usage)?;
    let setup = setup(&args)?;
    let pools = gather_pools(&relays, setup.proxy, Duration::from_secs(wait.into()))?;
    let matching: Vec<&Pool> = pools
        .iter()
        .filter(|p| p.id == wanted || p.public_key == wanted)
        .collect();
    let pool = match matching.as_slice() {
        [one] => (*one).clone(),
        [] => return Err(failed(format!("no open pool {wanted} on those relays"))),
        several => {
            let keys: Vec<&str> = several.iter().map(|p| p.public_key.as_str()).collect();
            return Err(failed(format!(
                "several pools are called {wanted}: name one by its key ({})",
                keys.join(", ")
            )));
        }
    };
    let coin = coin_for(&setup, pool.denom_sats())?;
    hold_and_confirm(
        &setup,
        &args,
        &pool,
        coin.0,
        coin.1.value.to_sat(),
        "Joining",
    )?;
    let pool_key = runtime()?
        .block_on(join_pool(&pool, setup.proxy, JOIN_WAIT, None))
        .map_err(|e| {
            let _ = setup.claims.release(&[coin.0]);
            failed(e)
        })?;
    println!("admitted to pool {}", pool.id);
    run_and_broadcast(setup, &pool, pool_key, false, coin)
}

/// `vortex-ng pool create`: announce a pool and take part in it with a coin of this wallet.
pub(crate) fn create(rest: &[String]) -> Result<(), Failure> {
    let mut valued = WALLET_OPTIONS.to_vec();
    valued.extend(["denomination", "peers", "fee-rate", "expires"]);
    let args = parse(rest, &valued, &["yes"])?;
    let relays = relays(&args)?;
    let Some(relay) = relays.first().cloned() else {
        return Err(usage("give the relay to announce on: `--relays <url>`"));
    };
    let Some(denomination) = args.sats("denomination").map_err(Failure::Usage)? else {
        return Err(usage("`--denomination <sats>` is required"));
    };
    let denomination_btc = denomination as f64 / 100_000_000.0;
    if denomination == 0
        || rules::denom_sats(denomination_btc) != i64::try_from(denomination).unwrap_or(-1)
    {
        return Err(usage("`--denomination` is a positive amount in satoshis"));
    }
    let peers = args.number("peers", 0, 2..=100).map_err(Failure::Usage)?;
    if peers == 0 {
        return Err(usage(
            "`--peers <n>` is required: how many peers the pool takes, ourselves included",
        ));
    }
    let fee_rate = args
        .number("fee-rate", 1, 1..=1_000)
        .map_err(Failure::Usage)?;
    let expires = args
        .number("expires", 3_600, 60..=86_400)
        .map_err(Failure::Usage)?;
    let setup = setup(&args)?;
    let coin = coin_for(&setup, i64::try_from(denomination).unwrap_or(i64::MAX))?;
    let pool_key = SecretKey::from_slice(&random_bytes::<32>()).map_err(failed)?;
    let id = random_bytes::<8>().to_lower_hex_string();
    let pool = Pool::create(
        &pool_key,
        &id,
        denomination_btc,
        peers,
        now() + i64::from(expires),
        &relay,
        f64::from(fee_rate),
    )
    .map_err(|e| failed(format!("{e:?}")))?;
    hold_and_confirm(
        &setup,
        &args,
        &pool,
        coin.0,
        coin.1.value.to_sat(),
        "Creating",
    )?;
    let network = network_name(setup.network);
    println!(
        "hosting pool {id} on {network}; waiting for {} more peers",
        peers - 1
    );
    run_and_broadcast(setup, &pool, pool_key, true, coin)
}
