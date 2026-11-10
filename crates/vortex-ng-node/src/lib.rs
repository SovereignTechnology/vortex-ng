//! Drives vortex-ng makers and takers over the Nostr message channel.
//!
//! The maker and taker crates are state machines with no I/O; this crate connects them to a
//! [`NickClient`]: it turns verified private lines into commands, signs and sends their answers (JMP-0001
//! lines with `hostid` `nostr-network`) to the peer's relays, publishes offers, and sends `!hp2` from a
//! throwaway nick.
//!
//! Chain lookups are synchronous (`ChainLookup`); a production daemon runs them on a blocking thread.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use vortex_ng_chain::ChainLookup;
use vortex_ng_core::bitcoin::Transaction;
use vortex_ng_core::bitcoin::secp256k1::Secp256k1;
use vortex_ng_core::command::{Command, ENCRYPTED, Outgoing, parse_plaintext};
use vortex_ng_core::line::{PrivMsg, sign_line};
use vortex_ng_core::offer::Offer;
use vortex_ng_core::protocol::NOSTR_HOSTID;
use vortex_ng_maker::Maker;
use vortex_ng_nostr::ChannelError;
use vortex_ng_nostr::client::{Incoming, NickClient, unix_now};
use vortex_ng_nostr::event::{offer_event, public_event};
use vortex_ng_nostr::keys::{NickKeys, nostr_public};
use vortex_ng_taker::{Progress, Taker, TakerConfig, TakerError, select_makers};
use vortex_ng_wallet::PitWallet;

/// Lifetime of a maker's offer event, seconds.
pub const OFFER_TTL: u64 = 1800;
/// How long a relay connection may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a driver stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    /// The Nostr channel failed.
    Channel(ChannelError),
    /// The taker's round failed.
    Taker(TakerError),
    /// The deadline passed.
    Timeout,
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Channel(e) => write!(f, "{e}"),
            NodeError::Taker(e) => write!(f, "{e}"),
            NodeError::Timeout => f.write_str("deadline passed"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<ChannelError> for NodeError {
    fn from(e: ChannelError) -> Self {
        NodeError::Channel(e)
    }
}

/// The Nostr channel's `network` tag value for a Bitcoin network.
pub fn channel_network(network: vortex_ng_core::bitcoin::Network) -> &'static str {
    use vortex_ng_core::bitcoin::Network;
    match network {
        Network::Bitcoin => "mainnet",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
        _ => "testnet",
    }
}

/// Where to reach a peer nick.
#[derive(Clone, Debug)]
struct Peer {
    key: nostr::key::PublicKey,
    relays: Vec<String>,
}

/// The commands a verified private line carries.
fn commands(msg: &PrivMsg) -> Vec<Command> {
    if ENCRYPTED.contains(&msg.command.as_str()) {
        return vec![Command::Encrypted {
            name: msg.command.clone(),
            ciphertext: msg.body.clone(),
        }];
    }
    parse_plaintext(&format!("!{} {}", msg.command, msg.body)).unwrap_or_default()
}

async fn send(
    client: &NickClient,
    peers: &HashMap<String, Peer>,
    to: &str,
    command: &str,
    body: &str,
) -> Result<(), NodeError> {
    let peer = peers
        .get(to)
        .ok_or(ChannelError::Invalid("no relays known for the recipient"))?;
    let line = sign_line(
        &Secp256k1::signing_only(),
        client.keys().secret(),
        to,
        command,
        body,
        NOSTR_HOSTID,
    )
    .map_err(ChannelError::Line)?;
    client.send_line(&peer.key, &peer.relays, &line).await?;
    Ok(())
}

async fn deliver(
    client: &NickClient,
    network: &str,
    peers: &HashMap<String, Peer>,
    outgoing: Vec<Outgoing>,
) -> Result<(), NodeError> {
    for out in outgoing {
        match out {
            Outgoing::Private { to, command, body } => {
                send(client, peers, &to, &command, &body).await?
            }
            Outgoing::PublicEphemeral(content) => {
                // A fresh nick on its own connection, closed afterwards (the draft's !hp2 rule).
                let throwaway = NickClient::connect(
                    NickKeys::generate(),
                    network,
                    client.relays(),
                    None,
                    CONNECT_TIMEOUT,
                )
                .await?;
                let relays: Vec<&str> = client.relays().iter().map(String::as_str).collect();
                let event = public_event(throwaway.keys(), network, &content, &relays, unix_now())?;
                let result = throwaway.publish(&event).await;
                throwaway.shutdown().await;
                result?;
            }
        }
    }
    Ok(())
}

fn remember(
    peers: &mut HashMap<String, Peer>,
    nick: &str,
    key: &vortex_ng_core::bitcoin::secp256k1::PublicKey,
    relays: &[String],
) {
    if let Ok(key) = nostr_public(key) {
        peers.insert(
            nick.to_string(),
            Peer {
                key,
                relays: relays.to_vec(),
            },
        );
    }
}

/// Run `maker` on `client` until `until`: publish its offers, answer `!orderbook` with its offers, and run
/// sessions for the takers that fill them.
pub async fn run_maker(
    maker: &mut Maker,
    client: &mut NickClient,
    chain: &impl ChainLookup,
    network: &str,
    until: Instant,
) -> Result<(), NodeError> {
    client
        .subscribe(unix_now().saturating_sub(60), false, true)
        .await?;
    let relays: Vec<&str> = client.relays().iter().map(String::as_str).collect();
    let pit = maker.pit();
    let event = offer_event(
        client.keys(),
        network,
        pit,
        maker.offers(),
        &[],
        &relays,
        unix_now(),
        OFFER_TTL,
    )?;
    client.publish(&event).await?;
    let mut peers: HashMap<String, Peer> = HashMap::new();
    while let Some(left) = until.checked_duration_since(Instant::now()) {
        let Some(incoming) = client.next(left).await else {
            break;
        };
        let outgoing = match incoming {
            Incoming::Public(author, cmds) => {
                remember(&mut peers, &author.nick, &author.key, &author.relays);
                let mut out = Vec::new();
                for cmd in cmds {
                    match cmd {
                        Command::Orderbook => out.extend(maker.on_orderbook(&author.nick)),
                        Command::Hp2(c) => maker.on_hp2(c),
                        _ => {}
                    }
                }
                out
            }
            Incoming::Private(msg, reply_relays) => {
                remember(&mut peers, &msg.from, &msg.key, &reply_relays);
                let mut out = Vec::new();
                for cmd in commands(&msg) {
                    out.extend(maker.handle(&msg.from, cmd, chain, unix_now()));
                }
                out
            }
            Incoming::Offers(..) => Vec::new(),
        };
        // A failed send to one taker must not stop the maker.
        let _ = deliver(client, network, &peers, outgoing).await;
    }
    Ok(())
}

/// Run one CoinJoin as the taker: gather offers for `gather`, pick makers, run the round, and return the
/// fully signed transaction (signed last, after every maker; channel funding hooks in before
/// `Taker::finish`).
pub async fn run_taker(
    taker: &mut Taker,
    wallet: &PitWallet,
    client: &mut NickClient,
    chain: &impl ChainLookup,
    cfg: &TakerConfig,
    gather: Duration,
    until: Instant,
) -> Result<Transaction, NodeError> {
    let network = channel_network(cfg.network);
    client
        .subscribe(unix_now().saturating_sub(60), true, false)
        .await?;
    let mut offers: Vec<(String, Offer)> = Vec::new();
    let mut peers: HashMap<String, Peer> = HashMap::new();
    let gather_until = Instant::now() + gather;
    while let Some(left) = gather_until.checked_duration_since(Instant::now()) {
        match client.next(left).await {
            Some(Incoming::Offers(author, list)) => {
                remember(&mut peers, &author.nick, &author.key, &author.relays);
                offers.extend(list.into_iter().map(|o| (author.nick.clone(), o)));
            }
            Some(_) => {}
            None => break,
        }
    }
    let chosen = select_makers(&offers, cfg);
    let in_round: std::collections::HashSet<String> =
        chosen.iter().map(|(nick, _)| nick.clone()).collect();
    let outgoing = taker.start(chosen).map_err(NodeError::Taker)?;
    deliver(client, network, &peers, outgoing).await?;
    while let Some(left) = until.checked_duration_since(Instant::now()) {
        let Some(Incoming::Private(msg, reply_relays)) = client.next(left).await else {
            continue;
        };
        // Anyone who sees our key on a gift wrap can write to us: only the round's makers are heard, so an
        // outsider cannot abort the round.
        if !in_round.contains(&msg.from) {
            continue;
        }
        remember(&mut peers, &msg.from, &msg.key, &reply_relays);
        for cmd in commands(&msg) {
            let (outgoing, progress) = taker
                .handle(&msg.from, cmd, chain)
                .map_err(NodeError::Taker)?;
            deliver(client, network, &peers, outgoing).await?;
            if progress == Progress::MakersSigned {
                return taker.finish(wallet).map_err(NodeError::Taker);
            }
        }
    }
    Err(NodeError::Timeout)
}

#[cfg(test)]
mod tests;
