//! Drives vortex-ng makers and takers over a message channel.
//!
//! The maker and taker crates are state machines with no I/O; this crate connects them to a [`Channel`]
//! (`vortex-ng-channel`): it turns the channel's verified private lines into commands, hands their answers
//! back to the channel to sign and send along the route the sender came by, announces offers, and has the
//! channel publish `!hp2` unlinked from the maker's nick. The Nostr client (`NickClient`) is one channel.
//!
//! Chain lookups are synchronous (`ChainLookup`); a production daemon runs them on a blocking thread.

pub mod joinstr;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use vortex_ng_chain::ChainLookup;
pub use vortex_ng_channel::{Channel, ChannelError, Incoming, Next};
use vortex_ng_core::bitcoin::Transaction;
use vortex_ng_core::command::{Command, ENCRYPTED, Outgoing, parse_plaintext};
use vortex_ng_core::line::PrivMsg;
use vortex_ng_core::offer::{Offer, Pit};
use vortex_ng_core::protocol::MAKER_CHANGE_THRESHOLD_SAT;
use vortex_ng_maker::Maker;
pub use vortex_ng_nostr::channel::{CONNECT_TIMEOUT, OFFER_TTL};
use vortex_ng_nostr::client::unix_now;
use vortex_ng_taker::{
    Progress, Taker, TakerConfig, TakerError, VerifiedBond, candidate_nicks, select_makers,
    verify_bond,
};
use vortex_ng_wallet::PitWallet;
use vortex_ng_wallet::sync::BlockSource;

/// A maker answers one nick's `!orderbook` at most once per this interval.
pub const ORDERBOOK_NICK_INTERVAL: Duration = Duration::from_secs(5);
/// A maker answers at most this many `!orderbook` requests a minute, from all nicks together.
pub const ORDERBOOK_ANSWERS_PER_MINUTE: u32 = 120;
/// A taker asks again (`!orderbook`) at most this often while it discovers makers that have not answered.
pub const REASK_INTERVAL: Duration = Duration::from_secs(1);
/// Most maker nicks a taker hears offers from in one gathering, and most offers it keeps per nick.
pub const MAX_ANSWERING_NICKS: usize = 1_000;
/// See [`MAX_ANSWERING_NICKS`].
pub const MAX_OFFERS_PER_NICK: usize = 16;
/// Most bond proofs a taker checks against the chain per round (up to two lookups each). Anyone can sign a proof
/// with a key of their own, so the signature alone does not earn a lookup.
pub const MAX_BOND_LOOKUPS: usize = 256;

/// Run synchronous work that may block on the chain backend (`ChainLookup` is a blocking call, a JSON-RPC
/// request for `CoreRpc`) without stalling the async runtime's other tasks: on a multi-threaded runtime the
/// worker is handed over for the duration. A current-thread runtime has nothing to hand over to, and just runs it.
fn blocking<T>(work: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(work),
        _ => work(),
    }
}

/// Check the `!tbond` proofs of the nicks worth it: those with an offer the taker would consider
/// (`candidates`), at most [`MAX_BOND_LOOKUPS`] of them, against a tip read once.
fn verify_bonds(
    proofs: &HashMap<String, String>,
    candidates: &HashSet<String>,
    me: &str,
    chain: &impl ChainLookup,
    now: u64,
    cfg: &TakerConfig,
) -> HashMap<String, VerifiedBond> {
    let Ok(height) = chain.tip_height() else {
        return HashMap::new();
    };
    proofs
        .iter()
        .filter(|(nick, _)| candidates.contains(*nick))
        .take(MAX_BOND_LOOKUPS)
        .filter_map(|(nick, proof)| {
            verify_bond(proof, me, nick, chain, height, now, cfg.bond_params)
                .ok()
                .map(|bond| (nick.clone(), bond))
        })
        .collect()
}

/// Why a driver stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    /// The message channel failed.
    Channel(ChannelError),
    /// The taker's round failed.
    Taker(TakerError),
    /// The deadline passed.
    Timeout,
    /// The maker could not start (its bond, its chain).
    Maker(String),
    /// A joinstr pool round failed.
    Pool(String),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Channel(e) => write!(f, "{e}"),
            NodeError::Taker(e) => write!(f, "{e}"),
            NodeError::Timeout => f.write_str("deadline passed"),
            NodeError::Maker(e) => write!(f, "maker: {e}"),
            NodeError::Pool(e) => write!(f, "pool: {e}"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<vortex_ng_joinstr::session::SessionError> for NodeError {
    fn from(e: vortex_ng_joinstr::session::SessionError) -> Self {
        NodeError::Pool(e.to_string())
    }
}

impl From<ChannelError> for NodeError {
    fn from(e: ChannelError) -> Self {
        NodeError::Channel(e)
    }
}

impl From<vortex_ng_nostr::ChannelError> for NodeError {
    fn from(e: vortex_ng_nostr::ChannelError) -> Self {
        NodeError::Channel(e.into())
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

/// Hand the state machines' answers to the channel: private lines to their recipients along the routes
/// the drivers know, `!hp2` to the channel's unlinked publishing, transactions to the chain.
async fn deliver<C: Channel>(
    client: &C,
    peers: &HashMap<String, C::Route>,
    chain: &impl ChainLookup,
    outgoing: Vec<Outgoing>,
) -> Result<(), NodeError> {
    for out in outgoing {
        match out {
            Outgoing::Private { to, command, body } => {
                let route = peers
                    .get(&to)
                    .ok_or(ChannelError::Invalid("no route known for the recipient"))?;
                client.send_private(route, &to, &command, &body).await?
            }
            // A taker asked us to broadcast the round we signed for it (`!push`). A failure is its
            // problem to notice (it watches for the transaction and has other makers to ask).
            Outgoing::Broadcast(tx) => {
                let _ = blocking(|| chain.broadcast(&tx));
            }
            Outgoing::PublicEphemeral(content) => client.publish_unlinked(&content).await?,
        }
    }
    Ok(())
}

fn remember<R: Clone>(peers: &mut HashMap<String, R>, nick: &str, route: &R) {
    peers.insert(nick.to_string(), route.clone());
}

/// The maker's `!orderbook` rate limits (the Nostr draft's SHOULD): each answer costs a proof and a gift
/// wrap per offer.
struct OrderbookLimiter {
    last: HashMap<String, Instant>,
    window: Instant,
    count: u32,
}

impl OrderbookLimiter {
    fn new() -> OrderbookLimiter {
        OrderbookLimiter {
            last: HashMap::new(),
            window: Instant::now(),
            count: 0,
        }
    }

    fn allow(&mut self, nick: &str, now: Instant) -> bool {
        if now.duration_since(self.window) >= Duration::from_secs(60) {
            self.window = now;
            self.count = 0;
            self.last
                .retain(|_, t| now.duration_since(*t) < ORDERBOOK_NICK_INTERVAL);
        }
        if self.count >= ORDERBOOK_ANSWERS_PER_MINUTE
            || self
                .last
                .get(nick)
                .is_some_and(|t| now.duration_since(*t) < ORDERBOOK_NICK_INTERVAL)
        {
            return false;
        }
        self.last.insert(nick.to_string(), now);
        self.count += 1;
        true
    }
}

/// Run `maker` on `client` until `until`: announce its offers, answer `!orderbook` with its offers, and run
/// sessions for the takers that fill them. `network` is the channel's own network name; the channel uses
/// the one it was opened with.
pub async fn run_maker<C: Channel>(
    maker: &mut Maker,
    client: &mut C,
    chain: &impl ChainLookup,
    network: &str,
    until: Instant,
) -> Result<(), NodeError> {
    let _ = network;
    blocking(|| maker.refresh_bond(chain, unix_now()))
        .map_err(|e| NodeError::Maker(e.to_string()))?;
    let me = client.nick().to_string();
    let mut limiter = OrderbookLimiter::new();
    client.listen(false, true).await?;
    client.announce_offers(maker.pit(), maker.offers()).await?;
    let mut peers: HashMap<String, C::Route> = HashMap::new();
    while let Some(left) = until.checked_duration_since(Instant::now()) {
        let Next::Message(incoming) = client.receive(left).await else {
            break;
        };
        let outgoing = maker_step(maker, chain, &mut peers, &mut limiter, &me, incoming);
        // A failed send to one taker must not stop the maker.
        let _ = deliver(client, &peers, chain, outgoing).await;
    }
    Ok(())
}

/// What a maker does with one message from the channel: the answers to send.
fn maker_step<R: Clone>(
    maker: &mut Maker,
    chain: &impl ChainLookup,
    peers: &mut HashMap<String, R>,
    limiter: &mut OrderbookLimiter,
    me: &str,
    incoming: Incoming<R>,
) -> Vec<Outgoing> {
    match incoming {
        Incoming::Public {
            nick,
            commands,
            route,
        } => {
            remember(peers, &nick, &route);
            let mut out = Vec::new();
            for cmd in commands {
                match cmd {
                    Command::Orderbook if limiter.allow(&nick, Instant::now()) => {
                        // A failed refresh keeps the current certificate while it lasts.
                        let _ = blocking(|| maker.refresh_bond(chain, unix_now()));
                        out.extend(maker.on_orderbook(&nick, me));
                    }
                    Command::Hp2(c) => maker.on_hp2(c),
                    _ => {}
                }
            }
            out
        }
        Incoming::Private { msg, route } => {
            remember(peers, &msg.from, &route);
            let mut out = Vec::new();
            for cmd in commands(&msg) {
                out.extend(blocking(|| maker.handle(&msg.from, cmd, chain, unix_now())));
            }
            out
        }
        Incoming::Offers { .. } => Vec::new(),
    }
}

/// What a maker charges for a round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfferFee {
    /// A fraction of the amount, as a decimal (`0.001`).
    Relative(String),
    /// Satoshis.
    Absolute(u64),
}

/// How a long-running maker offers its coins: one offer, sized to the wallet at every upkeep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferPolicy {
    /// The coinjoin fee asked.
    pub fee: OfferFee,
    /// Our contribution to each round's mining fee, satoshis.
    pub txfee: u64,
    /// The smallest round we join, satoshis.
    pub min_size: u64,
    /// The largest round we join, satoshis; none: whatever the wallet allows.
    pub max_size: Option<u64>,
}

impl OfferPolicy {
    /// The offer of a `pit` maker whose wallet can put `liquidity` into one round, or `None` when that is
    /// too little for the smallest round the policy allows (or the fee text is not a fee).
    ///
    /// Beyond the amount, a round takes our mining-fee share and must leave a change output no smaller
    /// than the threshold makers keep; the fee we earn is not counted on. So the largest amount offered is
    /// `liquidity - txfee - threshold`, capped by `max_size`.
    pub fn offer(&self, pit: Pit, liquidity: u64) -> Option<Offer> {
        let reserve = self.txfee.checked_add(MAKER_CHANGE_THRESHOLD_SAT)?;
        let available = liquidity.checked_sub(reserve)?;
        let max = self.max_size.map_or(available, |cap| cap.min(available));
        if max == 0 || max < self.min_size {
            return None;
        }
        let (kind, fee) = match &self.fee {
            OfferFee::Relative(text) => ("reloffer", text.clone()),
            OfferFee::Absolute(sats) => ("absoffer", sats.to_string()),
        };
        Offer::parse(
            &format!("{}{kind}", pit.prefix()),
            &format!("0 {} {max} {} {fee}", self.min_size, self.txfee),
        )
    }
}

/// The upkeep of a long-running maker.
#[derive(Clone, Debug)]
pub struct MakerService {
    /// How it offers its coins.
    pub policy: OfferPolicy,
    /// The wallet's birthday: blocks below it are not scanned.
    pub birthday: u32,
    /// How often the wallet is brought up to the chain's tip and the offer sized to it.
    pub upkeep: Duration,
}

/// What a long-running maker tells its operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MakerReport {
    /// The wallet is at `height` and `offer` is what is announced now (none: too little to offer).
    Offering {
        /// The height the wallet is synced to.
        height: u32,
        /// The most one round can draw on, satoshis.
        liquidity: u64,
        /// The announced offer.
        offer: Option<Offer>,
    },
    /// An upkeep step failed; the maker carries on with what it had and tries again.
    Trouble(String),
}

/// Run `maker` as a service until `until` (forever when `None`).
///
/// Unlike [`run_maker`], which serves fixed offers for one sitting, this keeps a maker fit to stay up:
/// every `service.upkeep` it brings the wallet up to the chain's tip (so coins received in a round are
/// offered once confirmed, and a round's spent coins are forgotten), refreshes the bond certificate, sizes
/// its one offer to the wallet (`service.policy`), and announces the offer when it changed or half its
/// lifetime ([`OFFER_TTL`]) has passed. When there is nothing to offer, the announced offer is withdrawn.
/// Upkeep failures (the node is away, a relay refused) are reported and retried; they do not stop the
/// maker. `network` is the channel's own network name; the channel uses the one it was opened with.
pub async fn serve_maker<B: ChainLookup + BlockSource, C: Channel>(
    maker: &mut Maker,
    client: &mut C,
    chain: &B,
    network: &str,
    service: &MakerService,
    until: Option<Instant>,
    report: &mut dyn FnMut(MakerReport),
) -> Result<(), NodeError> {
    let _ = network;
    let me = client.nick().to_string();
    let pit = maker.pit();
    let mut limiter = OrderbookLimiter::new();
    client.listen(false, true).await?;
    let mut peers: HashMap<String, C::Route> = HashMap::new();
    // What is announced now, and when it was last published.
    let mut announced: Option<(Option<Offer>, Instant)> = None;
    let mut next_upkeep = Instant::now();
    loop {
        let now = Instant::now();
        if until.is_some_and(|until| now >= until) {
            return Ok(());
        }
        if now >= next_upkeep {
            next_upkeep = now + service.upkeep;
            let synced = blocking(|| {
                let height = maker
                    .wallet_mut()
                    .sync(chain, service.birthday)
                    .map_err(|e| e.to_string())?;
                // A failed refresh keeps the current certificate while it lasts.
                let _ = maker.refresh_bond(chain, unix_now());
                let liquidity = maker.liquidity().map_err(|e| e.to_string())?;
                Ok::<_, String>((height, liquidity))
            });
            match synced {
                Err(why) => report(MakerReport::Trouble(why)),
                Ok((height, liquidity)) => {
                    let offer = service.policy.offer(pit, liquidity);
                    let due = match &announced {
                        None => true,
                        Some((old, at)) => {
                            *old != offer
                                || (offer.is_some()
                                    && at.elapsed() >= Duration::from_secs(OFFER_TTL / 2))
                        }
                    };
                    if due {
                        maker
                            .set_offers(offer.iter().cloned().collect())
                            .map_err(|e| NodeError::Maker(e.to_string()))?;
                        let published = match (&offer, &announced) {
                            (Some(_), _) => client.announce_offers(pit, maker.offers()).await,
                            // Nothing to offer any more: withdraw what was announced.
                            (None, Some((Some(_), _))) => client.withdraw_offers(pit).await,
                            (None, _) => Ok(()),
                        };
                        match published {
                            Ok(()) => {
                                announced = Some((offer.clone(), Instant::now()));
                                report(MakerReport::Offering {
                                    height,
                                    liquidity,
                                    offer,
                                });
                            }
                            // Not announced: the next upkeep tries again.
                            Err(e) => report(MakerReport::Trouble(e.to_string())),
                        }
                    }
                }
            }
        }
        let mut wait = next_upkeep.saturating_duration_since(Instant::now());
        if let Some(until) = until {
            wait = wait.min(until.saturating_duration_since(Instant::now()));
        }
        let incoming = match client.receive(wait).await {
            Next::Message(incoming) => incoming,
            // The next upkeep's turn.
            Next::Timeout => continue,
            // No live stream: pause rather than spin.
            Next::Closed => {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        };
        let outgoing = maker_step(maker, chain, &mut peers, &mut limiter, &me, incoming);
        // A failed send to one taker must not stop the maker.
        let _ = deliver(client, &peers, chain, outgoing).await;
    }
}

/// What makers answered to one `!orderbook` request. `R` is the channel's [`Channel::Route`].
#[derive(Debug)]
pub struct Orderbook<R> {
    /// Every offer received, with its maker's nick, in arrival order.
    pub offers: Vec<(String, Offer)>,
    /// Each answering maker's `!tbond` proof, not yet verified (see [`verify_bond`]).
    pub proofs: HashMap<String, String>,
    peers: HashMap<String, R>,
}

impl<R> Default for Orderbook<R> {
    fn default() -> Self {
        Orderbook {
            offers: Vec::new(),
            proofs: HashMap::new(),
            peers: HashMap::new(),
        }
    }
}

/// Ask for the orderbook and gather the makers' private answers for `gather`: offers and `!tbond` proofs.
/// Publicly announced offers serve only to discover makers that missed the request (it is then asked
/// again). `network` is the channel's own network name; the channel uses the one it was opened with.
pub async fn fetch_orderbook<C: Channel>(
    client: &mut C,
    network: &str,
    gather: Duration,
) -> Result<Orderbook<C::Route>, NodeError> {
    let _ = network;
    client.listen(true, false).await?;
    client.ask_orderbook().await?;
    let mut asked = Instant::now();
    let mut book = Orderbook::default();
    let mut per_nick: HashMap<String, usize> = HashMap::new();
    let gather_until = Instant::now() + gather;
    while let Some(left) = gather_until.checked_duration_since(Instant::now()) {
        match client.receive(left).await {
            Next::Message(Incoming::Offers { nick, route, .. }) => {
                if book.peers.contains_key(&nick) || book.peers.len() < MAX_ANSWERING_NICKS {
                    remember(&mut book.peers, &nick, &route);
                }
                // Public offers are a discovery cache (the draft): a maker that has not answered may have
                // started listening after our request, so ask again.
                if !per_nick.contains_key(&nick) && asked.elapsed() >= REASK_INTERVAL {
                    client.ask_orderbook().await?;
                    asked = Instant::now();
                }
            }
            Next::Message(Incoming::Private { msg, route }) => {
                if !per_nick.contains_key(&msg.from) && per_nick.len() >= MAX_ANSWERING_NICKS {
                    continue;
                }
                // Only a nick that answers with offers is remembered, and its `!tbond` kept: senders of
                // anything else cannot grow the taker's state.
                for cmd in commands(&msg) {
                    match cmd {
                        Command::Offer(offer) => {
                            let count = per_nick.entry(msg.from.clone()).or_default();
                            if *count < MAX_OFFERS_PER_NICK {
                                *count += 1;
                                book.offers.push((msg.from.clone(), offer));
                            }
                        }
                        Command::Tbond(proof) if per_nick.contains_key(&msg.from) => {
                            book.proofs.entry(msg.from.clone()).or_insert(proof);
                        }
                        _ => {}
                    }
                }
                if per_nick.contains_key(&msg.from) {
                    remember(&mut book.peers, &msg.from, &route);
                }
            }
            Next::Message(Incoming::Public { .. }) => {}
            Next::Timeout | Next::Closed => break,
        }
    }
    Ok(book)
}

/// Run one CoinJoin as the taker: ask for the orderbook, gather the makers' private answers (offers and
/// `!tbond` proofs; offer events serve only to discover makers that missed the request) for `gather`,
/// verify the bonds, pick makers, run the round, and return the fully signed transaction (signed last,
/// after every maker; channel funding hooks in before `Taker::finish`).
pub async fn run_taker<C: Channel>(
    taker: &mut Taker,
    wallet: &PitWallet,
    client: &mut C,
    chain: &impl ChainLookup,
    cfg: &TakerConfig,
    gather: Duration,
    until: Instant,
) -> Result<Transaction, NodeError> {
    let network = channel_network(cfg.network);
    let me = client.nick().to_string();
    let Orderbook {
        offers,
        proofs,
        mut peers,
    } = fetch_orderbook(client, network, gather).await?;
    let candidates = candidate_nicks(&offers, cfg);
    let bonds = blocking(|| verify_bonds(&proofs, &candidates, &me, chain, unix_now(), cfg));
    let chosen = select_makers(&offers, &bonds, cfg);
    let in_round: HashSet<String> = chosen.iter().map(|(nick, _)| nick.clone()).collect();
    let outgoing = taker.start(chosen).map_err(NodeError::Taker)?;
    deliver(client, &peers, chain, outgoing).await?;
    while let Some(left) = until.checked_duration_since(Instant::now()) {
        let Next::Message(Incoming::Private { msg, route }) = client.receive(left).await else {
            continue;
        };
        // Anyone who can reach our nick can write to us: only the round's makers are heard, so an outsider
        // cannot abort the round.
        if !in_round.contains(&msg.from) {
            continue;
        }
        remember(&mut peers, &msg.from, &route);
        for cmd in commands(&msg) {
            let (outgoing, progress) =
                blocking(|| taker.handle(&msg.from, cmd, chain)).map_err(NodeError::Taker)?;
            deliver(client, &peers, chain, outgoing).await?;
            if progress == Progress::MakersSigned {
                return taker.finish(wallet).map_err(NodeError::Taker);
            }
        }
    }
    Err(NodeError::Timeout)
}

#[cfg(test)]
mod tests;
