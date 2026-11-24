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
use vortex_ng_core::bitcoin::secp256k1::Secp256k1;
use vortex_ng_core::bond::BondProof;
use vortex_ng_core::command::{Command, ENCRYPTED, Outgoing, parse_plaintext};
use vortex_ng_core::line::PrivMsg;
use vortex_ng_core::offer::{Offer, Pit};
use vortex_ng_core::protocol::MAKER_CHANGE_THRESHOLD_SAT;
use vortex_ng_core::sig::InputSigner;
use vortex_ng_maker::Maker;
pub use vortex_ng_nostr::channel::{CONNECT_TIMEOUT, OFFER_TTL};
use vortex_ng_nostr::client::unix_now;
use vortex_ng_taker::{
    Progress, Taker, TakerConfig, TakerError, VerifiedBond, candidate_nicks, select_makers,
    usable_fee, verify_bond,
};
use vortex_ng_wallet::sync::BlockSource;

/// A maker answers one nick's `!orderbook` at most once per this interval.
pub const ORDERBOOK_NICK_INTERVAL: Duration = Duration::from_secs(5);
/// A maker answers `!orderbook` at this rate on each channel, from all nicks together.
pub const ORDERBOOK_ANSWERS_PER_SECOND: u32 = 2;
/// The most `!orderbook` requests a maker answers at once on a channel after a quiet time.
pub const ORDERBOOK_BURST: u32 = 20;
/// Most commands one private line may carry; a line with more is not one any maker or taker sends. (A maker's
/// answer is at most [`MAX_OFFERS_PER_NICK`] offers and a `!tbond`.)
pub const MAX_COMMANDS_PER_LINE: usize = 32;
/// Most peers a maker remembers a route for. Past it, those without a session are forgotten: any nick can
/// write to a maker for free.
pub const MAX_KNOWN_PEERS: usize = 10_000;
/// A taker asks again (`!orderbook`) at most this often while it discovers makers that have not answered.
pub const REASK_INTERVAL: Duration = Duration::from_secs(1);
/// Most maker nicks a taker keeps answers from per channel in one gathering, and most offers it keeps per nick.
/// Past this a random sample of the nicks is kept, so whoever answers first cannot fill the book; a nick whose
/// bond proof stands up on the chain keeps its place, and gets one (see [`fetch_orderbook_with_bonds`]).
pub const MAX_ANSWERING_NICKS: usize = 1_000;
/// See [`MAX_ANSWERING_NICKS`].
pub const MAX_OFFERS_PER_NICK: usize = 16;
/// Most bond proofs a taker checks against the chain per round (up to two lookups each), while it gathers
/// answers and again when it chooses makers. Anyone can sign a proof with a key of their own, so the signature
/// alone does not earn a lookup.
pub const MAX_BOND_LOOKUPS: usize = 2_048;

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
/// (`candidates`), at most [`MAX_BOND_LOOKUPS`] of them, against a tip read once. A proof is made out to
/// the nick the maker knows us by: `me(maker)`.
fn verify_bonds(
    proofs: &HashMap<String, String>,
    candidates: &HashSet<String>,
    me: impl Fn(&str) -> String,
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
            verify_bond(proof, &me(nick), nick, chain, height, now, cfg.bond_params)
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
    if msg.body.matches('!').count() >= MAX_COMMANDS_PER_LINE {
        return Vec::new();
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
    // One line that cannot go must not keep the next one, to another peer, from going.
    let mut result = Ok(());
    for out in outgoing {
        let sent = match out {
            Outgoing::Private { to, command, body } => match peers.get(&to) {
                Some(route) => client.send_private(route, &to, &command, &body).await,
                None => Err(ChannelError::Invalid("no route known for the recipient")),
            },
            // A taker asked us to broadcast the round we signed for it (`!push`). A failure is its
            // problem to notice (it watches for the transaction and has other makers to ask).
            Outgoing::Broadcast(tx) => {
                let _ = blocking(|| chain.broadcast(&tx));
                Ok(())
            }
            Outgoing::PublicEphemeral(content) => client.publish_unlinked(&content).await,
        };
        if result.is_ok() {
            result = sent.map_err(NodeError::from);
        }
    }
    result
}

/// Whether `proof` is a `!tbond` that `maker` made out to `me`. A proof names the taker it is for, so unlike the
/// rest of a signed line it cannot have been harvested from another exchange and delivered here.
fn proof_for_us(proof: &str, me: &str, maker: &str) -> bool {
    BondProof::from_base64(proof).is_ok_and(|p| {
        p.verify_signatures(&Secp256k1::verification_only(), me, maker)
            .is_ok()
    })
}

/// Learn how to reach `nick`. A private line is the authoritative route and replaces what was known; a
/// public line only fills in a nick not known yet, so a public line on another channel never moves a peer
/// off the channel its private lines use.
fn remember<R: Clone>(peers: &mut HashMap<String, R>, nick: &str, route: &R, private: bool) {
    if private {
        peers.insert(nick.to_string(), route.clone());
    } else {
        peers
            .entry(nick.to_string())
            .or_insert_with(|| route.clone());
    }
}

/// The maker's `!orderbook` rate limits (the Nostr draft's SHOULD): each answer costs a proof and a gift
/// wrap per offer.
///
/// `!orderbook` is unsigned and free to send from fresh nicks. Each channel has its own token bucket, so a flood
/// on one leaves the others alone, and within a channel a burst can spend only [`ORDERBOOK_BURST`] answers:
/// the rest of the budget arrives over time, for whoever is asking then.
struct OrderbookLimiter {
    last: HashMap<(usize, String), Instant>,
    swept: Instant,
    /// Per channel: the answers available, and when that was worked out.
    buckets: HashMap<usize, (f64, Instant)>,
}

impl OrderbookLimiter {
    fn new() -> OrderbookLimiter {
        OrderbookLimiter {
            last: HashMap::new(),
            swept: Instant::now(),
            buckets: HashMap::new(),
        }
    }

    fn allow(&mut self, channel: usize, nick: &str, now: Instant) -> bool {
        if now.duration_since(self.swept) >= Duration::from_secs(60) {
            self.swept = now;
            self.last
                .retain(|_, t| now.duration_since(*t) < ORDERBOOK_NICK_INTERVAL);
        }
        let key = (channel, nick.to_string());
        if self
            .last
            .get(&key)
            .is_some_and(|t| now.duration_since(*t) < ORDERBOOK_NICK_INTERVAL)
        {
            return false;
        }
        let burst = f64::from(ORDERBOOK_BURST);
        let (tokens, at) = self.buckets.entry(channel).or_insert((burst, now));
        let earned =
            now.duration_since(*at).as_secs_f64() * f64::from(ORDERBOOK_ANSWERS_PER_SECOND);
        *tokens = (*tokens + earned).min(burst);
        *at = now;
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        self.last.insert(key, now);
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
        let outgoing = maker_step(
            maker,
            client,
            chain,
            &mut peers,
            &mut limiter,
            &me,
            incoming,
        );
        // A failed send to one taker must not stop the maker.
        let _ = deliver(client, &peers, chain, outgoing).await;
    }
    Ok(())
}

/// What a maker does with one message from the channel: the answers to send.
fn maker_step<C: Channel>(
    maker: &mut Maker,
    client: &C,
    chain: &impl ChainLookup,
    peers: &mut HashMap<String, C::Route>,
    limiter: &mut OrderbookLimiter,
    me: &str,
    incoming: Incoming<C::Route>,
) -> Vec<Outgoing> {
    if peers.len() >= MAX_KNOWN_PEERS {
        let now = unix_now();
        peers.retain(|nick, _| maker.in_session(nick, now));
    }
    match incoming {
        Incoming::Public {
            nick,
            commands,
            route,
        } => {
            // Rate-limited per channel and nick: a taker asking on two channels is two askers.
            let channel = client.channel_of(&route);
            let mut out = Vec::new();
            for cmd in commands {
                match cmd {
                    Command::Orderbook if limiter.allow(channel, &nick, Instant::now()) => {
                        // Only a nick we answer is remembered.
                        remember(peers, &nick, &route, false);
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
            // Where a session's answers go. Until its `!auth` has been answered, the route follows the
            // taker's latest line, so a `!fill` that arrives again another way is answered there too (the
            // same `!pubkey`). After that only a line that moves the session forward moves the route: an
            // encrypted step only the taker could write, so the round follows the taker onto a direct
            // connection it opened meanwhile (joinmarket-clientserver's taker sends `!fill` through a
            // directory, then connects). A line delivered again by a directory or a peer that saw it never
            // takes a session away.
            let now = unix_now();
            let before = maker.progress(&msg.from, now);
            remember(peers, &msg.from, &route, before <= 1);
            let mut out = Vec::new();
            for cmd in commands(&msg) {
                out.extend(blocking(|| maker.handle(&msg.from, cmd, chain, unix_now())));
            }
            if before >= 1 && maker.progress(&msg.from, unix_now()) > before {
                peers.insert(msg.from.clone(), route);
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
        let outgoing = maker_step(
            maker,
            client,
            chain,
            &mut peers,
            &mut limiter,
            &me,
            incoming,
        );
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

impl<R> Orderbook<R> {
    /// How to reach maker `nick`: the route its private answer came by.
    pub fn route(&self, nick: &str) -> Option<&R> {
        self.peers.get(nick)
    }
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

/// What one maker answered on one channel.
struct Answer<R> {
    route: R,
    offers: Vec<Offer>,
    /// The first `!tbond` proof made out to the nick the maker knows us by there.
    proof: Option<String>,
    /// Whether that proof stands for a real bond, once the chain was asked (only while its channel is full).
    bonded: Option<bool>,
    /// When its first line came, in order of arrival.
    arrived: u64,
}

/// The answers gathered on one channel: at most [`MAX_ANSWERING_NICKS`] nicks, a random sample of those heard
/// once there are more. Nicks cost nothing, bonds do: once the channel is full, a nick whose bond proof stands
/// up on the chain keeps its place, and a newcomer with one gets a place.
struct ChannelAnswers<R> {
    answers: HashMap<String, Answer<R>>,
    nicks_heard: u64,
    /// Whether the places have run out, and the proofs of the nicks holding them were checked.
    full: bool,
}

impl<R: Clone> ChannelAnswers<R> {
    fn new() -> ChannelAnswers<R> {
        ChannelAnswers {
            answers: HashMap::new(),
            nicks_heard: 0,
            full: false,
        }
    }

    /// The place for `nick`'s answer, if it has or gets one. `draw` is a random number; `proof` is the bond
    /// proof made out to us that `nick`'s line carries, and `real` says whether a proof stands for a real
    /// bond, asking the chain (called only once the places have run out).
    fn place(
        &mut self,
        nick: &str,
        route: &R,
        arrived: u64,
        draw: u64,
        proof: Option<&str>,
        real: &mut dyn FnMut(&str, &str) -> bool,
    ) -> Option<&mut Answer<R>> {
        if !self.answers.contains_key(nick) {
            self.nicks_heard += 1;
            let mut bonded = None;
            if self.answers.len() >= MAX_ANSWERING_NICKS {
                if !self.full {
                    self.full = true;
                    for (maker, answer) in &mut self.answers {
                        if let Some(shown) = &answer.proof {
                            answer.bonded = Some(real(maker, shown));
                        }
                    }
                }
                bonded = proof.map(|shown| real(nick, shown));
                // A nick without a real bond is sampled as before; one with a bond always gets in. Either
                // way it takes the place of a nick without one, at random.
                let at = draw % self.nicks_heard;
                if bonded != Some(true) && at >= MAX_ANSWERING_NICKS as u64 {
                    return None;
                }
                let open: Vec<&String> = self
                    .answers
                    .iter()
                    .filter(|(_, answer)| answer.bonded != Some(true))
                    .map(|(name, _)| name)
                    .collect();
                if open.is_empty() {
                    return None;
                }
                let out = open[(draw % open.len() as u64) as usize].clone();
                self.answers.remove(&out);
            }
            self.answers.insert(
                nick.to_string(),
                Answer {
                    route: route.clone(),
                    offers: Vec::new(),
                    proof: None,
                    bonded,
                    arrived,
                },
            );
        }
        self.answers.get_mut(nick)
    }
}

/// One answer per maker. Every answer kept holds an offer the taker can use; a maker heard on several channels
/// is taken from one where it showed a bond proof made out to us, if any, and then from the earliest.
fn settle<R>(channels: HashMap<usize, ChannelAnswers<R>>) -> Orderbook<R> {
    let rank = |answer: &Answer<R>| (answer.proof.is_none(), answer.arrived);
    let mut best: HashMap<String, Answer<R>> = HashMap::new();
    for (nick, answer) in channels.into_values().flat_map(|c| c.answers) {
        match best.get(&nick) {
            Some(kept) if rank(kept) <= rank(&answer) => {}
            _ => {
                best.insert(nick, answer);
            }
        }
    }
    let mut makers: Vec<(String, Answer<R>)> = best.into_iter().collect();
    makers.sort_by_key(|(_, answer)| answer.arrived);
    let mut book = Orderbook::default();
    for (nick, answer) in makers {
        book.offers
            .extend(answer.offers.into_iter().map(|offer| (nick.clone(), offer)));
        if let Some(proof) = answer.proof {
            book.proofs.insert(nick.clone(), proof);
        }
        book.peers.insert(nick, answer.route);
    }
    book
}

/// Ask for the orderbook and gather the makers' private answers for `gather`: offers and `!tbond` proofs.
/// Publicly announced offers serve only to discover makers that missed the request (it is then asked
/// again). `network` is the channel's own network name; the channel uses the one it was opened with.
pub async fn fetch_orderbook<C: Channel>(
    client: &mut C,
    network: &str,
    gather: Duration,
) -> Result<Orderbook<C::Route>, NodeError> {
    fetch_orderbook_for(client, network, gather, |_| Some(0)).await
}

/// [`fetch_orderbook`] for a taker that will only consider offers `cost` puts a price on. Only those are kept,
/// one per offer type and id, the cheapest. The command of a signed line is not signed, so anyone can show a
/// maker's lines under an offer type it never offered, or deliver an older offer first; kept, they could use up
/// the maker's place for offers before its real one came, or stand in for it at a higher fee.
pub async fn fetch_orderbook_for<C: Channel>(
    client: &mut C,
    network: &str,
    gather: Duration,
    cost: impl Fn(&Offer) -> Option<u64>,
) -> Result<Orderbook<C::Route>, NodeError> {
    fetch_orderbook_with_bonds(client, network, gather, cost, |_, _, _| false).await
}

/// [`fetch_orderbook_for`], where `bond_is_real(maker, proof, us)` says whether `maker`'s `!tbond` proof,
/// made out to the nick `us` it knows us by, stands for a real bond, by the chain. It is asked only once a
/// channel's places for answers have run out ([`MAX_ANSWERING_NICKS`]), at most [`MAX_BOND_LOOKUPS`] times in
/// all and never past the end of `gather`: from then on a nick with a real bond keeps its place and a newcomer
/// with one gets a place, so a flood of nicks, which cost nothing, cannot push a bonded maker out of the
/// taker's sample. Past those limits nicks are sampled at random again.
pub async fn fetch_orderbook_with_bonds<C: Channel>(
    client: &mut C,
    network: &str,
    gather: Duration,
    cost: impl Fn(&Offer) -> Option<u64>,
    mut bond_is_real: impl FnMut(&str, &str, &str) -> bool,
) -> Result<Orderbook<C::Route>, NodeError> {
    let _ = network;
    let gather_until = Instant::now() + gather;
    // Checking costs chain lookups, which a slow node makes slow: never more than allowed, nor past the
    // gathering's end.
    let mut lookups = 0usize;
    let mut real = |maker: &str, proof: &str, us: &str| {
        if lookups >= MAX_BOND_LOOKUPS || Instant::now() >= gather_until {
            return false;
        }
        lookups += 1;
        bond_is_real(maker, proof, us)
    };
    client.listen(true, false).await?;
    client.ask_orderbook().await?;
    let mut asked = Instant::now();
    // When to ask again, for a maker we heard of that has not answered.
    let mut ask_again: Option<Instant> = None;
    // Kept per channel until the end: what one channel delivers first cannot take a maker off another.
    let mut channels: HashMap<usize, ChannelAnswers<C::Route>> = HashMap::new();
    let mut arrived = 0u64;
    while Instant::now() < gather_until {
        if ask_again.is_some_and(|at| Instant::now() >= at) {
            ask_again = None;
            client.ask_orderbook().await?;
            asked = Instant::now();
        }
        let wake = ask_again.map_or(gather_until, |at| at.min(gather_until));
        match client
            .receive(wake.saturating_duration_since(Instant::now()))
            .await
        {
            Next::Message(Incoming::Offers { nick, .. }) => {
                // Public offers are a discovery cache (the draft): a maker that has not answered may have
                // started listening after our request, which relays do not keep. Ask again, as soon as the
                // interval since the last request allows: its offers may be the last we hear of it.
                let answered = channels.values().any(|c| c.answers.contains_key(&nick));
                if !answered && ask_again.is_none() {
                    ask_again = Some(asked + REASK_INTERVAL);
                }
            }
            Next::Message(Incoming::Private { msg, route }) => {
                let line = commands(&msg);
                let us = client.nick_on(&route).to_string();
                let answers = channels
                    .entry(client.channel_of(&route))
                    .or_insert_with(ChannelAnswers::new);
                let full = answers.full;
                let mut real_here = |maker: &str, proof: &str| real(maker, proof, &us);
                // Only a nick that answers with an offer we can use gets a place: senders of anything else
                // cannot grow the taker's state.
                let has_usable = line
                    .iter()
                    .any(|c| matches!(c, Command::Offer(offer) if cost(offer).is_some()));
                let answer = if has_usable {
                    arrived += 1;
                    let draw = u64::from_be_bytes(vortex_ng_core::tx::random_bytes::<8>());
                    let proof = line.iter().find_map(|c| match c {
                        Command::Tbond(proof) if proof_for_us(proof, &us, &msg.from) => {
                            Some(proof.as_str())
                        }
                        _ => None,
                    });
                    answers.place(&msg.from, &route, arrived, draw, proof, &mut real_here)
                } else {
                    answers.answers.get_mut(&msg.from)
                };
                let Some(answer) = answer else {
                    continue;
                };
                for cmd in line {
                    match cmd {
                        Command::Offer(offer) => {
                            let Some(price) = cost(&offer) else {
                                continue;
                            };
                            let same = answer.offers.iter().position(|known| {
                                known.oid == offer.oid && known.offer_type == offer.offer_type
                            });
                            match same {
                                Some(index) => {
                                    if cost(&answer.offers[index]).is_none_or(|old| price < old) {
                                        answer.offers[index] = offer;
                                    }
                                }
                                None if answer.offers.len() < MAX_OFFERS_PER_NICK => {
                                    answer.offers.push(offer);
                                }
                                None => {}
                            }
                        }
                        Command::Tbond(proof)
                            if answer.proof.is_none() && proof_for_us(&proof, &us, &msg.from) =>
                        {
                            // A proof that comes after the places ran out is checked as it comes.
                            if full && answer.bonded.is_none() {
                                answer.bonded = Some(real_here(&msg.from, &proof));
                            }
                            answer.proof = Some(proof);
                        }
                        _ => {}
                    }
                }
            }
            Next::Message(Incoming::Public { .. }) => {}
            // The time to ask again, or the end of the gathering: the loop sees which.
            Next::Timeout => {}
            Next::Closed => break,
        }
    }
    Ok(settle(channels))
}

/// How long the chosen makers have to answer a `!fill` with their inputs before a round allowed to go on with
/// fewer does so (reference JoinMarket's `maker_timeout_sec`). At most half the time the round has left, so
/// that the makers still have time to sign.
const MAKER_ANSWER_TIME: Duration = Duration::from_secs(60);

/// Run one CoinJoin as the taker: ask for the orderbook, gather the makers' private answers (offers and
/// `!tbond` proofs; offer events serve only to discover makers that missed the request) for `gather`,
/// verify the bonds, pick makers, run the round, and return the fully signed transaction (signed last,
/// after every maker; channel funding hooks in before `Taker::finish`).
pub async fn run_taker<C: Channel>(
    taker: &mut Taker,
    signer: &(impl InputSigner + ?Sized),
    client: &mut C,
    chain: &impl ChainLookup,
    cfg: &TakerConfig,
    gather: Duration,
    until: Instant,
) -> Result<Transaction, NodeError> {
    let network = channel_network(cfg.network);
    // Only asked once a channel's places for answers run out; the tip is read the first time.
    let mut tip: Option<Option<u32>> = None;
    let bond_is_real = |maker: &str, proof: &str, us: &str| {
        blocking(|| {
            let height = *tip.get_or_insert_with(|| chain.tip_height().ok());
            height.is_some_and(|height| {
                verify_bond(proof, us, maker, chain, height, unix_now(), cfg.bond_params)
                    .is_ok_and(|bond| bond.value > 0)
            })
        })
    };
    let Orderbook {
        offers,
        proofs,
        peers,
    } = fetch_orderbook_with_bonds(
        client,
        network,
        gather,
        |offer| usable_fee(offer, cfg),
        bond_is_real,
    )
    .await?;
    let candidates = candidate_nicks(&offers, cfg);
    // Each maker made its proof out to the nick it knows us by, on the channel it answered on.
    let me = |maker: &str| match peers.get(maker) {
        Some(route) => client.nick_on(route).to_string(),
        None => client.nick().to_string(),
    };
    let bonds = blocking(|| verify_bonds(&proofs, &candidates, me, chain, unix_now(), cfg));
    let chosen = select_makers(&offers, &bonds, cfg);
    let in_round: HashSet<String> = chosen.iter().map(|(nick, _)| nick.clone()).collect();
    // Where a channel can reach a chosen maker more directly, it gets ready before the first line goes.
    let ready: Vec<(String, C::Route)> = chosen
        .iter()
        .filter_map(|(nick, _)| Some((nick.clone(), peers.get(nick)?.clone())))
        .collect();
    client.prepare(&ready).await;
    // One at a time: if a `!fill` cannot go the round is over, and the makers after it need not hear of it.
    for fill in taker.start(chosen).map_err(NodeError::Taker)? {
        deliver(client, &peers, chain, vec![fill]).await?;
    }
    let now = Instant::now();
    let answer_by = now + MAKER_ANSWER_TIME.min(until.saturating_duration_since(now) / 2);
    while let Some(left) = until.checked_duration_since(Instant::now()) {
        // Wake up for the answer time while it is still ahead.
        let wait = match answer_by.checked_duration_since(Instant::now()) {
            Some(to_answer) if !to_answer.is_zero() => left.min(to_answer),
            _ => left,
        };
        match client.receive(wait).await {
            // Anyone who can reach our nick can write to us: only the round's makers are heard, so an outsider
            // cannot abort the round.
            Next::Message(Incoming::Private { msg, route }) if in_round.contains(&msg.from) => {
                // The route stays the one the maker answered the orderbook on: a line delivered again through
                // another directory or channel must not move the round's replies there.
                for cmd in commands(&msg) {
                    // Where anyone could have delivered it, a lone `!error` says nothing about the maker: the
                    // round's deadline decides.
                    if matches!(cmd, Command::Error(_)) && !client.authenticates(&route) {
                        continue;
                    }
                    let (outgoing, progress) = blocking(|| taker.handle(&msg.from, cmd, chain))
                        .map_err(NodeError::Taker)?;
                    // A line that could not go (a full queue, say) does not end the round: the deadline does.
                    let _ = deliver(client, &peers, chain, outgoing).await;
                    if progress == Progress::MakersSigned {
                        return blocking(|| taker.finish(signer)).map_err(NodeError::Taker);
                    }
                }
            }
            Next::Closed => {
                return Err(NodeError::Channel(ChannelError::Transport(
                    "every channel closed during the round".into(),
                )));
            }
            _ => {}
        }
        if Instant::now() >= answer_by {
            let outgoing =
                blocking(|| taker.go_on_without_silent(chain)).map_err(NodeError::Taker)?;
            let _ = deliver(client, &peers, chain, outgoing).await;
        }
    }
    Err(NodeError::Timeout)
}

#[cfg(test)]
mod tests;
