//! The JoinMarket maker, as a state machine with no I/O.
//!
//! The transport (`vortex-ng-nostr`) verifies each private message line and hands the maker its sender's
//! nick and commands; the maker returns [`Outgoing`] messages for the transport to sign and wrap. Per
//! taker nick a session moves `!fill` → `!pubkey`, `!auth` → `!ioauth` (+ an `!hp2` broadcast),
//! `!tx` → one `!sig` per input, as JMP-0001 specifies, in the maker's pit (`sw0`, `tr0` or `wsh0`).
//! On any failure the session is dropped and a fixed, uninformative `!error` is returned.

use std::collections::{BTreeMap, HashMap, HashSet};

pub use vortex_ng_chain::ChainLookup as Chain;
use vortex_ng_core::bitcoin::base64::Engine;
use vortex_ng_core::bitcoin::base64::engine::general_purpose::STANDARD;
use vortex_ng_core::bitcoin::consensus::encode::deserialize;
use vortex_ng_core::bitcoin::hex::DisplayHex;
use vortex_ng_core::bitcoin::secp256k1::{PublicKey, Secp256k1};
use vortex_ng_core::bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use vortex_ng_core::bond::{BondTemplate, BondValueParams, bond_value};
use vortex_ng_core::command::Command;
pub use vortex_ng_core::command::Outgoing;
use vortex_ng_core::nacl::{NaclKeypair, Session};
use vortex_ng_core::offer::{Offer, Pit};
use vortex_ng_core::podle::{DEFAULT_INDICES, Podle};
use vortex_ng_core::protocol::MAKER_CHANGE_THRESHOLD_SAT;
use vortex_ng_core::sigmsg;
use vortex_ng_core::tx::{ChainView as TxChainView, MakerTerms, verify_unsigned};
use vortex_ng_wallet::{MIXDEPTHS, PitWallet};

/// Maker policy. Defaults follow the deployed JoinMarket implementations.
#[derive(Clone, Debug)]
pub struct MakerConfig {
    /// Our offers, all of the wallet's pit.
    pub offers: Vec<Offer>,
    /// NUMS indices we accept for the taker's PoDLE.
    pub podle_indices: Vec<u8>,
    /// Confirmations the taker's committed UTXO needs (`taker_utxo_age`).
    pub taker_utxo_age: u32,
    /// Minimum value of the taker's committed UTXO, percent of the amount (`taker_utxo_amtpercent`).
    pub taker_utxo_amtpercent: u64,
    /// The bond value formula's parameters, for choosing which of our bonds to prove.
    pub bond_params: BondValueParams,
}

impl MakerConfig {
    /// A config for `offers` with the deployed defaults (indices 0..=2, 5 confirmations, 20 %).
    pub fn new(offers: Vec<Offer>) -> MakerConfig {
        MakerConfig {
            offers,
            podle_indices: DEFAULT_INDICES.to_vec(),
            taker_utxo_age: 5,
            taker_utxo_amtpercent: 20,
            bond_params: BondValueParams::default(),
        }
    }
}

/// How a commitment came to be known as used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seen {
    /// This maker verified it, then showed its coins.
    Verified,
    /// Someone announced it (`!hp2`); nothing proves it was used.
    Announced,
}

/// Where a maker keeps the PoDLE commitments it has seen used, so that a restarted maker still refuses them
/// (issue #52). The maker does no I/O itself: the keeper does, called as each commitment is first seen.
pub trait CommitmentKeeper: Send {
    /// Keep `commitment`. A [`Seen::Verified`] one must be durable when this returns: the maker shows its
    /// coins next, and does not when this fails.
    fn keep(&mut self, seen: Seen, commitment: &[u8; 32]) -> Result<(), String>;
    /// Whether the store has grown enough that it should be rewritten from what the maker remembers.
    fn wants_rewrite(&self) -> bool;
    /// Replace what is kept with `remembered`, oldest first.
    fn rewrite(&mut self, remembered: &[(Seen, [u8; 32])]) -> Result<(), String>;
}

/// What a maker shares its wallet through with other users of it, such as a joinstr pool round run by
/// another process (issue #51): a coin one of them holds is never offered by another, and an address is
/// handed out once. The maker does no I/O itself; the implementation does, on each call.
pub trait WalletClaims: Send {
    /// The coins held by someone else now.
    fn held_elsewhere(&self) -> Result<HashSet<OutPoint>, String>;
    /// Hold `coins` for this maker for `seconds`. `Ok(false)`, and nothing held, if one of them is held
    /// elsewhere already.
    fn hold(&self, coins: &[OutPoint], seconds: u64) -> Result<bool, String>;
    /// The next address of `wallet`'s mixdepth `mixdepth` (its change chain when `change`) that no other user
    /// of the wallet has been given, now taken for good: `wallet` is moved past what others took.
    fn fresh_address(
        &self,
        wallet: &mut PitWallet,
        mixdepth: u32,
        change: bool,
    ) -> Result<vortex_ng_core::bitcoin::Address, String>;
}

/// Why the maker dropped a session, or did nothing. Only a fixed `!error` reaches the taker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MakerError {
    /// A line that verifies but does not belong to the session as it stands: a duplicate, a line from
    /// another exchange, one out of order, or an encrypted line that does not decrypt with the session's
    /// key. It is ignored: the session is kept as it was and nothing is sent (ADR 0007: on channels where a
    /// directory or server forwards lines, anyone who saw a line can deliver it again).
    Stray(&'static str),
    /// A message out of order, or for an unknown session.
    State(&'static str),
    /// The fill is not for one of our offers, or out of range.
    Offer(&'static str),
    /// The PoDLE or its UTXO was refused.
    Podle(String),
    /// We cannot fund the amount.
    Liquidity,
    /// The proposed transaction was refused (`vortex_ng_core::tx`).
    Tx(String),
    /// Decryption, chain or wallet failure.
    Internal(String),
}

impl std::fmt::Display for MakerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "maker refused: {self:?}")
    }
}

impl std::error::Error for MakerError {}

struct Filled {
    offer: Offer,
    amount: u64,
    commitment: [u8; 32],
    /// The taker's NaCl public key, hex, as its `!fill` gave it.
    taker_nacl: String,
    /// Our NaCl public key for this session, hex, as sent in `!pubkey`.
    our_nacl: String,
    /// How many times the same `!fill` was answered again (at most [`MAX_FILL_REPEATS`]).
    repeats: u8,
    session: Session,
}

struct Authed {
    filled: Filled,
    mixdepth: u32,
    our_utxos: BTreeMap<OutPoint, TxOut>,
    cj_script: ScriptBuf,
    change_script: ScriptBuf,
    cjfee: u64,
}

enum Stage {
    Filled(Filled),
    Authed(Box<Authed>),
    Signed(Txid),
}

impl Stage {
    /// Seconds a session at this stage may be open, counted from its `!fill`.
    fn time_limit(&self) -> u64 {
        match self {
            Stage::Filled(_) => FILLED_TTL,
            _ => SESSION_TTL,
        }
    }
}

/// A maker for one pit.
pub struct Maker {
    config: MakerConfig,
    wallet: PitWallet,
    sessions: HashMap<String, Stage>,
    /// When each session's `!fill` arrived.
    started: HashMap<String, u64>,
    /// The second sessions past their time were last forgotten: within one second there is nothing new to
    /// forget, and a flood of commands must not pay for a walk over the whole table each.
    pruned_at: Option<u64>,
    used_commitments: Commitments,
    /// Where seen commitments are kept beyond this process, if anywhere.
    keeper: Option<Box<dyn CommitmentKeeper>>,
    /// Who else uses the wallet, if anyone.
    claims: Option<Box<dyn WalletClaims>>,
    /// When we announced commitments handed to us privately, within the last window.
    hp2_relayed: std::collections::VecDeque<u64>,
    bond: Option<BondTemplate>,
}

impl std::fmt::Debug for Maker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Maker")
            .field("pit", &self.wallet.pit())
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

/// Most sessions a maker keeps open past `!auth`, each of which proved a coin; further ones are refused until
/// some end.
pub const MAX_SESSIONS: usize = 64;
/// Most times one session's `!fill`, arriving again, is answered again.
const MAX_FILL_REPEATS: u8 = 3;
/// Most sessions waiting for their `!auth`. A `!fill` costs its sender nothing, so these have a table of their
/// own, large enough that a burst of them does not push out a real taker between its `!fill` and its `!auth`.
pub const MAX_WAITING_SESSIONS: usize = 4_096;
/// Seconds a session may take from `!fill` to the end, signed rounds waiting for a `!push` included
/// (joinmarket-ng's `session_timeout_sec` default). Older sessions are forgotten, so quiet takers and
/// finished rounds cannot fill the table.
pub const SESSION_TTL: u64 = 300;
/// Seconds a session may wait between `!fill` and a valid `!auth`. A `!fill` proves nothing yet, so it must
/// not hold a place for long, and when their table is full a random such session gives way to a new one.
pub const FILLED_TTL: u64 = 60;

/// Most PoDLE commitments remembered as used, of each kind (see [`Commitments`]); the oldest are forgotten
/// first. Anyone can announce commitments, so the list must not grow without end.
pub const MAX_COMMITMENTS: usize = 100_000;
/// Commitments handed to us privately that we announce in [`HP2_RELAY_WINDOW`] seconds, at most. Each one
/// costs a throwaway nick's connections.
pub const HP2_RELAYS_PER_WINDOW: usize = 10;
/// See [`HP2_RELAYS_PER_WINDOW`].
pub const HP2_RELAY_WINDOW: u64 = 600;

/// A set of commitments, bounded: the oldest are forgotten first.
#[derive(Default)]
struct BoundedCommitments {
    seen: HashSet<[u8; 32]>,
    order: std::collections::VecDeque<[u8; 32]>,
}

impl BoundedCommitments {
    /// Remember `commitment`; whether it was new.
    fn insert(&mut self, commitment: [u8; 32]) -> bool {
        if !self.seen.insert(commitment) {
            return false;
        }
        self.order.push_back(commitment);
        while self.order.len() > MAX_COMMITMENTS {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        true
    }
}

/// PoDLE commitments seen used. The ones this maker verified itself, after which it showed its coins, are
/// kept apart from the ones merely announced by others (`!hp2`, unsigned and free to send), so a flood of
/// announcements cannot push a verified commitment out and let it be used again to see the coins twice.
#[derive(Default)]
struct Commitments {
    verified: BoundedCommitments,
    announced: BoundedCommitments,
}

impl Commitments {
    fn contains(&self, commitment: &[u8; 32]) -> bool {
        self.verified.seen.contains(commitment) || self.announced.seen.contains(commitment)
    }

    /// Remember a commitment someone announced; whether it was new.
    fn insert(&mut self, commitment: [u8; 32]) -> bool {
        !self.verified.seen.contains(&commitment) && self.announced.insert(commitment)
    }

    /// Remember a commitment this maker verified.
    fn insert_verified(&mut self, commitment: [u8; 32]) {
        self.verified.insert(commitment);
    }

    /// Everything remembered, oldest first: the verified ones, then the announced ones.
    fn remembered(&self) -> Vec<(Seen, [u8; 32])> {
        let verified = self.verified.order.iter().map(|c| (Seen::Verified, *c));
        let announced = self.announced.order.iter().map(|c| (Seen::Announced, *c));
        verified.chain(announced).collect()
    }
}

/// Most of our UTXOs looked up on the node while picking coins for one fill.
pub const MAX_SELECT_LOOKUPS: usize = 64;

/// The fixed error text a refused taker sees.
pub const ERROR_TEXT: &str = "coinjoin refused";

impl Maker {
    /// A maker for `wallet`'s pit with `config`.
    pub fn new(config: MakerConfig, wallet: PitWallet) -> Result<Maker, MakerError> {
        if config
            .offers
            .iter()
            .any(|o| o.offer_type.pit != wallet.pit())
        {
            return Err(MakerError::Offer("offers must be of the wallet's pit"));
        }
        Ok(Maker {
            config,
            wallet,
            sessions: HashMap::new(),
            started: HashMap::new(),
            pruned_at: None,
            used_commitments: Commitments::default(),
            keeper: None,
            claims: None,
            hp2_relayed: std::collections::VecDeque::new(),
            bond: None,
        })
    }

    /// Our offers.
    pub fn offers(&self) -> &[Offer] {
        &self.config.offers
    }

    /// The wallet (for syncing and addresses).
    pub fn wallet_mut(&mut self) -> &mut PitWallet {
        &mut self.wallet
    }

    /// Record a commitment another maker broadcast (`!hp2`).
    pub fn on_hp2(&mut self, commitment: [u8; 32]) {
        if self.used_commitments.insert(commitment) {
            self.keep_announced(&commitment);
        }
    }

    /// Remember `remembered` (what `keeper` holds from earlier runs, oldest first), and from now on hand
    /// `keeper` every commitment seen used for the first time.
    pub fn keep_commitments(
        &mut self,
        remembered: impl IntoIterator<Item = (Seen, [u8; 32])>,
        keeper: Box<dyn CommitmentKeeper>,
    ) {
        for (seen, commitment) in remembered {
            match seen {
                Seen::Verified => self.used_commitments.insert_verified(commitment),
                Seen::Announced => {
                    self.used_commitments.insert(commitment);
                }
            }
        }
        self.keeper = Some(keeper);
        self.rewrite_if_wanted();
    }

    /// Share the wallet with other users of it through `claims`: from now on the maker offers and spends only
    /// coins nobody else holds, holds the coins it shows a taker, and takes every address it hands out.
    pub fn share_wallet(&mut self, claims: Box<dyn WalletClaims>) {
        self.claims = Some(claims);
    }

    /// The coins held by other users of the wallet: none when it is not shared.
    fn held_elsewhere(&self) -> Result<HashSet<OutPoint>, MakerError> {
        match &self.claims {
            Some(claims) => claims.held_elsewhere().map_err(MakerError::Internal),
            None => Ok(HashSet::new()),
        }
    }

    /// The next address of `mixdepth`'s receiving or change chain, one no other user of the wallet was given.
    fn fresh_address(
        &mut self,
        mixdepth: u32,
        change: bool,
    ) -> Result<vortex_ng_core::bitcoin::Address, MakerError> {
        match &self.claims {
            Some(claims) => claims
                .fresh_address(&mut self.wallet, mixdepth, change)
                .map_err(MakerError::Internal),
            None => {
                let address = if change {
                    self.wallet.next_change_address(mixdepth)
                } else {
                    self.wallet.next_receive_address(mixdepth)
                };
                address.map_err(|e| MakerError::Internal(e.to_string()))
            }
        }
    }

    /// How many commitments are remembered as used: verified, announced.
    pub fn remembered_commitments(&self) -> (usize, usize) {
        (
            self.used_commitments.verified.seen.len(),
            self.used_commitments.announced.seen.len(),
        )
    }

    /// Hand an announced commitment to the keeper. Losing one costs little, so a failure is let go.
    fn keep_announced(&mut self, commitment: &[u8; 32]) {
        if let Some(keeper) = self.keeper.as_mut() {
            let _ = keeper.keep(Seen::Announced, commitment);
        }
        self.rewrite_if_wanted();
    }

    /// Rewrite the keeper's store from what is remembered, when it asks. A failure leaves the store as it
    /// was, only larger; the keeper decides when to try again.
    fn rewrite_if_wanted(&mut self) {
        if let Some(keeper) = self.keeper.as_mut()
            && keeper.wants_rewrite()
        {
            let _ = keeper.rewrite(&self.used_commitments.remembered());
        }
    }

    /// A commitment another maker handed to us privately to announce (joinmarket-clientserver's way on IRC:
    /// the maker in the round passes it to a random other maker, so the announcer is not the one being
    /// filled). Recorded; announced unlinked from our nick if it is new and we have announced fewer than
    /// [`HP2_RELAYS_PER_WINDOW`] such in the last [`HP2_RELAY_WINDOW`] seconds.
    fn on_private_hp2(&mut self, commitment: [u8; 32], now: u64) -> Vec<Outgoing> {
        if !self.used_commitments.insert(commitment) {
            return Vec::new();
        }
        self.keep_announced(&commitment);
        while self
            .hp2_relayed
            .front()
            .is_some_and(|at| now.saturating_sub(*at) >= HP2_RELAY_WINDOW)
        {
            self.hp2_relayed.pop_front();
        }
        if self.hp2_relayed.len() >= HP2_RELAYS_PER_WINDOW {
            return Vec::new();
        }
        self.hp2_relayed.push_back(now);
        vec![Outgoing::PublicEphemeral(format!(
            "!hp2 {}",
            commitment.to_lower_hex_string()
        ))]
    }

    /// Pick the wallet's most valuable fidelity bond and certify it for `!tbond` proofs (JMP-0001 "Fidelity
    /// Bonds"; the bond with the highest value, as joinmarket's makers choose). The current certificate is
    /// kept while it stays valid and its bond stays the best one. Returns the bond's value, or `None` (and
    /// no proofs) when the wallet holds no bond worth anything at `now`.
    pub fn refresh_bond(
        &mut self,
        chain: &impl Chain,
        now: u64,
    ) -> Result<Option<u64>, MakerError> {
        let height = chain.tip_height().map_err(MakerError::Internal)?;
        let mut best: Option<(u64, vortex_ng_wallet::bonds::BondUtxo)> = None;
        for bond in self.wallet.bonds() {
            let confirmed = chain
                .block_time(bond.height)
                .map_err(MakerError::Internal)?;
            let value = bond_value(
                bond.value.to_sat(),
                u64::from(confirmed),
                u64::from(bond.locktime),
                now,
                self.config.bond_params,
            );
            if value > 0 && best.as_ref().is_none_or(|(v, _)| value > *v) {
                best = Some((value, bond));
            }
        }
        let Some((value, bond)) = best else {
            self.bond = None;
            return Ok(None);
        };
        let keep = self
            .bond
            .as_ref()
            .is_some_and(|t| t.outpoint() == bond.outpoint && t.usable_at(height));
        if !keep {
            let key = self
                .wallet
                .bond_key(bond.timenumber)
                .map_err(|e| MakerError::Internal(e.to_string()))?;
            self.bond = Some(BondTemplate::new(
                &Secp256k1::signing_only(),
                &key,
                bond.outpoint,
                bond.locktime,
                height,
            ));
        }
        Ok(Some(value))
    }

    /// Answer `!orderbook` from taker `from` to us, `me`: one private message per offer, each followed by
    /// `!tbond` with our bond's proof for that taker when we have one (as joinmarket-ng's makers send it).
    pub fn on_orderbook(&self, from: &str, me: &str) -> Vec<Outgoing> {
        let tbond = self.bond.as_ref().and_then(|t| {
            t.proof(&Secp256k1::signing_only(), from, me)
                .to_base64()
                .ok()
        });
        self.config
            .offers
            .iter()
            .filter_map(|offer| {
                let line = offer.to_command();
                let (command, args) = line.trim_start_matches('!').split_once(' ')?;
                let mut body = args.to_string();
                if let Some(proof) = &tbond {
                    body.push_str("!tbond ");
                    body.push_str(proof);
                }
                Some(Outgoing::Private {
                    to: from.to_string(),
                    command: command.to_string(),
                    body,
                })
            })
            .collect()
    }

    /// Handle one verified command from taker `from`. A refusal drops the session and answers `!error`; a
    /// stray line (see [`MakerError::Stray`]) is ignored.
    pub fn handle(
        &mut self,
        from: &str,
        command: Command,
        chain: &impl Chain,
        now: u64,
    ) -> Vec<Outgoing> {
        // Forget sessions past their time before anything else, so they never count against the cap.
        if self.pruned_at != Some(now) {
            self.pruned_at = Some(now);
            let (sessions, started) = (&mut self.sessions, &mut self.started);
            sessions.retain(|nick, stage| {
                started
                    .get(nick)
                    .is_some_and(|at| now.saturating_sub(*at) <= stage.time_limit())
            });
            started.retain(|nick, _| sessions.contains_key(nick));
        }
        let result = match command {
            // `!orderbook` is a public command (JMP-0001); the transport answers it with `on_orderbook`.
            Command::Orderbook => return Vec::new(),
            Command::Push(tx) => return self.on_push(from, &tx),
            Command::Hp2(c) => return self.on_private_hp2(c, now),
            Command::Fill {
                oid,
                amount,
                nacl_pubkey,
                commitment,
            } => self.on_fill(from, oid, amount, &nacl_pubkey, commitment),
            Command::Encrypted { name, ciphertext } if name == "auth" => {
                self.on_auth(from, &ciphertext, chain)
            }
            Command::Encrypted { name, ciphertext } if name == "tx" => {
                self.on_tx(from, &ciphertext, chain, now)
            }
            _ => Err(MakerError::Stray("not a command a maker answers here")),
        };
        if self.sessions.contains_key(from) {
            self.started.entry(from.to_string()).or_insert(now);
        }
        match result {
            Ok(out) => out,
            Err(MakerError::Stray(_)) => Vec::new(),
            Err(_) => {
                self.sessions.remove(from);
                self.started.remove(from);
                vec![Outgoing::Private {
                    to: from.to_string(),
                    command: "error".into(),
                    body: ERROR_TEXT.into(),
                }]
            }
        }
    }

    fn on_fill(
        &mut self,
        from: &str,
        oid: u64,
        amount: u64,
        taker_nacl: &str,
        commitment: [u8; 32],
    ) -> Result<Vec<Outgoing>, MakerError> {
        if let Some(stage) = self.sessions.get_mut(from) {
            // The taker's own `!fill` again, another way: joinmarket-clientserver's taker sends it through a
            // directory and connects directly meanwhile, and anyone who saw it can deliver it again. While the
            // session waits for `!auth`, the same `!fill` gets the same answer, wherever it came from: the
            // `!pubkey` is public, and only the taker can use it. A few times only, so copies cannot draw a
            // stream of answers. Anything else is stray.
            return match stage {
                Stage::Filled(filled)
                    if filled.offer.oid == oid
                        && filled.amount == amount
                        && filled.taker_nacl == taker_nacl
                        && filled.commitment == commitment
                        && filled.repeats < MAX_FILL_REPEATS =>
                {
                    filled.repeats += 1;
                    Ok(vec![Outgoing::Private {
                        to: from.to_string(),
                        command: "pubkey".into(),
                        body: filled.our_nacl.clone(),
                    }])
                }
                _ => Err(MakerError::Stray("session exists")),
            };
        }
        let offer = self
            .config
            .offers
            .iter()
            .find(|o| o.oid == oid)
            .cloned()
            .ok_or(MakerError::Offer("unknown oid"))?;
        let cjfee = offer
            .fee_for(amount)
            .ok_or(MakerError::Offer("amount out of range"))?;
        // Refuse before the taker spends a PoDLE commitment on a round we would not sign.
        if cjfee < offer.txfee {
            return Err(MakerError::Offer("unprofitable at this amount"));
        }
        if self.used_commitments.contains(&commitment) {
            return Err(MakerError::Podle("commitment already used".into()));
        }
        // One commitment, one session: a copy under another nick would see our coins on the same proof.
        if self
            .sessions
            .values()
            .any(|stage| matches!(stage, Stage::Filled(f) if f.commitment == commitment))
        {
            return Err(MakerError::Stray("commitment held by another session"));
        }
        self.make_room();
        let ours = NaclKeypair::generate();
        let session = ours
            .session(taker_nacl)
            .map_err(|e| MakerError::Internal(e.to_string()))?;
        let reply = Outgoing::Private {
            to: from.to_string(),
            command: "pubkey".into(),
            body: ours.public_hex(),
        };
        self.sessions.insert(
            from.to_string(),
            Stage::Filled(Filled {
                offer,
                amount,
                commitment,
                taker_nacl: taker_nacl.to_string(),
                our_nacl: ours.public_hex(),
                repeats: 0,
                session,
            }),
        );
        Ok(vec![reply])
    }

    /// Room for one more session waiting for its `!auth`: when their table is full, a random one gives way, so
    /// a burst of fills cannot aim at the real taker among them. Sessions past `!auth` are never pushed out.
    fn make_room(&mut self) {
        let waiting = |stage: &&Stage| matches!(stage, Stage::Filled(_));
        let count = self.sessions.values().filter(waiting).count();
        if count < MAX_WAITING_SESSIONS {
            return;
        }
        let draw = u32::from_be_bytes(vortex_ng_core::tx::random_bytes::<4>()) as usize;
        let chosen = self
            .sessions
            .iter()
            .filter(|(_, stage)| matches!(stage, Stage::Filled(_)))
            .nth(draw % count)
            .map(|(nick, _)| nick.clone());
        if let Some(nick) = chosen {
            self.sessions.remove(&nick);
            self.started.remove(&nick);
        }
    }

    /// Whether `nick` has a session open at `now`.
    pub fn in_session(&self, nick: &str, now: u64) -> bool {
        self.progress(nick, now) > 0
    }

    /// How far `nick`'s session has come at `now`: 0 none, 1 its `!fill` answered, 2 its `!auth` answered,
    /// 3 its `!tx` signed. Past 1 it moves only on a line encrypted for the session, which only the taker
    /// could have written; a line delivered again, relabelled or not for this session leaves it where it is.
    /// So where such a line came from is where the taker is (the driver sends the rest of the round there).
    pub fn progress(&self, nick: &str, now: u64) -> u8 {
        let Some(stage) = self.sessions.get(nick) else {
            return 0;
        };
        let open = self
            .started
            .get(nick)
            .is_some_and(|at| now.saturating_sub(*at) <= stage.time_limit());
        match stage {
            _ if !open => 0,
            Stage::Filled(_) => 1,
            Stage::Authed(_) => 2,
            Stage::Signed(_) => 3,
        }
    }

    fn on_auth(
        &mut self,
        from: &str,
        ciphertext: &str,
        chain: &impl Chain,
    ) -> Result<Vec<Outgoing>, MakerError> {
        // Only a line encrypted for this session counts; anything else leaves the session as it is.
        let revelation = match self.sessions.get(from) {
            Some(Stage::Filled(filled)) => filled
                .session
                .decrypt(ciphertext)
                .map_err(|_| MakerError::Stray("auth not for this session"))?,
            _ => return Err(MakerError::Stray("auth out of place")),
        };
        // The command is not signed: another step's line, relabelled, also decrypts. Only a line that reads
        // as this step's may end the session.
        let podle = Podle::parse_revelation(&revelation)
            .map_err(|_| MakerError::Stray("auth is not a revelation"))?;
        let past_auth = self
            .sessions
            .values()
            .filter(|stage| !matches!(stage, Stage::Filled(_)))
            .count();
        if past_auth >= MAX_SESSIONS {
            return Err(MakerError::State("too many open sessions"));
        }
        let Some(Stage::Filled(filled)) = self.sessions.remove(from) else {
            return Err(MakerError::Stray("auth out of place"));
        };
        // A commitment shows our coins once. Only the ones we verified count here: one merely announced may
        // be this very round's, from another of its makers.
        if self
            .used_commitments
            .verified
            .seen
            .contains(&filled.commitment)
        {
            return Err(MakerError::Podle("commitment already used".into()));
        }
        let secp = Secp256k1::new();
        podle
            .verify(&secp, &filled.commitment, &self.config.podle_indices)
            .map_err(|e| MakerError::Podle(e.to_string()))?;
        let outpoint = podle
            .outpoint()
            .map_err(|e| MakerError::Podle(e.to_string()))?;
        let utxo = chain
            .utxo(&outpoint)
            .map_err(MakerError::Internal)?
            .ok_or(MakerError::Podle("utxo not found".into()))?;
        podle
            .check_binding(&utxo.script_pubkey)
            .map_err(|e| MakerError::Podle(e.to_string()))?;
        if utxo.confirmations < self.config.taker_utxo_age {
            return Err(MakerError::Podle("utxo too young".into()));
        }
        if u128::from(utxo.value.to_sat()) * 100
            < u128::from(filled.amount) * u128::from(self.config.taker_utxo_amtpercent)
        {
            return Err(MakerError::Podle("utxo too small".into()));
        }
        // Kept before the coins are shown: a maker restarted after this must still refuse it.
        if let Some(keeper) = self.keeper.as_mut() {
            keeper
                .keep(Seen::Verified, &filled.commitment)
                .map_err(|e| MakerError::Internal(format!("the commitment was not kept: {e}")))?;
        }
        self.used_commitments.insert_verified(filled.commitment);
        self.rewrite_if_wanted();
        let commitment_hex = filled.commitment.to_lower_hex_string();

        let cjfee = filled
            .offer
            .fee_for(filled.amount)
            .ok_or(MakerError::Offer("amount out of range"))?;
        let needed =
            (filled.amount + filled.offer.txfee + MAKER_CHANGE_THRESHOLD_SAT).saturating_sub(cjfee);
        let (mixdepth, selected) = self.select(needed, chain)?;
        // Held for the session's lifetime before they are shown: another user of the wallet that holds one
        // meanwhile wins it, and this round is refused.
        if let Some(claims) = &self.claims {
            let coins: Vec<OutPoint> = selected.iter().map(|u| u.outpoint).collect();
            if !claims
                .hold(&coins, SESSION_TTL)
                .map_err(MakerError::Internal)?
            {
                return Err(MakerError::Liquidity);
            }
        }
        let cj = self.fresh_address((mixdepth + 1) % MIXDEPTHS, false)?;
        let change = self.fresh_address(mixdepth, true)?;
        let keys = self
            .wallet
            .utxo_keys(mixdepth, &selected[0])
            .map_err(|e| MakerError::Internal(e.to_string()))?;
        let auth_public = PublicKey::from_secret_key(&secp, keys.auth())
            .serialize()
            .to_lower_hex_string();
        let auth = match keys.cosigner_public() {
            Some(c) => format!("{auth_public}{}", c.serialize().to_lower_hex_string()),
            None => auth_public,
        };
        // The maker signs its OWN NaCl key (the hex it sent in `!pubkey`) with the key of one of the
        // UTXOs it declares, tying its coins to its encryption identity (reference JoinMarket
        // `on_auth_received`, joinmarket-ng `handle_auth`).
        let btc_sig = sigmsg::sign(&secp, filled.our_nacl.as_bytes(), keys.auth());
        let utxo_list: Vec<String> = selected.iter().map(|u| u.outpoint.to_string()).collect();
        let plaintext = format!("{} {auth} {cj} {change} {btc_sig}", utxo_list.join(","));
        let ciphertext = filled
            .session
            .encrypt(&plaintext)
            .map_err(|e| MakerError::Internal(e.to_string()))?;
        let our_utxos = selected
            .iter()
            .map(|u| (u.outpoint, u.txout.clone()))
            .collect();
        self.sessions.insert(
            from.to_string(),
            Stage::Authed(Box::new(Authed {
                filled,
                mixdepth,
                our_utxos,
                cj_script: cj.script_pubkey(),
                change_script: change.script_pubkey(),
                cjfee,
            })),
        );
        Ok(vec![
            Outgoing::Private {
                to: from.to_string(),
                command: "ioauth".into(),
                body: ciphertext,
            },
            Outgoing::PublicEphemeral(format!("!hp2 {commitment_hex}")),
        ])
    }

    /// Confirmed UTXOs per mixdepth that no other user of the wallet holds, largest first, with each
    /// mixdepth's total.
    fn confirmed(
        &self,
    ) -> Result<Vec<(u64, u32, Vec<vortex_ng_wallet::bdk_wallet::LocalOutput>)>, MakerError> {
        let held = self.held_elsewhere()?;
        let mut all = Vec::new();
        for m in 0..MIXDEPTHS {
            let mut utxos: Vec<_> = self
                .wallet
                .utxos(m)
                .map_err(|e| MakerError::Internal(e.to_string()))?
                .into_iter()
                .filter(|u| u.chain_position.is_confirmed() && !held.contains(&u.outpoint))
                .collect();
            utxos.sort_by_key(|u| std::cmp::Reverse(u.txout.value));
            let total = utxos.iter().map(|u| u.txout.value.to_sat()).sum();
            all.push((total, m, utxos));
        }
        Ok(all)
    }

    /// The most one round can draw on: the largest confirmed total of any one mixdepth (a round spends
    /// from a single mixdepth), less coins another user of the wallet holds. What the wallet knows, without
    /// asking the node.
    pub fn liquidity(&self) -> Result<u64, MakerError> {
        Ok(self
            .confirmed()?
            .into_iter()
            .map(|(total, _, _)| total)
            .max()
            .unwrap_or(0))
    }

    /// Replace our offers (all of the wallet's pit; none withdraws them). Sessions already filled keep the
    /// offer they were filled on.
    pub fn set_offers(&mut self, offers: Vec<Offer>) -> Result<(), MakerError> {
        if offers.iter().any(|o| o.offer_type.pit != self.wallet.pit()) {
            return Err(MakerError::Offer("offers must be of the wallet's pit"));
        }
        self.config.offers = offers;
        Ok(())
    }

    /// Pick confirmed UTXOs that cover `needed` from one mixdepth: the mixdepth with the most confirmed
    /// value first, its largest UTXOs first.
    ///
    /// A UTXO the node no longer has unspent (mempool included) is passed over. The wallet learns of a
    /// spend only when its block arrives, so a maker that has just signed a round would otherwise put the
    /// same coins into the next taker's round, which then cannot confirm. At most [`MAX_SELECT_LOOKUPS`]
    /// UTXOs are looked up per fill.
    fn select(
        &self,
        needed: u64,
        chain: &impl Chain,
    ) -> Result<(u32, Vec<vortex_ng_wallet::bdk_wallet::LocalOutput>), MakerError> {
        let mut ranked: Vec<_> = self
            .confirmed()?
            .into_iter()
            .filter(|(total, _, _)| *total >= needed)
            .collect();
        ranked.sort_by_key(|(total, _, _)| std::cmp::Reverse(*total));
        let mut lookups = 0;
        for (_, m, utxos) in ranked {
            let mut picked = Vec::new();
            let mut sum = 0u64;
            for u in utxos {
                if sum >= needed || lookups >= MAX_SELECT_LOOKUPS {
                    break;
                }
                lookups += 1;
                if !matches!(chain.utxo(&u.outpoint), Ok(Some(_))) {
                    continue;
                }
                sum += u.txout.value.to_sat();
                picked.push(u);
            }
            if sum >= needed {
                return Ok((m, picked));
            }
        }
        Err(MakerError::Liquidity)
    }

    fn on_tx(
        &mut self,
        from: &str,
        ciphertext: &str,
        chain: &impl Chain,
        now: u64,
    ) -> Result<Vec<Outgoing>, MakerError> {
        // Only a line encrypted for this session counts; anything else leaves the session as it is.
        let plaintext = match self.sessions.get(from) {
            Some(Stage::Authed(authed)) => authed
                .filled
                .session
                .decrypt(ciphertext)
                .map_err(|_| MakerError::Stray("tx not for this session"))?,
            _ => return Err(MakerError::Stray("tx out of place")),
        };
        // As in `on_auth`: a relabelled line of another step decrypts too, and must leave the session alone.
        let raw = STANDARD
            .decode(plaintext)
            .map_err(|_| MakerError::Stray("tx is not base64"))?;
        let tx: Transaction =
            deserialize(&raw).map_err(|_| MakerError::Stray("tx is not a transaction"))?;
        let Some(Stage::Authed(authed)) = self.sessions.remove(from) else {
            return Err(MakerError::Stray("tx out of place"));
        };

        let mut prevouts = Vec::with_capacity(tx.input.len());
        let mut known = BTreeMap::new();
        for input in &tx.input {
            let op = input.previous_output;
            let prevout = match authed.our_utxos.get(&op) {
                Some(o) => o.clone(),
                None => {
                    let u = chain
                        .utxo(&op)
                        .map_err(MakerError::Internal)?
                        .ok_or(MakerError::Tx("input not found".into()))?;
                    TxOut {
                        value: u.value,
                        script_pubkey: u.script_pubkey,
                    }
                }
            };
            known.insert(op, prevout.clone());
            prevouts.push(prevout);
        }
        let terms = MakerTerms {
            pit: self.wallet.pit(),
            our_utxos: &authed.our_utxos,
            cj_script: &authed.cj_script,
            change_script: &authed.change_script,
            amount: authed.filled.amount,
            cjfee: authed.cjfee,
            txfee: authed.filled.offer.txfee,
        };
        let tip = chain.tip_height().map_err(MakerError::Internal)?;
        verify_unsigned(
            &tx,
            &terms,
            &known,
            &TxChainView {
                tip_height: Some(tip),
                now,
            },
        )
        .map_err(|e| MakerError::Tx(e.to_string()))?;
        let sigs = self
            .wallet
            .sign_inputs(
                authed.mixdepth,
                &tx,
                &prevouts,
                &authed.our_utxos.keys().copied().collect::<Vec<_>>(),
            )
            .map_err(|e| MakerError::Internal(e.to_string()))?;
        if sigs.len() != authed.our_utxos.len() {
            return Err(MakerError::Internal("could not sign every input".into()));
        }
        let mut out = Vec::with_capacity(sigs.len());
        for (_, payload) in sigs {
            let body = authed
                .filled
                .session
                .encrypt(&payload)
                .map_err(|e| MakerError::Internal(e.to_string()))?;
            out.push(Outgoing::Private {
                to: from.to_string(),
                command: "sig".into(),
                body,
            });
        }
        self.sessions
            .insert(from.to_string(), Stage::Signed(tx.compute_txid()));
        Ok(out)
    }

    /// `!push <base64 tx>` from `from`: broadcast it if, and only if, it is the transaction we signed for
    /// that taker in a session still open (joinmarket-ng's rule; the reference broadcasts anything).
    /// Anything else is ignored without an answer, as on other implementations.
    fn on_push(&mut self, from: &str, tx_base64: &str) -> Vec<Outgoing> {
        let Ok(bytes) = STANDARD.decode(tx_base64) else {
            return Vec::new();
        };
        let Ok(tx) = deserialize::<Transaction>(&bytes) else {
            return Vec::new();
        };
        if !self.push_allowed(from, &tx) {
            return Vec::new();
        }
        self.sessions.remove(from);
        self.started.remove(from);
        vec![Outgoing::Broadcast(tx)]
    }

    /// Whether `tx` is the transaction we signed for `from` (a `!push` request may be honoured).
    pub fn push_allowed(&self, from: &str, tx: &Transaction) -> bool {
        matches!(self.sessions.get(from), Some(Stage::Signed(txid)) if *txid == tx.compute_txid())
    }

    /// The maker's pit.
    pub fn pit(&self) -> Pit {
        self.wallet.pit()
    }
}

#[cfg(test)]
mod tests;
