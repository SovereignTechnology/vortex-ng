//! The JoinMarket taker, as a state machine with no I/O.
//!
//! The taker picks makers from offers, sends each `!fill` with one PoDLE commitment, answers each `!pubkey`
//! with `!auth`, checks each `!ioauth` (auth signature over our NaCl key, every declared UTXO on chain and of
//! the pit's family, the auth key's binding to one of them, the addresses), builds the CoinJoin and sends
//! `!tx`, and verifies every `!sig` against its input (JMP-0001; `tr0` per JMP-0010; `wsh0` per its draft).
//! It stops at [`Progress::MakersSigned`] before signing its own inputs: that is where a Lightning channel
//! funding output gets its peer's `funding_signed` (the channel-funding draft), before [`Taker::finish`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use vortex_ng_chain::ChainLookup;
use vortex_ng_core::bitcoin::absolute::LockTime;
use vortex_ng_core::bitcoin::base64::Engine;
use vortex_ng_core::bitcoin::base64::engine::general_purpose::STANDARD;
use vortex_ng_core::bitcoin::consensus::encode::serialize;
use vortex_ng_core::bitcoin::secp256k1::{Secp256k1, SecretKey};
use vortex_ng_core::bitcoin::transaction::Version;
use vortex_ng_core::bitcoin::{
    Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use vortex_ng_core::bond::{BondProof, BondValueParams, bond_value};
use vortex_ng_core::command::{Command, Ioauth, Outgoing};
use vortex_ng_core::nacl::{NaclKeypair, Session};
use vortex_ng_core::offer::{Offer, Pit};
use vortex_ng_core::podle::{Podle, generate};
use vortex_ng_core::protocol::MAKER_CHANGE_THRESHOLD_SAT;
use vortex_ng_core::script::{taproot_output_secret, wsh0_script_pubkey};
use vortex_ng_core::sig::verify_sig;
use vortex_ng_core::sigmsg;
use vortex_ng_core::tx::{random_u64, shuffle};
use vortex_ng_wallet::PitWallet;
use vortex_ng_wallet::bdk_wallet::LocalOutput;

/// The taker discards its own change at or below this (JMP-0001).
pub const TAKER_DUST_SAT: u64 = 2_730;

/// Transaction overhead weight: version, locktime, counts, segwit marker and flag.
const OVERHEAD_WU: u64 = 42;

fn input_weight(pit: Pit) -> u64 {
    match pit {
        Pit::Sw0 => 272,
        Pit::Tr0 => 230,
        Pit::Wsh0 => 386,
    }
}

fn output_weight(pit: Pit) -> u64 {
    match pit {
        Pit::Sw0 => 124,
        Pit::Tr0 | Pit::Wsh0 => 172,
    }
}

fn in_family(pit: Pit, script: &ScriptBuf) -> bool {
    match pit {
        Pit::Sw0 => script.is_p2wpkh(),
        Pit::Tr0 => script.is_p2tr(),
        Pit::Wsh0 => script.is_p2wsh(),
    }
}

/// Taker policy for one CoinJoin.
#[derive(Clone, Debug)]
pub struct TakerConfig {
    /// The pit.
    pub pit: Pit,
    /// The network (addresses in `!ioauth` must be for it).
    pub network: Network,
    /// The CoinJoin amount.
    pub amount: u64,
    /// How many makers.
    pub makers: usize,
    /// Highest coinjoin fee accepted from one maker, satoshis.
    pub max_cjfee: u64,
    /// Mining fee rate, satoshis per 1000 weight units.
    pub fee_rate_sat_per_kwu: u64,
    /// Most inputs one maker may contribute (the taker pays their mining fee).
    pub max_maker_utxos: usize,
    /// Per-slot chance of a uniform pick among zero-fee offers instead of a bond-weighted pick
    /// (joinmarket-ng's `bondless_makers_allowance`; [`DEFAULT_BONDLESS_ALLOWANCE`]).
    pub bondless_makers_allowance: f64,
    /// Admit makers without a bond only at a zero coinjoin fee (joinmarket-ng's
    /// `bondless_require_zero_fee`, on by default there: it keeps sybils from farming fees).
    pub bondless_require_zero_fee: bool,
    /// The bond value formula's parameters.
    pub bond_params: BondValueParams,
}

/// joinmarket-ng's default `bondless_makers_allowance`.
pub const DEFAULT_BONDLESS_ALLOWANCE: f64 = 0.05;

/// A maker's fidelity bond, verified against the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedBond {
    /// The bond UTXO: one bond counts once, whichever nicks present it.
    pub outpoint: OutPoint,
    /// Its value (joinmarket's formula).
    pub value: u64,
}

/// Verify maker `maker_nick`'s `!tbond` proof to us, `taker_nick`, and value it, as JMP-0001 "Fidelity
/// Bonds" specifies: both signatures verify, the UTXO is confirmed and pays the freeze script's P2WSH, the
/// certificate has not expired at `height` (the tip, read once by the caller). The value counts from the time
/// of the block the UTXO confirmed in. Costs two chain lookups, and none when a signature fails.
pub fn verify_bond(
    proof: &str,
    taker_nick: &str,
    maker_nick: &str,
    chain: &impl ChainLookup,
    height: u32,
    now: u64,
    params: BondValueParams,
) -> Result<VerifiedBond, String> {
    let proof = BondProof::from_base64(proof).map_err(|e| e.to_string())?;
    proof
        .verify_signatures(&Secp256k1::verification_only(), taker_nick, maker_nick)
        .map_err(|e| e.to_string())?;
    let utxo = chain.utxo(&proof.outpoint)?;
    let confirmations = utxo.as_ref().map_or(0, |u| u.confirmations);
    proof
        .check_utxo(
            height,
            utxo.as_ref().map(|u| u.script_pubkey.as_script()),
            confirmations,
        )
        .map_err(|e| e.to_string())?;
    let value = utxo.map_or(0, |u| u.value.to_sat());
    let confirmed_at = height
        .checked_add(1)
        .and_then(|h| h.checked_sub(confirmations))
        .ok_or("more confirmations than blocks")?;
    let time = chain.block_time(confirmed_at)?;
    Ok(VerifiedBond {
        outpoint: proof.outpoint,
        value: bond_value(
            value,
            u64::from(time),
            u64::from(proof.locktime),
            now,
            params,
        ),
    })
}

/// The offers a taker would consider: of the pit, covering the amount within the fee limit, the cheapest per
/// nick, cheapest first.
fn ranked_offers<'a>(
    offers: &'a [(String, Offer)],
    cfg: &TakerConfig,
) -> Vec<(&'a str, u64, &'a Offer)> {
    let mut best: BTreeMap<&str, (u64, &Offer)> = BTreeMap::new();
    for (nick, offer) in offers {
        if offer.offer_type.pit != cfg.pit {
            continue;
        }
        let Some(fee) = offer.fee_for(cfg.amount) else {
            continue;
        };
        if fee > cfg.max_cjfee || fee < offer.txfee {
            continue;
        }
        let entry = best.entry(nick.as_str()).or_insert((fee, offer));
        if fee < entry.0 {
            *entry = (fee, offer);
        }
    }
    let mut ranked: Vec<(&str, u64, &Offer)> = best
        .into_iter()
        .map(|(nick, (fee, offer))| (nick, fee, offer))
        .collect();
    ranked.sort_by_key(|(_, fee, _)| *fee);
    ranked
}

/// The nicks with an offer the taker would consider. Only these are worth a bond lookup.
pub fn candidate_nicks(offers: &[(String, Offer)], cfg: &TakerConfig) -> HashSet<String> {
    ranked_offers(offers, cfg)
        .into_iter()
        .map(|(nick, _, _)| nick.to_string())
        .collect()
}

/// Pick `cfg.makers` makers from `(nick, offer)` pairs and the bonds verified for their nicks, as
/// joinmarket-ng's `choose_orders` does with `fidelity_bond_weighted_choose`: offers of the pit that cover
/// the amount within the fee limit, the cheapest per nick; one nick per bond (the cheapest); bondless makers
/// only at zero fee when `bondless_require_zero_fee`; then each slot is, with probability
/// `bondless_makers_allowance`, a uniform pick among the zero-fee offers, and otherwise a pick weighted by
/// bond value, each falling back to the other. If no more makers qualify than are wanted, all are taken.
pub fn select_makers(
    offers: &[(String, Offer)],
    bonds: &HashMap<String, VerifiedBond>,
    cfg: &TakerConfig,
) -> Vec<(String, Offer)> {
    select_makers_with(offers, bonds, cfg, &mut random_u64)
}

/// [`select_makers`] drawing its randomness from `rng`.
pub fn select_makers_with(
    offers: &[(String, Offer)],
    bonds: &HashMap<String, VerifiedBond>,
    cfg: &TakerConfig,
    rng: &mut dyn FnMut() -> u64,
) -> Vec<(String, Offer)> {
    let mut ranked = ranked_offers(offers, cfg);
    let value = |nick: &str| bonds.get(nick).map_or(0, |b| b.value);
    // A bond shown by several nicks counts once, for the cheapest of them (`ranked` is cheapest first).
    let mut seen = HashSet::new();
    ranked.retain(|(nick, _, _)| match bonds.get(*nick) {
        Some(bond) if bond.value > 0 => seen.insert(bond.outpoint),
        _ => true,
    });
    if cfg.bondless_require_zero_fee {
        ranked.retain(|(nick, _, offer)| value(nick) > 0 || offer.cjfee.is_zero());
    }
    let take = |picked: Vec<(&str, u64, &Offer)>| {
        picked
            .into_iter()
            .map(|(nick, _, offer)| (nick.to_string(), offer.clone()))
            .collect()
    };
    if ranked.len() <= cfg.makers {
        return take(ranked);
    }
    let unit = |r: u64| (r >> 11) as f64 / (1u64 << 53) as f64;
    let mut chosen = Vec::with_capacity(cfg.makers);
    for _ in 0..cfg.makers {
        let allowance_pool: Vec<usize> = (0..ranked.len())
            .filter(|&i| !cfg.bondless_require_zero_fee || ranked[i].2.cjfee.is_zero())
            .collect();
        let uniform = |rng: &mut dyn FnMut() -> u64| {
            (!allowance_pool.is_empty())
                .then(|| allowance_pool[(rng() % allowance_pool.len() as u64) as usize])
        };
        let weighted = |rng: &mut dyn FnMut() -> u64| {
            let total: f64 = ranked.iter().map(|(n, _, _)| value(n) as f64).sum();
            if total <= 0.0 {
                return None;
            }
            let target = unit(rng()) * total;
            let mut cumulative = 0.0;
            let mut last = None;
            for (i, (nick, _, _)) in ranked.iter().enumerate() {
                let v = value(nick);
                if v == 0 {
                    continue;
                }
                cumulative += v as f64;
                last = Some(i);
                if target < cumulative {
                    return Some(i);
                }
            }
            last
        };
        let pick = if unit(rng()) < cfg.bondless_makers_allowance {
            uniform(rng).or_else(|| weighted(rng))
        } else {
            weighted(rng).or_else(|| uniform(rng))
        };
        let Some(i) = pick else {
            break;
        };
        chosen.push(ranked.remove(i));
    }
    take(chosen)
}

/// The PoDLE for one of our UTXOs (`tr0` uses the BIP86 output secret, `wsh0` adds the cosigner).
pub fn podle_for(
    wallet: &PitWallet,
    m: u32,
    utxo: &LocalOutput,
    index: u8,
) -> Result<Podle, TakerError> {
    let keys = wallet
        .utxo_keys(m, utxo)
        .map_err(|e| TakerError::Internal(e.to_string()))?;
    let secp = Secp256k1::new();
    let secret: SecretKey = match wallet.pit() {
        Pit::Tr0 => taproot_output_secret(&secp, keys.auth()),
        _ => *keys.auth(),
    };
    generate(
        &secp,
        &secret,
        &utxo.outpoint.to_string(),
        index,
        keys.cosigner_public(),
    )
    .map_err(|e| TakerError::Internal(e.to_string()))
}

/// Why a round failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TakerError {
    /// A maker misbehaved or refused (its nick and why).
    Maker(String, String),
    /// We cannot build the transaction (funds, fees).
    Funds(String),
    /// Out of order, or internal.
    Internal(String),
}

impl std::fmt::Display for TakerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "taker: {self:?}")
    }
}

impl std::error::Error for TakerError {}

/// Where the round is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress {
    /// Waiting for makers.
    Waiting,
    /// Every maker input is signed; the taker may now (after a channel's `funding_signed`) call `finish`.
    MakersSigned,
}

struct MakerIo {
    utxos: Vec<(OutPoint, TxOut)>,
    cj_script: ScriptBuf,
    change_script: ScriptBuf,
}

struct MakerSlot {
    offer: Offer,
    cjfee: u64,
    session: Option<Session>,
    io: Option<MakerIo>,
}

/// A taker running one CoinJoin.
pub struct Taker {
    cfg: TakerConfig,
    nacl: NaclKeypair,
    podle: Podle,
    mixdepth: u32,
    inputs: Vec<(OutPoint, TxOut)>,
    cj_script: ScriptBuf,
    change_script: ScriptBuf,
    makers: BTreeMap<String, MakerSlot>,
    tx: Option<Transaction>,
    prevouts: Vec<TxOut>,
    witnesses: BTreeMap<usize, Witness>,
}

impl std::fmt::Debug for Taker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Taker")
            .field("pit", &self.cfg.pit)
            .field("makers", &self.makers.len())
            .finish()
    }
}

fn err(nick: &str, why: impl Into<String>) -> TakerError {
    TakerError::Maker(nick.to_string(), why.into())
}

impl Taker {
    /// A taker spending `inputs` of mixdepth `mixdepth` (`podle` commits to one of our UTXOs), paying
    /// `cfg.amount` to `cj_script` (an address of ours, or a channel funding output) and change to
    /// `change_script`.
    pub fn new(
        cfg: TakerConfig,
        mixdepth: u32,
        inputs: Vec<(OutPoint, TxOut)>,
        podle: Podle,
        cj_script: ScriptBuf,
        change_script: ScriptBuf,
    ) -> Result<Taker, TakerError> {
        if inputs.is_empty()
            || !inputs
                .iter()
                .all(|(_, o)| in_family(cfg.pit, &o.script_pubkey))
        {
            return Err(TakerError::Funds("inputs must be of the pit".into()));
        }
        if !in_family(cfg.pit, &cj_script) || !in_family(cfg.pit, &change_script) {
            return Err(TakerError::Funds("outputs must be of the pit".into()));
        }
        Ok(Taker {
            cfg,
            nacl: NaclKeypair::generate(),
            podle,
            mixdepth,
            inputs,
            cj_script,
            change_script,
            makers: BTreeMap::new(),
            tx: None,
            prevouts: Vec::new(),
            witnesses: BTreeMap::new(),
        })
    }

    /// Send `!fill` to the chosen makers.
    pub fn start(&mut self, chosen: Vec<(String, Offer)>) -> Result<Vec<Outgoing>, TakerError> {
        if chosen.len() < self.cfg.makers {
            return Err(TakerError::Funds("not enough suitable offers".into()));
        }
        let commitment = self.podle.commitment_string();
        let mut out = Vec::new();
        for (nick, offer) in chosen {
            let cjfee = offer
                .fee_for(self.cfg.amount)
                .ok_or_else(|| err(&nick, "amount out of range"))?;
            out.push(Outgoing::Private {
                to: nick.clone(),
                command: "fill".into(),
                body: format!(
                    "{} {} {} {commitment}",
                    offer.oid,
                    self.cfg.amount,
                    self.nacl.public_hex()
                ),
            });
            self.makers.insert(
                nick,
                MakerSlot {
                    offer,
                    cjfee,
                    session: None,
                    io: None,
                },
            );
        }
        Ok(out)
    }

    /// The unsigned transaction, once built (for a channel's `funding_created`).
    pub fn unsigned_tx(&self) -> Option<&Transaction> {
        self.tx.as_ref()
    }

    /// Every input's prevout, in order, once the transaction is built.
    pub fn prevouts(&self) -> &[TxOut] {
        &self.prevouts
    }

    /// Handle a verified command from maker `from`.
    pub fn handle(
        &mut self,
        from: &str,
        command: Command,
        chain: &impl ChainLookup,
    ) -> Result<(Vec<Outgoing>, Progress), TakerError> {
        if !self.makers.contains_key(from) {
            return Err(err(from, "not one of our makers"));
        }
        match command {
            Command::Pubkey { nacl_pubkey, .. } => self.on_pubkey(from, &nacl_pubkey),
            Command::Encrypted { name, ciphertext } if name == "ioauth" => {
                self.on_ioauth(from, &ciphertext, chain)
            }
            Command::Encrypted { name, ciphertext } if name == "sig" => {
                self.on_sig(from, &ciphertext)
            }
            Command::Error(e) => Err(err(
                from,
                format!(
                    "maker error: {}",
                    e.chars()
                        .filter(|c| c.is_ascii_graphic() || *c == ' ')
                        .take(80)
                        .collect::<String>()
                ),
            )),
            _ => Err(err(from, "unexpected command")),
        }
    }

    fn on_pubkey(
        &mut self,
        from: &str,
        maker_nacl: &str,
    ) -> Result<(Vec<Outgoing>, Progress), TakerError> {
        let revelation = self.podle.revelation();
        let slot = self
            .makers
            .get_mut(from)
            .ok_or_else(|| err(from, "unknown"))?;
        if slot.session.is_some() {
            return Err(err(from, "second !pubkey"));
        }
        let session = self
            .nacl
            .session(maker_nacl)
            .map_err(|e| err(from, e.to_string()))?;
        let body = session
            .encrypt(&revelation)
            .map_err(|e| err(from, e.to_string()))?;
        slot.session = Some(session);
        Ok((
            vec![Outgoing::Private {
                to: from.to_string(),
                command: "auth".into(),
                body,
            }],
            Progress::Waiting,
        ))
    }

    fn address_script(&self, from: &str, address: &str) -> Result<ScriptBuf, TakerError> {
        let address: Address = address
            .parse::<Address<vortex_ng_core::bitcoin::address::NetworkUnchecked>>()
            .map_err(|_| err(from, "bad address"))?
            .require_network(self.cfg.network)
            .map_err(|_| err(from, "address for another network"))?;
        let script = address.script_pubkey();
        if !in_family(self.cfg.pit, &script) {
            return Err(err(from, "address not of the pit's type"));
        }
        Ok(script)
    }

    fn on_ioauth(
        &mut self,
        from: &str,
        ciphertext: &str,
        chain: &impl ChainLookup,
    ) -> Result<(Vec<Outgoing>, Progress), TakerError> {
        let secp = Secp256k1::new();
        let pit = self.cfg.pit;
        let our_nacl = self.nacl.public_hex();
        let (plaintext, already) = {
            let slot = self.makers.get(from).ok_or_else(|| err(from, "unknown"))?;
            let session = slot
                .session
                .as_ref()
                .ok_or_else(|| err(from, "!ioauth before !pubkey"))?;
            (
                session
                    .decrypt(ciphertext)
                    .map_err(|e| err(from, e.to_string()))?,
                slot.io.is_some(),
            )
        };
        if already {
            return Err(err(from, "second !ioauth"));
        }
        let io = Ioauth::parse(&plaintext).ok_or_else(|| err(from, "malformed !ioauth"))?;
        if io.utxos.len() > self.cfg.max_maker_utxos {
            return Err(err(from, "too many inputs"));
        }
        if !sigmsg::verify(
            &secp,
            our_nacl.as_bytes(),
            &io.btc_signature,
            &io.auth_pubkey,
        ) {
            return Err(err(from, "auth signature"));
        }
        // Every declared UTXO: unique in the round, on chain, confirmed, of the pit's family.
        let mut seen: BTreeSet<OutPoint> = self.inputs.iter().map(|(o, _)| *o).collect();
        for slot in self.makers.values() {
            if let Some(other) = &slot.io {
                seen.extend(other.utxos.iter().map(|(o, _)| *o));
            }
        }
        let mut utxos = Vec::with_capacity(io.utxos.len());
        for op in &io.utxos {
            if !seen.insert(*op) {
                return Err(err(from, "duplicate input"));
            }
            let u = chain
                .utxo(op)
                .map_err(TakerError::Internal)?
                .ok_or_else(|| err(from, "input not found"))?;
            if u.confirmations == 0 || !in_family(pit, &u.script_pubkey) {
                return Err(err(from, "input unconfirmed or of another type"));
            }
            utxos.push((
                *op,
                TxOut {
                    value: u.value,
                    script_pubkey: u.script_pubkey,
                },
            ));
        }
        // The auth key controls one of them.
        let auth_spk = match (pit, io.auth_cosigner) {
            (Pit::Sw0, None) => {
                ScriptBuf::new_p2wpkh(&CompressedPublicKey(io.auth_pubkey).wpubkey_hash())
            }
            (Pit::Tr0, None) => {
                let (internal, _) = io.auth_pubkey.x_only_public_key();
                ScriptBuf::new_p2tr(&secp, internal, None)
            }
            (Pit::Wsh0, Some(c)) => {
                wsh0_script_pubkey(&io.auth_pubkey, &c).ok_or_else(|| err(from, "auth keys"))?
            }
            _ => return Err(err(from, "auth key form")),
        };
        if !utxos.iter().any(|(_, o)| o.script_pubkey == auth_spk) {
            return Err(err(from, "auth key controls no declared input"));
        }
        let cj_script = self.address_script(from, &io.cj_address)?;
        let change_script = self.address_script(from, &io.change_address)?;
        if cj_script == change_script {
            return Err(err(from, "same coinjoin and change address"));
        }
        // No script may appear twice in the round (address reuse would link outputs).
        let mut taken = vec![&self.cj_script, &self.change_script];
        for slot in self.makers.values() {
            if let Some(other) = &slot.io {
                taken.push(&other.cj_script);
                taken.push(&other.change_script);
            }
        }
        if taken.contains(&&cj_script) || taken.contains(&&change_script) {
            return Err(err(from, "address already used in this round"));
        }
        let slot = self
            .makers
            .get_mut(from)
            .ok_or_else(|| err(from, "unknown"))?;
        slot.io = Some(MakerIo {
            utxos,
            cj_script,
            change_script,
        });
        if self.makers.values().all(|s| s.io.is_some()) {
            return self.build_and_send(chain);
        }
        Ok((Vec::new(), Progress::Waiting))
    }

    fn build_and_send(
        &mut self,
        chain: &impl ChainLookup,
    ) -> Result<(Vec<Outgoing>, Progress), TakerError> {
        let (pit, amount) = (self.cfg.pit, self.cfg.amount);
        let mut inputs: Vec<(OutPoint, TxOut)> = self.inputs.clone();
        let mut outputs = vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: self.cj_script.clone(),
        }];
        let (mut fees_to_makers, mut maker_txfees) = (0u64, 0u64);
        for (nick, slot) in &self.makers {
            let io = slot.io.as_ref().ok_or_else(|| err(nick, "no !ioauth"))?;
            let total: u64 = io.utxos.iter().map(|(_, o)| o.value.to_sat()).sum();
            let change = (total + slot.cjfee)
                .checked_sub(amount + slot.offer.txfee)
                .ok_or_else(|| err(nick, "inputs do not cover the amount"))?;
            if change < MAKER_CHANGE_THRESHOLD_SAT {
                return Err(err(nick, "maker change below the threshold"));
            }
            inputs.extend(io.utxos.iter().cloned());
            outputs.push(TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: io.cj_script.clone(),
            });
            outputs.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: io.change_script.clone(),
            });
            fees_to_makers += slot.cjfee;
            maker_txfees += slot.offer.txfee;
        }
        let our_total: u64 = self.inputs.iter().map(|(_, o)| o.value.to_sat()).sum();
        let weight = |n_out: usize| {
            OVERHEAD_WU
                + inputs.len() as u64 * input_weight(pit)
                + n_out as u64 * output_weight(pit)
        };
        let fee_for = |w: u64| (w * self.cfg.fee_rate_sat_per_kwu).div_ceil(1000);
        let with_change = fee_for(weight(outputs.len() + 1)).saturating_sub(maker_txfees);
        let spent = amount + fees_to_makers;
        let taker_change = our_total.saturating_sub(spent + with_change);
        if taker_change > TAKER_DUST_SAT {
            outputs.push(TxOut {
                value: Amount::from_sat(taker_change),
                script_pubkey: self.change_script.clone(),
            });
        } else {
            let without = fee_for(weight(outputs.len())).saturating_sub(maker_txfees);
            if our_total < spent + without {
                return Err(TakerError::Funds(
                    "inputs do not cover amount, maker fees and mining fee".into(),
                ));
            }
        }
        shuffle(&mut inputs);
        shuffle(&mut outputs);
        let tip = chain.tip_height().map_err(TakerError::Internal)?;
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_height(tip)
                .map_err(|e| TakerError::Internal(e.to_string()))?,
            input: inputs
                .iter()
                .map(|(o, _)| TxIn {
                    previous_output: *o,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs,
        };
        self.prevouts = inputs.into_iter().map(|(_, o)| o).collect();
        let b64 = STANDARD.encode(serialize(&tx));
        let mut out = Vec::new();
        for (nick, slot) in &self.makers {
            let session = slot
                .session
                .as_ref()
                .ok_or_else(|| err(nick, "no session"))?;
            let body = session
                .encrypt(&b64)
                .map_err(|e| err(nick, e.to_string()))?;
            out.push(Outgoing::Private {
                to: nick.clone(),
                command: "tx".into(),
                body,
            });
        }
        self.tx = Some(tx);
        Ok((out, Progress::Waiting))
    }

    fn on_sig(
        &mut self,
        from: &str,
        ciphertext: &str,
    ) -> Result<(Vec<Outgoing>, Progress), TakerError> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| err(from, "!sig before !tx"))?;
        let slot = self.makers.get(from).ok_or_else(|| err(from, "unknown"))?;
        let session = slot
            .session
            .as_ref()
            .ok_or_else(|| err(from, "no session"))?;
        let io = slot.io.as_ref().ok_or_else(|| err(from, "no !ioauth"))?;
        let payload = session
            .decrypt(ciphertext)
            .map_err(|e| err(from, e.to_string()))?;
        let secp = Secp256k1::verification_only();
        let theirs: BTreeSet<OutPoint> = io.utxos.iter().map(|(o, _)| *o).collect();
        let mut placed = false;
        for (index, input) in tx.input.iter().enumerate() {
            if !theirs.contains(&input.previous_output) || self.witnesses.contains_key(&index) {
                continue;
            }
            if let Ok(witness) =
                verify_sig(&secp, self.cfg.pit, &payload, tx, index, &self.prevouts)
            {
                self.witnesses.insert(index, witness);
                placed = true;
                break;
            }
        }
        if !placed {
            return Err(err(from, "signature fits none of its inputs"));
        }
        let maker_inputs: usize = self
            .makers
            .values()
            .filter_map(|s| s.io.as_ref())
            .map(|io| io.utxos.len())
            .sum();
        let progress = if self.witnesses.len() == maker_inputs {
            Progress::MakersSigned
        } else {
            Progress::Waiting
        };
        Ok((Vec::new(), progress))
    }

    /// Sign our own inputs (after every maker's, and after any channel's `funding_signed`) and return the
    /// complete transaction.
    pub fn finish(&mut self, wallet: &PitWallet) -> Result<Transaction, TakerError> {
        let mut tx = self
            .tx
            .clone()
            .ok_or_else(|| TakerError::Internal("no transaction".into()))?;
        let maker_inputs: usize = self
            .makers
            .values()
            .filter_map(|s| s.io.as_ref())
            .map(|io| io.utxos.len())
            .sum();
        if self.witnesses.len() != maker_inputs {
            return Err(TakerError::Internal("makers have not all signed".into()));
        }
        let ours: Vec<OutPoint> = self.inputs.iter().map(|(o, _)| *o).collect();
        let signed = wallet
            .sign_inputs(self.mixdepth, &tx, &self.prevouts, &ours)
            .map_err(|e| TakerError::Internal(e.to_string()))?;
        if signed.len() != ours.len() {
            return Err(TakerError::Internal(
                "could not sign every input of ours".into(),
            ));
        }
        let secp = Secp256k1::verification_only();
        for (index, payload) in signed {
            let witness = verify_sig(&secp, self.cfg.pit, &payload, &tx, index, &self.prevouts)
                .map_err(|e| TakerError::Internal(e.to_string()))?;
            self.witnesses.insert(index, witness);
        }
        for (index, witness) in &self.witnesses {
            tx.input[*index].witness = witness.clone();
        }
        if tx.input.iter().any(|i| i.witness.is_empty()) {
            return Err(TakerError::Internal("unsigned input left".into()));
        }
        Ok(tx)
    }
}

#[cfg(test)]
mod tests;
