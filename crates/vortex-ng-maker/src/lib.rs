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

/// Why the maker dropped a session. Only a fixed `!error` reaches the taker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MakerError {
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
    taker_nacl: String,
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

/// A maker for one pit.
pub struct Maker {
    config: MakerConfig,
    wallet: PitWallet,
    sessions: HashMap<String, Stage>,
    used_commitments: HashSet<[u8; 32]>,
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

/// Most sessions a maker keeps open at once; further fills are refused until some end.
pub const MAX_SESSIONS: usize = 64;

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
            used_commitments: HashSet::new(),
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
        self.used_commitments.insert(commitment);
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

    /// Handle one verified command from taker `from`. Errors drop the session and answer `!error`.
    pub fn handle(
        &mut self,
        from: &str,
        command: Command,
        chain: &impl Chain,
        now: u64,
    ) -> Vec<Outgoing> {
        let result = match command {
            // `!orderbook` is a public command (JMP-0001); the transport answers it with `on_orderbook`.
            Command::Orderbook => return Vec::new(),
            Command::Hp2(c) => {
                self.on_hp2(c);
                return Vec::new();
            }
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
            _ => Err(MakerError::State("unexpected command")),
        };
        result.unwrap_or_else(|_| {
            self.sessions.remove(from);
            vec![Outgoing::Private {
                to: from.to_string(),
                command: "error".into(),
                body: ERROR_TEXT.into(),
            }]
        })
    }

    fn on_fill(
        &mut self,
        from: &str,
        oid: u64,
        amount: u64,
        taker_nacl: &str,
        commitment: [u8; 32],
    ) -> Result<Vec<Outgoing>, MakerError> {
        if self.sessions.contains_key(from) {
            return Err(MakerError::State("session exists"));
        }
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(MakerError::State("too many open sessions"));
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
                session,
            }),
        );
        Ok(vec![reply])
    }

    fn on_auth(
        &mut self,
        from: &str,
        ciphertext: &str,
        chain: &impl Chain,
    ) -> Result<Vec<Outgoing>, MakerError> {
        let Some(Stage::Filled(filled)) = self.sessions.remove(from) else {
            return Err(MakerError::State("auth before fill"));
        };
        let revelation = filled
            .session
            .decrypt(ciphertext)
            .map_err(|e| MakerError::Internal(e.to_string()))?;
        let podle =
            Podle::parse_revelation(&revelation).map_err(|e| MakerError::Podle(e.to_string()))?;
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
        self.used_commitments.insert(filled.commitment);
        let commitment_hex = filled.commitment.to_lower_hex_string();

        let cjfee = filled
            .offer
            .fee_for(filled.amount)
            .ok_or(MakerError::Offer("amount out of range"))?;
        let needed =
            (filled.amount + filled.offer.txfee + MAKER_CHANGE_THRESHOLD_SAT).saturating_sub(cjfee);
        let (mixdepth, selected) = self.select(needed)?;
        let cj = self
            .wallet
            .next_receive_address((mixdepth + 1) % MIXDEPTHS)
            .map_err(|e| MakerError::Internal(e.to_string()))?;
        let change = self
            .wallet
            .next_change_address(mixdepth)
            .map_err(|e| MakerError::Internal(e.to_string()))?;
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
        let btc_sig = sigmsg::sign(&secp, filled.taker_nacl.as_bytes(), keys.auth());
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

    /// Pick the mixdepth with the most confirmed value that covers `needed`, and its largest confirmed
    /// UTXOs until they do.
    fn select(
        &self,
        needed: u64,
    ) -> Result<(u32, Vec<vortex_ng_wallet::bdk_wallet::LocalOutput>), MakerError> {
        let mut best: Option<(u64, u32, Vec<_>)> = None;
        for m in 0..MIXDEPTHS {
            let mut utxos: Vec<_> = self
                .wallet
                .utxos(m)
                .map_err(|e| MakerError::Internal(e.to_string()))?
                .into_iter()
                .filter(|u| u.chain_position.is_confirmed())
                .collect();
            let total: u64 = utxos.iter().map(|u| u.txout.value.to_sat()).sum();
            if total >= needed && best.as_ref().is_none_or(|(t, _, _)| total > *t) {
                utxos.sort_by_key(|u| std::cmp::Reverse(u.txout.value));
                best = Some((total, m, utxos));
            }
        }
        let (_, m, utxos) = best.ok_or(MakerError::Liquidity)?;
        let mut picked = Vec::new();
        let mut sum = 0u64;
        for u in utxos {
            if sum >= needed {
                break;
            }
            sum += u.txout.value.to_sat();
            picked.push(u);
        }
        Ok((m, picked))
    }

    fn on_tx(
        &mut self,
        from: &str,
        ciphertext: &str,
        chain: &impl Chain,
        now: u64,
    ) -> Result<Vec<Outgoing>, MakerError> {
        let Some(Stage::Authed(authed)) = self.sessions.remove(from) else {
            return Err(MakerError::State("tx before auth"));
        };
        let plaintext = authed
            .filled
            .session
            .decrypt(ciphertext)
            .map_err(|e| MakerError::Internal(e.to_string()))?;
        let raw = STANDARD
            .decode(plaintext)
            .map_err(|_| MakerError::Tx("tx base64".into()))?;
        let tx: Transaction =
            deserialize(&raw).map_err(|_| MakerError::Tx("tx encoding".into()))?;

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
