//! One peer's part in a pool, as a state machine with no I/O.
//!
//! The transport feeds it every decrypted message of the pool's channel, in arrival order; it answers with
//! messages to send and, at the end, the transaction to broadcast. Its state is the log of what the channel
//! said: after each message the round is derived again from the whole log with the same functions every
//! client's rules fix ([`crate::rules::collect_outputs`], [`crate::tx::collect_inputs`], ...), so two peers
//! that saw the same messages reach the same transaction whatever order they acted in.
//!
//! The happy path is: our `output`; once `peers` outputs are registered, our `input` (a registration
//! PSBT); once `peers` inputs are registered, the combined transaction. If the inputs do not all arrive,
//! the transport calls [`Peer::on_timeout`] and the recovery round starts ([`crate::recovery`]).

use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{Address, Network, OutPoint, ScriptBuf, Transaction, TxOut, Witness};

use crate::lsag::LsagError;
use crate::message::PoolMessage;
use crate::pool::Pool;
use crate::recovery::{self, Recovery, RingMember};
use crate::rules::{self, AmountError};
use crate::tx::{self, Terms, TxError};

/// What the transport must do next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Encrypt this plaintext to the pool key and publish it as the pool key.
    Send(String),
    /// The round is complete: broadcast this transaction.
    Broadcast(Transaction),
}

/// Why a peer left the round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// The pool's amounts or our coin break an amount rule.
    Amount(AmountError),
    /// A transaction rule refused the round.
    Tx(TxError),
    /// The recovery round could not start or be signed.
    Recovery(&'static str),
    /// The ring signature could not be made.
    Lsag(LsagError),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Amount(e) => write!(f, "{e}"),
            SessionError::Tx(e) => write!(f, "{e}"),
            SessionError::Recovery(why) => write!(f, "recovery round: {why}"),
            SessionError::Lsag(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SessionError {}

struct RecoveryState {
    members: Vec<RingMember>,
    plan: Option<Recovery>,
    witnesses: Vec<Option<Witness>>,
}

/// One peer in one pool.
pub struct Peer {
    pool: Pool,
    network: Network,
    address: Address,
    coin: OutPoint,
    coin_txout: TxOut,
    key: SecretKey,
    log: Vec<String>,
    template: Option<Vec<TxOut>>,
    recovery: Option<RecoveryState>,
    done: bool,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("pool", &self.pool.id)
            .field("messages", &self.log.len())
            .field("registered", &self.template.is_some())
            .field("recovering", &self.recovery.is_some())
            .finish_non_exhaustive()
    }
}

impl Peer {
    /// Take part in `pool` with `coin` (`coin_txout`, spent with `key`: see
    /// [`tx::build_registration`]), to be paid at `address`. The coin must be in the pool's input window
    /// (R5.4); the address must be on `network`.
    pub fn new(
        pool: Pool,
        network: Network,
        address: Address,
        coin: OutPoint,
        coin_txout: TxOut,
        key: SecretKey,
    ) -> Result<Peer, SessionError> {
        let denom = pool.denom_sats();
        let value = i64::try_from(coin_txout.value.to_sat()).unwrap_or(i64::MAX);
        if value < denom.saturating_add(rules::INPUT_SLACK_MIN)
            || value > denom.saturating_add(rules::INPUT_SLACK_MAX)
        {
            return Err(SessionError::Amount(AmountError::InputWindow));
        }
        if coin_txout.script_pubkey == address.script_pubkey() {
            return Err(SessionError::Tx(TxError::Combine(
                "an output pays a spent scriptPubKey",
            )));
        }
        Ok(Peer {
            pool,
            network,
            address,
            coin,
            coin_txout,
            key,
            log: Vec::new(),
            template: None,
            recovery: None,
            done: false,
        })
    }

    /// The most channel messages a peer keeps: enough for every phase of a full pool several times over.
    fn log_cap(&self) -> usize {
        64 * self.pool.peers as usize + 256
    }

    fn terms(&self) -> Terms {
        Terms {
            denomination: self.pool.denomination,
            peers: self.pool.peers,
        }
    }

    fn fee_bounds(&self) -> bool {
        // The reference skips the fee bound of the combined transaction on regtest only.
        self.network != Network::Regtest
    }

    fn send(&mut self, message: &PoolMessage) -> Action {
        let text = message.to_plaintext();
        // What we send is part of the channel whether or not the relay echoes it back to us.
        self.log.push(text.clone());
        Action::Send(text)
    }

    /// Whether the round has produced its transaction.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Whether our registration has been sent (the moment from which missing inputs mean recovery).
    pub fn has_registered(&self) -> bool {
        self.template.is_some()
    }

    /// Begin: register our output.
    pub fn start(&mut self) -> Result<Vec<Action>, SessionError> {
        let output = PoolMessage::Output {
            address: self.address.to_string(),
        };
        let mut actions = vec![self.send(&output)];
        actions.extend(self.step()?);
        Ok(actions)
    }

    /// A decrypted message of the pool's channel arrived (ours included, if the relay echoes them).
    pub fn on_message(&mut self, plaintext: &str) -> Result<Vec<Action>, SessionError> {
        if self.done || self.log.len() >= self.log_cap() || self.log.iter().any(|m| m == plaintext)
        {
            return Ok(Vec::new());
        }
        self.log.push(plaintext.to_string());
        self.step()
    }

    /// The inputs did not all arrive: start the recovery round. A no-op before our registration, after
    /// the round is done, or once recovery has started.
    pub fn on_timeout(&mut self) -> Result<Vec<Action>, SessionError> {
        let Some(template) = self.template.clone() else {
            return Ok(Vec::new());
        };
        if self.done || self.recovery.is_some() {
            return Ok(Vec::new());
        }
        let registrations: Vec<tx::Registration> = tx::collect_inputs(
            self.log.iter().map(String::as_str),
            Some(&template),
            self.terms(),
        )
        .into_iter()
        .map(|(_, r)| r)
        .collect();
        let members = recovery::ring_members(&registrations);
        if members.len() < 2 {
            return Err(SessionError::Recovery(
                "fewer than two inputs were registered",
            ));
        }
        if !members.iter().any(|m| m.outpoint == self.coin) {
            return Err(SessionError::Recovery(
                "our input is not in the ring (only P2WPKH coins are)",
            ));
        }
        let ring: Vec<PublicKey> = members.iter().map(|m| m.key).collect();
        let message =
            recovery::build_reregister(&self.address.to_string(), &self.pool.id, &ring, &self.key)
                .map_err(SessionError::Lsag)?;
        let witnesses = vec![None; members.len()];
        self.recovery = Some(RecoveryState {
            members,
            plan: None,
            witnesses,
        });
        let mut actions = vec![self.send(&message)];
        actions.extend(self.step()?);
        Ok(actions)
    }

    fn step(&mut self) -> Result<Vec<Action>, SessionError> {
        if self.done {
            return Ok(Vec::new());
        }
        if self.recovery.is_some() {
            return self.recovery_step();
        }
        let mut actions = Vec::new();
        let outputs = rules::collect_outputs(
            self.log.iter().map(String::as_str),
            self.pool.peers,
            self.network,
        );
        if outputs.len() < self.pool.peers as usize {
            return Ok(actions);
        }
        let template = match &self.template {
            Some(template) => template.clone(),
            None => {
                let scripts: Vec<ScriptBuf> = outputs.iter().map(Address::script_pubkey).collect();
                let sats = rules::check_amounts(
                    self.pool.denomination,
                    self.pool.fee_rate,
                    self.pool.peers,
                    &scripts,
                )
                .map_err(SessionError::Amount)?;
                rules::check_input(self.coin_txout.value.to_sat(), self.pool.denomination, sats)
                    .map_err(SessionError::Amount)?;
                let template = tx::template(&scripts, sats);
                let psbt = tx::build_registration(
                    self.coin,
                    &self.coin_txout,
                    &template,
                    &self.address.script_pubkey(),
                    self.pool.peers,
                    &self.key,
                )
                .map_err(SessionError::Tx)?;
                self.template = Some(template.clone());
                let input = PoolMessage::Input {
                    psbt: psbt.to_string(),
                };
                actions.push(self.send(&input));
                template
            }
        };
        let registrations: Vec<tx::Registration> = tx::collect_inputs(
            self.log.iter().map(String::as_str),
            Some(&template),
            self.terms(),
        )
        .into_iter()
        .map(|(_, r)| r)
        .collect();
        if registrations.len() >= self.pool.peers as usize {
            let transaction = tx::combine(&registrations, &template, self.fee_bounds())
                .map_err(SessionError::Tx)?;
            self.done = true;
            actions.push(Action::Broadcast(transaction));
        }
        Ok(actions)
    }

    fn recovery_step(&mut self) -> Result<Vec<Action>, SessionError> {
        let mut actions = Vec::new();
        let Some((members, planned)) = self
            .recovery
            .as_ref()
            .map(|s| (s.members.clone(), s.plan.clone()))
        else {
            return Ok(actions);
        };
        let ring: Vec<PublicKey> = members.iter().map(|m| m.key).collect();
        let outputs = recovery::collect_reregistrations(
            self.log.iter().map(String::as_str),
            &self.pool.id,
            &ring,
            self.network,
        );
        if outputs.len() < ring.len() {
            return Ok(actions);
        }
        let plan = match planned {
            Some(plan) => plan,
            None => {
                let scripts: Vec<ScriptBuf> =
                    outputs.iter().map(|o| o.address.script_pubkey()).collect();
                let plan = recovery::recovery_transaction(
                    &members,
                    &scripts,
                    self.pool.denomination,
                    self.pool.fee_rate,
                    true,
                )
                .map_err(SessionError::Tx)?;
                let resign =
                    recovery::build_resign(&plan, &self.address.script_pubkey(), &self.key)
                        .map_err(SessionError::Tx)?;
                if let Some(state) = self.recovery.as_mut() {
                    state.plan = Some(plan.clone());
                }
                actions.push(self.send(&resign));
                plan
            }
        };
        let chunks: Vec<String> = self
            .log
            .iter()
            .filter_map(|m| match PoolMessage::parse(m) {
                Some(PoolMessage::Resign { psbt }) => Some(psbt),
                _ => None,
            })
            .collect();
        let Some(state) = self.recovery.as_mut() else {
            return Ok(actions);
        };
        for chunk in chunks {
            // A chunk for another transaction, or one that does not parse, is skipped.
            for (index, witness) in recovery::accept_resign(&chunk, &plan).unwrap_or_default() {
                if let Some(slot) = state.witnesses.get_mut(index) {
                    slot.get_or_insert(witness);
                }
            }
        }
        if let Some(transaction) = recovery::finish(&plan, &state.witnesses) {
            self.done = true;
            actions.push(Action::Broadcast(transaction));
        }
        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Amount, CompressedPublicKey, Txid};

    use super::*;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn address(k: &SecretKey) -> Address {
        Address::p2wpkh(
            &CompressedPublicKey(k.public_key(&Secp256k1::new())),
            Network::Regtest,
        )
    }

    fn pool(peers: u32) -> Pool {
        Pool::create(
            &key(200),
            "pool1",
            0.001,
            peers,
            2_000_000_000,
            "wss://relay.example",
            2.5,
        )
        .unwrap()
    }

    fn peer(i: u8, peers: u32) -> Peer {
        let coin = TxOut {
            value: Amount::from_sat(101_000 + u64::from(i)),
            script_pubkey: address(&key(i)).script_pubkey(),
        };
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([i; 32]),
            vout: u32::from(i),
        };
        Peer::new(
            pool(peers),
            Network::Regtest,
            address(&key(100 + i)),
            outpoint,
            coin,
            key(i),
        )
        .unwrap()
    }

    /// Deliver every sent message to every peer until the channel is quiet. Returns the transactions
    /// broadcast, per peer.
    fn run(peers: &mut [Peer], mut queue: Vec<String>) -> Vec<Option<Transaction>> {
        let mut txs: Vec<Option<Transaction>> = vec![None; peers.len()];
        while !queue.is_empty() {
            let message = queue.remove(0);
            for (i, peer) in peers.iter_mut().enumerate() {
                for action in peer.on_message(&message).unwrap() {
                    match action {
                        Action::Send(text) => queue.push(text),
                        Action::Broadcast(tx) => txs[i] = Some(tx),
                    }
                }
            }
        }
        txs
    }

    fn sends(actions: Vec<Action>) -> Vec<String> {
        actions
            .into_iter()
            .filter_map(|a| match a {
                Action::Send(text) => Some(text),
                Action::Broadcast(_) => None,
            })
            .collect()
    }

    #[test]
    fn three_peers_reach_the_same_coinjoin() {
        let mut peers: Vec<Peer> = (1..=3).map(|i| peer(i, 3)).collect();
        let mut queue = Vec::new();
        for p in &mut peers {
            queue.extend(sends(p.start().unwrap()));
        }
        let txs = run(&mut peers, queue);
        let first = txs[0].clone().expect("a transaction");
        assert!(
            txs.iter().all(|t| t.as_ref() == Some(&first)),
            "every peer builds the same transaction"
        );
        assert_eq!((first.input.len(), first.output.len()), (3, 3));
        assert!(first.output.iter().all(|o| o.value.to_sat() == 99_750));
        assert!(peers.iter().all(Peer::is_done));
        // Nothing more happens after the round, and a timeout is a no-op.
        assert!(peers[0].on_message("anything").unwrap().is_empty());
        assert!(peers[0].on_timeout().unwrap().is_empty());
    }

    #[test]
    fn a_withheld_input_is_recovered_from_by_the_others() {
        // Four slots: three honest peers and one that registers an output and never an input.
        let mut peers: Vec<Peer> = (1..=3).map(|i| peer(i, 4)).collect();
        let mut queue = vec![
            PoolMessage::Output {
                address: address(&key(150)).to_string(),
            }
            .to_plaintext(),
        ];
        for p in &mut peers {
            queue.extend(sends(p.start().unwrap()));
        }
        let txs = run(&mut peers, queue);
        assert!(
            txs.iter().all(Option::is_none),
            "three inputs for four outputs: no transaction"
        );
        assert!(peers.iter().all(|p| p.has_registered() && !p.is_done()));

        // The inputs never complete: every honest peer times out and the recovery round runs.
        let mut queue = Vec::new();
        for p in &mut peers {
            queue.extend(sends(p.on_timeout().unwrap()));
        }
        let txs = run(&mut peers, queue);
        let first = txs[0].clone().expect("a recovery transaction");
        assert!(txs.iter().all(|t| t.as_ref() == Some(&first)));
        assert_eq!(
            (first.input.len(), first.output.len()),
            (3, 3),
            "the absent peer's output is gone"
        );
        // 100 * 3 + 68 * 3 + 100 = 604 vbytes at 2.5 sat/vB: 1510 // 3 = 503 per output.
        assert!(
            first
                .output
                .iter()
                .all(|o| o.value.to_sat() == 100_000 - 503)
        );
        assert!(first.input.iter().all(|i| i.witness.len() == 2));
    }

    #[test]
    fn a_peer_leaves_rounds_that_would_cost_it() {
        // A coin outside the window never enters.
        let coin = TxOut {
            value: Amount::from_sat(120_000),
            script_pubkey: address(&key(1)).script_pubkey(),
        };
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1; 32]),
            vout: 0,
        };
        let refused = Peer::new(
            pool(2),
            Network::Regtest,
            address(&key(101)),
            outpoint,
            coin.clone(),
            key(1),
        );
        assert_eq!(
            refused.unwrap_err(),
            SessionError::Amount(AmountError::InputWindow)
        );
        // Paying back to the address being spent is address reuse.
        let small = TxOut {
            value: Amount::from_sat(101_000),
            script_pubkey: coin.script_pubkey,
        };
        let reuse = Peer::new(
            pool(2),
            Network::Regtest,
            address(&key(1)),
            outpoint,
            small,
            key(1),
        );
        assert!(matches!(reuse.unwrap_err(), SessionError::Tx(_)));
        // The pool fills with other people's outputs before ours arrives: we do not sign.
        let mut late = peer(1, 2);
        let others: Vec<String> = (150..152)
            .map(|i| {
                PoolMessage::Output {
                    address: address(&key(i)).to_string(),
                }
                .to_plaintext()
            })
            .collect();
        late.on_message(&others[0]).unwrap();
        assert!(matches!(
            late.on_message(&others[1]),
            Err(SessionError::Tx(TxError::Template(_)))
        ));
        // Recovery needs our input in a ring of at least two.
        let mut alone = peer(1, 2);
        let mut queue = sends(alone.start().unwrap());
        queue.push(
            PoolMessage::Output {
                address: address(&key(150)).to_string(),
            }
            .to_plaintext(),
        );
        run(std::slice::from_mut(&mut alone), queue);
        assert_eq!(
            alone.on_timeout().unwrap_err(),
            SessionError::Recovery("fewer than two inputs were registered")
        );
    }

    #[test]
    fn junk_and_repeats_do_not_disturb_a_round() {
        let mut peers: Vec<Peer> = (1..=2).map(|i| peer(i, 2)).collect();
        let mut queue = vec![
            "junk".to_string(),
            r#"{"type": "input", "psbt": "AAAA"}"#.to_string(),
        ];
        for p in &mut peers {
            let sent = sends(p.start().unwrap());
            queue.extend(sent.clone());
            queue.extend(sent); // the relay echoes, or a peer repeats itself
        }
        queue.push(
            r#"{"type": "output", "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}"#
                .to_string(),
        );
        let txs = run(&mut peers, queue);
        assert!(txs[0].is_some() && txs[0] == txs[1]);
    }
}
