//! Whole CoinJoins in memory: a vortex-ng taker and two vortex-ng makers exchange the real protocol
//! messages (commands, NaCl, PoDLE, `!ioauth`, `!tx`, `!sig`) over a fake chain, in every pit.

use std::collections::{HashMap, VecDeque};

use vortex_ng_chain::Utxo;
use vortex_ng_core::bitcoin::block::{Header, Version as BlockVersion};
use vortex_ng_core::bitcoin::blockdata::constants::genesis_block;
use vortex_ng_core::bitcoin::hashes::Hash;
use vortex_ng_core::bitcoin::{Block, BlockHash, CompactTarget, TxMerkleNode, Txid, absolute};
use vortex_ng_core::command::{ENCRYPTED, parse_plaintext};
use vortex_ng_maker::{Maker, MakerConfig};
use vortex_ng_wallet::Seed;

use super::*;

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const AMOUNT: u64 = 300_000;
const NOW: u64 = 1_800_000_000;

#[derive(Default)]
struct FakeChain {
    utxos: HashMap<OutPoint, Utxo>,
}

impl ChainLookup for FakeChain {
    fn utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, String> {
        Ok(self.utxos.get(outpoint).cloned())
    }
    fn tip_height(&self) -> Result<u32, String> {
        Ok(300)
    }
    fn block_time(&self, height: u32) -> Result<u32, String> {
        Ok(1_700_000_000 + height * 600)
    }
}

/// A wallet for `pit` (seed passphrase `who`) with one confirmed UTXO of `value` in mixdepth 0, also
/// registered in `chain`.
fn funded(pit: Pit, who: &str, value: u64, salt: u8, chain: &mut FakeChain) -> PitWallet {
    let mut wallet = PitWallet::new(
        &Seed::from_mnemonic(WORDS, who, Network::Regtest).unwrap(),
        pit,
    )
    .unwrap();
    let address = wallet.next_receive_address(0).unwrap();
    let funding = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([salt; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: address.script_pubkey(),
        }],
    };
    let genesis = genesis_block(Network::Regtest);
    let block = Block {
        header: Header {
            version: BlockVersion::TWO,
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: genesis.header.time + 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: u32::from(salt),
        },
        txdata: vec![funding.clone()],
    };
    wallet.apply_block(&block, 1).unwrap();
    chain.utxos.insert(
        OutPoint {
            txid: funding.compute_txid(),
            vout: 0,
        },
        Utxo {
            value: Amount::from_sat(value),
            script_pubkey: address.script_pubkey(),
            confirmations: 10,
            coinbase: false,
        },
    );
    let _ = BlockHash::all_zeros();
    wallet
}

fn to_command(command: &str, body: &str) -> Command {
    if ENCRYPTED.contains(&command) {
        Command::Encrypted {
            name: command.into(),
            ciphertext: body.into(),
        }
    } else {
        parse_plaintext(&format!("!{command} {body}"))
            .unwrap()
            .remove(0)
    }
}

fn offer(pit: Pit, oid: u64) -> Offer {
    Offer::parse(
        &format!("{}absoffer", pit.prefix()),
        &format!("{oid} 10000 10000000 100 500"),
    )
    .unwrap()
}

/// Run one CoinJoin in `pit`; returns the final transaction and the taker's wallet.
/// Whether a reply is the maker's fixed refusal.
fn is_refusal(out: &Outgoing) -> bool {
    matches!(out, Outgoing::Private { command, .. } if command == "error")
}

/// Whether a reply to a repeated `!fill` from `taker` is the `!pubkey` the maker already gave it.
fn is_same_pubkey(out: &Outgoing, taker: &str, earlier: Option<&String>) -> bool {
    matches!(out, Outgoing::Private { to, command, body }
        if command == "pubkey" && to == taker && Some(body) == earlier)
}

/// A round between the taker and two makers. With `noisy`, the channel misbehaves as a directory or IRC
/// server may: every line arrives twice, every line seen so far is delivered again after each step, and every
/// line the taker sent also reaches the other maker. None of that may change the round. A maker may answer a
/// repeated `!fill` with the `!pubkey` it already sent (the taker may have moved to another connection).
fn coinjoin_with(pit: Pit, noisy: bool) -> (Transaction, PitWallet) {
    coinjoin_after(pit, noisy, 0)
}

/// As [`coinjoin_with`]. `stale_pubkeys` `!pubkey` lines of each maker from other exchanges (keys the round
/// does not use) reach the taker before anything else.
fn coinjoin_after(pit: Pit, noisy: bool, stale_pubkeys: usize) -> (Transaction, PitWallet) {
    let mut chain = FakeChain::default();
    let mut makers: BTreeMap<String, Maker> = BTreeMap::new();
    for (i, nick) in ["J5makerA", "J5makerB"].iter().enumerate() {
        let wallet = funded(pit, nick, 500_000, 10 + i as u8, &mut chain);
        makers.insert(
            nick.to_string(),
            Maker::new(MakerConfig::new(vec![offer(pit, i as u64)]), wallet).unwrap(),
        );
    }
    let mut taker_wallet = funded(pit, "taker", 600_000, 20, &mut chain);
    let utxo = taker_wallet.utxos(0).unwrap().remove(0);
    let podle = podle_for(&taker_wallet, 0, &utxo, 0).unwrap();
    let cfg = TakerConfig {
        pit,
        network: Network::Regtest,
        amount: AMOUNT,
        makers: 2,
        max_cjfee: 1_000,
        fee_rate_sat_per_kwu: 2_500,
        max_maker_utxos: 20,
        bondless_makers_allowance: DEFAULT_BONDLESS_ALLOWANCE,
        bondless_require_zero_fee: false,
        bond_params: BondValueParams::default(),
    };
    let offers: Vec<(String, Offer)> = makers
        .iter()
        .map(|(n, m)| {
            (
                n.clone(),
                offer(m.pit(), if n == "J5makerA" { 0 } else { 1 }),
            )
        })
        .collect();
    let chosen = select_makers(&offers, &HashMap::new(), &cfg);
    assert_eq!(chosen.len(), 2);
    let cj = taker_wallet
        .next_receive_address(1)
        .unwrap()
        .script_pubkey();
    let change = taker_wallet.next_change_address(0).unwrap().script_pubkey();
    let mut taker = Taker::new(
        cfg,
        0,
        vec![(utxo.outpoint, utxo.txout.clone())],
        podle,
        cj,
        change,
    )
    .unwrap();

    let mut queue: VecDeque<(String, Outgoing)> = taker
        .start(chosen)
        .unwrap()
        .into_iter()
        .map(|o| ("J5taker".to_string(), o))
        .collect();
    for _ in 0..stale_pubkeys {
        for nick in makers.keys() {
            queue.push_front((
                nick.clone(),
                Outgoing::Private {
                    to: "J5taker".into(),
                    command: "pubkey".into(),
                    body: vortex_ng_core::nacl::NaclKeypair::generate().public_hex(),
                },
            ));
        }
    }
    let mut progress = Progress::Waiting;
    let mut seen: Vec<(String, String, String, String)> = Vec::new();
    // Each maker's `!pubkey` of this round, as it first sent it.
    let mut pubkeys: BTreeMap<String, String> = BTreeMap::new();
    while let Some((from, message)) = queue.pop_front() {
        let Outgoing::Private { to, command, body } = message else {
            continue;
        };
        let cmd = to_command(&command, &body);
        if let Some(maker) = makers.get_mut(&to) {
            for out in maker.handle(&from, cmd, &chain, NOW) {
                if let Outgoing::Private { command, body, .. } = &out
                    && command == "pubkey"
                {
                    pubkeys.entry(to.clone()).or_insert_with(|| body.clone());
                }
                queue.push_back((to.clone(), out));
            }
        } else {
            assert_eq!(to, "J5taker");
            let (outs, p) = taker.handle(&from, cmd, &chain).unwrap();
            progress = p;
            queue.extend(outs.into_iter().map(|o| ("J5taker".to_string(), o)));
        }
        if !noisy {
            continue;
        }
        seen.push((from, to, command, body));
        for (from, to, command, body) in &seen {
            let mut targets = vec![to.clone()];
            if from == "J5taker" {
                targets.extend(makers.keys().filter(|nick| *nick != to).cloned());
            }
            for target in targets {
                let cmd = to_command(command, body);
                if let Some(maker) = makers.get_mut(&target) {
                    // Nothing but a refusal of a fill that was never this maker's; the refusal goes nowhere
                    // the taker would act on (a driver drops a lone `!error` on such a channel). Its own fill,
                    // repeated, gets the same `!pubkey` again and nothing new.
                    let outs = maker.handle(from, cmd, &chain, NOW);
                    let repeat = command == "fill" && *to == target;
                    assert!(
                        outs.iter().all(|out| is_refusal(out)
                            || (repeat && is_same_pubkey(out, from, pubkeys.get(&target)))),
                        "{pit:?}: {target} answered a stray !{command}: {outs:?}"
                    );
                } else {
                    let (outs, p) = taker.handle(from, cmd, &chain).unwrap_or_else(|e| {
                        panic!("{pit:?}: a stray !{command} ended the round: {e}")
                    });
                    assert!(
                        outs.is_empty(),
                        "{pit:?}: the taker answered a stray !{command}"
                    );
                    assert_eq!(p, progress, "{pit:?}: a stray !{command} moved the round");
                }
            }
        }
    }
    assert_eq!(progress, Progress::MakersSigned, "{pit:?}");
    // Here a channel's funding_signed would be awaited; then the taker signs last.
    let tx = taker.finish(&taker_wallet).unwrap();
    taker_wallet.utxos(0).unwrap();
    (tx, taker_wallet)
}

fn check(pit: Pit) {
    check_with(pit, false);
}

#[test]
fn a_pubkey_from_another_exchange_does_not_end_the_round() {
    // As many as leave room for the real key, which then still wins.
    for stale in [1, MAX_PUBKEY_CANDIDATES - 1] {
        let (tx, _) = coinjoin_after(Pit::Sw0, false, stale);
        assert_eq!(tx.input.len(), 3);
        assert!(tx.input.iter().all(|i| !i.witness.is_empty()));
    }
}

fn check_with(pit: Pit, noisy: bool) {
    let (tx, _) = coinjoin_with(pit, noisy);
    assert_eq!(tx.input.len(), 3);
    assert!(
        tx.input.iter().all(|i| !i.witness.is_empty()),
        "{pit:?}: every input signed"
    );
    let equal = tx
        .output
        .iter()
        .filter(|o| o.value.to_sat() == AMOUNT)
        .count();
    assert_eq!(equal, 3, "{pit:?}: three equal outputs");
    // Each maker's change: 500,000 - 300,000 - txfee 100 + cjfee 500.
    assert_eq!(
        tx.output
            .iter()
            .filter(|o| o.value.to_sat() == 200_400)
            .count(),
        2,
        "{pit:?}"
    );
    let total_in = 500_000 * 2 + 600_000u64;
    let total_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    assert!(
        total_out < total_in && total_in - total_out < 10_000,
        "{pit:?}: fee {}",
        total_in - total_out
    );
    assert!(
        tx.output.iter().all(|o| in_family(pit, &o.script_pubkey)),
        "{pit:?}: one script family"
    );
}

#[test]
fn sw0_coinjoin_end_to_end() {
    check(Pit::Sw0);
}

#[test]
fn tr0_coinjoin_end_to_end() {
    check(Pit::Tr0);
}

#[test]
fn wsh0_coinjoin_end_to_end() {
    check(Pit::Wsh0);
}

#[test]
fn duplicated_and_replayed_lines_do_not_change_the_round() {
    for pit in [Pit::Sw0, Pit::Tr0, Pit::Wsh0] {
        check_with(pit, true);
    }
}

#[test]
fn a_maker_line_out_of_place_is_ignored() {
    // Garbage where a maker's encrypted lines go, before anything was asked of it: no error, nothing sent.
    let (taker, chain) = {
        let mut chain = FakeChain::default();
        let wallet = funded(Pit::Sw0, "taker", 600_000, 20, &mut chain);
        let utxo = wallet.utxos(0).unwrap().remove(0);
        let podle = podle_for(&wallet, 0, &utxo, 0).unwrap();
        let cj = wallet.peek_address(1, false, 0).unwrap().script_pubkey();
        let change = wallet.peek_address(0, true, 0).unwrap().script_pubkey();
        let cfg = choice_cfg(AMOUNT);
        let taker =
            Taker::new(cfg, 0, vec![(utxo.outpoint, utxo.txout)], podle, cj, change).unwrap();
        (taker, chain)
    };
    let mut taker = taker;
    let chosen = vec![
        ("J5makerA".to_string(), offer(Pit::Sw0, 0)),
        ("J5makerB".to_string(), offer(Pit::Sw0, 1)),
    ];
    assert_eq!(taker.start(chosen).unwrap().len(), 2);
    for (from, cmd) in [
        ("J5makerA", to_command("ioauth", "AAAA")),
        ("J5makerA", to_command("sig", "AAAA")),
        ("J5makerA", Command::Orderbook),
        ("J5stranger", to_command("pubkey", &"ab".repeat(32))),
    ] {
        let (outs, p) = taker.handle(from, cmd, &chain).unwrap();
        assert!(outs.is_empty() && p == Progress::Waiting);
    }
    // A maker's `!error` is still an error to the state machine; whether to pass it on is the driver's call.
    assert!(
        taker
            .handle("J5makerA", Command::Error("no".into()), &chain)
            .is_err()
    );
}

/// A taker and three makers (`J5makerA`, `B`, `C`), the `!fill`s queued and not yet delivered.
struct Round {
    chain: FakeChain,
    makers: BTreeMap<String, Maker>,
    taker: Taker,
    wallet: PitWallet,
    queue: VecDeque<(String, Outgoing)>,
}

const MAKER_C: &str = "J5makerC";

fn round_of_three(min_makers: usize) -> Round {
    round_with(min_makers, false)
}

/// With `twins`, `MAKER_C` runs `J5makerA`'s wallet, so the two declare the same coin and addresses.
fn round_with(min_makers: usize, twins: bool) -> Round {
    let pit = Pit::Sw0;
    let mut chain = FakeChain::default();
    let mut makers = BTreeMap::new();
    let mut chosen = Vec::new();
    for (i, nick) in ["J5makerA", "J5makerB", MAKER_C].iter().enumerate() {
        let (who, salt) = if twins && *nick == MAKER_C {
            ("J5makerA", 10)
        } else {
            (*nick, 10 + i as u8)
        };
        let wallet = funded(pit, who, 500_000, salt, &mut chain);
        let maker = Maker::new(MakerConfig::new(vec![offer(pit, i as u64)]), wallet).unwrap();
        makers.insert(nick.to_string(), maker);
        chosen.push((nick.to_string(), offer(pit, i as u64)));
    }
    let mut wallet = funded(pit, "taker", 600_000, 20, &mut chain);
    let utxo = wallet.utxos(0).unwrap().remove(0);
    let podle = podle_for(&wallet, 0, &utxo, 0).unwrap();
    let cfg = TakerConfig {
        makers: 3,
        ..choice_cfg(AMOUNT)
    };
    let cj = wallet.next_receive_address(1).unwrap().script_pubkey();
    let change = wallet.next_change_address(0).unwrap().script_pubkey();
    let mut taker = Taker::new(cfg, 0, vec![(utxo.outpoint, utxo.txout)], podle, cj, change)
        .unwrap()
        .allow_fewer_makers(min_makers)
        .unwrap();
    let queue = taker
        .start(chosen)
        .unwrap()
        .into_iter()
        .map(|out| ("J5taker".to_string(), out))
        .collect();
    Round {
        chain,
        makers,
        taker,
        wallet,
        queue,
    }
}

impl Round {
    /// Carry every queued line and what it leads to, except lines to the makers in `silent`.
    fn carry(&mut self, silent: &[&str]) -> Result<Progress, TakerError> {
        let mut progress = Progress::Waiting;
        while let Some((from, message)) = self.queue.pop_front() {
            let Outgoing::Private { to, command, body } = message else {
                continue;
            };
            if silent.contains(&to.as_str()) {
                continue;
            }
            let cmd = to_command(&command, &body);
            if let Some(maker) = self.makers.get_mut(&to) {
                for out in maker.handle(&from, cmd, &self.chain, NOW) {
                    self.queue.push_back((to.clone(), out));
                }
            } else {
                let (outs, now) = self.taker.handle(&from, cmd, &self.chain)?;
                progress = now;
                self.queue
                    .extend(outs.into_iter().map(|o| ("J5taker".to_string(), o)));
            }
        }
        Ok(progress)
    }

    fn send(&mut self, outs: Vec<Outgoing>) {
        self.queue
            .extend(outs.into_iter().map(|o| ("J5taker".to_string(), o)));
    }

    /// Take the queued lines to `nick` out of the queue, to deliver late.
    fn hold(&mut self, nick: &str) -> Vec<(String, Outgoing)> {
        let (held, rest): (Vec<_>, Vec<_>) = self
            .queue
            .drain(..)
            .partition(|(_, out)| matches!(out, Outgoing::Private { to, .. } if to == nick));
        self.queue = rest.into();
        held
    }

    /// `MAKER_C` as a maker whose `!ioauth` decrypts and is nonsense: only it could have written that.
    fn bad_ioauth(&mut self) -> Result<(Vec<Outgoing>, Progress), TakerError> {
        let key = vortex_ng_core::nacl::NaclKeypair::generate();
        let pubkey = to_command("pubkey", &key.public_hex());
        let (auth, _) = self.taker.handle(MAKER_C, pubkey, &self.chain).unwrap();
        assert_eq!(auth.len(), 1);
        let session = key.session(&self.taker.nacl.public_hex()).unwrap();
        let ioauth = Command::Encrypted {
            name: "ioauth".into(),
            ciphertext: session.encrypt("not an ioauth").unwrap(),
        };
        self.taker.handle(MAKER_C, ioauth, &self.chain)
    }

    /// The finished round has the taker and two makers in it, each with an equal output.
    fn assert_two_makers_signed(mut self) {
        assert_eq!(self.taker.makers_in_round(), 2);
        let tx = self.taker.finish(&self.wallet).unwrap();
        assert_eq!(tx.input.len(), 3);
        assert!(tx.input.iter().all(|i| !i.witness.is_empty()));
        let equal = tx
            .output
            .iter()
            .filter(|o| o.value.to_sat() == AMOUNT)
            .count();
        assert_eq!(equal, 3);
    }
}

#[test]
fn a_silent_maker_is_left_out_once_its_time_is_up() {
    let mut round = round_of_three(2);
    assert_eq!(round.carry(&[MAKER_C]).unwrap(), Progress::Waiting);
    let txs = round.taker.go_on_without_silent(&round.chain).unwrap();
    assert_eq!(txs.len(), 2, "one !tx for each maker that answered");
    round.send(txs);
    assert_eq!(round.carry(&[]).unwrap(), Progress::MakersSigned);
    round.assert_two_makers_signed();
}

#[test]
fn by_default_a_round_waits_for_every_maker() {
    let mut round = round_of_three(3);
    let late = round.hold(MAKER_C);
    assert_eq!(round.carry(&[]).unwrap(), Progress::Waiting);
    assert!(
        round
            .taker
            .go_on_without_silent(&round.chain)
            .unwrap()
            .is_empty()
    );
    assert_eq!(round.taker.makers_in_round(), 3);
    round.queue.extend(late);
    assert_eq!(round.carry(&[]).unwrap(), Progress::MakersSigned);
    let tx = round.taker.finish(&round.wallet).unwrap();
    assert_eq!(tx.input.len(), 4);
}

#[test]
fn too_few_answers_wait_for_a_late_one() {
    let mut round = round_of_three(2);
    let late_b = round.hold("J5makerB");
    let _never = round.hold(MAKER_C);
    assert_eq!(round.carry(&[]).unwrap(), Progress::Waiting);
    // One answer of the two needed: nobody is dropped yet.
    assert!(
        round
            .taker
            .go_on_without_silent(&round.chain)
            .unwrap()
            .is_empty()
    );
    assert_eq!(round.taker.makers_in_round(), 3);
    round.queue.extend(late_b);
    assert_eq!(round.carry(&[]).unwrap(), Progress::Waiting);
    let txs = round.taker.go_on_without_silent(&round.chain).unwrap();
    assert_eq!(txs.len(), 2);
    round.send(txs);
    assert_eq!(round.carry(&[]).unwrap(), Progress::MakersSigned);
    round.assert_two_makers_signed();
}

#[test]
fn a_maker_whose_ioauth_does_not_hold_up_is_left_out() {
    // It fails first: the others then finish the round.
    let mut round = round_of_three(2);
    let (outs, _) = round.bad_ioauth().unwrap();
    assert!(outs.is_empty());
    assert_eq!(round.taker.makers_in_round(), 2);
    assert_eq!(round.carry(&[MAKER_C]).unwrap(), Progress::MakersSigned);
    round.assert_two_makers_signed();

    // It fails last: dropping it is what lets the transaction go out.
    let mut round = round_of_three(2);
    assert_eq!(round.carry(&[MAKER_C]).unwrap(), Progress::Waiting);
    let (txs, _) = round.bad_ioauth().unwrap();
    assert_eq!(txs.len(), 2);
    round.send(txs);
    assert_eq!(round.carry(&[]).unwrap(), Progress::MakersSigned);
    round.assert_two_makers_signed();

    // Without room to lose it, the round ends and names it.
    let mut round = round_of_three(3);
    match round.bad_ioauth() {
        Err(TakerError::Maker(nick, _)) => assert_eq!(nick, MAKER_C),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_maker_that_says_error_is_left_out_and_not_heard_again() {
    let mut round = round_of_three(2);
    assert_eq!(round.carry(&[MAKER_C]).unwrap(), Progress::Waiting);
    let (txs, _) = round
        .taker
        .handle(MAKER_C, Command::Error("no".into()), &round.chain)
        .unwrap();
    assert_eq!(txs.len(), 2);
    let pubkey = to_command("pubkey", &"ab".repeat(32));
    let (outs, _) = round.taker.handle(MAKER_C, pubkey, &round.chain).unwrap();
    assert!(outs.is_empty(), "no !auth for a maker that left the round");
    round.send(txs);
    assert_eq!(round.carry(&[]).unwrap(), Progress::MakersSigned);
    round.assert_two_makers_signed();
}

#[test]
fn once_the_transaction_is_out_every_maker_in_it_is_needed() {
    let mut round = round_of_three(1);
    assert_eq!(round.carry(&[MAKER_C]).unwrap(), Progress::Waiting);
    assert_eq!(
        round
            .taker
            .go_on_without_silent(&round.chain)
            .unwrap()
            .len(),
        2
    );
    assert!(round.taker.unsigned_tx().is_some());
    let failed = round
        .taker
        .handle("J5makerA", Command::Error("no".into()), &round.chain);
    assert!(matches!(failed, Err(TakerError::Maker(..))), "{failed:?}");
    assert_eq!(round.taker.makers_in_round(), 2);
}

#[test]
fn two_makers_claiming_one_coin_both_leave() {
    // Which of them lied cannot be told, so neither stays: the first to claim a coin gains nothing.
    let mut round = round_with(1, true);
    assert_eq!(round.carry(&[]).unwrap(), Progress::MakersSigned);
    assert_eq!(round.taker.makers_in_round(), 1);
    let tx = round.taker.finish(&round.wallet).unwrap();
    assert_eq!(tx.input.len(), 2, "the taker and the one maker left");

    // Without room to lose both, the round ends.
    let mut round = round_with(2, true);
    assert!(matches!(round.carry(&[]), Err(TakerError::Maker(..))));
}

#[test]
fn a_line_the_maker_need_not_have_written_does_not_take_it_out() {
    let mut round = round_of_three(1);
    for cmd in [
        to_command("ioauth", "AAAA"),
        to_command("sig", "AAAA"),
        Command::Pubkey {
            nacl_pubkey: "not a key".into(),
            extensions: Vec::new(),
        },
    ] {
        let (outs, _) = round.taker.handle(MAKER_C, cmd, &round.chain).unwrap();
        assert!(outs.is_empty());
    }
    assert_eq!(round.taker.makers_in_round(), 3);
}

#[test]
fn the_floor_is_between_one_and_the_makers_asked_for() {
    let taker = |min| {
        let mut chain = FakeChain::default();
        let wallet = funded(Pit::Sw0, "taker", 600_000, 20, &mut chain);
        let utxo = wallet.utxos(0).unwrap().remove(0);
        let podle = podle_for(&wallet, 0, &utxo, 0).unwrap();
        let cj = wallet.peek_address(1, false, 0).unwrap().script_pubkey();
        let change = wallet.peek_address(0, true, 0).unwrap().script_pubkey();
        let cfg = TakerConfig {
            makers: 3,
            ..choice_cfg(AMOUNT)
        };
        Taker::new(cfg, 0, vec![(utxo.outpoint, utxo.txout)], podle, cj, change)
            .unwrap()
            .allow_fewer_makers(min)
    };
    assert!(taker(0).is_err());
    assert!(taker(1).is_ok());
    assert!(taker(3).is_ok());
    assert!(taker(4).is_err());
}

#[test]
fn maker_selection() {
    let cfg = TakerConfig {
        pit: Pit::Sw0,
        network: Network::Regtest,
        amount: 100_000,
        makers: 2,
        max_cjfee: 300,
        fee_rate_sat_per_kwu: 1_000,
        max_maker_utxos: 20,
        bondless_makers_allowance: DEFAULT_BONDLESS_ALLOWANCE,
        bondless_require_zero_fee: false,
        bond_params: BondValueParams::default(),
    };
    let o = |cmd: &str, args: &str| Offer::parse(cmd, args).unwrap();
    let offers = vec![
        ("A".to_string(), o("sw0absoffer", "0 10000 1000000 0 250")),
        ("A".to_string(), o("sw0absoffer", "1 10000 1000000 0 200")), // A's cheaper offer
        ("B".to_string(), o("sw0reloffer", "0 10000 1000000 0 0.001")), // 100 sat
        ("C".to_string(), o("sw0absoffer", "0 10000 1000000 0 400")), // above max
        ("D".to_string(), o("tr0absoffer", "0 10000 1000000 0 1")),   // other pit
        ("E".to_string(), o("sw0absoffer", "0 200000 1000000 0 1")),  // amount below minsize
        ("F".to_string(), o("sw0absoffer", "0 10000 1000000 500 100")), // unprofitable for the maker
    ];
    let chosen = select_makers(&offers, &HashMap::new(), &cfg);
    let names: Vec<&str> = chosen.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["B", "A"]);
    assert_eq!(chosen[1].1.oid, 1);
}

#[test]
fn a_maker_reusing_a_round_address_is_rejected() {
    let pit = Pit::Sw0;
    let mut chain = FakeChain::default();
    let maker_wallet = funded(pit, "J5makerA", 500_000, 10, &mut chain);
    let mut maker = Maker::new(MakerConfig::new(vec![offer(pit, 0)]), maker_wallet).unwrap();
    let mut taker_wallet = funded(pit, "taker", 600_000, 20, &mut chain);
    let utxo = taker_wallet.utxos(0).unwrap().remove(0);
    let podle = podle_for(&taker_wallet, 0, &utxo, 0).unwrap();
    let cfg = TakerConfig {
        pit,
        network: Network::Regtest,
        amount: AMOUNT,
        makers: 1,
        max_cjfee: 1_000,
        fee_rate_sat_per_kwu: 2_500,
        max_maker_utxos: 20,
        bondless_makers_allowance: DEFAULT_BONDLESS_ALLOWANCE,
        bondless_require_zero_fee: false,
        bond_params: BondValueParams::default(),
    };
    // The taker's own coinjoin address is the one the maker will announce as its change (simulated by
    // taking the maker wallet's next change address, which the maker hands out at !auth).
    let maker_change = maker
        .wallet_mut()
        .peek_address(0, true, 0)
        .unwrap()
        .script_pubkey();
    let change = taker_wallet.next_change_address(0).unwrap().script_pubkey();
    let mut taker = Taker::new(
        cfg,
        0,
        vec![(utxo.outpoint, utxo.txout.clone())],
        podle,
        maker_change,
        change,
    )
    .unwrap();
    let mut queue: VecDeque<(String, Outgoing)> = taker
        .start(vec![("J5makerA".to_string(), offer(pit, 0))])
        .unwrap()
        .into_iter()
        .map(|o| ("J5taker".to_string(), o))
        .collect();
    let mut failure = None;
    while let Some((from, Outgoing::Private { to, command, body })) = queue.pop_front() {
        let cmd = to_command(&command, &body);
        if to == "J5makerA" {
            queue.extend(
                maker
                    .handle(&from, cmd, &chain, NOW)
                    .into_iter()
                    .map(|o| ("J5makerA".to_string(), o)),
            );
        } else {
            match taker.handle(&from, cmd, &chain) {
                Ok((outs, _)) => queue.extend(outs.into_iter().map(|o| ("J5taker".to_string(), o))),
                Err(e) => failure = Some(e),
            }
        }
    }
    assert_eq!(
        failure,
        Some(TakerError::Maker(
            "J5makerA".into(),
            "address already used in this round".into()
        ))
    );
}

#[test]
fn bonds_are_verified_against_the_chain() {
    use vortex_ng_core::bitcoin::secp256k1::PublicKey;
    use vortex_ng_core::bond::{BondTemplate, freeze_script, timenumber_locktime};
    let secp = Secp256k1::new();
    let utxo_key = SecretKey::from_slice(&[3; 32]).unwrap();
    let locktime = timenumber_locktime(120).unwrap();
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([4; 32]),
        vout: 1,
    };
    let spk = ScriptBuf::new_p2wsh(
        &freeze_script(&PublicKey::from_secret_key(&secp, &utxo_key), locktime).wscript_hash(),
    );
    let proof = BondTemplate::new(&secp, &utxo_key, outpoint, locktime, 300)
        .proof(&secp, "J5taker", "J5maker")
        .to_base64()
        .unwrap();
    let params = BondValueParams::default();
    let mut chain = FakeChain::default();
    // Missing UTXO.
    assert!(verify_bond(&proof, "J5taker", "J5maker", &chain, 300, NOW, params).is_err());
    chain.utxos.insert(
        outpoint,
        Utxo {
            value: Amount::from_sat(2_000_000),
            script_pubkey: spk.clone(),
            confirmations: 10,
            coinbase: false,
        },
    );
    let bond = verify_bond(&proof, "J5taker", "J5maker", &chain, 300, NOW, params).unwrap();
    // Confirmed in block 291 (tip 300, 10 confirmations).
    let expected = bond_value(
        2_000_000,
        1_700_000_000 + 291 * 600,
        u64::from(locktime),
        NOW,
        params,
    );
    assert_eq!(
        bond,
        VerifiedBond {
            outpoint,
            value: expected
        }
    );
    assert!(bond.value > 0);
    // A proof made for another taker, or shown by another maker nick, is refused.
    assert!(verify_bond(&proof, "J5other", "J5maker", &chain, 300, NOW, params).is_err());
    assert!(verify_bond(&proof, "J5taker", "J5thief", &chain, 300, NOW, params).is_err());
    // A UTXO paying anything but the freeze script, or unconfirmed, is refused.
    chain.utxos.get_mut(&outpoint).unwrap().confirmations = 0;
    assert!(verify_bond(&proof, "J5taker", "J5maker", &chain, 300, NOW, params).is_err());
    let u = chain.utxos.get_mut(&outpoint).unwrap();
    u.confirmations = 10;
    u.script_pubkey = ScriptBuf::new_p2wsh(
        &freeze_script(&PublicKey::from_secret_key(&secp, &utxo_key), locktime + 1).wscript_hash(),
    );
    assert!(verify_bond(&proof, "J5taker", "J5maker", &chain, 300, NOW, params).is_err());
}

#[test]
fn selection_is_weighted_by_bond_value() {
    let o = |cmd: &str, args: &str| Offer::parse(cmd, args).unwrap();
    let bond = |byte: u8, value: u64| VerifiedBond {
        outpoint: OutPoint {
            txid: Txid::from_byte_array([byte; 32]),
            vout: 0,
        },
        value,
    };
    let offers = vec![
        ("A".to_string(), o("sw0absoffer", "0 10000 1000000 0 100")),
        ("B".to_string(), o("sw0absoffer", "0 10000 1000000 0 150")),
        ("C".to_string(), o("sw0absoffer", "0 10000 1000000 0 50")), // bondless, charges a fee
        ("D".to_string(), o("sw0absoffer", "0 10000 1000000 0 0")),  // bondless, free
        ("E".to_string(), o("sw0absoffer", "0 10000 1000000 0 120")), // shows B's bond, cheaper
    ];
    let bonds: HashMap<String, VerifiedBond> = [
        ("A".to_string(), bond(1, 1_000)),
        ("B".to_string(), bond(2, 3_000)),
        ("E".to_string(), bond(2, 3_000)),
    ]
    .into();
    let mut cfg = TakerConfig {
        pit: Pit::Sw0,
        network: Network::Regtest,
        amount: 100_000,
        makers: 1,
        max_cjfee: 1_000,
        fee_rate_sat_per_kwu: 1_000,
        max_maker_utxos: 20,
        bondless_makers_allowance: DEFAULT_BONDLESS_ALLOWANCE,
        bondless_require_zero_fee: true,
        bond_params: BondValueParams::default(),
    };
    // xorshift64*: deterministic, so the counts are reproducible.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut rng = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let mut counts: HashMap<String, u32> = HashMap::new();
    let runs = 4_000;
    for _ in 0..runs {
        for (nick, _) in select_makers_with(&offers, &bonds, &cfg, &mut rng) {
            *counts.entry(nick).or_default() += 1;
        }
    }
    let share = |n: &str| f64::from(counts.get(n).copied().unwrap_or(0)) / f64::from(runs);
    // B is dropped for E (same bond, cheaper); C is bondless and charges a fee.
    assert_eq!(share("B"), 0.0);
    assert_eq!(share("C"), 0.0);
    // E: 0.95 * 3/4; A: 0.95 * 1/4; D only through the 5 % allowance.
    assert!((0.66..0.77).contains(&share("E")), "E {}", share("E"));
    assert!((0.19..0.29).contains(&share("A")), "A {}", share("A"));
    assert!((0.02..0.09).contains(&share("D")), "D {}", share("D"));

    // Without the zero-fee rule a bondless maker charging a fee may fill an allowance slot.
    cfg.bondless_require_zero_fee = false;
    cfg.bondless_makers_allowance = 1.0;
    let mut seen_c = false;
    for _ in 0..200 {
        seen_c |= select_makers_with(&offers, &bonds, &cfg, &mut rng)
            .iter()
            .any(|(n, _)| n == "C");
    }
    assert!(seen_c);
    // Too few qualify: every one is taken, cheapest first.
    cfg.bondless_require_zero_fee = true;
    cfg.makers = 3;
    let all: Vec<String> = select_makers_with(&offers, &bonds, &cfg, &mut rng)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(all, ["D", "A", "E"]);
}

#[test]
fn candidate_nicks_are_the_makers_selection_would_consider() {
    let o = |cmd: &str, args: &str| Offer::parse(cmd, args).unwrap();
    let offers = vec![
        ("A".to_string(), o("sw0absoffer", "0 10000 1000000 0 250")),
        ("A".to_string(), o("sw0absoffer", "1 10000 1000000 0 200")),
        ("C".to_string(), o("sw0absoffer", "0 10000 1000000 0 400")), // above max_cjfee
        ("D".to_string(), o("tr0absoffer", "0 10000 1000000 0 1")),   // other pit
        ("E".to_string(), o("sw0absoffer", "0 200000 1000000 0 1")),  // amount below minsize
    ];
    let cfg = TakerConfig {
        pit: Pit::Sw0,
        network: Network::Regtest,
        amount: 100_000,
        makers: 2,
        max_cjfee: 300,
        fee_rate_sat_per_kwu: 1_000,
        max_maker_utxos: 20,
        bondless_makers_allowance: DEFAULT_BONDLESS_ALLOWANCE,
        bondless_require_zero_fee: true,
        bond_params: BondValueParams::default(),
    };
    assert_eq!(
        candidate_nicks(&offers, &cfg),
        HashSet::from(["A".to_string()])
    );
}

fn coin(byte: u8, value: u64, confirmations: u32) -> Coin {
    use vortex_ng_wallet::bdk_wallet::KeychainKind;
    use vortex_ng_wallet::bdk_wallet::chain::ChainPosition;

    Coin {
        utxo: LocalOutput {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([byte; 32]),
                vout: 0,
            },
            txout: TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new(),
            },
            keychain: KeychainKind::External,
            is_spent: false,
            derivation_index: u32::from(byte),
            chain_position: ChainPosition::Unconfirmed {
                first_seen: None,
                last_seen: None,
            },
        },
        confirmations,
    }
}

fn choice_cfg(amount: u64) -> TakerConfig {
    TakerConfig {
        pit: Pit::Sw0,
        network: Network::Regtest,
        amount,
        makers: 2,
        max_cjfee: 1_000,
        fee_rate_sat_per_kwu: 2_500,
        max_maker_utxos: 20,
        bondless_makers_allowance: DEFAULT_BONDLESS_ALLOWANCE,
        bondless_require_zero_fee: true,
        bond_params: BondValueParams::default(),
    }
}

#[test]
fn the_cost_estimate_counts_maker_fees_and_the_whole_mining_fee() {
    let cfg = choice_cfg(1_000_000);
    // Two makers at 1,000 each; 1 + 2 * 3 inputs and 3 * 2 outputs of sw0 at 2.5 sat per weight unit.
    let weight = 42 + 7 * 272 + 6 * 124;
    assert_eq!(
        estimated_cost(&cfg, 1, ASSUMED_MAKER_INPUTS),
        2_000 + (weight * 2_500u64).div_ceil(1000)
    );
    // One more input of ours costs its weight.
    assert_eq!(
        estimated_cost(&cfg, 2, ASSUMED_MAKER_INPUTS)
            - estimated_cost(&cfg, 1, ASSUMED_MAKER_INPUTS),
        680
    );
    // Absurd settings saturate instead of wrapping.
    let absurd = TakerConfig {
        max_cjfee: u64::MAX,
        fee_rate_sat_per_kwu: u64::MAX,
        ..cfg
    };
    assert_eq!(estimated_cost(&absurd, usize::MAX, usize::MAX), u64::MAX);
}

#[test]
fn coins_are_chosen_for_the_commitment_first_and_no_more_than_needed() {
    let ids = |coins: &[Coin]| -> Vec<u8> {
        coins
            .iter()
            .map(|c| c.utxo.outpoint.txid.to_byte_array()[0])
            .collect()
    };
    let cfg = choice_cfg(1_000_000);

    // One coin covers it: only that coin, though others are there.
    let chosen = choose_coins(
        &cfg,
        vec![
            coin(1, 300_000, 10),
            coin(2, 5_000_000, 10),
            coin(3, 900_000, 10),
        ],
    )
    .unwrap();
    assert_eq!(ids(&chosen), [2]);

    // The largest coin is too young to commit to: the largest that is fit comes first, then the
    // largest of the rest until the round is covered.
    let chosen = choose_coins(
        &cfg,
        vec![
            coin(1, 300_000, 10),
            coin(2, 600_000, 4),
            coin(3, 250_000, 5),
            coin(4, 200_000, 100),
        ],
    )
    .unwrap();
    assert_eq!(ids(&chosen), [1, 2, 3]);

    // A coin worth less than a fifth of the amount cannot carry the commitment, however old.
    assert!(!coin(1, 199_999, 100).fit_to_commit(1_000_000));
    assert!(coin(1, 200_000, 5).fit_to_commit(1_000_000));
    let none = choose_coins(&cfg, vec![coin(1, 5_000_000, 4), coin(2, 199_999, 100)]);
    assert!(matches!(none, Err(TakerError::Funds(why)) if why.contains("no coin to commit to")));
    assert!(matches!(
        choose_coins(&cfg, Vec::new()),
        Err(TakerError::Funds(_))
    ));

    // Not enough in all: said with both numbers. Exactly enough is enough.
    let need = 1_000_000 + estimated_cost(&cfg, 2, ASSUMED_MAKER_INPUTS);
    let short = choose_coins(
        &cfg,
        vec![coin(1, 600_000, 10), coin(2, need - 600_001, 10)],
    );
    assert!(
        matches!(&short, Err(TakerError::Funds(why)) if why.contains(&format!("needs about {need}"))),
        "{short:?}"
    );
    let exact = choose_coins(
        &cfg,
        vec![coin(1, 600_000, 10), coin(2, need - 600_000, 10)],
    )
    .unwrap();
    assert_eq!(exact.len(), 2);
}
