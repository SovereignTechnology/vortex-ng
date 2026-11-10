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
fn coinjoin(pit: Pit) -> (Transaction, PitWallet) {
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
    let mut progress = Progress::Waiting;
    while let Some((from, message)) = queue.pop_front() {
        let Outgoing::Private { to, command, body } = message else {
            continue;
        };
        let cmd = to_command(&command, &body);
        if let Some(maker) = makers.get_mut(&to) {
            for out in maker.handle(&from, cmd, &chain, NOW) {
                queue.push_back((to.clone(), out));
            }
        } else {
            assert_eq!(to, "J5taker");
            let (outs, p) = taker.handle(&from, cmd, &chain).unwrap();
            progress = p;
            queue.extend(outs.into_iter().map(|o| ("J5taker".to_string(), o)));
        }
    }
    assert_eq!(progress, Progress::MakersSigned, "{pit:?}");
    // Here a channel's funding_signed would be awaited; then the taker signs last.
    let tx = taker.finish(&taker_wallet).unwrap();
    taker_wallet.utxos(0).unwrap();
    (tx, taker_wallet)
}

fn check(pit: Pit) {
    let (tx, _) = coinjoin(pit);
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
