//! A whole maker session against a simulated taker and a fake chain: `!fill` → `!pubkey`, `!auth` →
//! `!ioauth` + `!hp2`, `!tx` → `!sig`, with the taker's own checks of `!ioauth` and every `!sig`.

use std::collections::HashMap;
use std::str::FromStr;

use vortex_ng_core::bitcoin::block::{Header, Version as BlockVersion};
use vortex_ng_core::bitcoin::blockdata::constants::genesis_block;
use vortex_ng_core::bitcoin::consensus::encode::serialize;
use vortex_ng_core::bitcoin::hashes::Hash;
use vortex_ng_core::bitcoin::secp256k1::SecretKey;
use vortex_ng_core::bitcoin::transaction::Version;
use vortex_ng_core::bitcoin::{
    Address, Amount, Block, CompactTarget, CompressedPublicKey, Network, Sequence, TxIn,
    TxMerkleNode, Witness, absolute,
};
use vortex_ng_core::command::{Command, Ioauth};
use vortex_ng_core::podle::generate;
use vortex_ng_core::sig::verify_sig;
use vortex_ng_wallet::Seed;

use vortex_ng_chain::Utxo;

use super::*;

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const NOW: u64 = 1_800_000_000;
const AMOUNT: u64 = 400_000;

struct FakeChain {
    utxos: HashMap<OutPoint, Utxo>,
    tip: u32,
}

impl Chain for FakeChain {
    fn utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, String> {
        Ok(self.utxos.get(outpoint).cloned())
    }
    fn tip_height(&self) -> Result<u32, String> {
        Ok(self.tip)
    }
    fn block_time(&self, height: u32) -> Result<u32, String> {
        Ok(1_700_000_000 + height * 600)
    }
}

fn spend(txid_byte: u8) -> TxIn {
    TxIn {
        previous_output: OutPoint {
            txid: Txid::from_byte_array([txid_byte; 32]),
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

fn maker_wallet() -> PitWallet {
    PitWallet::new(
        &Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap(),
        Pit::Sw0,
    )
    .unwrap()
}

/// The transaction that pays the maker its two coins.
fn maker_funding(wallet: &mut PitWallet) -> Transaction {
    let a = wallet.next_receive_address(0).unwrap().script_pubkey();
    let b = wallet.next_receive_address(0).unwrap().script_pubkey();
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![spend(1)],
        output: vec![
            TxOut {
                value: Amount::from_sat(500_000),
                script_pubkey: a,
            },
            TxOut {
                value: Amount::from_sat(300_000),
                script_pubkey: b,
            },
        ],
    }
}

/// The maker's two coins as the node has them: unspent, 10 confirmations.
fn maker_coins() -> Vec<(OutPoint, Utxo)> {
    let funding = maker_funding(&mut maker_wallet());
    let txid = funding.compute_txid();
    funding
        .output
        .iter()
        .enumerate()
        .map(|(vout, out)| {
            (
                OutPoint {
                    txid,
                    vout: vout as u32,
                },
                Utxo {
                    value: out.value,
                    script_pubkey: out.script_pubkey.clone(),
                    confirmations: 10,
                    coinbase: false,
                },
            )
        })
        .collect()
}

/// A maker whose mixdepth 0 holds 500,000 and 300,000 sats, confirmed.
fn funded_maker() -> Maker {
    let mut wallet = maker_wallet();
    let funding = maker_funding(&mut wallet);
    let genesis = genesis_block(Network::Regtest);
    let block = Block {
        header: Header {
            version: BlockVersion::TWO,
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: genesis.header.time + 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![funding],
    };
    wallet.apply_block(&block, 1).unwrap();
    let offer = Offer::parse("sw0reloffer", "0 10000 10000000 100 0.001").unwrap();
    Maker::new(MakerConfig::new(vec![offer]), wallet).unwrap()
}

struct Taker {
    key: SecretKey,
    utxo: OutPoint,
    nacl: NaclKeypair,
}

fn new_taker() -> (Taker, FakeChain) {
    let key = SecretKey::from_slice(&[42; 32]).unwrap();
    let public = PublicKey::from_secret_key(&Secp256k1::new(), &key);
    let utxo = OutPoint {
        txid: Txid::from_byte_array([77; 32]),
        vout: 0,
    };
    let spk = ScriptBuf::new_p2wpkh(&CompressedPublicKey(public).wpubkey_hash());
    let mut chain = FakeChain {
        utxos: HashMap::from([(
            utxo,
            Utxo {
                value: Amount::from_sat(1_000_000),
                script_pubkey: spk,
                confirmations: 10,
                coinbase: false,
            },
        )]),
        tip: 200,
    };
    // The node also has the maker's own coins: a maker offers only coins the node shows unspent.
    chain.utxos.extend(maker_coins());
    (
        Taker {
            key,
            utxo,
            nacl: NaclKeypair::generate(),
        },
        chain,
    )
}

fn private(out: &Outgoing) -> (&str, &str) {
    match out {
        Outgoing::Private { command, body, .. } => (command, body),
        Outgoing::PublicEphemeral(_) | Outgoing::Broadcast(_) => {
            panic!("expected a private message")
        }
    }
}

#[test]
fn full_session_signs_a_valid_coinjoin() {
    let secp = Secp256k1::new();
    let mut maker = funded_maker();
    let (taker, chain) = new_taker();
    let podle = generate(&secp, &taker.key, &taker.utxo.to_string(), 0, None).unwrap();

    // !fill -> !pubkey
    let fill = Command::Fill {
        oid: 0,
        amount: AMOUNT,
        nacl_pubkey: taker.nacl.public_hex(),
        commitment: podle.commitment(),
    };
    let out = maker.handle("J5taker", fill, &chain, NOW);
    let (cmd, maker_nacl) = private(&out[0]);
    assert_eq!(cmd, "pubkey");
    let session = taker.nacl.session(maker_nacl).unwrap();

    // !auth -> !ioauth + !hp2
    let auth = Command::Encrypted {
        name: "auth".into(),
        ciphertext: session.encrypt(&podle.revelation()).unwrap(),
    };
    let out = maker.handle("J5taker", auth, &chain, NOW);
    assert_eq!(out.len(), 2);
    let (cmd, ciphertext) = private(&out[0]);
    assert_eq!(cmd, "ioauth");
    assert_eq!(
        out[1],
        Outgoing::PublicEphemeral(format!("!hp2 {}", podle.commitment().to_lower_hex_string()))
    );
    let ioauth = Ioauth::parse(&session.decrypt(ciphertext).unwrap()).unwrap();
    // The taker's checks: the auth key signed the maker's own NaCl key (not the taker's) and controls
    // a declared UTXO.
    assert!(!sigmsg::verify(
        &secp,
        taker.nacl.public_hex().as_bytes(),
        &ioauth.btc_signature,
        &ioauth.auth_pubkey
    ));
    assert!(sigmsg::verify(
        &secp,
        maker_nacl.as_bytes(),
        &ioauth.btc_signature,
        &ioauth.auth_pubkey
    ));
    assert_eq!(
        ioauth.utxos.len(),
        1,
        "the 500,000 UTXO alone covers amount + fee + change threshold"
    );

    // Build the coinjoin: maker input + taker input; equal outputs; both changes.
    let maker_in = ioauth.utxos[0];
    let maker_value = 500_000u64;
    let script = |a: &str| {
        Address::from_str(a)
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap()
            .script_pubkey()
    };
    let taker_out = ScriptBuf::new_p2wpkh(
        &CompressedPublicKey(PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[43; 32]).unwrap(),
        ))
        .wpubkey_hash(),
    );
    let maker_change = maker_value - AMOUNT - 100 + 400;
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::from_consensus(200),
        input: vec![
            TxIn {
                previous_output: maker_in,
                ..spend(0)
            },
            TxIn {
                previous_output: taker.utxo,
                ..spend(0)
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(AMOUNT),
                script_pubkey: script(&ioauth.cj_address),
            },
            TxOut {
                value: Amount::from_sat(maker_change),
                script_pubkey: script(&ioauth.change_address),
            },
            TxOut {
                value: Amount::from_sat(AMOUNT),
                script_pubkey: taker_out.clone(),
            },
            TxOut {
                value: Amount::from_sat(1_000_000 - AMOUNT - 400 - 1_000),
                script_pubkey: taker_out,
            },
        ],
    };
    let tx_b64 = STANDARD.encode(serialize(&tx));
    let out = maker.handle(
        "J5taker",
        Command::Encrypted {
            name: "tx".into(),
            ciphertext: session.encrypt(&tx_b64).unwrap(),
        },
        &chain,
        NOW,
    );
    assert_eq!(out.len(), 1);
    let (cmd, sig_ct) = private(&out[0]);
    assert_eq!(cmd, "sig");
    assert_eq!(maker.progress("J5taker", NOW), 3);
    let payload = session.decrypt(sig_ct).unwrap();
    let prevouts = vec![
        maker
            .wallet
            .utxos(0)
            .unwrap()
            .into_iter()
            .find(|u| u.outpoint == maker_in)
            .unwrap()
            .txout,
        TxOut {
            value: Amount::from_sat(1_000_000),
            script_pubkey: chain.utxos[&taker.utxo].script_pubkey.clone(),
        },
    ];
    verify_sig(&secp, Pit::Sw0, &payload, &tx, 0, &prevouts).unwrap();
    assert!(maker.push_allowed("J5taker", &tx));

    // !push: only the transaction we signed, only from the taker we signed it for, only once.
    let push = |tx: &Transaction| Command::Push(STANDARD.encode(serialize(tx)));
    let mut other = tx.clone();
    other.output[0].value = Amount::from_sat(1);
    assert!(
        maker
            .handle("J5taker", push(&other), &chain, NOW)
            .is_empty()
    );
    assert!(maker.handle("J5other", push(&tx), &chain, NOW).is_empty());
    assert!(
        maker
            .handle("J5taker", Command::Push("not base64!".into()), &chain, NOW)
            .is_empty()
    );
    assert_eq!(
        maker.handle("J5taker", push(&tx), &chain, NOW),
        vec![Outgoing::Broadcast(tx.clone())]
    );
    assert!(maker.handle("J5taker", push(&tx), &chain, NOW).is_empty());
}

#[test]
fn sessions_expire_and_never_block_new_takers() {
    let mut maker = funded_maker();
    let (_, chain) = new_taker();
    let fill = |i: usize| Command::Fill {
        oid: 0,
        amount: AMOUNT,
        nacl_pubkey: NaclKeypair::generate().public_hex(),
        commitment: numbered_commitment(i),
    };
    // The table fills with takers that never continue. More of them than could ever finish a round fit, so
    // a burst between a real taker's `!fill` and its `!auth` does not push it out.
    for i in 0..MAX_WAITING_SESSIONS {
        let out = maker.handle(&format!("J5quiet{i}"), fill(i), &chain, NOW);
        assert_eq!(private(&out[0]).0, "pubkey", "fill {i}");
        if i == MAX_SESSIONS {
            assert!(maker.in_session("J5quiet0", NOW), "past the old limit");
        }
    }
    // A full table does not lock a new taker out: one session waiting for `!auth` gives way.
    let out = maker.handle("J5late", fill(MAX_WAITING_SESSIONS), &chain, NOW + 1);
    assert_eq!(private(&out[0]).0, "pubkey", "a new taker is served");
    assert_eq!(maker.sessions.len(), MAX_WAITING_SESSIONS);
    assert!(maker.in_session("J5late", NOW + 1));
    // Once they are out of time they no longer count as open, before anything has pruned them.
    assert!(!maker.in_session("J5late", NOW + 1 + FILLED_TTL + 1));
    let later = fill(MAX_WAITING_SESSIONS + 1);
    let out = maker.handle("J5later", later, &chain, NOW + FILLED_TTL + 2);
    assert_eq!(private(&out[0]).0, "pubkey");
    assert_eq!(maker.sessions.len(), 1);
    assert_eq!(maker.started.len(), 1);
}

fn numbered_commitment(i: usize) -> [u8; 32] {
    let mut commitment = [0x5a; 32];
    commitment[..8].copy_from_slice(&(i as u64).to_be_bytes());
    commitment
}

#[test]
fn one_commitment_opens_one_session() {
    let mut maker = funded_maker();
    let (_, chain) = new_taker();
    let fill = || Command::Fill {
        oid: 0,
        amount: AMOUNT,
        nacl_pubkey: NaclKeypair::generate().public_hex(),
        commitment: numbered_commitment(1),
    };
    let out = maker.handle("J5first", fill(), &chain, NOW);
    assert_eq!(private(&out[0]).0, "pubkey");
    // The same commitment under another nick gets nothing, and the first session is left alone.
    assert!(maker.handle("J5copy", fill(), &chain, NOW).is_empty());
    assert!(!maker.in_session("J5copy", NOW));
    assert!(maker.in_session("J5first", NOW));
}

#[test]
fn a_flood_of_announcements_cannot_free_a_verified_commitment() {
    let key = |i: usize| {
        let mut c = [0xee; 32];
        c[..8].copy_from_slice(&(i as u64).to_be_bytes());
        c
    };
    let mut commitments = Commitments::default();
    commitments.insert_verified([1; 32]);
    for i in 0..=MAX_COMMITMENTS {
        commitments.insert(key(i));
    }
    assert!(commitments.contains(&[1; 32]), "still refused");
    assert!(!commitments.contains(&key(0)), "announcements are bounded");
    assert!(!commitments.insert([1; 32]), "not new");
}

#[test]
fn a_line_relabelled_to_another_step_leaves_the_session() {
    let secp = Secp256k1::new();
    let (taker, chain) = new_taker();
    let podle = generate(&secp, &taker.key, &taker.utxo.to_string(), 0, None).unwrap();
    let mut maker = funded_maker();
    let fill = Command::Fill {
        oid: 0,
        amount: AMOUNT,
        nacl_pubkey: taker.nacl.public_hex(),
        commitment: podle.commitment(),
    };
    let out = maker.handle("J5taker", fill, &chain, NOW);
    let session = taker.nacl.session(private(&out[0]).1).unwrap();
    let encrypted = |name: &str, text: &str| Command::Encrypted {
        name: name.into(),
        ciphertext: session.encrypt(text).unwrap(),
    };
    // It decrypts, but is not a revelation: nothing happens, and the real `!auth` still works.
    assert!(
        maker
            .handle(
                "J5taker",
                encrypted("auth", "not a revelation"),
                &chain,
                NOW
            )
            .is_empty()
    );
    let out = maker.handle(
        "J5taker",
        encrypted("auth", &podle.revelation()),
        &chain,
        NOW,
    );
    assert_eq!(private(&out[0]).0, "ioauth");
    // The `!auth` again, relabelled `!tx`: it decrypts, is no transaction, and ends nothing.
    assert!(
        maker
            .handle("J5taker", encrypted("tx", &podle.revelation()), &chain, NOW)
            .is_empty()
    );
    assert!(matches!(
        maker.sessions.get("J5taker"),
        Some(Stage::Authed(_))
    ));
}

/// Run `!fill` and `!auth` for `amount`: the maker's `!ioauth`, or `None` when it refused.
fn auth_round(maker: &mut Maker, taker: &Taker, chain: &FakeChain, amount: u64) -> Option<Ioauth> {
    let secp = Secp256k1::new();
    let podle = generate(&secp, &taker.key, &taker.utxo.to_string(), 0, None).unwrap();
    let fill = Command::Fill {
        oid: 0,
        amount,
        nacl_pubkey: taker.nacl.public_hex(),
        commitment: podle.commitment(),
    };
    let out = maker.handle("J5taker", fill, chain, NOW);
    let (cmd, maker_nacl) = private(&out[0]);
    if cmd != "pubkey" {
        return None;
    }
    let session = taker.nacl.session(maker_nacl).unwrap();
    let auth = Command::Encrypted {
        name: "auth".into(),
        ciphertext: session.encrypt(&podle.revelation()).unwrap(),
    };
    let out = maker.handle("J5taker", auth, chain, NOW);
    let (cmd, ciphertext) = private(&out[0]);
    (cmd == "ioauth").then(|| Ioauth::parse(&session.decrypt(ciphertext).unwrap()).unwrap())
}

#[test]
fn coins_the_node_shows_spent_are_passed_over() {
    let coins: Vec<OutPoint> = maker_coins().into_iter().map(|(coin, _)| coin).collect();
    // Both of the maker's coins are unspent: the 500,000 covers a 200,000 round alone.
    let (taker, chain) = new_taker();
    let ioauth = auth_round(&mut funded_maker(), &taker, &chain, 200_000).unwrap();
    assert_eq!(ioauth.utxos, vec![coins[0]]);

    // The node shows the 500,000 spent (say, in a round this maker signed a moment ago, not yet in a
    // block, so the wallet still lists it): the 300,000 is used instead.
    let (taker, mut chain) = new_taker();
    chain.utxos.remove(&coins[0]);
    let ioauth = auth_round(&mut funded_maker(), &taker, &chain, 200_000).unwrap();
    assert_eq!(ioauth.utxos, vec![coins[1]]);

    // What is left cannot cover a 400,000 round: refused, rather than offering a spent coin.
    assert!(auth_round(&mut funded_maker(), &taker, &chain, 400_000).is_none());
    // With both unspent the same round takes both coins.
    let (taker, chain) = new_taker();
    let ioauth = auth_round(&mut funded_maker(), &taker, &chain, 500_000).unwrap();
    assert_eq!(ioauth.utxos.len(), 2);
}

#[test]
fn liquidity_and_offers_follow_the_wallet() {
    let mut maker = funded_maker();
    // One round spends from one mixdepth; both coins are in mixdepth 0.
    assert_eq!(maker.liquidity().unwrap(), 800_000);
    assert_eq!(maker.offers().len(), 1);

    let offer = Offer::parse("sw0absoffer", "0 20000 700000 0 250").unwrap();
    maker.set_offers(vec![offer.clone()]).unwrap();
    assert_eq!(maker.offers(), [offer]);
    // Another pit's offer is refused and changes nothing.
    let other = Offer::parse("tr0absoffer", "0 20000 700000 0 250").unwrap();
    assert!(maker.set_offers(vec![other]).is_err());
    assert_eq!(maker.offers().len(), 1);
    // No offers: nothing is said to a taker that asks.
    maker.set_offers(Vec::new()).unwrap();
    assert!(maker.on_orderbook("J5taker", "J5maker").is_empty());
}

#[test]
fn a_commitment_handed_over_privately_is_announced_once_and_sparingly() {
    let mut maker = funded_maker();
    let (taker, chain) = new_taker();
    let hp2 = |c: [u8; 32]| Command::Hp2(c);
    let announce = |c: [u8; 32]| {
        vec![Outgoing::PublicEphemeral(format!(
            "!hp2 {}",
            c.to_lower_hex_string()
        ))]
    };
    // A new commitment from another maker: announced, unlinked from our nick.
    assert_eq!(
        maker.handle("J5other", hp2([1; 32]), &chain, NOW),
        announce([1; 32])
    );
    // The same again, or one already seen in public, is not announced again.
    assert!(
        maker
            .handle("J5other", hp2([1; 32]), &chain, NOW)
            .is_empty()
    );
    maker.on_hp2([2; 32]);
    assert!(
        maker
            .handle("J5other", hp2([2; 32]), &chain, NOW)
            .is_empty()
    );
    // At most HP2_RELAYS_PER_WINDOW in a window; later, again.
    for i in 1..HP2_RELAYS_PER_WINDOW {
        let c = [10 + i as u8; 32];
        assert_eq!(
            maker.handle("J5other", hp2(c), &chain, NOW + 1),
            announce(c)
        );
    }
    assert!(
        maker
            .handle("J5other", hp2([99; 32]), &chain, NOW + 2)
            .is_empty()
    );
    let later = NOW + HP2_RELAY_WINDOW + 1;
    assert_eq!(
        maker.handle("J5other", hp2([100; 32]), &chain, later),
        announce([100; 32])
    );
    // Whatever was handed over, announced or not, is refused in a fill.
    let secp = Secp256k1::new();
    let podle = generate(&secp, &taker.key, &taker.utxo.to_string(), 0, None).unwrap();
    assert!(
        maker
            .handle("J5x", hp2(podle.commitment()), &chain, later)
            .len()
            <= 1
    );
    let out = maker.handle(
        "J5taker",
        Command::Fill {
            oid: 0,
            amount: AMOUNT,
            nacl_pubkey: taker.nacl.public_hex(),
            commitment: podle.commitment(),
        },
        &chain,
        later,
    );
    assert_eq!(private(&out[0]).0, "error");
}

#[test]
fn remembered_commitments_are_bounded() {
    let mut commitments = Commitments::default();
    let key = |i: usize| {
        let mut c = [0u8; 32];
        c[..8].copy_from_slice(&(i as u64).to_be_bytes());
        c
    };
    for i in 0..=MAX_COMMITMENTS {
        assert!(commitments.insert(key(i)));
    }
    assert!(!commitments.insert(key(MAX_COMMITMENTS)));
    // The oldest went first.
    assert!(!commitments.contains(&key(0)));
    assert!(commitments.contains(&key(1)));
    assert_eq!(commitments.announced.seen.len(), MAX_COMMITMENTS);
}

#[test]
fn a_stray_line_leaves_the_session_as_it_was() {
    let secp = Secp256k1::new();
    let mut maker = funded_maker();
    let (taker, chain) = new_taker();
    let podle = generate(&secp, &taker.key, &taker.utxo.to_string(), 0, None).unwrap();
    let fill = Command::Fill {
        oid: 0,
        amount: AMOUNT,
        nacl_pubkey: taker.nacl.public_hex(),
        commitment: podle.commitment(),
    };
    let garbage = |name: &str| Command::Encrypted {
        name: name.into(),
        ciphertext: "AAAA".into(),
    };
    // Before any `!fill`: nothing is sent and nothing is started.
    for stray in [garbage("auth"), garbage("tx"), Command::Error("x".into())] {
        assert!(maker.handle("J5taker", stray, &chain, NOW).is_empty());
    }
    assert!(maker.sessions.is_empty());

    assert_eq!(maker.progress("J5taker", NOW), 0);
    let out = maker.handle("J5taker", fill.clone(), &chain, NOW);
    assert_eq!(private(&out[0]).0, "pubkey");
    let pubkey = private(&out[0]).1.to_string();
    let session = taker.nacl.session(&pubkey).unwrap();
    assert_eq!(maker.progress("J5taker", NOW), 1);
    // The same `!fill` again, delivered another way: the same answer, and the session as it was. A few
    // times only: copies cannot draw a stream of answers.
    for _ in 0..MAX_FILL_REPEATS {
        let again = maker.handle("J5taker", fill.clone(), &chain, NOW);
        assert_eq!(private(&again[0]), ("pubkey", pubkey.as_str()));
        assert_eq!(maker.progress("J5taker", NOW), 1);
    }
    assert!(
        maker
            .handle("J5taker", fill.clone(), &chain, NOW)
            .is_empty()
    );
    assert_eq!(maker.progress("J5taker", NOW), 1);
    // Filled: another `!fill`, lines not encrypted for this session, lines out of order.
    let other_fill = Command::Fill {
        oid: 0,
        amount: AMOUNT + 1,
        nacl_pubkey: taker.nacl.public_hex(),
        commitment: podle.commitment(),
    };
    for stray in [
        other_fill,
        garbage("auth"),
        garbage("tx"),
        garbage("sig"),
        Command::Error("x".into()),
    ] {
        assert!(maker.handle("J5taker", stray, &chain, NOW).is_empty());
        assert!(matches!(
            maker.sessions.get("J5taker"),
            Some(Stage::Filled(_))
        ));
    }
    // An `!auth` encrypted for another session (another maker's, or an old one) is not this session's.
    let elsewhere = NaclKeypair::generate();
    let foreign = taker.nacl.session(&elsewhere.public_hex()).unwrap();
    let foreign_auth = Command::Encrypted {
        name: "auth".into(),
        ciphertext: foreign.encrypt(&podle.revelation()).unwrap(),
    };
    assert!(
        maker
            .handle("J5taker", foreign_auth, &chain, NOW)
            .is_empty()
    );

    // The real `!auth` still works, and afterwards its copy is stray too.
    let auth = Command::Encrypted {
        name: "auth".into(),
        ciphertext: session.encrypt(&podle.revelation()).unwrap(),
    };
    assert_eq!(maker.progress("J5taker", NOW), 1);
    let out = maker.handle("J5taker", auth.clone(), &chain, NOW);
    assert_eq!(private(&out[0]).0, "ioauth");
    assert_eq!(maker.progress("J5taker", NOW), 2);
    for stray in [auth, fill, garbage("tx")] {
        assert!(maker.handle("J5taker", stray, &chain, NOW).is_empty());
        assert!(matches!(
            maker.sessions.get("J5taker"),
            Some(Stage::Authed(_))
        ));
        assert_eq!(maker.progress("J5taker", NOW), 2);
    }
}

#[test]
fn refusals_end_the_session_with_a_fixed_error() {
    let secp = Secp256k1::new();
    let (taker, chain) = new_taker();
    let podle = generate(&secp, &taker.key, &taker.utxo.to_string(), 0, None).unwrap();
    let fill = |amount| Command::Fill {
        oid: 0,
        amount,
        nacl_pubkey: taker.nacl.public_hex(),
        commitment: podle.commitment(),
    };
    let error = vec![Outgoing::Private {
        to: "J5taker".into(),
        command: "error".into(),
        body: ERROR_TEXT.into(),
    }];

    // Out of range, unknown oid.
    let mut maker = funded_maker();
    assert_eq!(maker.handle("J5taker", fill(5_000), &chain, NOW), error);
    assert_eq!(
        maker.handle(
            "J5taker",
            Command::Fill {
                oid: 7,
                amount: AMOUNT,
                nacl_pubkey: taker.nacl.public_hex(),
                commitment: podle.commitment(),
            },
            &chain,
            NOW
        ),
        error
    );

    // A commitment seen in an !hp2 broadcast is refused.
    let mut maker = funded_maker();
    maker.handle("J5x", Command::Hp2(podle.commitment()), &chain, NOW);
    assert_eq!(maker.handle("J5taker", fill(AMOUNT), &chain, NOW), error);

    // A PoDLE for a UTXO the chain does not know, or too young, is refused.
    for confirmations in [None, Some(4)] {
        let mut maker = funded_maker();
        let mut chain = new_taker().1;
        match confirmations {
            None => chain.utxos.clear(),
            Some(c) => chain.utxos.values_mut().for_each(|u| u.confirmations = c),
        }
        let out = maker.handle("J5taker", fill(AMOUNT), &chain, NOW);
        let session = taker.nacl.session(private(&out[0]).1).unwrap();
        let auth = Command::Encrypted {
            name: "auth".into(),
            ciphertext: session.encrypt(&podle.revelation()).unwrap(),
        };
        assert_eq!(
            maker.handle("J5taker", auth, &chain, NOW),
            error,
            "{confirmations:?}"
        );
    }

    // More than the maker holds.
    let mut maker = funded_maker();
    let out = maker.handle("J5taker", fill(900_000), &chain, NOW);
    let session = taker.nacl.session(private(&out[0]).1).unwrap();
    let auth = Command::Encrypted {
        name: "auth".into(),
        ciphertext: session.encrypt(&podle.revelation()).unwrap(),
    };
    assert_eq!(maker.handle("J5taker", auth, &chain, NOW), error);
}

#[test]
fn a_transaction_that_shortchanges_the_maker_is_not_signed() {
    let secp = Secp256k1::new();
    let mut maker = funded_maker();
    let (taker, chain) = new_taker();
    let podle = generate(&secp, &taker.key, &taker.utxo.to_string(), 1, None).unwrap();
    let out = maker.handle(
        "J5taker",
        Command::Fill {
            oid: 0,
            amount: AMOUNT,
            nacl_pubkey: taker.nacl.public_hex(),
            commitment: podle.commitment(),
        },
        &chain,
        NOW,
    );
    let session = taker.nacl.session(private(&out[0]).1).unwrap();
    let out = maker.handle(
        "J5taker",
        Command::Encrypted {
            name: "auth".into(),
            ciphertext: session.encrypt(&podle.revelation()).unwrap(),
        },
        &chain,
        NOW,
    );
    let ioauth = Ioauth::parse(&session.decrypt(private(&out[0]).1).unwrap()).unwrap();
    let script = |a: &str| {
        Address::from_str(a)
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap()
            .script_pubkey()
    };
    // The change is one satoshi short of what the maker is owed.
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: ioauth.utxos[0],
                ..spend(0)
            },
            TxIn {
                previous_output: taker.utxo,
                ..spend(0)
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(AMOUNT),
                script_pubkey: script(&ioauth.cj_address),
            },
            TxOut {
                value: Amount::from_sat(500_000 - AMOUNT - 100 + 400 - 1),
                script_pubkey: script(&ioauth.change_address),
            },
        ],
    };
    let tx_b64 = STANDARD.encode(serialize(&tx));
    let out = maker.handle(
        "J5taker",
        Command::Encrypted {
            name: "tx".into(),
            ciphertext: session.encrypt(&tx_b64).unwrap(),
        },
        &chain,
        NOW,
    );
    assert_eq!(private(&out[0]), ("error", ERROR_TEXT));
    assert!(!maker.push_allowed("J5taker", &tx));
}

#[test]
fn an_unprofitable_fill_is_refused_before_the_podle() {
    let (taker, chain) = new_taker();
    let mut maker = funded_maker();
    maker.config.offers = vec![Offer::parse("sw0reloffer", "0 10000 10000000 500 0.001").unwrap()];
    let fill = Command::Fill {
        oid: 0,
        amount: AMOUNT,
        nacl_pubkey: taker.nacl.public_hex(),
        commitment: [1; 32],
    };
    // cjfee 400 < txfee 500 at this amount.
    assert_eq!(
        private(&maker.handle("J5taker", fill, &chain, NOW)[0]),
        ("error", ERROR_TEXT)
    );
}

#[test]
fn an_undeclared_utxo_of_the_maker_is_never_signed() {
    let secp = Secp256k1::new();
    let mut maker = funded_maker();
    let (taker, chain) = new_taker();
    let podle = generate(&secp, &taker.key, &taker.utxo.to_string(), 2, None).unwrap();
    let out = maker.handle(
        "J5taker",
        Command::Fill {
            oid: 0,
            amount: AMOUNT,
            nacl_pubkey: taker.nacl.public_hex(),
            commitment: podle.commitment(),
        },
        &chain,
        NOW,
    );
    let session = taker.nacl.session(private(&out[0]).1).unwrap();
    let auth = Command::Encrypted {
        name: "auth".into(),
        ciphertext: session.encrypt(&podle.revelation()).unwrap(),
    };
    let out = maker.handle("J5taker", auth, &chain, NOW);
    let ioauth = Ioauth::parse(&session.decrypt(private(&out[0]).1).unwrap()).unwrap();
    // The maker's other UTXO (300,000), which it did not declare, slipped in by the taker.
    let other = maker
        .wallet
        .utxos(0)
        .unwrap()
        .into_iter()
        .find(|u| !ioauth.utxos.contains(&u.outpoint))
        .unwrap();
    let script = |a: &str| {
        Address::from_str(a)
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap()
            .script_pubkey()
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: ioauth.utxos[0],
                ..spend(0)
            },
            TxIn {
                previous_output: other.outpoint,
                ..spend(0)
            },
            TxIn {
                previous_output: taker.utxo,
                ..spend(0)
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(AMOUNT),
                script_pubkey: script(&ioauth.cj_address),
            },
            TxOut {
                value: Amount::from_sat(500_000 - AMOUNT - 100 + 400),
                script_pubkey: script(&ioauth.change_address),
            },
        ],
    };
    let mut chain = chain;
    chain.utxos.insert(
        other.outpoint,
        Utxo {
            value: other.txout.value,
            script_pubkey: other.txout.script_pubkey.clone(),
            confirmations: 9,
            coinbase: false,
        },
    );
    let tx_b64 = STANDARD.encode(serialize(&tx));
    let out = maker.handle(
        "J5taker",
        Command::Encrypted {
            name: "tx".into(),
            ciphertext: session.encrypt(&tx_b64).unwrap(),
        },
        &chain,
        NOW,
    );
    assert_eq!(private(&out[0]), ("error", ERROR_TEXT));
}

/// A maker with two offers and two fidelity bonds (1,000,000 sats until 2028-01, 2,000,000 until
/// 2030-01), confirmed at height 1. Returns the bonds' outpoints too.
fn bonded_maker() -> (Maker, OutPoint, OutPoint, Block) {
    let mut wallet = PitWallet::new(
        &Seed::from_mnemonic(WORDS, "bonds", Network::Regtest).unwrap(),
        Pit::Sw0,
    )
    .unwrap();
    let funding = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![spend(9)],
        output: vec![
            TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: wallet.bond_address(96).unwrap().script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(2_000_000),
                script_pubkey: wallet.bond_address(120).unwrap().script_pubkey(),
            },
        ],
    };
    let txid = funding.compute_txid();
    let genesis = genesis_block(Network::Regtest);
    let block = Block {
        header: Header {
            version: BlockVersion::TWO,
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: genesis.header.time + 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 9,
        },
        txdata: vec![funding],
    };
    wallet.apply_block(&block, 1).unwrap();
    let offers = vec![
        Offer::parse("sw0reloffer", "0 10000 10000000 100 0.001").unwrap(),
        Offer::parse("sw0absoffer", "1 10000 10000000 100 500").unwrap(),
    ];
    let maker = Maker::new(MakerConfig::new(offers), wallet).unwrap();
    (
        maker,
        OutPoint { txid, vout: 0 },
        OutPoint { txid, vout: 1 },
        block,
    )
}

fn tbond_of(out: &Outgoing) -> BondProofOf {
    let (_, body) = private(out);
    let (_, proof) = body.split_once("!tbond ").expect("a !tbond");
    vortex_ng_core::bond::BondProof::from_base64(proof).unwrap()
}

type BondProofOf = vortex_ng_core::bond::BondProof;

#[test]
fn the_most_valuable_bond_is_proven_to_each_taker() {
    let (mut maker, small, big, block) = bonded_maker();
    let chain = FakeChain {
        utxos: HashMap::new(),
        tip: 300,
    };
    let value = maker.refresh_bond(&chain, NOW).unwrap().unwrap();
    let expected = bond_value(
        2_000_000,
        1_700_000_600,
        u64::from(vortex_ng_core::bond::timenumber_locktime(120).unwrap()),
        NOW,
        BondValueParams::default(),
    );
    assert_eq!(value, expected);
    let out = maker.on_orderbook("J5taker", "J5maker");
    assert_eq!(out.len(), 2, "one private message per offer");
    let secp = Secp256k1::new();
    for o in &out {
        let proof = tbond_of(o);
        proof
            .verify_signatures(&secp, "J5taker", "J5maker")
            .unwrap();
        assert!(
            proof
                .verify_signatures(&secp, "J5other", "J5maker")
                .is_err()
        );
        assert_eq!(proof.outpoint, big);
        let spk = maker.wallet.bond_address(120).unwrap().script_pubkey();
        proof.check_utxo(300, Some(&spk), 10).unwrap();
    }
    assert!(
        private(&out[0])
            .1
            .starts_with("0 10000 10000000 100 0.001!tbond ")
    );
    // The same certificate while it is valid; a new one once the big bond is spent.
    let cert = tbond_of(&out[0]).cert_pubkey;
    maker.refresh_bond(&chain, NOW).unwrap();
    assert_eq!(
        tbond_of(&maker.on_orderbook("J5t", "J5m")[0]).cert_pubkey,
        cert
    );
    let spend_big = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: big,
            ..spend(0)
        }],
        output: vec![TxOut::NULL],
    };
    let next = Block {
        header: Header {
            prev_blockhash: block.block_hash(),
            nonce: 10,
            ..block.header
        },
        txdata: vec![spend_big],
    };
    maker.wallet_mut().apply_block(&next, 2).unwrap();
    maker.refresh_bond(&chain, NOW).unwrap().unwrap();
    assert_eq!(
        tbond_of(&maker.on_orderbook("J5t", "J5m")[0]).outpoint,
        small
    );
}

#[test]
fn without_a_bond_offers_carry_no_tbond() {
    let mut maker = funded_maker();
    let chain = FakeChain {
        utxos: HashMap::new(),
        tip: 300,
    };
    assert_eq!(maker.refresh_bond(&chain, NOW).unwrap(), None);
    let out = maker.on_orderbook("J5taker", "J5maker");
    assert_eq!(out.len(), 1);
    assert!(!private(&out[0]).1.contains("!tbond"));
    // `!orderbook` is public only: a private one gets no answer.
    assert!(
        maker
            .handle("J5taker", Command::Orderbook, &chain, NOW)
            .is_empty()
    );
}

/// A keeper in memory, shared with the test: what it was given, and whether it fails.
#[derive(Clone, Default)]
struct MemoryKeeper(std::sync::Arc<std::sync::Mutex<KeeperState>>);

#[derive(Default)]
struct KeeperState {
    kept: Vec<(Seen, [u8; 32])>,
    failing: bool,
    rewrite_at: Option<usize>,
    rewrites: usize,
}

impl MemoryKeeper {
    fn kept(&self) -> Vec<(Seen, [u8; 32])> {
        self.0.lock().unwrap().kept.clone()
    }
}

impl CommitmentKeeper for MemoryKeeper {
    fn keep(&mut self, seen: Seen, commitment: &[u8; 32]) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        if state.failing {
            return Err("the disk is full".into());
        }
        state.kept.push((seen, *commitment));
        Ok(())
    }

    fn wants_rewrite(&self) -> bool {
        let state = self.0.lock().unwrap();
        state.rewrite_at.is_some_and(|at| state.kept.len() >= at)
    }

    fn rewrite(&mut self, remembered: &[(Seen, [u8; 32])]) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        state.kept = remembered.to_vec();
        state.rewrite_at = state.rewrite_at.map(|at| at + remembered.len());
        state.rewrites += 1;
        Ok(())
    }
}

#[test]
fn a_restarted_maker_still_refuses_the_commitments_it_saw() {
    let (taker, chain) = new_taker();
    let keeper = MemoryKeeper::default();
    let mut maker = funded_maker();
    maker.keep_commitments(Vec::new(), Box::new(keeper.clone()));
    maker.on_hp2([7; 32]);
    maker.on_hp2([7; 32]);
    assert!(auth_round(&mut maker, &taker, &chain, AMOUNT).is_some());
    // Each kept once, the announced one as announced, the round's as verified.
    let kept = keeper.kept();
    assert_eq!(kept.len(), 2, "{kept:?}");
    assert_eq!(kept[0], (Seen::Announced, [7; 32]));
    assert_eq!(kept[1].0, Seen::Verified);

    // The same wallet in a new process that was handed what was kept: neither opens a session.
    let mut again = funded_maker();
    again.keep_commitments(kept, Box::new(MemoryKeeper::default()));
    assert_eq!(again.remembered_commitments(), (1, 1));
    assert!(auth_round(&mut again, &taker, &chain, AMOUNT).is_none());
    let fill = Command::Fill {
        oid: 0,
        amount: AMOUNT,
        nacl_pubkey: NaclKeypair::generate().public_hex(),
        commitment: [7; 32],
    };
    let out = again.handle("J5other", fill, &chain, NOW);
    assert_eq!(private(&out[0]).0, "error");
    // Without what was kept, the very same round goes ahead.
    assert!(auth_round(&mut funded_maker(), &taker, &chain, AMOUNT).is_some());
}

#[test]
fn coins_are_not_shown_when_the_commitment_cannot_be_kept() {
    let (taker, chain) = new_taker();
    let keeper = MemoryKeeper::default();
    let mut maker = funded_maker();
    maker.keep_commitments(Vec::new(), Box::new(keeper.clone()));
    keeper.0.lock().unwrap().failing = true;
    // An announcement is still remembered in memory: losing it on disk costs little.
    maker.on_hp2([8; 32]);
    assert_eq!(maker.remembered_commitments(), (0, 1));
    // The round's commitment is not on disk, so no `!ioauth`, and the commitment is not counted as used.
    assert!(auth_round(&mut maker, &taker, &chain, AMOUNT).is_none());
    assert_eq!(maker.remembered_commitments(), (0, 1));
    assert!(!maker.in_session("J5taker", NOW));
    // Once the disk is back, the taker can try again with the same commitment.
    keeper.0.lock().unwrap().failing = false;
    assert!(auth_round(&mut maker, &taker, &chain, AMOUNT).is_some());
    assert_eq!(
        keeper
            .kept()
            .iter()
            .filter(|(seen, _)| *seen == Seen::Verified)
            .count(),
        1
    );
}

#[test]
fn the_keeper_is_rewritten_from_what_is_remembered_when_it_asks() {
    let keeper = MemoryKeeper::default();
    keeper.0.lock().unwrap().rewrite_at = Some(3);
    let mut maker = funded_maker();
    // Loaded at start, with a duplicate the maker remembers once.
    let earlier = vec![
        (Seen::Verified, [1; 32]),
        (Seen::Announced, [2; 32]),
        (Seen::Announced, [2; 32]),
    ];
    keeper.0.lock().unwrap().kept = earlier.clone();
    maker.keep_commitments(earlier, Box::new(keeper.clone()));
    assert_eq!(keeper.0.lock().unwrap().rewrites, 1);
    assert_eq!(
        keeper.kept(),
        vec![(Seen::Verified, [1; 32]), (Seen::Announced, [2; 32])]
    );
    maker.on_hp2([3; 32]);
    assert_eq!(keeper.0.lock().unwrap().rewrites, 1);
    assert_eq!(keeper.kept().len(), 3);
}

/// Claims in memory, shared with the test: coins held by another user of the wallet, those held for the
/// maker, and the highest address index handed out on each chain (mixdepth, change).
#[derive(Clone, Default)]
struct MemoryClaims(std::sync::Arc<std::sync::Mutex<ClaimsState>>);

#[derive(Default)]
struct ClaimsState {
    elsewhere: HashSet<OutPoint>,
    ours: Vec<OutPoint>,
    issued: HashMap<(u32, bool), u32>,
}

impl WalletClaims for MemoryClaims {
    fn held_elsewhere(&self) -> Result<HashSet<OutPoint>, String> {
        Ok(self.0.lock().unwrap().elsewhere.clone())
    }

    fn hold(&self, coins: &[OutPoint], _seconds: u64) -> Result<bool, String> {
        let mut state = self.0.lock().unwrap();
        if coins.iter().any(|c| state.elsewhere.contains(c)) {
            return Ok(false);
        }
        state.ours.extend_from_slice(coins);
        Ok(true)
    }

    fn fresh_address(
        &self,
        wallet: &mut PitWallet,
        mixdepth: u32,
        change: bool,
    ) -> Result<vortex_ng_core::bitcoin::Address, String> {
        let mut state = self.0.lock().unwrap();
        if let Some(highest) = state.issued.get(&(mixdepth, change)) {
            wallet
                .reveal_through(mixdepth, change, *highest)
                .map_err(|e| e.to_string())?;
        }
        let (index, address) = wallet
            .next_address_indexed(mixdepth, change)
            .map_err(|e| e.to_string())?;
        state.issued.insert((mixdepth, change), index);
        Ok(address)
    }
}

#[test]
fn a_coin_held_by_another_user_of_the_wallet_is_never_offered_or_spent() {
    let (taker, chain) = new_taker();
    let coins: Vec<OutPoint> = maker_coins().into_iter().map(|(coin, _)| coin).collect();
    let big = coins
        .iter()
        .copied()
        .find(|c| {
            maker_coins()
                .iter()
                .any(|(o, u)| o == c && u.value.to_sat() == 500_000)
        })
        .unwrap();
    let claims = MemoryClaims::default();
    let mut maker = funded_maker();
    assert_eq!(maker.liquidity().unwrap(), 800_000);
    maker.share_wallet(Box::new(claims.clone()));
    // A joinstr round in another process holds the 500,000 coin.
    claims.0.lock().unwrap().elsewhere.insert(big);
    assert_eq!(
        maker.liquidity().unwrap(),
        300_000,
        "only what nobody else holds"
    );
    // A round the other coin covers goes ahead without it; the coins shown are now held for the maker.
    let ioauth = auth_round(&mut maker, &taker, &chain, 200_000).expect("an !ioauth");
    assert!(!ioauth.utxos.contains(&big));
    assert_eq!(claims.0.lock().unwrap().ours, ioauth.utxos);
}

#[test]
fn a_round_is_refused_when_its_coins_are_taken_meanwhile_and_addresses_are_handed_out_once() {
    let (taker, chain) = new_taker();
    let claims = MemoryClaims::default();
    let mut maker = funded_maker();
    maker.share_wallet(Box::new(claims.clone()));
    // Another user of the wallet already took the first addresses this maker would hand out: index 0 of
    // mixdepth 1's receiving chain (the round's output) and of mixdepth 0's change chain.
    {
        let mut state = claims.0.lock().unwrap();
        state.issued.insert((1, false), 0);
        state.issued.insert((0, true), 0);
    }
    let ioauth = auth_round(&mut maker, &taker, &chain, 200_000).expect("an !ioauth");
    let reference = maker_wallet();
    assert_eq!(
        ioauth.cj_address,
        reference.peek_address(1, false, 1).unwrap().to_string()
    );
    assert_eq!(
        ioauth.change_address,
        reference.peek_address(0, true, 1).unwrap().to_string()
    );
    let state = claims.0.lock().unwrap();
    assert_eq!(
        (state.issued[&(1, false)], state.issued[&(0, true)]),
        (1, 1),
        "what was handed out is written down"
    );
    drop(state);

    // Its coins held elsewhere between the choice and the hold: the round is refused, nothing shown.
    let mut maker = funded_maker();
    let racing = MemoryClaims::default();
    maker.share_wallet(Box::new(RaceClaims(racing.clone())));
    assert!(auth_round(&mut maker, &taker, &chain, 200_000).is_none());
    assert!(racing.0.lock().unwrap().ours.is_empty());
}

/// Claims that let the maker choose any coin and then refuse to hold it, as when another process holds it
/// between the two.
struct RaceClaims(MemoryClaims);

impl WalletClaims for RaceClaims {
    fn held_elsewhere(&self) -> Result<HashSet<OutPoint>, String> {
        Ok(HashSet::new())
    }

    fn hold(&self, _coins: &[OutPoint], _seconds: u64) -> Result<bool, String> {
        Ok(false)
    }

    fn fresh_address(
        &self,
        wallet: &mut PitWallet,
        mixdepth: u32,
        change: bool,
    ) -> Result<vortex_ng_core::bitcoin::Address, String> {
        self.0.fresh_address(wallet, mixdepth, change)
    }
}
