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

/// A maker whose mixdepth 0 holds 500,000 and 300,000 sats, confirmed.
fn funded_maker() -> Maker {
    let mut wallet = PitWallet::new(
        &Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap(),
        Pit::Sw0,
    )
    .unwrap();
    let a = wallet.next_receive_address(0).unwrap().script_pubkey();
    let b = wallet.next_receive_address(0).unwrap().script_pubkey();
    let funding = Transaction {
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
    };
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
    let chain = FakeChain {
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
        Outgoing::PublicEphemeral(_) => panic!("expected a private message"),
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
    // The taker's checks: the auth key signed our NaCl key and controls a declared UTXO.
    assert!(sigmsg::verify(
        &secp,
        taker.nacl.public_hex().as_bytes(),
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

    // Out of range, unknown oid, auth before fill.
    let mut maker = funded_maker();
    assert_eq!(maker.handle("J5taker", fill(5_000), &chain, NOW), error);
    assert_eq!(
        maker.handle(
            "J5taker",
            Command::Encrypted {
                name: "auth".into(),
                ciphertext: "AAAA".into()
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
