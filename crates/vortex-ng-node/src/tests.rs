//! A whole CoinJoin over a real relay: two makers and a taker, each with its own nick and wallet, talking
//! only through gift-wrapped Nostr events on nostr-sdk's in-process relay. The makers hold fidelity bonds
//! and charge a fee, so under joinmarket-ng's default policy (bondless makers only at zero fee) the round
//! happens only if their `!tbond` proofs cross the relay and verify against the chain.

use std::collections::HashMap;
use std::sync::Arc;

use nostr_sdk::prelude::MockRelay;
use vortex_ng_chain::Utxo;
use vortex_ng_core::bitcoin::block::{Header, Version as BlockVersion};
use vortex_ng_core::bitcoin::blockdata::constants::genesis_block;
use vortex_ng_core::bitcoin::hashes::Hash;
use vortex_ng_core::bitcoin::transaction::Version;
use vortex_ng_core::bitcoin::{
    Amount, Block, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, TxIn, TxMerkleNode,
    TxOut, Txid, Witness, absolute,
};
use vortex_ng_core::offer::Pit;
use vortex_ng_maker::MakerConfig;
use vortex_ng_taker::podle_for;
use vortex_ng_wallet::Seed;

use super::*;

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const AMOUNT: u64 = 300_000;

#[derive(Clone, Default)]
struct SharedChain(Arc<HashMap<OutPoint, Utxo>>);

impl ChainLookup for SharedChain {
    fn utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, String> {
        Ok(self.0.get(outpoint).cloned())
    }
    fn tip_height(&self) -> Result<u32, String> {
        Ok(300)
    }
    fn block_time(&self, height: u32) -> Result<u32, String> {
        Ok(1_700_000_000 + height * 600)
    }
}

/// A wallet with `value` confirmed in mixdepth 0 and, with `bond`, a fidelity bond of that many sats
/// locked until timenumber 120 (2030-01), all registered in `utxos` with 10 confirmations.
fn funded(
    pit: Pit,
    who: &str,
    value: u64,
    bond: Option<u64>,
    salt: u8,
    utxos: &mut HashMap<OutPoint, Utxo>,
) -> PitWallet {
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
        output: [(value, address.script_pubkey())]
            .into_iter()
            .chain(bond.map(|b| (b, wallet.bond_address(120).unwrap().script_pubkey())))
            .map(|(v, spk)| TxOut {
                value: Amount::from_sat(v),
                script_pubkey: spk,
            })
            .collect(),
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
    for (vout, out) in funding.output.iter().enumerate() {
        utxos.insert(
            OutPoint {
                txid: funding.compute_txid(),
                vout: vout as u32,
            },
            Utxo {
                value: out.value,
                script_pubkey: out.script_pubkey.clone(),
                confirmations: 10,
                coinbase: false,
            },
        );
    }
    if bond.is_some() {
        assert_eq!(wallet.bonds().len(), 1);
    }
    wallet
}

#[tokio::test(flavor = "multi_thread")]
async fn a_whole_coinjoin_over_a_nostr_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let pit = Pit::Tr0;
    let mut utxos = HashMap::new();
    let maker_wallets: Vec<PitWallet> = (0..2)
        .map(|i| {
            let bond = Some(1_000_000 + u64::from(i));
            funded(pit, &format!("maker{i}"), 500_000, bond, 10 + i, &mut utxos)
        })
        .collect();
    let mut taker_wallet = funded(pit, "taker", 600_000, None, 20, &mut utxos);
    let chain = SharedChain(Arc::new(utxos));
    let until = Instant::now() + Duration::from_secs(60);

    // Two makers, each its own task, nick and connection.
    let mut handles = Vec::new();
    for (i, wallet) in maker_wallets.into_iter().enumerate() {
        let (chain, url) = (chain.clone(), url.clone());
        handles.push(tokio::spawn(async move {
            let offer =
                Offer::parse("tr0absoffer", &format!("{i} 10000 10000000 100 500")).unwrap();
            let mut maker = Maker::new(MakerConfig::new(vec![offer]), wallet).unwrap();
            let mut client = NickClient::connect(
                NickKeys::generate(),
                "regtest",
                &[url],
                None,
                CONNECT_TIMEOUT,
            )
            .await
            .unwrap();
            run_maker(&mut maker, &mut client, &chain, "regtest", until).await
        }));
    }

    // The taker gathers the two offers, then runs the round.
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
        bondless_makers_allowance: vortex_ng_taker::DEFAULT_BONDLESS_ALLOWANCE,
        bondless_require_zero_fee: true,
        bond_params: Default::default(),
    };
    let cj = taker_wallet
        .next_receive_address(1)
        .unwrap()
        .script_pubkey();
    let change = taker_wallet.next_change_address(0).unwrap().script_pubkey();
    let mut taker = Taker::new(
        cfg.clone(),
        0,
        vec![(utxo.outpoint, utxo.txout.clone())],
        podle,
        cj,
        change,
    )
    .unwrap();
    let mut client = NickClient::connect(
        NickKeys::generate(),
        "regtest",
        std::slice::from_ref(&url),
        None,
        CONNECT_TIMEOUT,
    )
    .await
    .unwrap();
    // An outsider writes to the taker during the round; it must be ignored, not abort the round.
    let taker_key = client.keys().nostr().public_key();
    let taker_nick = client.keys().nick().to_string();
    let eve_url = url.clone();
    let eve = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(3_300)).await;
        let eve = NickClient::connect(
            NickKeys::generate(),
            "regtest",
            std::slice::from_ref(&eve_url),
            None,
            CONNECT_TIMEOUT,
        )
        .await
        .unwrap();
        let line = sign_line(
            &Secp256k1::signing_only(),
            eve.keys().secret(),
            &taker_nick,
            "error",
            "abort please",
            NOSTR_HOSTID,
        )
        .unwrap();
        eve.send_line(&taker_key, &[eve_url], &line).await.unwrap();
    });
    let tx = run_taker(
        &mut taker,
        &taker_wallet,
        &mut client,
        &chain,
        &cfg,
        Duration::from_secs(3),
        until,
    )
    .await
    .unwrap();

    assert_eq!(tx.input.len(), 3);
    assert!(tx.input.iter().all(|i| !i.witness.is_empty()));
    assert_eq!(
        tx.output
            .iter()
            .filter(|o| o.value.to_sat() == AMOUNT)
            .count(),
        3
    );
    assert_eq!(
        tx.output
            .iter()
            .filter(|o| o.value.to_sat() == 200_400)
            .count(),
        2
    );
    assert!(tx.output.iter().all(|o| o.script_pubkey.is_p2tr()));
    eve.await.unwrap();
    for handle in handles {
        handle.abort();
    }
}
