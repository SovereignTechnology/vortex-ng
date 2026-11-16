//! Whole CoinJoins against a real regtest node, so real consensus code judges what we sign.
//!
//! Skipped unless `VORTEX_NG_REGTEST_RPC` (for example `http://127.0.0.1:18443`) and
//! `VORTEX_NG_REGTEST_COOKIE` (the node's `.cookie` file) are set; `tools/itest/run.sh` starts a pinned
//! Bitcoin Core and sets them. For each pit: two makers with fidelity bonds and a taker are funded by mined
//! coinbases, sync their wallets from the node's blocks, run a round over an in-process Nostr relay with the
//! node as chain backend, and the result must pass `testmempoolaccept`, confirm, and show up in every wallet.
//! A copy with one signature byte flipped must be refused (the node really checks signatures).

// A test harness: a failed step should panic with its error.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::MockRelay;
use vortex_ng_chain::{Auth, CoreRpc};
use vortex_ng_core::bitcoin::{Amount, Network, OutPoint, Transaction, Witness};
use vortex_ng_core::offer::{Offer, Pit};
use vortex_ng_maker::{Maker, MakerConfig};
use vortex_ng_node::{CONNECT_TIMEOUT, run_maker, run_taker};
use vortex_ng_nostr::client::NickClient;
use vortex_ng_nostr::keys::NickKeys;
use vortex_ng_taker::{DEFAULT_BONDLESS_ALLOWANCE, Taker, TakerConfig, podle_for};
use vortex_ng_wallet::{MIXDEPTHS, PitWallet, Seed};

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const AMOUNT: u64 = 1_000_000;
const CJFEE: u64 = 500;
const TXFEE: u64 = 100;
/// The bond timelock: timenumber 120, January 2030.
const BOND_TIMENUMBER: u32 = 120;

#[derive(Clone)]
struct Node {
    url: String,
    cookie: PathBuf,
}

impl Node {
    fn from_env() -> Option<Node> {
        Some(Node {
            url: std::env::var("VORTEX_NG_REGTEST_RPC").ok()?,
            cookie: std::env::var("VORTEX_NG_REGTEST_COOKIE").ok()?.into(),
        })
    }

    fn rpc(&self) -> CoreRpc {
        CoreRpc::new(
            &self.url,
            &Auth::CookieFile(self.cookie.clone()),
            Duration::from_secs(60),
        )
        .unwrap()
    }
}

fn wallet(pit: Pit, who: &str) -> PitWallet {
    let seed = Seed::from_mnemonic(WORDS, &format!("{pit:?}-{who}"), Network::Regtest).unwrap();
    PitWallet::new(&seed, pit).unwrap()
}

fn total(wallet: &PitWallet) -> Amount {
    (0..MIXDEPTHS)
        .map(|m| wallet.confirmed_balance(m).unwrap())
        .sum()
}

/// `tx` with one byte of its first input's first signature-sized witness element flipped.
fn corrupted(tx: &Transaction) -> Transaction {
    let mut bad = tx.clone();
    let mut items: Vec<Vec<u8>> = bad.input[0].witness.iter().map(<[u8]>::to_vec).collect();
    let sig = items.iter_mut().find(|i| i.len() >= 60).unwrap();
    sig[10] ^= 1;
    bad.input[0].witness = Witness::from_slice(&items);
    bad
}

async fn coinjoin(node: &Node, pit: Pit) {
    let rpc = node.rpc();
    assert_eq!(rpc.network().unwrap(), Network::Regtest, "regtest only");
    let prefix = match pit {
        Pit::Sw0 => "sw0",
        Pit::Tr0 => "tr0",
        Pit::Wsh0 => "wsh0",
    };

    // Fund: a coinbase to each party and to each maker's bond, then 100 blocks to mature them.
    let mut makers = vec![wallet(pit, "maker0"), wallet(pit, "maker1")];
    let mut taker_wallet = wallet(pit, "taker");
    for maker in &mut makers {
        rpc.generate_to_address(1, &maker.next_receive_address(0).unwrap())
            .unwrap();
        rpc.generate_to_address(1, &maker.bond_address(BOND_TIMENUMBER).unwrap())
            .unwrap();
    }
    rpc.generate_to_address(1, &taker_wallet.next_receive_address(0).unwrap())
        .unwrap();
    let sink = wallet(pit, "sink").next_receive_address(0).unwrap();
    rpc.generate_to_address(100, &sink).unwrap();
    let mut funded = Vec::new();
    for maker in &mut makers {
        maker.sync(&rpc, 0).unwrap();
        assert_eq!(
            maker.bonds().len(),
            1,
            "{pit:?}: the bond is found in real blocks"
        );
        funded.push(total(maker));
    }
    taker_wallet.sync(&rpc, 0).unwrap();

    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let until = Instant::now() + Duration::from_secs(120);
    let mut handles = Vec::new();
    for (i, wallet) in makers.into_iter().enumerate() {
        let (node, url) = (node.clone(), url.clone());
        handles.push(tokio::spawn(async move {
            let offer = Offer::parse(
                &format!("{prefix}absoffer"),
                &format!("{i} 10000 100000000 {TXFEE} {CJFEE}"),
            )
            .unwrap();
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
            run_maker(&mut maker, &mut client, &node.rpc(), "regtest", until).await
        }));
    }

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
        // The makers charge a fee: they are only chosen if their bonds verify against the node.
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
    let tx = run_taker(
        &mut taker,
        &taker_wallet,
        &mut client,
        &rpc,
        &cfg,
        Duration::from_secs(4),
        until,
    )
    .await
    .unwrap_or_else(|e| panic!("{pit:?}: round failed: {e}"));
    for handle in handles {
        handle.abort();
    }

    // The node judges: the corrupted copy is refused, the real one accepted, mined, and spendable.
    assert!(
        rpc.test_accept(&corrupted(&tx)).unwrap().is_err(),
        "{pit:?}: a flipped signature byte must be refused"
    );
    rpc.test_accept(&tx)
        .unwrap()
        .unwrap_or_else(|why| panic!("{pit:?}: the node refuses our CoinJoin: {why}"));
    let txid = rpc.broadcast(&tx).unwrap();
    rpc.generate_to_address(1, &sink).unwrap();
    for vout in 0..tx.output.len() as u32 {
        let out = rpc
            .utxo(&OutPoint { txid, vout })
            .unwrap()
            .expect("confirmed output");
        assert_eq!(out.confirmations, 1);
    }
    assert_eq!(tx.input.len(), 3);
    assert_eq!(
        tx.output
            .iter()
            .filter(|o| o.value.to_sat() == AMOUNT)
            .count(),
        3
    );

    // Every wallet sees its outputs: the taker's coinjoin output in mixdepth 1, and each maker (restored
    // from its seed) ends with what it had plus its fee, less its share of the mining fee.
    taker_wallet.sync(&rpc, 0).unwrap();
    assert_eq!(
        taker_wallet.confirmed_balance(1).unwrap(),
        Amount::from_sat(AMOUNT)
    );
    for (i, before) in funded.into_iter().enumerate() {
        let mut restored = wallet(pit, &format!("maker{i}"));
        restored.sync(&rpc, 0).unwrap();
        assert_eq!(
            total(&restored),
            before + Amount::from_sat(CJFEE - TXFEE),
            "{pit:?}: maker{i}"
        );
        assert_eq!(restored.bonds().len(), 1);
    }
    println!("{pit:?}: CoinJoin {txid} confirmed on the regtest node");
}

#[tokio::test(flavor = "multi_thread")]
async fn coinjoins_confirm_on_a_real_node_in_every_pit() {
    let Some(node) = Node::from_env() else {
        println!(
            "skipped: set VORTEX_NG_REGTEST_RPC and VORTEX_NG_REGTEST_COOKIE (tools/itest/run.sh)"
        );
        return;
    };
    for pit in [Pit::Sw0, Pit::Tr0, Pit::Wsh0] {
        coinjoin(&node, pit).await;
    }
}
