//! Whole joinstr pools against a real regtest node (ADR 0006), so real consensus code judges what we sign.
//!
//! Skipped unless `VORTEX_NG_REGTEST_RPC` and `VORTEX_NG_REGTEST_COOKIE` are set (`tools/itest/run.sh`).
//! Peers are funded by mined coinbases, sync their wallets from the node's blocks, and run a pool over an
//! in-process Nostr relay with the node as chain backend. Two rounds: a pool of two P2WPKH coins and one
//! P2TR coin that completes normally, and a pool where one peer registers an output and never an input, so
//! the others finish through the recovery round (ring signatures, re-signing). Each transaction must pass
//! `testmempoolaccept`, confirm, and pay every peer's wallet; a copy with one signature byte flipped must
//! be refused.

// A test harness: a failed step should panic with its error.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use nostr_sdk::prelude::MockRelay;
use vortex_ng_chain::{Auth, CoreRpc};
use vortex_ng_core::bitcoin::secp256k1::{Secp256k1, SecretKey};
use vortex_ng_core::bitcoin::{Amount, Network, OutPoint, Transaction, Witness};
use vortex_ng_core::offer::Pit;
use vortex_ng_core::script::taproot_output_secret;
use vortex_ng_joinstr::message::PoolMessage;
use vortex_ng_joinstr::pool::Pool;
use vortex_ng_joinstr::rules;
use vortex_ng_joinstr::session::Peer;
use vortex_ng_node::joinstr::{Hosting, join_pool, list_pools, pool_client, run_pool};
use vortex_ng_nostr::client::unix_now;
use vortex_ng_wallet::{PitWallet, Seed};

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const FEE_RATE: f64 = 2.5;
/// How far above the denomination each coin sits (the window is 500 to 5000 sats).
const SLACK: u64 = 2_500;
/// Regtest halves the subsidy every 150 blocks; coins of one pool must come from one era.
const HALVING: u32 = 150;

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
    let seed = Seed::from_mnemonic(WORDS, &format!("joinstr-{who}"), Network::Regtest).unwrap();
    PitWallet::new(&seed, pit).unwrap()
}

/// `tx` with one byte of its first input's signature flipped.
fn corrupted(tx: &Transaction) -> Transaction {
    let mut bad = tx.clone();
    let mut items: Vec<Vec<u8>> = bad.input[0].witness.iter().map(<[u8]>::to_vec).collect();
    let sig = items.iter_mut().find(|i| i.len() >= 60).unwrap();
    sig[10] ^= 1;
    bad.input[0].witness = Witness::from_slice(&items);
    bad
}

/// A wallet's one coin and the key a registration signs it with (the taproot output key's secret for a
/// `tr0` wallet).
fn coin(wallet: &PitWallet) -> (OutPoint, vortex_ng_core::bitcoin::TxOut, SecretKey) {
    let utxo = wallet.utxos(0).unwrap().remove(0);
    let keys = wallet.utxo_keys(0, &utxo).unwrap();
    let key = match wallet.pit() {
        Pit::Tr0 => taproot_output_secret(&Secp256k1::new(), keys.auth()),
        _ => *keys.auth(),
    };
    (utxo.outpoint, utxo.txout, key)
}

/// One pool on the node: `pits` are the honest peers' wallets (the first one creates the pool). With
/// `ghost`, a further peer joins, registers an output and never an input, and the round ends in recovery.
async fn pool_round(node: &Node, label: &str, pits: &[Pit], ghost: bool) {
    let rpc = node.rpc();
    assert_eq!(rpc.network().unwrap(), Network::Regtest, "regtest only");
    let n = pits.len();
    let sink = wallet(Pit::Sw0, &format!("{label}-sink"))
        .next_receive_address(0)
        .unwrap();

    // Fund: one coinbase each, all in one subsidy era so they are worth the same, then 100 blocks.
    let height = rpc.tip_height().unwrap();
    let room = HALVING - height % HALVING;
    if room <= n as u32 {
        rpc.generate_to_address(room, &sink).unwrap();
    }
    let mut wallets: Vec<PitWallet> = pits
        .iter()
        .enumerate()
        .map(|(i, pit)| wallet(*pit, &format!("{label}-peer{i}")))
        .collect();
    for w in &mut wallets {
        rpc.generate_to_address(1, &w.next_receive_address(0).unwrap())
            .unwrap();
    }
    rpc.generate_to_address(100, &sink).unwrap();
    for w in &mut wallets {
        w.sync(&rpc, 0).unwrap();
    }
    let value = coin(&wallets[0]).1.value.to_sat();
    assert!(
        wallets.iter().all(|w| coin(w).1.value.to_sat() == value),
        "{label}: one subsidy era"
    );
    let denomination = (value - SLACK) as f64 / 100_000_000.0;
    assert_eq!(
        rules::denom_sats(denomination),
        i64::try_from(value - SLACK).unwrap()
    );

    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let since = unix_now() - 60;
    let slots = (n + usize::from(ghost)) as u32;
    let pool_key = SecretKey::from_slice(
        &vortex_ng_nostr::nostr::key::Keys::generate()
            .secret_key()
            .secret_bytes(),
    )
    .unwrap();
    let timeout = i64::try_from(unix_now()).unwrap() + 3600;
    let pool = Pool::create(
        &pool_key,
        &format!("{label}{since}"),
        denomination,
        slots,
        timeout,
        &url,
        FEE_RATE,
    )
    .unwrap();
    let input_wait = Duration::from_secs(if ghost { 6 } else { 60 });
    let until = Instant::now() + Duration::from_secs(120);

    let mut handles = Vec::new();
    let mut paid_to = Vec::new();
    for (i, w) in wallets.iter_mut().enumerate() {
        let (outpoint, txout, key) = coin(w);
        let address = w.next_receive_address(1).unwrap();
        paid_to.push(address.clone());
        let (node, url, pool, creator) = (node.clone(), url.clone(), pool.clone(), i == 0);
        handles.push(tokio::spawn(async move {
            let (pool, pool_key) = if creator {
                (pool, pool_key)
            } else {
                let listed = list_pools(&url, None, since, Duration::from_secs(3), false)
                    .await
                    .unwrap();
                let found = listed
                    .into_iter()
                    .find(|p| p.public_key == pool.public_key)
                    .expect("pool listed");
                let key = join_pool(&found, None, Duration::from_secs(30), None)
                    .await
                    .unwrap();
                (found, key)
            };
            let mut client = pool_client(&pool_key, &pool.relay, None).await.unwrap();
            if creator {
                client.announce(&pool.announcement()).await.unwrap();
            }
            let mut peer = Peer::new(
                pool.clone(),
                Network::Regtest,
                address,
                outpoint,
                txout,
                key,
            )
            .unwrap();
            let hosting = creator.then_some(Hosting {
                pool: &pool,
                key: &pool_key,
                autct: None,
            });
            run_pool(
                &mut peer,
                &mut client,
                hosting,
                &node.rpc(),
                since,
                input_wait,
                until,
            )
            .await
        }));
    }
    if ghost {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let key = join_pool(&pool, None, Duration::from_secs(30), None)
            .await
            .unwrap();
        let client = pool_client(&key, &url, None).await.unwrap();
        let address = wallet(Pit::Sw0, &format!("{label}-ghost"))
            .next_receive_address(0)
            .unwrap();
        let output = PoolMessage::Output {
            address: address.to_string(),
        };
        client
            .send(&pool.public_key, &output.to_plaintext())
            .await
            .unwrap();
    }

    let mut txs = Vec::new();
    for handle in handles {
        txs.push(
            handle
                .await
                .unwrap()
                .unwrap_or_else(|e| panic!("{label}: round failed: {e}")),
        );
    }
    let tx = txs[0].clone();
    assert!(
        txs.iter().all(|t| *t == tx),
        "{label}: every peer builds the same transaction"
    );
    assert_eq!((tx.input.len(), tx.output.len()), (n, n));

    // The node judges: the corrupted copy is refused, the real one accepted, mined, and spendable.
    assert!(
        rpc.test_accept(&corrupted(&tx)).unwrap().is_err(),
        "{label}: a flipped signature byte must be refused"
    );
    rpc.test_accept(&tx)
        .unwrap()
        .unwrap_or_else(|why| panic!("{label}: the node refuses our coinjoin: {why}"));
    let txid = rpc.broadcast(&tx).unwrap();
    rpc.generate_to_address(1, &sink).unwrap();
    let paid = tx.output[0].value;
    for vout in 0..tx.output.len() as u32 {
        let out = rpc
            .utxo(&OutPoint { txid, vout })
            .unwrap()
            .expect("confirmed output");
        assert_eq!((out.confirmations, out.value), (1, paid));
    }
    // Every peer's wallet holds exactly the pool's output, at the address it registered.
    for (w, address) in wallets.iter_mut().zip(&paid_to) {
        w.sync(&rpc, 0).unwrap();
        assert_eq!(w.confirmed_balance(1).unwrap(), paid, "{label}");
        assert_eq!(
            w.confirmed_balance(0).unwrap(),
            Amount::ZERO,
            "{label}: the coin is spent"
        );
        assert!(
            tx.output
                .iter()
                .any(|o| o.script_pubkey == address.script_pubkey())
        );
    }
    println!("{label}: joinstr pool {txid} confirmed on the regtest node ({n} peers, {paid} each)");
}

#[tokio::test(flavor = "multi_thread")]
async fn joinstr_pools_confirm_on_a_real_node() {
    let Some(node) = Node::from_env() else {
        println!(
            "skipped: set VORTEX_NG_REGTEST_RPC and VORTEX_NG_REGTEST_COOKIE (tools/itest/run.sh)"
        );
        return;
    };
    // Unique wallets per run, so a node that already holds an earlier run's blocks does not confuse them.
    let run = unix_now();
    pool_round(
        &node,
        &format!("mixed{run}"),
        &[Pit::Sw0, Pit::Sw0, Pit::Tr0],
        false,
    )
    .await;
    pool_round(
        &node,
        &format!("recovery{run}"),
        &[Pit::Sw0, Pit::Sw0, Pit::Sw0],
        true,
    )
    .await;
}
