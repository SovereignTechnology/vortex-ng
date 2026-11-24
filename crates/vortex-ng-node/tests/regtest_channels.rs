//! One maker with one nick on a Nostr relay, an onion directory and an IRC server at once, against a real
//! regtest node (ADR 0007, #44): three takers in turn, one per channel, each complete a CoinJoin with it.
//!
//! The maker runs as a service with one spendable coin, so each round after the first is funded by what the
//! one before paid it. A taker pays its fee only to a maker whose bond proof verifies against the node for that
//! taker's nick on that channel. Each round's answers must appear on the taker's channel and on no other, and
//! the maker must end with what it had plus three fees, less its three mining-fee shares.
//!
//! Skipped unless `VORTEX_NG_REGTEST_RPC` and `VORTEX_NG_REGTEST_COOKIE` are set (`tools/itest/run.sh` sets
//! them). A test binary of its own: it mines blocks, and the tests of `regtest.rs` count confirmations.

// A test harness: a failed step should panic with its error.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use nostr_sdk::prelude::MockRelay;
use vortex_ng_chain::{Auth, CoreRpc};
use vortex_ng_channel::Channel;
use vortex_ng_channel::set::{ChannelSet, DynChannel};
use vortex_ng_channel::socks::Outbound;
use vortex_ng_core::bitcoin::{Amount, Network, OutPoint};
use vortex_ng_core::nick::NickIdentity;
use vortex_ng_core::offer::Pit;
use vortex_ng_irc::testing::TestIrc;
use vortex_ng_irc::{IrcChannel, IrcConfig};
use vortex_ng_maker::{Maker, MakerConfig};
use vortex_ng_node::{
    CONNECT_TIMEOUT, MakerReport, MakerService, OfferFee, OfferPolicy, run_taker, serve_maker,
};
use vortex_ng_nostr::client::NickClient;
use vortex_ng_nostr::keys::NickKeys;
use vortex_ng_onion::testing::TestDirectory;
use vortex_ng_onion::{OnionChannel, OnionConfig, PeerPolicy, Serve};
use vortex_ng_taker::{DEFAULT_BONDLESS_ALLOWANCE, Taker, TakerConfig, podle_for};
use vortex_ng_wallet::{MIXDEPTHS, PitWallet, Seed};

const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const AMOUNT: u64 = 1_000_000;
const CJFEE: u64 = 500;
const TXFEE: u64 = 100;
/// The bond timelock: timenumber 120, January 2030.
const BOND_TIMENUMBER: u32 = 120;
/// How often the maker brings its wallet to the tip and sizes its offer.
const UPKEEP: Duration = Duration::from_secs(1);
const ROUNDS: u64 = 3;

fn wallet(who: &str) -> PitWallet {
    let seed = Seed::from_mnemonic(WORDS, &format!("three-{who}"), Network::Regtest).unwrap();
    PitWallet::new(&seed, Pit::Sw0).unwrap()
}

fn total(wallet: &PitWallet) -> Amount {
    (0..MIXDEPTHS)
        .map(|m| wallet.confirmed_balance(m).unwrap())
        .sum()
}

#[tokio::test(flavor = "multi_thread")]
async fn one_maker_on_three_channels_confirms_a_round_on_each() {
    let (Ok(url), Ok(cookie)) = (
        std::env::var("VORTEX_NG_REGTEST_RPC"),
        std::env::var("VORTEX_NG_REGTEST_COOKIE"),
    ) else {
        println!(
            "skipped: set VORTEX_NG_REGTEST_RPC and VORTEX_NG_REGTEST_COOKIE (tools/itest/run.sh)"
        );
        return;
    };
    let cookie = PathBuf::from(cookie);
    let connect = || {
        CoreRpc::new(
            &url,
            &Auth::CookieFile(cookie.clone()),
            Duration::from_secs(60),
        )
        .unwrap()
    };
    let rpc = connect();
    assert_eq!(rpc.network().unwrap(), Network::Regtest, "regtest only");
    let birthday = rpc.tip_height().unwrap();

    // Fund: the maker's one coin, its bond, a coin for each taker, then 100 blocks to mature them.
    let mut maker_wallet = wallet("maker");
    rpc.generate_to_address(1, &maker_wallet.next_receive_address(0).unwrap())
        .unwrap();
    rpc.generate_to_address(1, &maker_wallet.bond_address(BOND_TIMENUMBER).unwrap())
        .unwrap();
    let mut taker_wallets: Vec<PitWallet> =
        (0..ROUNDS).map(|i| wallet(&format!("taker{i}"))).collect();
    for taker in &mut taker_wallets {
        rpc.generate_to_address(1, &taker.next_receive_address(0).unwrap())
            .unwrap();
    }
    let sink = wallet("sink").next_receive_address(0).unwrap();
    rpc.generate_to_address(100, &sink).unwrap();
    maker_wallet.sync(&rpc, birthday).unwrap();
    assert_eq!(maker_wallet.bonds().len(), 1);
    let before = total(&maker_wallet);
    for taker in &mut taker_wallets {
        taker.sync(&rpc, birthday).unwrap();
    }

    // The three places to meet.
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let directory = TestDirectory::start("regtest", None).await;
    let irc = TestIrc::start(Some("TestNet")).await;
    let onion_config = OnionConfig {
        directories: vec![directory.directory()],
        network: "regtest".into(),
        timeout: Duration::from_secs(5),
        peers: PeerPolicy::Relay,
        serve: Serve::None,
    };
    let irc_config = IrcConfig {
        server: irc.server(),
        network: "regtest".into(),
        timeout: Duration::from_secs(5),
    };

    // The maker: one nick on all three.
    let identity = NickIdentity::generate();
    let maker_channels: Vec<Box<dyn DynChannel>> = vec![
        Box::new(
            NickClient::connect(
                NickKeys::from_identity(identity.clone()).unwrap(),
                "regtest",
                std::slice::from_ref(&relay_url),
                None,
                CONNECT_TIMEOUT,
            )
            .await
            .unwrap(),
        ),
        Box::new(
            OnionChannel::connect(identity.clone(), onion_config.clone(), &Outbound::Direct)
                .await
                .unwrap(),
        ),
        Box::new(
            IrcChannel::connect(identity.clone(), irc_config.clone(), &Outbound::Direct)
                .await
                .unwrap(),
        ),
    ];
    let mut maker_set = ChannelSet::new(maker_channels).unwrap();
    let maker_nick = maker_set.nick().to_string();
    assert_eq!(maker_nick, identity.nick());
    let mut maker = Maker::new(MakerConfig::new(Vec::new()), maker_wallet).unwrap();
    let service = MakerService {
        policy: OfferPolicy {
            fee: OfferFee::Absolute(CJFEE),
            txfee: TXFEE,
            min_size: 100_000,
            max_size: None,
        },
        birthday,
        upkeep: UPKEEP,
    };
    let offering = AtomicBool::new(false);
    let mut report = |report: MakerReport| match report {
        MakerReport::Offering { offer: Some(_), .. } => offering.store(true, Ordering::SeqCst),
        MakerReport::Offering { offer: None, .. } => {}
        MakerReport::Trouble(why) => eprintln!("maker upkeep: {why}"),
    };
    // IRC keeps to one line per 1.3 s.
    let until = Instant::now() + Duration::from_secs(420);
    let maker_rpc = connect();
    let serving = serve_maker(
        &mut maker,
        &mut maker_set,
        &maker_rpc,
        "regtest",
        &service,
        Some(until),
        &mut report,
    );

    let rounds = async {
        let ready = Instant::now() + Duration::from_secs(30);
        while !(offering.load(Ordering::SeqCst)
            && directory.nicks().contains(&maker_nick)
            && irc.nicks().contains(&maker_nick))
        {
            assert!(
                Instant::now() < ready,
                "the maker did not come up on all three channels"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;

        for (i, taker_wallet) in taker_wallets.iter_mut().enumerate() {
            let channel: Box<dyn DynChannel> = match i {
                0 => Box::new(
                    NickClient::connect(
                        NickKeys::generate(),
                        "regtest",
                        std::slice::from_ref(&relay_url),
                        None,
                        CONNECT_TIMEOUT,
                    )
                    .await
                    .unwrap(),
                ),
                1 => Box::new(
                    OnionChannel::connect(
                        NickIdentity::generate(),
                        onion_config.clone(),
                        &Outbound::Direct,
                    )
                    .await
                    .unwrap(),
                ),
                _ => Box::new(
                    IrcChannel::connect(
                        NickIdentity::generate(),
                        irc_config.clone(),
                        &Outbound::Direct,
                    )
                    .await
                    .unwrap(),
                ),
            };
            let name = ["Nostr", "onion", "IRC"][i];
            let mut set = ChannelSet::new(vec![channel]).unwrap();
            let taker_nick = set.nick().to_string();
            let utxo = taker_wallet.utxos(0).unwrap().remove(0);
            let podle = podle_for(taker_wallet, 0, &utxo, 0).unwrap();
            let cfg = TakerConfig {
                pit: Pit::Sw0,
                network: Network::Regtest,
                amount: AMOUNT,
                makers: 1,
                max_cjfee: 1_000,
                fee_rate_sat_per_kwu: 2_500,
                max_maker_utxos: 20,
                bondless_makers_allowance: DEFAULT_BONDLESS_ALLOWANCE,
                // The maker charges a fee: it is chosen only if its bond proof verifies on this channel.
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
            let tx = run_taker(
                &mut taker,
                taker_wallet,
                &mut set,
                &rpc,
                &cfg,
                Duration::from_secs(8),
                until,
            )
            .await
            .unwrap_or_else(|e| panic!("the round on {name} failed: {e}"));
            set.shutdown().await;

            rpc.test_accept(&tx)
                .unwrap()
                .unwrap_or_else(|why| panic!("{name}: the node refuses the CoinJoin: {why}"));
            let txid = rpc.broadcast(&tx).unwrap();
            rpc.generate_to_address(1, &sink).unwrap();
            for vout in 0..tx.output.len() as u32 {
                let out = rpc
                    .utxo(&OutPoint { txid, vout })
                    .unwrap()
                    .expect("confirmed output");
                assert_eq!(out.confirmations, 1, "{name}");
            }
            assert_eq!(tx.input.len(), 2, "{name}");
            assert_eq!(
                tx.output
                    .iter()
                    .filter(|o| o.value.to_sat() == AMOUNT)
                    .count(),
                2,
                "{name}"
            );
            taker_wallet.sync(&rpc, birthday).unwrap();
            assert_eq!(
                taker_wallet.confirmed_balance(1).unwrap(),
                Amount::from_sat(AMOUNT),
                "{name}"
            );

            // The maker answered on this taker's channel and on no other legacy one. A taker's nick exists
            // only on its own channel, so a Nostr round shows on neither.
            let on_directory = directory.received().iter().any(|(from, kind, line)| {
                *from == maker_nick
                    && *kind == vortex_ng_onion::wire::PRIVMSG
                    && line.starts_with(&format!("{maker_nick}!{taker_nick}!"))
            });
            let on_irc = irc.received().iter().any(|(from, line)| {
                *from == maker_nick && line.starts_with(&format!("PRIVMSG {taker_nick} :"))
            });
            assert_eq!((on_directory, on_irc), (i == 1, i == 2), "{name}");
            println!("{name}: CoinJoin {txid} confirmed with the maker on three channels");

            // Two upkeeps: the maker sees the block and offers what the round paid it.
            tokio::time::sleep(UPKEEP * 3).await;
        }
    };
    tokio::select! {
        stopped = serving => panic!("the maker stopped: {stopped:?}"),
        () = rounds => {}
    }
    maker_set.shutdown().await;

    let mut restored = wallet("maker");
    restored.sync(&rpc, birthday).unwrap();
    assert_eq!(
        total(&restored),
        before + Amount::from_sat(ROUNDS * (CJFEE - TXFEE)),
        "the maker's coins, plus three fees, less its three mining-fee shares"
    );
    assert_eq!(restored.bonds().len(), 1);
    println!("One maker, one nick, three channels: {ROUNDS} CoinJoins confirmed");
}
