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
use vortex_ng_core::bitcoin::secp256k1::Secp256k1;
use vortex_ng_core::bitcoin::transaction::Version;
use vortex_ng_core::bitcoin::{
    Amount, Block, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, TxIn, TxMerkleNode,
    TxOut, Txid, Witness, absolute,
};
use vortex_ng_core::line::sign_line;
use vortex_ng_core::offer::Pit;
use vortex_ng_core::protocol::NOSTR_HOSTID;
use vortex_ng_maker::MakerConfig;
use vortex_ng_nostr::client::NickClient;
use vortex_ng_nostr::keys::NickKeys;
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

/// Counts the chain lookups a bond check makes.
#[derive(Default)]
struct CountingChain {
    tips: std::sync::atomic::AtomicUsize,
    utxos: std::sync::atomic::AtomicUsize,
}

impl ChainLookup for CountingChain {
    fn utxo(&self, _: &OutPoint) -> Result<Option<Utxo>, String> {
        self.utxos.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(None)
    }
    fn tip_height(&self) -> Result<u32, String> {
        self.tips.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(300)
    }
    fn block_time(&self, _: u32) -> Result<u32, String> {
        Ok(1_700_000_000)
    }
}

fn pit_config() -> TakerConfig {
    TakerConfig {
        pit: Pit::Tr0,
        network: Network::Regtest,
        amount: AMOUNT,
        makers: 2,
        max_cjfee: 1_000,
        fee_rate_sat_per_kwu: 2_500,
        max_maker_utxos: 20,
        bondless_makers_allowance: vortex_ng_taker::DEFAULT_BONDLESS_ALLOWANCE,
        bondless_require_zero_fee: true,
        bond_params: Default::default(),
    }
}

#[test]
fn an_offer_is_sized_to_the_wallet() {
    use vortex_ng_core::offer::{CjFee, RelativeFee};

    let policy = OfferPolicy {
        fee: OfferFee::Relative("0.001".into()),
        txfee: 100,
        min_size: 100_000,
        max_size: None,
    };
    // What a round takes beyond its amount: our mining-fee share and the change we must keep.
    let reserve = 100 + MAKER_CHANGE_THRESHOLD_SAT;
    let offer = policy.offer(Pit::Sw0, 1_000_000).unwrap();
    assert_eq!(offer.offer_type.command(), "sw0reloffer");
    assert_eq!(
        (offer.oid, offer.minsize, offer.maxsize, offer.txfee),
        (0, 100_000, 1_000_000 - reserve, 100)
    );
    assert_eq!(
        offer.cjfee,
        CjFee::Relative(RelativeFee::parse("0.001").unwrap())
    );

    // Just enough for the smallest round, and one satoshi short of it.
    let offer = policy.offer(Pit::Sw0, 100_000 + reserve).unwrap();
    assert_eq!((offer.minsize, offer.maxsize), (100_000, 100_000));
    assert_eq!(policy.offer(Pit::Sw0, 100_000 + reserve - 1), None);
    assert_eq!(policy.offer(Pit::Sw0, 0), None);

    // A cap holds the offer down but never above what the wallet has.
    let capped = OfferPolicy {
        max_size: Some(250_000),
        ..policy.clone()
    };
    assert_eq!(capped.offer(Pit::Sw0, 1_000_000).unwrap().maxsize, 250_000);
    assert_eq!(
        capped.offer(Pit::Sw0, 200_000 + reserve).unwrap().maxsize,
        200_000
    );
    let below_min = OfferPolicy {
        max_size: Some(50_000),
        ..policy.clone()
    };
    assert_eq!(below_min.offer(Pit::Sw0, 1_000_000), None);

    // An absolute fee, in another pit.
    let absolute = OfferPolicy {
        fee: OfferFee::Absolute(500),
        txfee: 0,
        ..policy.clone()
    };
    let offer = absolute.offer(Pit::Tr0, 1_000_000).unwrap();
    assert_eq!(offer.offer_type.command(), "tr0absoffer");
    assert_eq!(offer.cjfee, CjFee::Absolute(500));
    assert_eq!(offer.maxsize, 1_000_000 - MAKER_CHANGE_THRESHOLD_SAT);

    // A fee that is not a fee, and a mining-fee share no wallet could cover, give no offer.
    for fee in ["-0.001", "free", ""] {
        let nonsense = OfferPolicy {
            fee: OfferFee::Relative(fee.into()),
            ..policy.clone()
        };
        assert_eq!(nonsense.offer(Pit::Sw0, 1_000_000), None, "{fee}");
    }
    let greedy = OfferPolicy {
        txfee: u64::MAX,
        ..policy
    };
    assert_eq!(greedy.offer(Pit::Sw0, u64::MAX), None);
}

#[test]
fn bond_lookups_are_bounded_and_only_for_candidates() {
    use std::sync::atomic::Ordering::SeqCst;
    use vortex_ng_core::bitcoin::secp256k1::{Secp256k1, SecretKey};
    use vortex_ng_core::bond::BondTemplate;
    let secp = Secp256k1::new();
    // More nicks than the cap, each with a proof signed by a key of its own (valid signatures) for an outpoint
    // that does not exist: the signature alone must not buy a lookup for all of them.
    let mut proofs = HashMap::new();
    for i in 0..(MAX_BOND_LOOKUPS as u32 + 100) {
        let nick = format!("J5fake{i}");
        let key = SecretKey::from_slice(&[(i % 250 + 1) as u8; 32]).unwrap();
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([(i % 250) as u8; 32]),
            vout: i,
        };
        let proof = BondTemplate::new(&secp, &key, outpoint, 1_893_456_000, 300)
            .proof(&secp, "J5taker", &nick)
            .to_base64()
            .unwrap();
        proofs.insert(nick.clone(), proof);
    }
    let cfg = pit_config();
    // Every nick a candidate: the cap holds.
    let all: HashSet<String> = proofs.keys().cloned().collect();
    let chain = CountingChain::default();
    let bonds = verify_bonds(
        &proofs,
        &all,
        |_| "J5taker".into(),
        &chain,
        1_800_000_000,
        &cfg,
    );
    assert!(bonds.is_empty(), "no such UTXOs");
    assert_eq!(chain.tips.load(SeqCst), 1, "the tip is read once");
    assert_eq!(chain.utxos.load(SeqCst), MAX_BOND_LOOKUPS);
    // A hundred candidates: a lookup for each of them and for nobody else.
    let some: HashSet<String> = all.iter().take(100).cloned().collect();
    let chain = CountingChain::default();
    verify_bonds(
        &proofs,
        &some,
        |_| "J5taker".into(),
        &chain,
        1_800_000_000,
        &cfg,
    );
    assert_eq!(chain.utxos.load(SeqCst), 100);
    // No candidates: no lookups at all.
    let chain = CountingChain::default();
    verify_bonds(
        &proofs,
        &HashSet::new(),
        |_| "J5taker".into(),
        &chain,
        1_800_000_000,
        &cfg,
    );
    assert_eq!(chain.utxos.load(SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn blocking_work_leaves_the_other_tasks_running() {
    // A multi-threaded runtime keeps serving a task while another thread's work blocks.
    let ticker = tokio::spawn(async {
        let mut ticks = 0;
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            ticks += 1;
        }
        ticks
    });
    blocking(|| std::thread::sleep(Duration::from_millis(200)));
    assert_eq!(ticker.await.unwrap(), 5);
}

#[tokio::test(flavor = "current_thread")]
async fn blocking_work_just_runs_on_a_current_thread_runtime() {
    assert_eq!(blocking(|| 7), 7);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_maker_on_two_channels_is_reached_through_one() {
    use vortex_ng_channel::set::ChannelSet;
    use vortex_ng_channel::testing::{MockRoute, Sent, mock_channel};
    use vortex_ng_core::nick::NickIdentity;

    let (a, on_a) = mock_channel("J5takerOnA", true);
    let (b, on_b) = mock_channel("J5takerOnB", false);
    let mut set = ChannelSet::new(vec![Box::new(a), Box::new(b)]).unwrap();
    let maker = NickIdentity::generate();
    // Its private answer on channel B comes first. Its copy on channel A, and its public offers there, come
    // later and change nothing.
    on_b.deliver_private(
        &maker,
        "J5takerOnB",
        "sw0absoffer",
        "0 10000 100000000 0 500",
        "b",
    );
    let later = on_a.clone();
    let late_maker = maker.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        later.deliver_private(
            &late_maker,
            "J5takerOnA",
            "sw0absoffer",
            "0 10000 100000000 0 500",
            "a",
        );
        later.deliver(Incoming::Offers {
            nick: late_maker.nick().to_string(),
            offers: Vec::new(),
            route: MockRoute("a".into()),
        });
    });
    let book = fetch_orderbook(&mut set, "regtest", Duration::from_millis(400))
        .await
        .unwrap();
    assert_eq!(book.offers.len(), 1, "{:?}", book.offers);
    let route = book.route(maker.nick()).unwrap();
    assert_eq!(set.channel_of(route), 1);
    // A bond proof from it is checked against the nick it knows us by there.
    assert_eq!(set.nick_on(route), "J5takerOnB");
    for channel in [&on_a, &on_b] {
        assert!(channel.sent().contains(&Sent::AskOrderbook));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_whole_coinjoin_through_an_onion_directory() {
    whole_coinjoin_through_a_directory(false).await;
}

/// The same round through a directory that delivers every private line twice, to everyone, and replays
/// each recipient's previous line before the next (ADR 0007, rule 3): the round still completes.
#[tokio::test(flavor = "multi_thread")]
async fn a_whole_coinjoin_through_a_mischievous_directory() {
    whole_coinjoin_through_a_directory(true).await;
}

async fn whole_coinjoin_through_a_directory(mischief: bool) {
    use vortex_ng_channel::socks::Outbound;
    use vortex_ng_core::nick::NickIdentity;
    use vortex_ng_core::protocol::ONION_HOSTID;
    use vortex_ng_onion::testing::TestDirectory;
    use vortex_ng_onion::{OnionChannel, OnionConfig};

    let directory = TestDirectory::start("regtest", None).await;
    directory.set_mischief(mischief);
    let config = OnionConfig {
        directories: vec![directory.directory()],
        network: "regtest".into(),
        timeout: Duration::from_secs(5),
        peers: vortex_ng_onion::PeerPolicy::Relay,
        serve: vortex_ng_onion::Serve::None,
    };
    let pit = Pit::Sw0;
    let mut utxos = HashMap::new();
    let maker_wallets: Vec<PitWallet> = (0..2)
        .map(|i| {
            let bond = Some(1_000_000 + u64::from(i));
            funded(
                pit,
                &format!("onion-maker{i}"),
                500_000,
                bond,
                30 + i,
                &mut utxos,
            )
        })
        .collect();
    let mut taker_wallet = funded(pit, "onion-taker", 600_000, None, 40, &mut utxos);
    let chain = SharedChain(Arc::new(utxos));
    let until = Instant::now() + Duration::from_secs(60);

    let mut handles = Vec::new();
    for (i, wallet) in maker_wallets.into_iter().enumerate() {
        let (chain, config) = (chain.clone(), config.clone());
        handles.push(tokio::spawn(async move {
            let offer =
                Offer::parse("sw0absoffer", &format!("{i} 10000 10000000 100 500")).unwrap();
            let mut maker = Maker::new(MakerConfig::new(vec![offer]), wallet).unwrap();
            let mut channel =
                OnionChannel::connect(NickIdentity::generate(), config, &Outbound::Direct)
                    .await
                    .unwrap();
            run_maker(&mut maker, &mut channel, &chain, "regtest", until).await
        }));
    }
    // The makers are listening before the taker asks.
    for _ in 0..100 {
        if directory.nicks().len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

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
    let mut channel =
        OnionChannel::connect(NickIdentity::generate(), config.clone(), &Outbound::Direct)
            .await
            .unwrap();
    // During the round, someone has the directory deliver a signed `!error` to the taker. On a channel that
    // vouches for nobody it must not end the round.
    let taker_nick = channel.nick().to_string();
    let eve = NickIdentity::generate();
    let error = sign_line(
        &Secp256k1::signing_only(),
        eve.secret(),
        &taker_nick,
        "error",
        "abort please",
        ONION_HOSTID,
    )
    .unwrap();
    let directory = Arc::new(directory);
    let injector = Arc::clone(&directory);
    let eve = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(3_300)).await;
        injector.send(&taker_nick, vortex_ng_onion::wire::PRIVMSG, &error)
    });
    let tx = run_taker(
        &mut taker,
        &taker_wallet,
        &mut channel,
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
    assert!(tx.output.iter().all(|o| o.script_pubkey.is_p2wpkh()));
    assert!(eve.await.unwrap(), "the outsider's line was delivered");
    // The commitment went out unlinked: a public `!hp2` from a nick that is neither maker's.
    let makers: Vec<String> = directory
        .received()
        .iter()
        .filter(|(_, kind, line)| {
            *kind == vortex_ng_onion::wire::PUBMSG && line.contains("absoffer")
        })
        .map(|(nick, _, _)| nick.clone())
        .collect();
    let hp2_from: Vec<String> = directory
        .received()
        .into_iter()
        .filter(|(_, _, line)| line.contains("!PUBLIC!hp2 "))
        .map(|(nick, _, _)| nick)
        .collect();
    assert_eq!(hp2_from.len(), 2, "one per maker");
    assert!(hp2_from.iter().all(|nick| !makers.contains(nick)));
    if mischief {
        assert!(
            directory.mischief_done() > 0,
            "the directory did no mischief"
        );
    }
    for handle in handles {
        handle.abort();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_whole_coinjoin_on_an_irc_server() {
    use vortex_ng_channel::socks::Outbound;
    use vortex_ng_core::nick::NickIdentity;
    use vortex_ng_irc::testing::TestIrc;
    use vortex_ng_irc::{IrcChannel, IrcConfig};

    let irc = TestIrc::start(Some("TestNet")).await;
    let config = IrcConfig {
        server: irc.server(),
        network: "regtest".into(),
        timeout: Duration::from_secs(5),
    };
    let pit = Pit::Sw0;
    let mut utxos = HashMap::new();
    let maker_wallets: Vec<PitWallet> = (0..2)
        .map(|i| {
            let bond = Some(1_000_000 + u64::from(i));
            funded(
                pit,
                &format!("irc-maker{i}"),
                500_000,
                bond,
                50 + i,
                &mut utxos,
            )
        })
        .collect();
    let mut taker_wallet = funded(pit, "irc-taker", 600_000, None, 60, &mut utxos);
    let chain = SharedChain(Arc::new(utxos));
    // IRC keeps to one line per 1.3 s: a round is slow.
    let until = Instant::now() + Duration::from_secs(240);

    let mut handles = Vec::new();
    for (i, wallet) in maker_wallets.into_iter().enumerate() {
        let (chain, config) = (chain.clone(), config.clone());
        handles.push(tokio::spawn(async move {
            let offer =
                Offer::parse("sw0absoffer", &format!("{i} 10000 10000000 100 500")).unwrap();
            let mut maker = Maker::new(MakerConfig::new(vec![offer]), wallet).unwrap();
            let mut channel =
                IrcChannel::connect(NickIdentity::generate(), config, &Outbound::Direct)
                    .await
                    .unwrap();
            run_maker(&mut maker, &mut channel, &chain, "regtest", until).await
        }));
    }
    for _ in 0..100 {
        if irc.nicks().len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

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
    let mut channel = IrcChannel::connect(NickIdentity::generate(), config, &Outbound::Direct)
        .await
        .unwrap();
    let tx = run_taker(
        &mut taker,
        &taker_wallet,
        &mut channel,
        &chain,
        &cfg,
        Duration::from_secs(8),
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
    // Every private line of the round went as pieces of at most 450 characters.
    assert!(
        irc.received()
            .iter()
            .filter(|(_, line)| line.starts_with("PRIVMSG J"))
            .all(|(_, line)| line.len() <= 450)
    );
    for handle in handles {
        handle.abort();
    }
}

/// One maker with one nick on a Nostr relay, an onion directory and an IRC server at once (ADR 0007), and a
/// taker on each of them in turn: each round runs on the taker's channel, with the maker's bond proof made
/// for that taker's nick there.
#[tokio::test(flavor = "multi_thread")]
async fn one_maker_on_three_channels_serves_a_taker_on_each() {
    use vortex_ng_channel::set::{ChannelSet, DynChannel};
    use vortex_ng_channel::socks::Outbound;
    use vortex_ng_core::nick::NickIdentity;
    use vortex_ng_irc::testing::TestIrc;
    use vortex_ng_irc::{IrcChannel, IrcConfig};
    use vortex_ng_onion::testing::TestDirectory;
    use vortex_ng_onion::{OnionChannel, OnionConfig};

    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let directory = TestDirectory::start("regtest", None).await;
    let irc = TestIrc::start(Some("TestNet")).await;
    let onion_config = OnionConfig {
        directories: vec![directory.directory()],
        network: "regtest".into(),
        timeout: Duration::from_secs(5),
        peers: vortex_ng_onion::PeerPolicy::Relay,
        serve: vortex_ng_onion::Serve::None,
    };
    let irc_config = IrcConfig {
        server: irc.server(),
        network: "regtest".into(),
        timeout: Duration::from_secs(5),
    };
    let pit = Pit::Sw0;
    let mut utxos = HashMap::new();
    let maker_wallet = funded(
        pit,
        "three-maker",
        2_000_000,
        Some(1_000_000),
        70,
        &mut utxos,
    );
    let taker_wallets: Vec<PitWallet> = (0..3u8)
        .map(|i| {
            funded(
                pit,
                &format!("three-taker{i}"),
                600_000,
                None,
                71 + i,
                &mut utxos,
            )
        })
        .collect();
    let chain = SharedChain(Arc::new(utxos));
    // IRC keeps to one line per 1.3 s.
    let until = Instant::now() + Duration::from_secs(300);

    // The maker: one nick on all three channels.
    let identity = NickIdentity::generate();
    let maker_channels: Vec<Box<dyn DynChannel>> = vec![
        Box::new(
            NickClient::connect(
                NickKeys::from_identity(identity.clone()).unwrap(),
                "regtest",
                std::slice::from_ref(&url),
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
    let maker_chain = chain.clone();
    let maker = tokio::spawn(async move {
        let offer = Offer::parse("sw0absoffer", "0 10000 10000000 100 500").unwrap();
        let mut maker = Maker::new(MakerConfig::new(vec![offer]), maker_wallet).unwrap();
        run_maker(&mut maker, &mut maker_set, &maker_chain, "regtest", until).await
    });
    for _ in 0..100 {
        if directory.nicks().len() == 1 && irc.nicks().len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    for (i, mut taker_wallet) in taker_wallets.into_iter().enumerate() {
        let channel: Box<dyn DynChannel> = match i {
            0 => Box::new(
                NickClient::connect(
                    NickKeys::generate(),
                    "regtest",
                    std::slice::from_ref(&url),
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
        let mut set = ChannelSet::new(vec![channel]).unwrap();
        let taker_nick = set.nick().to_string();
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
            bondless_makers_allowance: vortex_ng_taker::DEFAULT_BONDLESS_ALLOWANCE,
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
            &taker_wallet,
            &mut set,
            &chain,
            &cfg,
            Duration::from_secs(8),
            until,
        )
        .await
        .unwrap_or_else(|e| panic!("the round on channel {i} failed: {e}"));
        assert_eq!(tx.input.len(), 2, "channel {i}");
        assert!(tx.input.iter().all(|input| !input.witness.is_empty()));
        assert_eq!(
            tx.output
                .iter()
                .filter(|o| o.value.to_sat() == AMOUNT)
                .count(),
            2,
            "channel {i}"
        );
        // The round's private lines went over the taker's channel.
        match i {
            1 => assert!(directory.received().iter().any(|(from, kind, line)| {
                *from == taker_nick
                    && *kind == vortex_ng_onion::wire::PRIVMSG
                    && line.starts_with(&format!("{taker_nick}!{maker_nick}!fill "))
            })),
            2 => assert!(irc.received().iter().any(|(from, line)| {
                *from == taker_nick && line.starts_with(&format!("PRIVMSG {maker_nick} :!fill "))
            })),
            _ => {}
        }
        set.shutdown().await;
    }
    assert!(!maker.is_finished(), "the maker kept serving");
    maker.abort();
}

/// A whole round where the directory only introduces: two makers serve (on loopback, as on regtest), the
/// directory's peer list says where, and the taker talks to each over a direct connection (#45, #46). None of
/// the taker's private lines goes through the directory.
#[tokio::test(flavor = "multi_thread")]
async fn a_whole_coinjoin_over_direct_connections() {
    use vortex_ng_channel::set::{ChannelSet, DynChannel};
    use vortex_ng_channel::socks::Outbound;
    use vortex_ng_core::nick::NickIdentity;
    use vortex_ng_onion::testing::TestDirectory;
    use vortex_ng_onion::{OnionChannel, OnionConfig, PeerPolicy, Serve};

    let directory = TestDirectory::start("regtest", None).await;
    let config = |peers, serve| OnionConfig {
        directories: vec![directory.directory()],
        network: "regtest".into(),
        timeout: Duration::from_secs(5),
        peers,
        serve,
    };
    let pit = Pit::Sw0;
    let mut utxos = HashMap::new();
    let maker_wallets: Vec<PitWallet> = (0..2u8)
        .map(|i| {
            let bond = Some(1_000_000 + u64::from(i));
            funded(
                pit,
                &format!("direct-maker{i}"),
                500_000,
                bond,
                80 + i,
                &mut utxos,
            )
        })
        .collect();
    let mut taker_wallet = funded(pit, "direct-taker", 600_000, None, 90, &mut utxos);
    let chain = SharedChain(Arc::new(utxos));
    let until = Instant::now() + Duration::from_secs(90);

    let mut handles = Vec::new();
    let mut entries = Vec::new();
    for (i, wallet) in maker_wallets.into_iter().enumerate() {
        let mut channel = OnionChannel::connect(
            NickIdentity::generate(),
            config(PeerPolicy::Relay, Serve::Loopback),
            &Outbound::Direct,
        )
        .await
        .unwrap();
        entries.push(format!(
            "{};{}",
            channel.nick(),
            channel.location().unwrap()
        ));
        let chain = chain.clone();
        handles.push(tokio::spawn(async move {
            let offer =
                Offer::parse("sw0absoffer", &format!("{i} 10000 10000000 100 500")).unwrap();
            let mut maker = Maker::new(MakerConfig::new(vec![offer]), wallet).unwrap();
            run_maker(&mut maker, &mut channel, &chain, "regtest", until).await
        }));
    }
    // The directory names the makers when asked (JoinMarket-NG's way).
    directory.set_peerlist(&entries);
    for _ in 0..100 {
        if directory.nicks().len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

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
    let onion = OnionChannel::connect(
        NickIdentity::generate(),
        config(PeerPolicy::Local, Serve::None),
        &Outbound::Direct,
    )
    .await
    .unwrap();
    let taker_nick = onion.nick().to_string();
    let channels: Vec<Box<dyn DynChannel>> = vec![Box::new(onion)];
    let mut client = ChannelSet::new(channels).unwrap();
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
    // The directory carried the taker's `!orderbook` and nothing private from it.
    let from_taker: Vec<u64> = directory
        .received()
        .iter()
        .filter(|(from, _, _)| *from == taker_nick)
        .map(|(_, kind, _)| *kind)
        .collect();
    assert!(from_taker.contains(&vortex_ng_onion::wire::PUBMSG));
    assert!(
        !from_taker.contains(&vortex_ng_onion::wire::PRIVMSG),
        "{from_taker:?}"
    );
    for handle in handles {
        handle.abort();
    }
}

/// A third maker announces an offer and then never answers its `!fill`: a taker allowed to go on with two does.
#[tokio::test(flavor = "multi_thread")]
async fn a_round_goes_on_without_a_maker_that_never_answers() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let pit = Pit::Sw0;
    let mut utxos = HashMap::new();
    let maker_wallets: Vec<PitWallet> = (0..2u8)
        .map(|i| funded(pit, &format!("left{i}"), 500_000, None, 100 + i, &mut utxos))
        .collect();
    let mut taker_wallet = funded(pit, "left-taker", 600_000, None, 110, &mut utxos);
    let chain = SharedChain(Arc::new(utxos));
    let until = Instant::now() + Duration::from_secs(24);
    let mut handles = Vec::new();
    for (i, wallet) in maker_wallets.into_iter().enumerate() {
        let (chain, url) = (chain.clone(), url.clone());
        handles.push(tokio::spawn(async move {
            let offer =
                Offer::parse("sw0absoffer", &format!("{i} 10000 10000000 100 500")).unwrap();
            let mut maker = Maker::new(MakerConfig::new(vec![offer]), wallet).unwrap();
            let keys = NickKeys::generate();
            let mut client = NickClient::connect(keys, "regtest", &[url], None, CONNECT_TIMEOUT)
                .await
                .unwrap();
            run_maker(&mut maker, &mut client, &chain, "regtest", until).await
        }));
    }
    // Answers `!orderbook` like any maker, and nothing else.
    let mut silent = NickClient::connect(
        NickKeys::generate(),
        "regtest",
        std::slice::from_ref(&url),
        None,
        CONNECT_TIMEOUT,
    )
    .await
    .unwrap();
    silent.listen(false, true).await.unwrap();
    let quiet = tokio::spawn(async move {
        while Instant::now() < until {
            let next = silent.receive(Duration::from_millis(200)).await;
            if let Next::Message(Incoming::Public {
                nick,
                commands,
                route,
            }) = next
                && commands.iter().any(|c| matches!(c, Command::Orderbook))
            {
                let body = "2 10000 10000000 100 500";
                let _ = silent
                    .send_private(&route, &nick, "sw0absoffer", body)
                    .await;
            }
        }
    });

    let utxo = taker_wallet.utxos(0).unwrap().remove(0);
    let podle = podle_for(&taker_wallet, 0, &utxo, 0).unwrap();
    let cfg = TakerConfig {
        pit,
        makers: 3,
        bondless_require_zero_fee: false,
        ..pit_config()
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
    .unwrap()
    .allow_fewer_makers(2)
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
        &chain,
        &cfg,
        Duration::from_secs(3),
        until,
    )
    .await
    .unwrap();
    assert_eq!(taker.makers_in_round(), 2);
    assert_eq!(tx.input.len(), 3);
    assert!(tx.input.iter().all(|i| !i.witness.is_empty()));
    quiet.abort();
    for handle in handles {
        handle.abort();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_round_ends_when_its_channels_close() {
    use vortex_ng_channel::testing::{Sent, mock_channel};
    use vortex_ng_core::nick::NickIdentity;

    let pit = Pit::Sw0;
    let mut utxos = HashMap::new();
    let mut taker_wallet = funded(pit, "closing-taker", 600_000, None, 120, &mut utxos);
    let chain = SharedChain(Arc::new(utxos));
    let utxo = taker_wallet.utxos(0).unwrap().remove(0);
    let podle = podle_for(&taker_wallet, 0, &utxo, 0).unwrap();
    let cfg = TakerConfig {
        pit,
        makers: 1,
        bondless_require_zero_fee: false,
        ..pit_config()
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
    let (mut channel, handle) = mock_channel("J5taker", true);
    let maker = NickIdentity::generate();
    handle.deliver_private(
        &maker,
        "J5taker",
        "sw0absoffer",
        "0 10000 10000000 100 500",
        "a",
    );
    let closer = handle.clone();
    tokio::spawn(async move {
        loop {
            let filled = closer
                .sent()
                .iter()
                .any(|s| matches!(s, Sent::Private { command, .. } if command == "fill"));
            if filled {
                closer.close();
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    let started = Instant::now();
    let round = run_taker(
        &mut taker,
        &taker_wallet,
        &mut channel,
        &chain,
        &cfg,
        Duration::from_millis(200),
        started + Duration::from_secs(30),
    )
    .await;
    assert!(matches!(round, Err(NodeError::Channel(_))), "{round:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_flood_of_orderbook_requests_leaves_room_for_real_takers() {
    let start = Instant::now();
    let mut limiter = OrderbookLimiter::new();
    // A burst on channel 0 spends that channel's bucket, and only that channel's.
    let answered = (0..ORDERBOOK_BURST * 10)
        .filter(|i| limiter.allow(0, &format!("J5flood{i}"), start))
        .count();
    assert_eq!(answered, ORDERBOOK_BURST as usize);
    assert!(!limiter.allow(0, "J5real", start));
    assert!(limiter.allow(1, "J5real", start));
    // The budget comes back over time, so a burst at the start of a minute cannot spend the minute.
    let soon = start + Duration::from_secs(1);
    assert!(limiter.allow(0, "J5real", soon));
    assert!(limiter.allow(0, "J5second", soon));
    assert!(!limiter.allow(0, "J5third", soon));
    // A nick is answered once per interval.
    let later = soon + Duration::from_secs(2);
    assert!(!limiter.allow(0, "J5real", later));
    // A quiet time refills the bucket, but no further than one burst.
    let quiet = soon + Duration::from_secs(3_600);
    let answered = (0..ORDERBOOK_BURST * 2)
        .filter(|i| limiter.allow(0, &format!("J5after{i}"), quiet))
        .count();
    assert_eq!(answered, ORDERBOOK_BURST as usize);
}

#[test]
fn a_line_of_thousands_of_commands_is_not_read() {
    let msg = |body: String| PrivMsg {
        from: "J5maker".into(),
        to: "J5taker".into(),
        command: "sw0absoffer".into(),
        body,
        key: *NickKeys::generate().identity().public(),
    };
    let flood = format!("0 10000 100000000 0 500{}", "!a".repeat(30_000));
    assert!(commands(&msg(flood)).is_empty());
    let answer = "0 10000 100000000 0 500!sw0absoffer 1 10000 100000000 0 500".to_string();
    assert_eq!(commands(&msg(answer)).len(), 2);
}

#[test]
fn past_the_cap_a_channel_keeps_a_sample_of_who_answered() {
    let mut book: ChannelAnswers<u8> = ChannelAnswers::new();
    for i in 0..MAX_ANSWERING_NICKS {
        assert!(
            book.place(&format!("J5first{i}"), &0, i as u64, 0)
                .is_some()
        );
    }
    // A later nick gets a place when its draw lands inside the table, and pushes one out.
    let heard = MAX_ANSWERING_NICKS as u64 + 1;
    assert!(book.place("J5late", &0, heard, 3).is_some());
    assert_eq!(book.answers.len(), MAX_ANSWERING_NICKS);
    assert!(book.answers.contains_key("J5late"));
    // When it lands past the table it does not, and nothing moves.
    let past = MAX_ANSWERING_NICKS as u64 + 1;
    assert!(book.place("J5unlucky", &0, heard + 1, past).is_none());
    assert!(!book.answers.contains_key("J5unlucky"));
    assert_eq!(book.answers.len(), MAX_ANSWERING_NICKS);
}

#[tokio::test]
async fn a_line_relabelled_on_one_channel_does_not_take_the_maker_off_another() {
    use vortex_ng_channel::set::ChannelSet;
    use vortex_ng_channel::testing::mock_channel;
    use vortex_ng_core::nick::NickIdentity;

    let (a, on_a) = mock_channel("J5takerOnA", false);
    let (b, on_b) = mock_channel("J5takerOnB", false);
    let mut set = ChannelSet::new(vec![Box::new(a), Box::new(b)]).unwrap();
    let maker = NickIdentity::generate();
    let body = "0 10000 100000000 0 500";
    // First, on channel A, its sw0 offer shown as one of another pit. Then the real one on channel B.
    on_a.deliver_private(&maker, "J5takerOnA", "tr0absoffer", body, "a");
    let (later, late_maker) = (on_b.clone(), maker.clone());
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        later.deliver_private(&late_maker, "J5takerOnB", "sw0absoffer", body, "b");
    });
    let usable = |offer: &Offer| offer.offer_type.pit == Pit::Sw0;
    let book = fetch_orderbook_for(&mut set, "regtest", Duration::from_millis(400), usable)
        .await
        .unwrap();
    assert_eq!(book.offers.len(), 1, "{:?}", book.offers);
    assert_eq!(book.offers[0].1.offer_type.pit, Pit::Sw0);
    assert_eq!(set.channel_of(book.route(maker.nick()).unwrap()), 1);
}

#[tokio::test]
async fn offers_a_taker_cannot_use_do_not_take_the_place_of_one_it_can() {
    use vortex_ng_channel::testing::mock_channel;
    use vortex_ng_core::nick::NickIdentity;

    let (mut channel, handle) = mock_channel("J5taker", false);
    let maker = NickIdentity::generate();
    // On the one channel: enough of its lines shown under another pit to fill its place, and copies of the
    // real offer, before the real one.
    for i in 0..MAX_OFFERS_PER_NICK {
        let body = format!("{i} 10000 100000000 0 500");
        handle.deliver_private(&maker, "J5taker", "tr0absoffer", &body, "a");
    }
    for _ in 0..2 {
        let real = "99 10000 100000000 0 500";
        handle.deliver_private(&maker, "J5taker", "sw0absoffer", real, "a");
    }
    let usable = |offer: &Offer| offer.offer_type.pit == Pit::Sw0;
    let book = fetch_orderbook_for(&mut channel, "regtest", Duration::from_millis(300), usable)
        .await
        .unwrap();
    assert_eq!(book.offers.len(), 1, "{:?}", book.offers);
    assert_eq!(book.offers[0].1.oid, 99);
    assert!(book.route(maker.nick()).is_some());
}

#[tokio::test]
async fn a_replayed_offer_does_not_cost_a_maker_its_bond_or_its_route() {
    use vortex_ng_channel::set::ChannelSet;
    use vortex_ng_channel::testing::mock_channel;
    use vortex_ng_core::bitcoin::secp256k1::{Secp256k1, SecretKey};
    use vortex_ng_core::bond::BondTemplate;
    use vortex_ng_core::nick::NickIdentity;

    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[7; 32]).unwrap();
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([9; 32]),
        vout: 0,
    };
    let bond = BondTemplate::new(&secp, &key, outpoint, 1_893_456_000, 300);
    let (a, on_a) = mock_channel("J5takerOnA", false);
    let (b, on_b) = mock_channel("J5takerOnB", false);
    let mut set = ChannelSet::new(vec![Box::new(a), Box::new(b)]).unwrap();
    let maker = NickIdentity::generate();
    let line = |taker: &str| {
        let proof = bond.proof(&secp, taker, maker.nick()).to_base64().unwrap();
        format!("0 10000 100000000 0 500!tbond {proof}")
    };
    // Its answer to somebody else, delivered first on channel A, even relabelled as a `!fill`.
    on_a.deliver_private(&maker, "J5takerOnA", "fill", &line("J5someoneElse"), "a");
    on_a.deliver_private(
        &maker,
        "J5takerOnA",
        "sw0absoffer",
        &line("J5someoneElse"),
        "a",
    );
    // Its real answer, on channel B.
    let (later, real_line) = (on_b.clone(), line("J5takerOnB"));
    let late_maker = maker.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        later.deliver_private(&late_maker, "J5takerOnB", "sw0absoffer", &real_line, "b");
    });
    let book = fetch_orderbook(&mut set, "regtest", Duration::from_millis(400))
        .await
        .unwrap();
    assert_eq!(book.offers.len(), 1, "the replay's offer is gone");
    assert_eq!(set.channel_of(book.route(maker.nick()).unwrap()), 1);
    let kept = BondProof::from_base64(&book.proofs[maker.nick()]).unwrap();
    assert!(
        kept.verify_signatures(&secp, "J5takerOnB", maker.nick())
            .is_ok(),
        "the proof made out to us"
    );
}
