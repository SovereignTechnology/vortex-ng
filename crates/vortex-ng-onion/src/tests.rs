//! The onion channel against directory nodes in memory.

use vortex_ng_core::bitcoin::secp256k1::Secp256k1;
use vortex_ng_core::line::sign_line;
use vortex_ng_core::protocol::NOSTR_HOSTID;

use super::*;
use crate::testing::TestDirectory;

const WAIT: Duration = Duration::from_secs(5);

fn config(directories: &[&TestDirectory], network: &str) -> OnionConfig {
    OnionConfig {
        directories: directories.iter().map(|d| d.directory()).collect(),
        network: network.to_string(),
        timeout: Duration::from_secs(5),
    }
}

async fn join(directories: &[&TestDirectory]) -> OnionChannel {
    OnionChannel::connect(
        NickIdentity::generate(),
        config(directories, "regtest"),
        &Outbound::Direct,
    )
    .await
    .unwrap()
}

/// Wait until every directory has `count` peers connected (connections finish in the background).
async fn settled(directories: &[&TestDirectory], count: usize) {
    for _ in 0..100 {
        if directories.iter().all(|d| d.nicks().len() >= count) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the peers did not all connect");
}

#[tokio::test]
async fn a_round_trip_through_a_directory() {
    let directory = TestDirectory::start("regtest", None).await;
    let mut maker = join(&[&directory]).await;
    let mut taker = join(&[&directory]).await;
    settled(&[&directory], 2).await;
    maker.listen(false, true).await.unwrap();
    taker.listen(true, false).await.unwrap();

    // The taker's public request reaches the maker; its route leads back.
    taker.ask_orderbook().await.unwrap();
    let Next::Message(Incoming::Public {
        nick,
        commands,
        route,
    }) = maker.receive(WAIT).await
    else {
        panic!("the request")
    };
    assert_eq!(
        (nick.as_str(), commands),
        (taker.nick(), vec![Command::Orderbook])
    );
    // A private answer, signed for the onion channel, verified on arrival.
    maker
        .send_private(&route, taker.nick(), "sw0absoffer", "0 10000 100000 0 500")
        .await
        .unwrap();
    let Next::Message(Incoming::Private { msg, .. }) = taker.receive(WAIT).await else {
        panic!("the answer")
    };
    assert_eq!(
        (msg.from.as_str(), msg.command.as_str()),
        (maker.nick(), "sw0absoffer")
    );

    // Public offers, and their withdrawal (seen by a peer that listens to public messages too).
    taker.listen(true, true).await.unwrap();
    let offer = Offer::parse("sw0absoffer", "0 10000 100000 0 500").unwrap();
    maker
        .announce_offers(Pit::Sw0, std::slice::from_ref(&offer))
        .await
        .unwrap();
    let Next::Message(Incoming::Offers { nick, offers, .. }) = taker.receive(WAIT).await else {
        panic!("the offers")
    };
    assert_eq!((nick.as_str(), offers), (maker.nick(), vec![offer]));
    maker.withdraw_offers(Pit::Sw0).await.unwrap();
    let Next::Message(Incoming::Public { commands, .. }) = taker.receive(WAIT).await else {
        panic!("the cancel")
    };
    assert_eq!(commands, vec![Command::Cancel(0)]);
    // A channel that relays lines vouches for nobody.
    assert!(!maker.authenticates(&route));
    assert!(matches!(
        maker.receive(Duration::from_millis(200)).await,
        Next::Timeout
    ));
}

#[tokio::test]
async fn copies_from_other_directories_and_foreign_lines_are_dropped() {
    let (one, two) = (
        TestDirectory::start("regtest", None).await,
        TestDirectory::start("regtest", None).await,
    );
    let mut taker = join(&[&one, &two]).await;
    taker.listen(true, true).await.unwrap();
    settled(&[&one, &two], 1).await;
    let maker = NickIdentity::generate();
    let secp = Secp256k1::signing_only();
    let line = |to: &str, hostid: &str| {
        sign_line(
            &secp,
            maker.secret(),
            to,
            "pubkey",
            &"ab".repeat(32),
            hostid,
        )
        .unwrap()
    };
    // The same line from both directories arrives once.
    let good = line(taker.nick(), ONION_HOSTID);
    assert!(one.send(taker.nick(), PRIVMSG, &good));
    assert!(two.send(taker.nick(), PRIVMSG, &good));
    assert!(matches!(
        taker.receive(WAIT).await,
        Next::Message(Incoming::Private { .. })
    ));
    // A line signed for another channel, one addressed to someone else, and a public line claiming our
    // own nick are not messages.
    assert!(one.send(taker.nick(), PRIVMSG, &line(taker.nick(), NOSTR_HOSTID)));
    assert!(one.send(
        taker.nick(),
        PRIVMSG,
        &line("J5someoneElseOOOO", ONION_HOSTID)
    ));
    assert!(one.send(
        taker.nick(),
        PUBMSG,
        &public_line(taker.nick(), "!orderbook")
    ));
    assert!(matches!(
        taker.receive(Duration::from_millis(300)).await,
        Next::Timeout
    ));
}

#[tokio::test]
async fn nick_authentication_and_pings() {
    let directory = TestDirectory::start("regtest", Some("test-directory:5222")).await;
    let channel = join(&[&directory]).await;
    settled(&[&directory], 1).await;
    assert_eq!(directory.verified(), vec![channel.nick().to_string()]);
    directory.ping_all();
    for _ in 0..100 {
        if directory.pongs() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(directory.pongs(), 1);
    assert_eq!(channel.connected(), 1);
}

#[tokio::test]
async fn refusals_at_connection() {
    let directory = TestDirectory::start("regtest", None).await;
    // Another network.
    let refused = OnionChannel::connect(
        NickIdentity::generate(),
        config(&[&directory], "signet"),
        &Outbound::Direct,
    )
    .await;
    assert!(refused.is_err());
    // A nick already connected (JoinMarket-NG's directory keeps the first).
    let identity = NickIdentity::generate();
    let _first = OnionChannel::connect(
        identity.clone(),
        config(&[&directory], "regtest"),
        &Outbound::Direct,
    )
    .await
    .unwrap();
    let second = OnionChannel::connect(
        identity,
        config(&[&directory], "regtest"),
        &Outbound::Direct,
    )
    .await;
    assert!(second.is_err());
    // No directories.
    let none = OnionChannel::connect(
        NickIdentity::generate(),
        config(&[], "regtest"),
        &Outbound::Direct,
    )
    .await;
    assert!(matches!(none, Err(ChannelError::Invalid(_))));
}

#[tokio::test]
async fn an_unlinked_line_comes_from_a_stranger() {
    let directory = TestDirectory::start("regtest", None).await;
    let maker = join(&[&directory]).await;
    let mut watcher = join(&[&directory]).await;
    watcher.listen(false, true).await.unwrap();
    settled(&[&directory], 2).await;
    let commitment = "cd".repeat(32);
    maker
        .publish_unlinked(&format!("!hp2 {commitment}"))
        .await
        .unwrap();
    let Next::Message(Incoming::Public { nick, commands, .. }) = watcher.receive(WAIT).await else {
        panic!("the commitment")
    };
    assert_ne!(nick, maker.nick());
    assert!(matches!(commands.as_slice(), [Command::Hp2(_)]));
}

#[tokio::test]
async fn lines_are_bounded() {
    let long = format!("{}\n", "x".repeat(wire::MAX_RECEIVE_LINE + 10));
    let mut reader = BufReader::new(long.as_bytes());
    assert!(read_line(&mut reader).await.is_err());
    let mut reader = BufReader::new(&b"{\"type\":687,\"line\":\"x\"}\r\n"[..]);
    assert_eq!(read_line(&mut reader).await.unwrap(), (PUBMSG, "x".into()));
    let mut reader = BufReader::new(&b"{\"type\":687,\"line\":\"cut"[..]);
    assert!(read_line(&mut reader).await.is_err());
    assert_eq!(
        Directory::parse("abc.onion"),
        Some(Directory {
            host: "abc.onion".into(),
            port: DIRECTORY_PORT,
            id: None,
        })
    );
    assert_eq!(
        Directory::parse("127.0.0.1:7000").map(|d| d.port),
        Some(7000)
    );
    assert_eq!(Directory::parse("bad host:1"), None);
}
