//! The onion channel against directory nodes in memory.

use vortex_ng_core::bitcoin::secp256k1::Secp256k1;
use vortex_ng_core::line::sign_line;
use vortex_ng_core::protocol::NOSTR_HOSTID;

use super::*;
use crate::testing::{TestDirectory, TestPeer};

const WAIT: Duration = Duration::from_secs(5);

fn config(directories: &[&TestDirectory], network: &str) -> OnionConfig {
    OnionConfig {
        directories: directories.iter().map(|d| d.directory()).collect(),
        network: network.to_string(),
        timeout: Duration::from_secs(5),
        peers: PeerPolicy::Relay,
        serve: Serve::None,
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

/// Wait until `check` holds (connections and forwarding finish in the background).
async fn eventually(check: impl Fn() -> bool) -> bool {
    for _ in 0..100 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    false
}

/// A taker channel that may connect to loopback peers, with a route to `maker` learned from a private line
/// the directory relayed (and, before it, the directory's peer list naming where `maker` serves, as
/// joinmarket-clientserver's directories send when they relay a line).
async fn taker_with_route(
    directory: &TestDirectory,
    maker: &NickIdentity,
    location: Option<String>,
) -> (OnionChannel, OnionRoute) {
    taker_through(
        directory,
        maker,
        location,
        PeerPolicy::Local,
        &Outbound::Direct,
    )
    .await
}

/// [`taker_with_route`], with its own peer policy and way out.
async fn taker_through(
    directory: &TestDirectory,
    maker: &NickIdentity,
    location: Option<String>,
    peers: PeerPolicy,
    outbound: &Outbound,
) -> (OnionChannel, OnionRoute) {
    let mut cfg = config(&[directory], "regtest");
    cfg.peers = peers;
    let mut taker = OnionChannel::connect(NickIdentity::generate(), cfg, outbound)
        .await
        .unwrap();
    taker.listen(true, false).await.unwrap();
    settled(&[directory], 1).await;
    if let Some(location) = location {
        assert!(directory.send(
            taker.nick(),
            PEERLIST,
            &format!("{};{location}", maker.nick())
        ));
    }
    let offer = sign_line(
        &Secp256k1::signing_only(),
        maker.secret(),
        taker.nick(),
        "sw0absoffer",
        "0 10000 100000 0 500",
        ONION_HOSTID,
    )
    .unwrap();
    assert!(directory.send(taker.nick(), PRIVMSG, &offer));
    let Next::Message(Incoming::Private { route, .. }) = taker.receive(WAIT).await else {
        panic!("the offer")
    };
    (taker, route)
}

#[tokio::test]
async fn a_chosen_maker_is_reached_directly() {
    // joinmarket-clientserver's maker accepts a handshake silently; JoinMarket-NG's answers it.
    for answer in [false, true] {
        let directory = TestDirectory::start("regtest", None).await;
        let maker = NickIdentity::generate();
        let peer = TestPeer::start("regtest", maker.nick(), answer).await;
        let (mut taker, route) = taker_with_route(&directory, &maker, Some(peer.location())).await;
        taker
            .prepare(&[(maker.nick().to_string(), route.clone())])
            .await;
        let handshakes = peer.handshakes();
        assert_eq!(handshakes.len(), 1, "answer {answer}");
        assert!(
            handshakes[0].contains(taker.nick()) && handshakes[0].contains("NOT-SERVING-ONION")
        );

        // The round's lines go over the direct connection; the directory never sees them.
        taker
            .send_private(&route, maker.nick(), "fill", "0 50000 abc")
            .await
            .unwrap();
        let fill = format!("{}!{}!fill ", taker.nick(), maker.nick());
        assert!(
            eventually(|| peer
                .received()
                .iter()
                .any(|(kind, line)| *kind == PRIVMSG && line.starts_with(&fill)))
            .await
        );
        assert!(
            !directory
                .received()
                .iter()
                .any(|(_, _, line)| line.contains("!fill "))
        );

        // Only the maker's own lines count on its connection.
        let secp = Secp256k1::signing_only();
        let stranger = NickIdentity::generate();
        let foreign = sign_line(
            &secp,
            stranger.secret(),
            taker.nick(),
            "pubkey",
            &"ab".repeat(32),
            ONION_HOSTID,
        )
        .unwrap();
        let answer_line = sign_line(
            &secp,
            maker.secret(),
            taker.nick(),
            "pubkey",
            &"cd".repeat(32),
            ONION_HOSTID,
        )
        .unwrap();
        assert!(peer.send(PRIVMSG, &foreign));
        assert!(peer.send(PRIVMSG, &answer_line));
        let Next::Message(Incoming::Private { msg, .. }) = taker.receive(WAIT).await else {
            panic!("the maker's answer")
        };
        assert_eq!(
            (msg.from.as_str(), msg.command.as_str()),
            (maker.nick(), "pubkey")
        );
        assert!(matches!(
            taker.receive(Duration::from_millis(300)).await,
            Next::Timeout
        ));
    }
}

#[tokio::test]
async fn without_a_direct_way_lines_go_by_the_directory() {
    let directory = TestDirectory::start("regtest", None).await;
    let maker = NickIdentity::generate();
    // Where nobody listens; named only in answer to GETPEERLIST, as JoinMarket-NG's directories do.
    let closed = {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    directory.set_peerlist(&[format!("{};127.0.0.1:{closed}", maker.nick())]);
    let (taker, route) = taker_with_route(&directory, &maker, None).await;
    taker
        .prepare(&[(maker.nick().to_string(), route.clone())])
        .await;
    assert!(
        directory
            .received()
            .iter()
            .any(|(from, kind, _)| from == taker.nick() && *kind == GETPEERLIST)
    );
    taker
        .send_private(&route, maker.nick(), "fill", "0 50000 abc")
        .await
        .unwrap();
    assert!(
        eventually(|| directory
            .received()
            .iter()
            .any(|(_, kind, line)| *kind == PRIVMSG && line.contains("!fill ")))
        .await
    );
}

#[tokio::test]
async fn when_a_direct_connection_drops_the_lines_go_by_the_directory() {
    let directory = TestDirectory::start("regtest", None).await;
    let maker = NickIdentity::generate();
    let peer = TestPeer::start("regtest", maker.nick(), true).await;
    let (taker, route) = taker_with_route(&directory, &maker, Some(peer.location())).await;
    taker
        .prepare(&[(maker.nick().to_string(), route.clone())])
        .await;
    taker
        .send_private(&route, maker.nick(), "fill", "0 50000 abc")
        .await
        .unwrap();
    let fill = format!("{}!{}!fill ", taker.nick(), maker.nick());
    assert!(
        eventually(|| peer
            .received()
            .iter()
            .any(|(kind, line)| *kind == PRIVMSG && line.starts_with(&fill)))
        .await
    );

    // The maker hangs up in the middle of the round: the rest of it goes by the directory.
    peer.hang_up();
    assert!(eventually(|| taker.shared.link(maker.nick()).is_none()).await);
    taker
        .send_private(&route, maker.nick(), "auth", "abc")
        .await
        .unwrap();
    assert!(
        eventually(|| directory
            .received()
            .iter()
            .any(|(from, kind, line)| from == taker.nick()
                && *kind == PRIVMSG
                && line.contains("!auth ")))
        .await
    );
    assert!(
        !directory
            .received()
            .iter()
            .any(|(_, _, line)| line.contains("!fill "))
    );
}

/// A maker that serves on loopback, connected to `directory`.
async fn serving_maker(directory: &TestDirectory, identity: NickIdentity) -> OnionChannel {
    let mut cfg = config(&[directory], "regtest");
    cfg.serve = Serve::Loopback;
    OnionChannel::connect(identity, cfg, &Outbound::Direct)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_serving_maker_is_reached_directly_both_ways() {
    let directory = TestDirectory::start("regtest", None).await;
    let identity = NickIdentity::generate();
    let mut maker = serving_maker(&directory, identity.clone()).await;
    maker.listen(false, true).await.unwrap();
    let location = maker.location().expect("a location").to_string();
    assert!(location.starts_with("127.0.0.1:"));
    let (mut taker, route) = taker_with_route(&directory, &identity, Some(location)).await;
    settled(&[&directory], 2).await;
    taker
        .prepare(&[(identity.nick().to_string(), route.clone())])
        .await;
    assert!(eventually(|| maker.direct() == 1 && taker.direct() == 1).await);

    // The taker's line reaches the maker on the connection, and the maker answers on it.
    taker
        .send_private(&route, identity.nick(), "fill", "0 50000 abc")
        .await
        .unwrap();
    let Next::Message(Incoming::Private { msg, route: back }) = maker.receive(WAIT).await else {
        panic!("the fill")
    };
    assert_eq!(
        (msg.from.as_str(), msg.command.as_str()),
        (taker.nick(), "fill")
    );
    maker
        .send_private(&back, taker.nick(), "pubkey", &"ab".repeat(32))
        .await
        .unwrap();
    let Next::Message(Incoming::Private { msg, .. }) = taker.receive(WAIT).await else {
        panic!("the answer")
    };
    assert_eq!(
        (msg.from.as_str(), msg.command.as_str()),
        (identity.nick(), "pubkey")
    );
    // The directory saw neither.
    assert!(
        !directory
            .received()
            .iter()
            .any(|(_, _, line)| line.contains("!fill ") || line.contains("!pubkey "))
    );
}

#[tokio::test]
async fn a_maker_serving_a_configured_onion_is_reached_through_the_proxy() {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use vortex_ng_channel::testing::AuthSocks;

    let directory = TestDirectory::start("regtest", None).await;
    let identity = NickIdentity::generate();
    let host = format!("{}.onion", "c".repeat(56));
    let free = || {
        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        probe.local_addr().unwrap().port()
    };
    // Only a v3 onion name and a real port will do.
    for (name, port) in [("example.com".to_string(), free()), (host.clone(), 0)] {
        let mut cfg = config(&[&directory], "regtest");
        cfg.serve = Serve::Onion { host: name, port };
        assert!(matches!(
            OnionChannel::connect(identity.clone(), cfg, &Outbound::Direct).await,
            Err(ChannelError::Invalid(_))
        ));
    }
    let port = free();
    let mut cfg = config(&[&directory], "regtest");
    cfg.serve = Serve::Onion {
        host: host.clone(),
        port,
    };
    let mut maker = OnionChannel::connect(identity.clone(), cfg, &Outbound::Direct)
        .await
        .unwrap();
    maker.listen(false, true).await.unwrap();
    let location = format!("{host}:{port}");
    assert_eq!(maker.location(), Some(location.as_str()));

    // The taker reaches the maker by its onion name, through the proxy, as through Tor.
    let proxy =
        AuthSocks::start_with_onions(HashMap::from([(host.clone(), Ipv4Addr::LOCALHOST.into())]))
            .await
            .unwrap();
    let (mut taker, route) = taker_through(
        &directory,
        &identity,
        Some(location.clone()),
        PeerPolicy::Onion,
        &Outbound::IsolatingProxy(proxy.addr()),
    )
    .await;
    settled(&[&directory], 2).await;
    taker
        .prepare(&[(identity.nick().to_string(), route.clone())])
        .await;
    assert!(eventually(|| maker.direct() == 1 && taker.direct() == 1).await);
    assert!(proxy.seen().iter().any(|(_, to)| *to == location));

    taker
        .send_private(&route, identity.nick(), "fill", "0 50000 abc")
        .await
        .unwrap();
    let Next::Message(Incoming::Private { msg, route: back }) = maker.receive(WAIT).await else {
        panic!("the fill")
    };
    assert_eq!(
        (msg.from.as_str(), msg.command.as_str()),
        (taker.nick(), "fill")
    );
    maker
        .send_private(&back, taker.nick(), "pubkey", &"ab".repeat(32))
        .await
        .unwrap();
    let Next::Message(Incoming::Private {
        msg,
        route: answered,
    }) = taker.receive(WAIT).await
    else {
        panic!("the answer")
    };
    assert_eq!(
        (msg.from.as_str(), msg.command.as_str()),
        (identity.nick(), "pubkey")
    );
    // A line on a direct connection came from the peer on the other end, in either direction; a line a
    // directory relayed can be any line it was ever handed. Neither route is authenticated: a directory chose
    // whom the taker connected to.
    assert!(taker.first_hand(&answered) && maker.first_hand(&back));
    assert!(!taker.first_hand(&route));
    assert!(!taker.authenticates(&answered) && !maker.authenticates(&back));
    assert!(
        !directory
            .received()
            .iter()
            .any(|(_, _, line)| line.contains("!fill ") || line.contains("!pubkey "))
    );
}

#[tokio::test]
async fn inbound_peers_are_held_to_their_handshake() {
    use tokio::net::TcpStream;

    let directory = TestDirectory::start("regtest", None).await;
    let identity = NickIdentity::generate();
    let mut maker = serving_maker(&directory, identity.clone()).await;
    maker.listen(false, true).await.unwrap();
    let location = maker.location().unwrap().to_string();
    async fn say(stream: &mut TcpStream, kind: u64, line: &str) {
        let encoded = encode(kind, line).unwrap();
        stream.write_all(encoded.as_bytes()).await.unwrap();
    }
    // Another network, and our own nick: refused.
    let stranger = NickIdentity::generate();
    for hello in [
        wire::client_handshake(stranger.nick(), "signet", &[], None),
        wire::client_handshake(identity.nick(), "regtest", &[], None),
    ] {
        let mut conn = TcpStream::connect(&location).await.unwrap();
        say(&mut conn, HANDSHAKE, &hello).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(maker.direct(), 0);
    }
    // A valid handshake: a link, which carries only its own nick's lines.
    let mut conn = TcpStream::connect(&location).await.unwrap();
    say(
        &mut conn,
        HANDSHAKE,
        &wire::client_handshake(stranger.nick(), "regtest", &[], None),
    )
    .await;
    assert!(eventually(|| maker.direct() == 1).await);
    // The peer gets our handshake back, with where we serve.
    let mut reader = BufReader::new(&mut conn);
    let (kind, hello) = tokio::time::timeout(WAIT, read_line(&mut reader))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kind, HANDSHAKE);
    assert!(hello.contains(identity.nick()) && hello.contains(&location));
    let secp = Secp256k1::signing_only();
    let other = NickIdentity::generate();
    let foreign = sign_line(
        &secp,
        other.secret(),
        identity.nick(),
        "fill",
        "0 50000 abc",
        ONION_HOSTID,
    )
    .unwrap();
    let own = sign_line(
        &secp,
        stranger.secret(),
        identity.nick(),
        "fill",
        "0 50000 abc",
        ONION_HOSTID,
    )
    .unwrap();
    say(&mut conn, PRIVMSG, &foreign).await;
    say(&mut conn, PRIVMSG, &own).await;
    let Next::Message(Incoming::Private { msg, .. }) = maker.receive(WAIT).await else {
        panic!("the peer's own line")
    };
    assert_eq!(msg.from, stranger.nick());
    assert!(matches!(
        maker.receive(Duration::from_millis(300)).await,
        Next::Timeout
    ));
}

#[tokio::test]
async fn a_stranger_claiming_a_nick_gets_none_of_its_lines() {
    use tokio::net::TcpStream;

    let directory = TestDirectory::start("regtest", None).await;
    let identity = NickIdentity::generate();
    let mut maker = serving_maker(&directory, identity.clone()).await;
    maker.listen(false, true).await.unwrap();
    let location = maker.location().unwrap().to_string();
    // The real taker, on the directory, with a route to the maker.
    let taker = NickIdentity::generate();
    let mut cfg = config(&[&directory], "regtest");
    cfg.peers = PeerPolicy::Relay;
    let taker_channel = OnionChannel::connect(taker.clone(), cfg, &Outbound::Direct)
        .await
        .unwrap();
    settled(&[&directory], 2).await;
    // A stranger connects to the maker claiming the taker's nick, and more than once: no place is held.
    let mut strangers = Vec::new();
    for _ in 0..2 {
        let mut conn = TcpStream::connect(&location).await.unwrap();
        let hello = encode(
            HANDSHAKE,
            &wire::client_handshake(taker.nick(), "regtest", &[], None),
        )
        .unwrap();
        conn.write_all(hello.as_bytes()).await.unwrap();
        strangers.push(conn);
    }
    assert!(eventually(|| maker.direct() == 2).await);
    // The taker's line comes by the directory, so the answer goes back by the directory.
    let fill = sign_line(
        &Secp256k1::signing_only(),
        taker.secret(),
        identity.nick(),
        "fill",
        "0 50000 abc",
        ONION_HOSTID,
    )
    .unwrap();
    assert!(directory.send(identity.nick(), PRIVMSG, &fill));
    let Next::Message(Incoming::Private { route, .. }) = maker.receive(WAIT).await else {
        panic!("the fill")
    };
    maker
        .send_private(&route, taker.nick(), "pubkey", &"ab".repeat(32))
        .await
        .unwrap();
    assert!(
        eventually(|| directory
            .received()
            .iter()
            .any(|(from, kind, line)| from == identity.nick()
                && *kind == PRIVMSG
                && line.contains("!pubkey ")))
        .await
    );
    // The strangers got our handshake and nothing else.
    for conn in &mut strangers {
        let mut reader = BufReader::new(conn);
        let (kind, _) = tokio::time::timeout(WAIT, read_line(&mut reader))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kind, HANDSHAKE);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), read_line(&mut reader))
                .await
                .is_err()
        );
    }
    drop(taker_channel);
}

#[tokio::test]
async fn only_the_directory_a_maker_answered_through_is_believed_about_it() {
    let honest = TestDirectory::start("regtest", None).await;
    let other = TestDirectory::start("regtest", None).await;
    let maker = NickIdentity::generate();
    let trap = TestPeer::start("regtest", maker.nick(), true).await;
    let mut cfg = config(&[&honest, &other], "regtest");
    cfg.peers = PeerPolicy::Local;
    let mut taker = OnionChannel::connect(NickIdentity::generate(), cfg, &Outbound::Direct)
        .await
        .unwrap();
    taker.listen(true, false).await.unwrap();
    settled(&[&honest, &other], 1).await;
    // The other directory says the maker is at the trap; the maker's answer came through the honest one.
    assert!(other.send(
        taker.nick(),
        PEERLIST,
        &format!("{};{}", maker.nick(), trap.location())
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let offer = sign_line(
        &Secp256k1::signing_only(),
        maker.secret(),
        taker.nick(),
        "sw0absoffer",
        "0 10000 100000 0 500",
        ONION_HOSTID,
    )
    .unwrap();
    assert!(honest.send(taker.nick(), PRIVMSG, &offer));
    let Next::Message(Incoming::Private { route, .. }) = taker.receive(WAIT).await else {
        panic!("the offer")
    };
    taker
        .prepare(&[(maker.nick().to_string(), route.clone())])
        .await;
    assert!(trap.handshakes().is_empty());
    assert_eq!(taker.direct(), 0);
}

#[tokio::test]
async fn another_nick_answering_at_a_location_is_not_linked() {
    let directory = TestDirectory::start("regtest", None).await;
    let maker = NickIdentity::generate();
    let impostor = TestPeer::start("regtest", "J5impostorOOOOOO", true).await;
    let (taker, route) = taker_with_route(&directory, &maker, Some(impostor.location())).await;
    taker
        .prepare(&[(maker.nick().to_string(), route.clone())])
        .await;
    assert_eq!(taker.direct(), 0);
}
