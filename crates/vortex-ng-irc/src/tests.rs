//! The IRC channel against a server in memory.

use std::time::Duration;

use vortex_ng_channel::socks::Outbound;
use vortex_ng_channel::{Channel, Incoming, Next};
use vortex_ng_core::bitcoin::secp256k1::Secp256k1;
use vortex_ng_core::command::Command;
use vortex_ng_core::line::sign_line;
use vortex_ng_core::nick::NickIdentity;
use vortex_ng_core::offer::{Offer, Pit};

use crate::codec::private_lines;
use crate::testing::{TestIrc, other_roots, test_roots};
use crate::{IrcChannel, IrcConfig, IrcServer};

const WAIT: Duration = Duration::from_secs(10);

fn config(server: IrcServer) -> IrcConfig {
    IrcConfig {
        server,
        network: "regtest".into(),
        timeout: Duration::from_secs(5),
    }
}

async fn join(irc: &TestIrc) -> IrcChannel {
    IrcChannel::connect(
        NickIdentity::generate(),
        config(irc.server()),
        &Outbound::Direct,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_round_trip_on_the_pit() {
    let irc = TestIrc::start(Some("TestNet")).await;
    let mut maker = join(&irc).await;
    let mut taker = join(&irc).await;
    // The signature domain is what the server announced.
    assert_eq!(maker.hostid(), "TestNet");
    maker.listen(false, true).await.unwrap();
    taker.listen(true, true).await.unwrap();

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
    // A private line long enough to need several pieces, signed over the server's domain.
    let body = format!("0 10000 100000 0 500!tbond {}", "Ab".repeat(400));
    maker
        .send_private(&route, taker.nick(), "sw0absoffer", &body)
        .await
        .unwrap();
    let Next::Message(Incoming::Private { msg, .. }) = taker.receive(WAIT).await else {
        panic!("the answer")
    };
    assert_eq!(
        (msg.from.as_str(), msg.command.as_str(), msg.body.as_str()),
        (maker.nick(), "sw0absoffer", body.as_str())
    );
    let pieces = irc
        .received()
        .iter()
        .filter(|(from, line)| {
            from == maker.nick() && line.contains(&format!("PRIVMSG {} :", taker.nick()))
        })
        .count();
    assert!(pieces > 1, "{pieces} piece(s)");

    // Offers in public, packed as the reference packs them, and their withdrawal.
    let offer = Offer::parse("sw0absoffer", "0 10000 100000 0 500").unwrap();
    maker
        .announce_offers(Pit::Sw0, std::slice::from_ref(&offer))
        .await
        .unwrap();
    let Next::Message(Incoming::Offers { offers, .. }) = taker.receive(WAIT).await else {
        panic!("the offers")
    };
    assert_eq!(offers, vec![offer]);
    maker.withdraw_offers(Pit::Sw0).await.unwrap();
    let Next::Message(Incoming::Public { commands, .. }) = taker.receive(WAIT).await else {
        panic!("the cancel")
    };
    assert_eq!(commands, vec![Command::Cancel(0)]);
    assert!(!maker.authenticates(&route));
}

#[tokio::test]
async fn foreign_lines_are_dropped() {
    let irc = TestIrc::start(Some("TestNet")).await;
    let mut taker = join(&irc).await;
    taker.listen(true, true).await.unwrap();
    let maker = NickIdentity::generate();
    let secp = Secp256k1::signing_only();
    let me = taker.nick().to_string();
    // As the server would relay a line from `maker`, signed over `domain`.
    let deliver = |domain: &str, to: &str| {
        let line = sign_line(
            &secp,
            maker.secret(),
            to,
            "pubkey",
            &"ab".repeat(32),
            domain,
        )
        .unwrap();
        let message = line
            .splitn(3, '!')
            .nth(2)
            .unwrap()
            .split_once(' ')
            .unwrap()
            .1
            .to_string();
        for piece in private_lines(&me, "pubkey", &message).unwrap() {
            let text = piece.trim_end().split_once(" :").unwrap().1.to_string();
            irc.send(
                &me,
                &format!(":{}!u@test PRIVMSG {} :{text}", maker.nick(), me),
            );
        }
    };
    // Signed over another domain: not a message. CTCP neither. (A copy of a line sent to another nick does
    // verify here: an IRC line carries no recipient but its target, and the signature never covered one. The
    // maker and taker ignore such stray lines.)
    deliver("onion-network", &me);
    irc.send(
        &me,
        &format!(":{}!u@test PRIVMSG {} :\u{1}VERSION\u{1}", maker.nick(), me),
    );
    assert!(matches!(
        taker.receive(Duration::from_millis(500)).await,
        Next::Timeout
    ));
    // The right domain: a message.
    deliver("TestNet", &me);
    assert!(matches!(
        taker.receive(WAIT).await,
        Next::Message(Incoming::Private { .. })
    ));
}

#[tokio::test]
async fn refusals_at_connection() {
    // A server that announces another network than the one expected.
    let irc = TestIrc::start(Some("Elsewhere")).await;
    let mut server = irc.server();
    server.expected_network = Some("TestNet".into());
    assert!(
        IrcChannel::connect(NickIdentity::generate(), config(server), &Outbound::Direct)
            .await
            .is_err()
    );
    // A nick in use.
    let identity = NickIdentity::generate();
    let _first = IrcChannel::connect(identity.clone(), config(irc.server()), &Outbound::Direct)
        .await
        .unwrap();
    assert!(
        IrcChannel::connect(identity, config(irc.server()), &Outbound::Direct)
            .await
            .is_err()
    );
    // A server that announces no network: host and port.
    let quiet = TestIrc::start(None).await;
    let channel = join(&quiet).await;
    let server = quiet.server();
    assert_eq!(channel.hostid(), format!("{}{}", server.host, server.port));
    assert!(channel.connected());
}

#[tokio::test]
async fn an_unlinked_line_comes_from_a_stranger() {
    let irc = TestIrc::start(Some("TestNet")).await;
    let maker = join(&irc).await;
    let mut watcher = join(&irc).await;
    watcher.listen(false, true).await.unwrap();
    maker
        .publish_unlinked(&format!("!hp2 {}", "cd".repeat(32)))
        .await
        .unwrap();
    let Next::Message(Incoming::Public { nick, commands, .. }) = watcher.receive(WAIT).await else {
        panic!("the commitment")
    };
    assert_ne!(nick, maker.nick());
    assert!(matches!(commands.as_slice(), [Command::Hp2(_)]));
}

#[tokio::test]
async fn a_rounds_lines_go_before_orderbook_answers() {
    let irc = TestIrc::start(Some("TestNet")).await;
    let maker = join(&irc).await;
    let taker = join(&irc).await;
    let route = crate::IrcRoute;
    // A queue of what anyone can ask for (answers to `!orderbook`, replies to `!fill`), then a line of a
    // round that has proved a coin.
    for i in 0..4 {
        let (command, body) = if i % 2 == 0 {
            ("sw0absoffer", format!("{i} 10000 100000 0 500"))
        } else {
            ("pubkey", "ab".repeat(32))
        };
        maker
            .send_private(&route, taker.nick(), command, &body)
            .await
            .unwrap();
    }
    maker
        .send_private(&route, taker.nick(), "ioauth", "QUJD")
        .await
        .unwrap();
    let order = || -> Vec<bool> {
        irc.received()
            .iter()
            .filter(|(from, line)| from == maker.nick() && line.starts_with("PRIVMSG J"))
            .map(|(_, line)| line.contains("!ioauth "))
            .collect()
    };
    for _ in 0..80 {
        if order().contains(&true) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let seen = order();
    let at = seen
        .iter()
        .position(|is_round| *is_round)
        .expect("the round's line");
    assert!(at <= 1, "the round's line went out as line {at}: {seen:?}");
    // Past its small queue, an answer is refused rather than queued for minutes.
    let mut refused = false;
    for i in 0..(super::channel::BULK_QUEUE_FOR_TESTS + 2) {
        refused |= maker
            .send_private(
                &route,
                taker.nick(),
                "sw0absoffer",
                &format!("{i} 10000 100000 0 500"),
            )
            .await
            .is_err();
    }
    assert!(refused);
}

#[test]
fn a_server_address_says_how_it_is_protected() {
    let tls = |text: &str| IrcServer::parse(text).unwrap().tls;
    assert!(tls("irc.example.org:6697"));
    assert!(tls("198.51.100.7:6697"));
    assert!(!tls("abcdefghijklmnop.onion:6667"), "Tor encrypts it");
    assert!(!tls("127.0.0.1:6667"));
    assert!(!tls("localhost:6667"));
    assert!(!tls("irc://irc.example.org:6667"));
    assert!(tls("ircs://127.0.0.1:6697"));
    assert!(tls("ircs://abcdefghijklmnop.onion:6697"));
    assert!(IrcServer::parse("http://irc.example.org:6667").is_none());
    assert!(IrcServer::parse("ircs://:6697").is_none());
    // A name that merely looks private is not.
    assert!(tls("127.0.0.1.example.org:6697"));
    assert!(tls("onion.example.org:6697"));
    assert!(
        IrcServer::parse("irc://irc.example.org:6667")
            .unwrap()
            .is_exposed()
    );
    assert!(
        !IrcServer::parse("irc://127.0.0.1:6667")
            .unwrap()
            .is_exposed()
    );
    assert!(
        !IrcServer::parse("irc.example.org:6697")
            .unwrap()
            .is_exposed()
    );
}

#[tokio::test]
async fn plain_text_to_a_remote_server_is_refused_off_regtest() {
    let server = IrcServer::parse("irc://irc.example.invalid:6667").unwrap();
    let refused = IrcChannel::connect(
        NickIdentity::generate(),
        IrcConfig {
            network: "signet".into(),
            ..config(server)
        },
        &Outbound::Direct,
    )
    .await;
    assert!(matches!(
        refused,
        Err(vortex_ng_channel::ChannelError::Invalid(_))
    ));
}

async fn over_tls(
    server: IrcServer,
    roots: tokio_rustls::rustls::RootCertStore,
) -> Result<IrcChannel, vortex_ng_channel::ChannelError> {
    IrcChannel::connect_with_roots(
        NickIdentity::generate(),
        config(server),
        &Outbound::Direct,
        roots,
    )
    .await
}

#[tokio::test]
async fn a_round_trip_over_tls() {
    let irc = TestIrc::start_tls(Some("TestNet")).await;
    let mut maker = over_tls(irc.server(), test_roots()).await.unwrap();
    let taker = over_tls(irc.server(), test_roots()).await.unwrap();
    assert_eq!(maker.hostid(), "TestNet");
    maker.listen(false, true).await.unwrap();
    taker.ask_orderbook().await.unwrap();
    let Next::Message(Incoming::Public { nick, commands, .. }) = maker.receive(WAIT).await else {
        panic!("the request")
    };
    assert_eq!(
        (nick.as_str(), commands),
        (taker.nick(), vec![Command::Orderbook])
    );
}

#[tokio::test]
async fn a_certificate_from_an_authority_we_do_not_trust_is_refused() {
    let irc = TestIrc::start_tls(None).await;
    assert!(over_tls(irc.server(), other_roots()).await.is_err());
    assert!(irc.nicks().is_empty(), "nothing was said to the server");
}

#[tokio::test]
async fn a_certificate_for_another_name_is_refused() {
    let irc = TestIrc::start_tls(None).await;
    let server = IrcServer {
        host: "localhost".into(),
        ..irc.server()
    };
    assert!(over_tls(server, test_roots()).await.is_err());
    assert!(irc.nicks().is_empty(), "nothing was said to the server");
}

#[tokio::test]
async fn a_server_without_tls_gets_no_plain_text_from_a_tls_client() {
    let irc = TestIrc::start(None).await;
    let server = IrcServer {
        tls: true,
        ..irc.server()
    };
    assert!(over_tls(server, test_roots()).await.is_err());
    assert!(irc.nicks().is_empty());
    assert!(irc.received().is_empty());
}
