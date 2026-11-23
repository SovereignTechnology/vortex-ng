//! IRC as JoinMarket uses it, without I/O.
//!
//! - Lines: `[:prefix] COMMAND params [:trailing]`, at most 512 bytes with `\r\n` (RFC 1459). Only the few
//!   commands JoinMarket needs are built.
//! - Public messages: `PRIVMSG #joinmarket-pit :!command args`, unchunked. joinmarket-clientserver ends its
//!   offer lines with ` ~`; [`public_text`] removes it.
//! - Private messages: `PRIVMSG <nick> :` and the JMP-0001 line without its `from!to!` (the IRC prefix says
//!   who sent it, the target whom), cut into pieces that fit [`MAX_PRIVMSG_LEN`]: the first starts with
//!   `!command `, each ends with ` ;` (more follows) or ` ~` (the last). Pieces are chosen by position, not
//!   by comparing their text as joinmarket-clientserver does (which mislabels equal pieces); its receivers
//!   read either the same way.
//! - Reassembly per sender, bounded in size, time and senders.
//! - The signature domain (`hostid`) is the server's `NETWORK=` from its `005` line; see [`Hostid`].
//! - One line per [`LINE_INTERVAL`], the rate joinmarket-clientserver keeps ([`Pacer`]).
//! - CTCP (`\x01…\x01`) is never answered.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// The longest line, `\r\n` included.
pub const MAX_LINE: usize = 512;
/// joinmarket-clientserver's limit on a `PRIVMSG` line it sends, header included.
pub const MAX_PRIVMSG_LEN: usize = 450;
/// One line per this interval at most (joinmarket-clientserver's `lineRate`).
pub const LINE_INTERVAL: Duration = Duration::from_millis(1_300);
/// The pit channel's name before its network suffix.
pub const PIT: &str = "#joinmarket-pit";
/// The longest private message reassembled (joinmarket-clientserver's onion limit is 40,000 bytes).
pub const MAX_MESSAGE: usize = 64 * 1024;
/// How long the pieces of one message may take.
pub const REASSEMBLY_TTL: Duration = Duration::from_secs(60);
/// Most senders with a message half received.
pub const MAX_PENDING: usize = 256;

/// The pit channel for a network: `#joinmarket-pit`, with `-test` on testnet and regtest (joinmarket-clientserver
/// runs regtest as testnet) and `-sig` on signet.
pub fn pit_channel(network: &str) -> String {
    match network {
        "testnet" | "testnet4" | "regtest" => format!("{PIT}-test"),
        "signet" => format!("{PIT}-sig"),
        _ => PIT.to_string(),
    }
}

/// One IRC message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Who sent it (`nick!user@host`, or a server name).
    pub prefix: Option<String>,
    /// The command or numeric, upper case.
    pub command: String,
    /// The parameters, the trailing one included.
    pub params: Vec<String>,
}

impl Message {
    /// The sender's nick, if a user sent it.
    pub fn nick(&self) -> Option<&str> {
        let prefix = self.prefix.as_deref()?;
        let nick = prefix.split(['!', '@']).next()?;
        (!nick.is_empty()).then_some(nick)
    }
}

/// Parse a line (without `\r\n`). `None` for an empty or malformed line, or one with IRCv3 tags (never
/// asked for).
pub fn parse(line: &str) -> Option<Message> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() || line.starts_with('@') || line.contains('\0') {
        return None;
    }
    let (prefix, rest) = match line.strip_prefix(':') {
        Some(rest) => {
            let (prefix, rest) = rest.split_once(' ')?;
            (Some(prefix.to_string()), rest)
        }
        None => (None, line),
    };
    let (head, trailing) = match rest.split_once(" :") {
        Some((head, trailing)) => (head, Some(trailing)),
        None => (rest, None),
    };
    let mut words = head.split(' ').filter(|w| !w.is_empty());
    let command = words.next()?.to_ascii_uppercase();
    let mut params: Vec<String> = words.map(str::to_string).collect();
    if let Some(trailing) = trailing {
        params.push(trailing.to_string());
    }
    Some(Message {
        prefix,
        command,
        params,
    })
}

/// A line to send, `\r\n` included. `None` if a parameter would break the line (a newline, a NUL, a space
/// or leading `:` anywhere but in the last one) or the line is too long.
pub fn build(command: &str, params: &[&str]) -> Option<String> {
    let mut line = command.to_string();
    for (i, param) in params.iter().enumerate() {
        if param.contains(['\r', '\n', '\0']) {
            return None;
        }
        let last = i + 1 == params.len();
        if last && (param.is_empty() || param.contains(' ') || param.starts_with(':')) {
            line.push_str(" :");
        } else if param.is_empty() || param.contains(' ') || param.starts_with(':') {
            return None;
        } else {
            line.push(' ');
        }
        line.push_str(param);
    }
    line.push_str("\r\n");
    (line.len() <= MAX_LINE).then_some(line)
}

/// The text of a public message, without joinmarket-clientserver's ` ~` at the end of offer lines.
pub fn public_text(text: &str) -> &str {
    text.strip_suffix(" ~").unwrap_or(text)
}

/// Whether a message is CTCP (never answered).
pub fn is_ctcp(text: &str) -> bool {
    text.starts_with('\u{1}')
}

/// The `PRIVMSG` lines that carry `!command message` to `to`: `message` is a JMP-0001 private line after its
/// command (body, key, signature). `None` when it cannot be sent (not ASCII, or `to` or `command` leave no
/// room).
pub fn private_lines(to: &str, command: &str, message: &str) -> Option<Vec<String>> {
    if !message.is_ascii() || message.is_empty() || command.is_empty() {
        return None;
    }
    let header = format!("PRIVMSG {to} :");
    // The first piece also carries `!` and the command and a space; every piece a two-character trailer.
    let room = MAX_PRIVMSG_LEN
        .checked_sub(header.len() + command.len() + 4)
        .filter(|room| *room > 0)?;
    let pieces: Vec<&str> = message
        .as_bytes()
        .chunks(room)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect();
    let last = pieces.len() - 1;
    let mut lines = Vec::with_capacity(pieces.len());
    for (i, piece) in pieces.iter().enumerate() {
        let trailer = if i == last { " ~" } else { " ;" };
        let text = if i == 0 {
            format!("!{command} {piece}{trailer}")
        } else {
            format!("{piece}{trailer}")
        };
        lines.push(build("PRIVMSG", &[to, &text])?);
    }
    Some(lines)
}

/// Public offer lines as joinmarket-clientserver sends them: as many `!offer …` as fit on one line, each line
/// ending in ` ~`. An offer too long for a line on its own is sent alone.
pub fn offer_lines(channel: &str, offers: &[String]) -> Vec<String> {
    let header = format!("PRIVMSG {channel} :");
    let mut lines = Vec::new();
    let mut current = String::new();
    for offer in offers {
        if !current.is_empty() && header.len() + current.len() + offer.len() + 2 > MAX_PRIVMSG_LEN {
            lines.push(current);
            current = String::new();
        }
        current.push_str(offer);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
        .into_iter()
        .filter_map(|text| build("PRIVMSG", &[channel, &format!("{text} ~")]))
        .collect()
}

/// Private messages put back together from their pieces, per sender, with bounded memory.
#[derive(Debug, Default)]
pub struct Reassembler {
    pending: HashMap<String, (String, Instant)>,
}

impl Reassembler {
    /// Take one piece from `from`. Returns the whole message (`!command body key signature`) once its last
    /// piece has come. A piece that does not fit (no trailer, a first piece without `!`, too long, too late)
    /// throws away what was gathered from that sender.
    pub fn push(&mut self, from: &str, text: &str, now: Instant) -> Option<String> {
        self.pending
            .retain(|_, (_, at)| now.duration_since(*at) < REASSEMBLY_TTL);
        let (piece, last) = if let Some(piece) = text.strip_suffix(" ~") {
            (piece, true)
        } else if let Some(piece) = text.strip_suffix(" ;") {
            (piece, false)
        } else {
            self.pending.remove(from);
            return None;
        };
        let gathered = match self.pending.remove(from) {
            Some((mut gathered, at)) => {
                gathered.push_str(piece);
                (gathered, at)
            }
            None => {
                if !piece.starts_with('!') {
                    return None;
                }
                // A message in one piece needs no room, so a full table cannot hold it up.
                if last {
                    return (piece.len() <= MAX_MESSAGE).then(|| piece.to_string());
                }
                // Not the oldest: that is usually a long real message, which a burst of first pieces could
                // then always push out. The map's order is one a sender cannot predict.
                if self.pending.len() >= MAX_PENDING
                    && let Some(nick) = self.pending.keys().next().cloned()
                {
                    self.pending.remove(&nick);
                }
                (piece.to_string(), now)
            }
        };
        if gathered.0.len() > MAX_MESSAGE {
            return None;
        }
        if last {
            return Some(gathered.0);
        }
        self.pending.insert(from.to_string(), gathered);
        None
    }

    /// Senders with a message half received.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}

/// Why a server's signature domain was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostidError(pub &'static str);

impl std::fmt::Display for HostidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// The server's signature domain (`hostid`), taken once and then frozen.
///
/// joinmarket-clientserver signs and verifies private lines over `body + hostid`, where the hostid is the
/// `NETWORK=` value the server announces in its `005` line, or `host` and `port` run together when it
/// announces none. The value comes from the server and is joined to the body without a separator, so here
/// it is taken from the first `005` line only, checked (length, characters), compared with the value
/// expected for this server when one is configured, and never changed afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hostid {
    value: String,
    frozen: bool,
}

impl Hostid {
    /// What it is before the server says: `host` and `port` together, as joinmarket-clientserver starts.
    pub fn new(host: &str, port: u16) -> Hostid {
        Hostid {
            value: format!("{host}{port}"),
            frozen: false,
        }
    }

    /// Take the server's `005` line parameters into account (the first one only). `expected`, when given, is
    /// the value configured for this server.
    pub fn read_isupport(
        &mut self,
        params: &[String],
        expected: Option<&str>,
    ) -> Result<(), HostidError> {
        if self.frozen {
            return Ok(());
        }
        let announced = params
            .iter()
            .find_map(|p| p.strip_prefix("NETWORK="))
            .map(str::to_string);
        if let Some(network) = announced {
            let valid = !network.is_empty()
                && network.len() <= 64
                && network
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
            if !valid {
                return Err(HostidError("the server's NETWORK name is not a plain name"));
            }
            self.value = network;
        }
        if let Some(expected) = expected
            && expected != self.value
        {
            return Err(HostidError(
                "the server's NETWORK name is not the one expected",
            ));
        }
        self.frozen = true;
        Ok(())
    }

    /// Settle on what is known now (a server that never sent `005`).
    pub fn freeze(&mut self) {
        self.frozen = true;
    }

    /// The value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Whether two channels' signature domains could be confused: equal, or one ending the other (the body
    /// a signature covers comes right before it), ignoring case (joinmarket-clientserver retries a failed
    /// check with the domain in lower case).
    pub fn confusable(a: &str, b: &str) -> bool {
        let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
        a.ends_with(&b) || b.ends_with(&a)
    }
}

/// Keeps sending to one line per [`LINE_INTERVAL`].
#[derive(Debug, Default)]
pub struct Pacer {
    next: Option<Instant>,
}

impl Pacer {
    /// When the next line may go, given that it is `now`; the slot after it is reserved.
    pub fn slot(&mut self, now: Instant) -> Instant {
        let at = self.next.map_or(now, |next| next.max(now));
        self.next = Some(at + LINE_INTERVAL);
        at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_parse_and_build() {
        let m = parse(":J5abc!~u@host PRIVMSG J5me :!fill 0 1 ;\r\n").unwrap();
        assert_eq!(m.nick(), Some("J5abc"));
        assert_eq!(m.command, "PRIVMSG");
        assert_eq!(m.params, vec!["J5me".to_string(), "!fill 0 1 ;".into()]);
        let m = parse(":irc.example 005 J5me NETWORK=Hackint CHANTYPES=# :are supported").unwrap();
        assert_eq!(m.command, "005");
        assert!(m.params.contains(&"NETWORK=Hackint".to_string()));
        assert_eq!(
            parse("PING :token").unwrap().params,
            vec!["token".to_string()]
        );
        for bad in ["", "@tag=1 PING x", ":onlyprefix"] {
            assert_eq!(parse(bad), None, "{bad}");
        }
        assert_eq!(build("NICK", &["J5me"]).unwrap(), "NICK J5me\r\n");
        assert_eq!(
            build("PRIVMSG", &["#joinmarket-pit", "!orderbook"]).unwrap(),
            "PRIVMSG #joinmarket-pit !orderbook\r\n"
        );
        assert_eq!(
            build("USER", &["u", "0", "*", "real name"]).unwrap(),
            "USER u 0 * :real name\r\n"
        );
        assert_eq!(build("PRIVMSG", &["a b", "x"]), None);
        assert_eq!(build("PRIVMSG", &["x", "line\nbreak"]), None);
        assert_eq!(build("PRIVMSG", &["x", &"y".repeat(600)]), None);
        assert_eq!(pit_channel("mainnet"), "#joinmarket-pit");
        assert_eq!(pit_channel("regtest"), "#joinmarket-pit-test");
        assert_eq!(pit_channel("signet"), "#joinmarket-pit-sig");
    }

    /// Send `message` to `to` as pieces and read them back as joinmarket-clientserver would.
    fn round_trip(to: &str, command: &str, message: &str) -> String {
        let lines = private_lines(to, command, message).unwrap();
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        let mut out = None;
        for (i, line) in lines.iter().enumerate() {
            assert!(line.len() <= MAX_PRIVMSG_LEN + 2, "{} > limit", line.len());
            let text = &parse(line).unwrap().params[1];
            let whole = reassembler.push("J5sender", text, now);
            assert_eq!(whole.is_some(), i + 1 == lines.len());
            out = whole.or(out);
        }
        out.unwrap()
    }

    #[test]
    fn private_messages_survive_chunking_at_every_length() {
        let to = "J5abcdefghijklmn";
        for len in [1, 2, 300, 399, 400, 401, 402, 403, 800, 801, 40_000] {
            // Repeating text: equal pieces are what joinmarket-clientserver's own sender mislabels.
            let message: String = "ab".repeat(len).chars().take(len).collect();
            assert_eq!(
                round_trip(to, "tx", &message),
                format!("!tx {message}"),
                "{len}"
            );
        }
        assert_eq!(private_lines(to, "tx", "ünicode"), None);
        assert_eq!(private_lines(&"J".repeat(460), "tx", "x"), None);
    }

    #[test]
    fn reassembly_is_bounded_and_strict() {
        let now = Instant::now();
        let mut r = Reassembler::default();
        // Interleaved senders keep their own pieces.
        assert_eq!(r.push("A", "!auth one ;", now), None);
        assert_eq!(r.push("B", "!auth uno ;", now), None);
        assert_eq!(r.push("A", "two ~", now).as_deref(), Some("!auth onetwo"));
        assert_eq!(r.push("B", "dos ~", now).as_deref(), Some("!auth unodos"));
        // A first piece without `!`, or a piece without a trailer, is dropped (and drops what was gathered).
        assert_eq!(r.push("A", "nothing ~", now), None);
        assert_eq!(r.push("A", "!auth x ;", now), None);
        assert_eq!(r.push("A", "no trailer", now), None);
        assert_eq!(r.push("A", "rest ~", now), None);
        // Too slow.
        assert_eq!(r.push("A", "!auth x ;", now), None);
        assert_eq!(r.push("A", "y ~", now + REASSEMBLY_TTL), None);
        // Too long.
        let mut r = Reassembler::default();
        assert_eq!(r.push("A", "!tx x ;", now), None);
        let big = format!("{} ;", "x".repeat(10_000));
        for _ in 0..7 {
            let _ = r.push("A", &big, now);
        }
        assert_eq!(r.push("A", "end ~", now), None);
        // Too many senders at once.
        let mut r = Reassembler::default();
        for i in 0..MAX_PENDING + 10 {
            let _ = r.push(&format!("N{i}"), "!auth x ;", now);
        }
        assert_eq!(r.pending(), MAX_PENDING);
        // A message in one piece still gets through, and a new sender takes another's place.
        assert_eq!(
            r.push("Nfree", "!pubkey x ~", now).as_deref(),
            Some("!pubkey x")
        );
        assert_eq!(
            r.push("Nnew", "!auth x ;", now + Duration::from_secs(1)),
            None
        );
        assert_eq!(r.pending(), MAX_PENDING);
        assert_eq!(
            r.push("Nnew", "y ~", now + Duration::from_secs(1))
                .as_deref(),
            Some("!auth xy")
        );
    }

    #[test]
    fn offer_lines_pack_and_end_like_the_reference() {
        let offers: Vec<String> = (0..12)
            .map(|i| format!("!sw0reloffer {i} 27300 1000000000 0 0.00002"))
            .collect();
        let lines = offer_lines("#joinmarket-pit", &offers);
        assert!(lines.len() > 1);
        let mut seen = String::new();
        for line in &lines {
            assert!(line.len() <= MAX_PRIVMSG_LEN + 2);
            let text = &parse(line).unwrap().params[1];
            assert!(text.ends_with(" ~"));
            seen.push_str(public_text(text));
        }
        assert_eq!(seen, offers.concat());
        assert!(is_ctcp("\u{1}VERSION\u{1}"));
    }

    #[test]
    fn the_signature_domain_is_taken_once_and_checked() {
        let mut hostid = Hostid::new("irc.example", 6697);
        assert_eq!(hostid.value(), "irc.example6697");
        hostid
            .read_isupport(&["J5me".into(), "NETWORK=Hackint".into()], Some("Hackint"))
            .unwrap();
        assert_eq!(hostid.value(), "Hackint");
        // Later lines change nothing.
        hostid
            .read_isupport(&["NETWORK=onion-network".into()], None)
            .unwrap();
        assert_eq!(hostid.value(), "Hackint");
        // Not a plain name, or not the one expected.
        for (network, expected) in [
            ("NETWORK=bad name", None),
            ("NETWORK=Other", Some("Hackint")),
        ] {
            let mut h = Hostid::new("irc.example", 6697);
            assert!(
                h.read_isupport(&[network.into()], expected).is_err(),
                "{network}"
            );
        }
        // A server that says nothing keeps the host and port.
        let mut quiet = Hostid::new("127.0.0.1", 6667);
        quiet.read_isupport(&["CHANTYPES=#".into()], None).unwrap();
        assert_eq!(quiet.value(), "127.0.0.16667");
        // Domains that one ends the other, in any case, could be confused.
        assert!(Hostid::confusable("xonion-network", "onion-network"));
        assert!(Hostid::confusable("Onion-Network", "onion-network"));
        assert!(!Hostid::confusable("Hackint", "onion-network"));
    }

    #[test]
    fn the_pacer_keeps_the_line_rate() {
        let mut pacer = Pacer::default();
        let now = Instant::now();
        let first = pacer.slot(now);
        let second = pacer.slot(now);
        assert_eq!(first, now);
        assert_eq!(second, now + LINE_INTERVAL);
        // After a quiet while, the next line goes at once.
        let later = now + Duration::from_secs(60);
        assert_eq!(pacer.slot(later), later);
    }
}
