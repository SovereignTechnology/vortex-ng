//! JoinMarket's IRC message channel, as joinmarket-clientserver (`jmdaemon/irc.py`) speaks it (ADR 0007).
//!
//! [`codec`] is the part without I/O: IRC lines, JoinMarket's chunking of private messages and its
//! reassembly, the pit channel's name, the server's signature domain, and the line rate servers tolerate.

pub mod codec;
