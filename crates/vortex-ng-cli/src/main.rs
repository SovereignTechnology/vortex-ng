//! `vortex-ng`: the command line of vortex-ng.
//!
//! The wallet commands create or restore a wallet file (a seed encrypted at rest, see
//! `vortex_ng_wallet::file`) and read addresses out of it; `orderbook` asks the makers on a set of relays
//! what they offer; `maker` offers the wallet's coins until stopped; `coinjoin` does one CoinJoin as the
//! taker; `balance` shows what the wallet holds. Exit status 0 on success, 1 when the command
//! failed, 2 when it was not understood.

mod args;
mod market;
mod podle_log;
mod secret;
mod wallet;

use std::process::ExitCode;

/// Why a command did not succeed.
pub(crate) enum Failure {
    /// The command line was not understood: the usage is shown.
    Usage(String),
    /// The command was understood and failed.
    Failed(String),
}

const USAGE: &str = "\
vortex-ng: JoinMarket CoinJoins over Nostr (pre-release, unaudited)

Usage:
  vortex-ng wallet new          --wallet <file> --network <network> [--words 12|24] [--birthday <height>]
  vortex-ng wallet restore      --wallet <file> --network <network> [--mnemonic-file <file>]
                                [--bip39-passphrase | --bip39-passphrase-file <file>] [--birthday <height>]
  vortex-ng wallet info         --wallet <file>
  vortex-ng wallet addresses    --wallet <file> [--pit sw0|tr0|wsh0] [--mixdepth 0-4] [--count <n>] [--change]
  vortex-ng wallet bond-address --wallet <file> --locktime <YYYY-MM>
  vortex-ng orderbook --network <network> where [--pit sw0|tr0|wsh0] [--wait <seconds>]
                      [node]
  vortex-ng maker     --wallet <file> where node (--fee-rel <fraction> | --fee-abs <sats>)
                      [--pit sw0|tr0|wsh0] [--txfee <sats>] [--min-size <sats>] [--max-size <sats>]
                      [--upkeep <seconds>]
  vortex-ng coinjoin  --wallet <file> where node --amount <sats> [--makers <n>]
                      [--min-makers <n>] [--mixdepth 0-4] [--destination <address>] [--pit sw0|tr0|wsh0]
                      [--fee-rate <sat/vB>] [--max-maker-fee <sats>] [--wait <seconds>]
                      [--allow-bondless-fees] [--yes]
  vortex-ng balance   --wallet <file> node [--pit sw0|tr0|wsh0]
  vortex-ng --version

where: any of --relays <url[,url...]> (Nostr relays), --directories <host:port[,...]> (JoinMarket's onion
directory nodes) and --irc <host:port[,...]> (JoinMarket's IRC pit; onion IRC hosts reach the server through
the proxy); the last two on regtest only in this pre-release. A maker uses one nick on all of them, a taker a
different nick on each. Who sees what on each channel: the README, section 'Command line'.

node: --rpc-url <url> with --rpc-cookie-file <file>, or with --rpc-user <name> [--rpc-password-file <file>].
A Bitcoin Core compatible node on the wallet's network. `orderbook` verifies fidelity bonds when given one.

`orderbook`, `maker` and `coinjoin` take `--proxy <address>`: a SOCKS5 proxy that isolates streams by
username and password, such as a Tor daemon's SOCKS port (127.0.0.1:9050). Every nick, a maker's throwaway
`!hp2` nick included, then reaches the relays under credentials of its own. Without it the relays see this
machine's address, and the command says so.

Networks: regtest, signet, testnet4, testnet. Mainnet wallets are disabled in this pre-release.

The wallet password is asked on the terminal, or read from `--password-file <file>`: a file only you can
read. Seed words and passwords are never taken from the command line, where other programs can see them.
A wallet file is created once and never overwritten.";

fn run(args: &[String]) -> Result<(), Failure> {
    match args {
        [] => Err(Failure::Usage("no command".into())),
        [only] if only == "--version" || only == "-V" => {
            println!("vortex-ng {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [only] if only == "--help" || only == "-h" || only == "help" => {
            println!("{USAGE}");
            Ok(())
        }
        [group, command, rest @ ..] if group == "wallet" => wallet::run(command, rest),
        [command, rest @ ..] if command == "orderbook" => market::orderbook(rest),
        [command, rest @ ..] if command == "maker" => market::maker(rest),
        [command, rest @ ..] if command == "coinjoin" => market::coinjoin(rest),
        [command, rest @ ..] if command == "balance" => market::balance(rest),
        [group] if group == "wallet" => Err(Failure::Usage("wallet: which command?".into())),
        [other, ..] => Err(Failure::Usage(format!("unknown command `{other}`"))),
    }
}

fn main() -> ExitCode {
    let args: Result<Vec<String>, _> = std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect();
    let result = match args {
        Ok(args) => run(&args),
        Err(_) => Err(Failure::Failed("arguments must be UTF-8".into())),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(why)) => {
            eprintln!("vortex-ng: {why}\n\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failure::Failed(why)) => {
            eprintln!("vortex-ng: {why}");
            ExitCode::FAILURE
        }
    }
}
