//! `vortex-ng`: the command line of vortex-ng.
//!
//! So far the wallet commands: create or restore a wallet file (a seed encrypted at rest, see
//! `vortex_ng_wallet::file`) and read addresses out of it. Exit status 0 on success, 1 when the command
//! failed, 2 when it was not understood.

mod args;
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
  vortex-ng --version

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
