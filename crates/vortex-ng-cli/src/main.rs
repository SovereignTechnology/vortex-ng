//! `vortex-ng`: the command line of vortex-ng.
//!
//! The wallet commands create or restore a wallet file (a seed encrypted at rest, see
//! `vortex_ng_wallet::file`) and read addresses out of it; `orderbook` asks the makers on a set of relays
//! what they offer; `maker` offers the wallet's coins until stopped; `coinjoin` does one CoinJoin as the
//! taker; `balance` shows what the wallet holds; `coins` lists its coins and marks the ones a Lightning
//! channel close paid it (`coinjoin --from-closes` spends only those); `lnd-coins` does the same for an LND node's wallet, and
//! `coinjoin --from-lnd` spends from it with the node signing; `pools`, `pool join` and `pool create` take part
//! in joinstr pools (ADR 0006). Exit status 0 on success, 1 when the command failed, 2 when it was not
//! understood.

mod args;
mod claims;
mod lightning;
mod market;
mod podle_log;
mod pool;
mod secret;
mod seen_log;
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
                      [--upkeep <seconds>] [--serve-onion <name>.onion:<port>]
  vortex-ng coinjoin  --wallet <file> where node --amount <sats> [--makers <n>]
                      [--min-makers <n>] [--mixdepth 0-4] [--destination <address>] [--pit sw0|tr0|wsh0]
                      [--fee-rate <sat/vB>] [--max-maker-fee <sats>] [--wait <seconds>]
                      [--allow-bondless-fees] [--from-closes | --from-lnd lnd [--merge-closes]] [--yes]
  vortex-ng balance   --wallet <file> node [--pit sw0|tr0|wsh0]
  vortex-ng coins     --wallet <file> node [--pit sw0|tr0|wsh0] [--mixdepth 0-4] [--closes-only]
                      [--outpoints]
  vortex-ng lnd-coins --network <network> lnd [--closes-only] [--outpoints]
  vortex-ng pools     --relays <url[,url...]> [--wait <seconds>] [--proxy <address>]
  vortex-ng pool join   --wallet <file> --relays <url[,url...]> --pool <id|key> node [--pit sw0|tr0]
                        [--mixdepth 0-4] [--wait <seconds>] [--proxy <address>] [--yes]
  vortex-ng pool create --wallet <file> --relays <url> --denomination <sats> --peers <n> node
                        [--pit sw0|tr0] [--mixdepth 0-4] [--fee-rate <sat/vB>] [--expires <seconds>]
                        [--proxy <address>] [--yes]
  vortex-ng --version

where: at least one of these. None is on by default.
  --relays <url[,url...]>          Nostr relays.
  --directories <host:port[,...]>  JoinMarket's onion directory nodes.
  --irc <host:port[,...]>          JoinMarket's IRC pit. TLS unless the host is an onion or loopback;
                                   `irc://host:port` is plain text, for regtest.
--directories and --irc work on regtest only in this pre-release, and are refused elsewhere; outside regtest
they also need --proxy. A maker uses one nick on all its channels, a taker a different nick on each. A round
stays on the channel its `!fill` came on. `orderbook` shows the channel each offer came from.

--serve-onion <name>.onion:<port> (maker, with --directories): a v3 onion service your Tor daemon already
forwards to 127.0.0.1:<port> (torrc: HiddenServicePort <port> 127.0.0.1:<port>). The maker listens there and
names it to the directory nodes, so takers can connect to it directly.

Who sees what:
  a Nostr relay      the recipient key and timing of private messages; public messages.
  a directory node   offers and who is present. For each private line it relays: sender, recipient, size and
                     timing, with `!fill` (order id, amount, commitment) and `!pubkey` in plain text. The
                     encrypted steps stay encrypted from a directory that only reads them; one that also
                     alters lines can do more (README, issue #52). When a taker connects to a maker's onion directly, the
                     rest of their round leaves the directory, except a `!fill` some takers still send
                     through it first (and its `!pubkey`) and the answers of a maker that replies through
                     it anyway.
  an IRC server      the same as a relaying directory node, in its own logs.
A maker's one nick and its key link its presence on all its channels. More: the README, 'Command line'.

Pools are joinstr's (another protocol, over Nostr relays): one coin worth the denomination plus 500 to 5000 sat
goes in, one output of the denomination less a share of the mining fee comes out, in the next mixdepth; nobody
is paid. `coinjoin --amount <sats>` leaves a coin of exactly that much in the next mixdepth. Relays see who
writes to a pool and when, and every peer can read every pool message.

Commands on one wallet share <wallet>.claims: a coin held by a maker's round, a coinjoin or a pool is never put
into another, and no address is handed out twice, so `maker` and `pool` can run on one wallet at once.

node: --rpc-url <url> with --rpc-cookie-file <file>, or with --rpc-user <name> [--rpc-password-file <file>].
A Bitcoin Core compatible node on the wallet's network. `orderbook` verifies fidelity bonds when given one.

lnd: --lnd-rest <host:port> --lnd-tls-cert <file> --lnd-macaroon <file>. The node's `tls.cert` is pinned. The
macaroon must be in a file only you can read (mode 600): one that may sign can spend every coin of the node's
wallet. Bake it by `uri:` permission, as the README shows, not with `signer:generate`.

Channel closes: close a channel with one of the wallet's addresses as the delivery address (`vortex-ng wallet
addresses` lists them; LND `closechannel --delivery_addr`, CLN `close <id> <timeout> <address>`). `coins` then
marks what the close paid, and `coinjoin --from-closes` spends those coins and no others, so they are not
merged with coins that have another history. Only the transaction that created a coin is read: a force close
that the node sweeps into its own wallet, and the coin sent on from there, look like an ordinary payment and
are not recognised here. The recognition is evidence, not proof, and a mutual close of a taproot channel is
not recognised.

From an LND node's own wallet, force closes included: `lnd-coins` marks the coins by the node's close records,
and `coinjoin --from-lnd --mixdepth <n>` spends one of them, the node signing. The amount goes to this wallet
and the change back to the node. It never takes what the node must keep to fee-bump its open anchor channels,
and it merges coins of different channels only with `--merge-closes`. The node cannot prove a PoDLE, so mixdepth
<n> must hold a coin of the pit to commit to (five confirmations, a fifth of the amount, not from a CoinJoin,
never committed to before). The makers see that coin and can link it to the round: keep a small one for it.

`orderbook`, `maker` and `coinjoin` take `--proxy <address>`: a SOCKS5 proxy that isolates streams by
username and password, such as a Tor daemon's SOCKS port (127.0.0.1:9050). Every nick, a maker's throwaway
`!hp2` nick included, then reaches its channels under credentials of its own. Without it every relay,
directory node and IRC server named sees this machine's address, and the command says so.

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
        [command, rest @ ..] if command == "coins" => market::coins(rest),
        [command, rest @ ..] if command == "lnd-coins" => lightning::lnd_coins(rest),
        [command, rest @ ..] if command == "pools" => pool::pools(rest),
        [group, command, rest @ ..] if group == "pool" && command == "join" => pool::join(rest),
        [group, command, rest @ ..] if group == "pool" && command == "create" => pool::create(rest),
        [group, ..] if group == "pool" => Err(Failure::Usage("pool: join or create?".into())),
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
