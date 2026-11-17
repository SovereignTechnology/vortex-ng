//! Secrets from the user: a file only its owner can read, or a terminal prompt that does not echo.
//!
//! Never the command line or the environment: both are visible to other processes.

use std::io::{BufRead, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::termios::{LocalModes, OptionalActions, isatty, tcgetattr, tcsetattr};
use zeroize::Zeroizing;

/// A secret is at most this long (a 24-word mnemonic is at most 215 bytes).
const MAX_SECRET_BYTES: u64 = 4096;

/// Without the line ending a file or a terminal line carries.
fn without_newline(mut text: Zeroizing<String>) -> Zeroizing<String> {
    while text.ends_with('\n') || text.ends_with('\r') {
        text.pop();
    }
    text
}

/// The secret in the file `path`: its contents without the final line ending. Refused when anyone but the
/// file's owner can read it, as ssh refuses a private key.
pub(crate) fn from_file(path: &str) -> Result<Zeroizing<String>, String> {
    let fail = |e: std::io::Error| format!("{path}: {e}");
    let file = std::fs::File::open(Path::new(path)).map_err(fail)?;
    let meta = file.metadata().map_err(fail)?;
    if !meta.is_file() {
        return Err(format!("{path}: not a regular file"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{path}: readable by others (mode {:03o}); run `chmod 600 {path}`",
            meta.mode() & 0o777
        ));
    }
    let mut text = Zeroizing::new(String::new());
    file.take(MAX_SECRET_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(fail)?;
    if text.len() as u64 > MAX_SECRET_BYTES {
        return Err(format!("{path}: too long"));
    }
    let text = without_newline(text);
    if text.is_empty() {
        return Err(format!("{path}: empty"));
    }
    Ok(text)
}

/// Ask on the terminal with echo off. An error when standard input is not a terminal.
pub(crate) fn prompt(label: &str) -> Result<Zeroizing<String>, String> {
    let stdin = std::io::stdin();
    if !isatty(&stdin) {
        return Err(format!(
            "no terminal to ask for the {label}: give it in a file"
        ));
    }
    let fail = |e: std::io::Error| format!("terminal: {e}");
    let shown = tcgetattr(&stdin).map_err(|e| fail(e.into()))?;
    let mut hidden = shown.clone();
    hidden.local_modes.remove(LocalModes::ECHO);
    eprint!("{label}: ");
    std::io::stderr().flush().map_err(fail)?;
    tcsetattr(&stdin, OptionalActions::Now, &hidden).map_err(|e| fail(e.into()))?;
    let mut line = Zeroizing::new(String::new());
    let read = stdin.lock().read_line(&mut line);
    // Echo comes back whatever happened to the read.
    let restored = tcsetattr(&stdin, OptionalActions::Now, &shown);
    eprintln!();
    read.map_err(fail)?;
    restored.map_err(|e| fail(e.into()))?;
    Ok(without_newline(line))
}

/// The secret called `label`: from `file` when given, else asked on the terminal (twice when `confirm`, and
/// the two must match).
pub(crate) fn obtain(
    label: &str,
    file: Option<&str>,
    confirm: bool,
) -> Result<Zeroizing<String>, String> {
    if let Some(path) = file {
        return from_file(path);
    }
    let first = prompt(label)?;
    if first.is_empty() {
        return Err(format!("the {label} is empty"));
    }
    if confirm && *prompt(&format!("{label} again"))? != *first {
        return Err(format!("the two entries of the {label} differ"));
    }
    Ok(first)
}
