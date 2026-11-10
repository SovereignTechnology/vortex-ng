//! vortex-ng-cli: not functional yet (vortex-ng milestone M0). See README.md for the plan.

fn main() {
    eprintln!(
        "{} {}: not functional yet (milestone M0)",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(2);
}
