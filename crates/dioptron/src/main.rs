//! Dioptron daemon entry point.

use std::process::ExitCode;

fn main() -> ExitCode {
    // WHY fail rather than exit 0: a daemon that starts and does nothing
    // would read as a working service to any supervisor.
    eprintln!(
        "dioptron {}: no commands are implemented yet",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::FAILURE
}
