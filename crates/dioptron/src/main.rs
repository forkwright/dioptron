//! Dioptron daemon entry point. See [`dioptron::cli`] for the commands.

use std::error::Error as _;
use std::process::ExitCode;

use dioptron::Error;
use dioptron::cli::{self, USAGE};

fn main() -> ExitCode {
    let args: Result<Vec<String>, _> = std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect();
    let Ok(args) = args else {
        eprintln!("dioptron: arguments must be UTF-8\n{USAGE}");
        return ExitCode::from(2);
    };
    let command = match cli::parse(args) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("dioptron: {error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match cli::run(command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&error);
            if matches!(error, Error::Usage { .. }) {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

/// Prints `error` and its causes.
fn report(error: &Error) {
    eprintln!("dioptron: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}
