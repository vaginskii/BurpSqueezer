//! Thin binary: parse arguments, run the pipeline, map failures to exit codes.

use std::error::Error as _;
use std::process::ExitCode;

use clap::Parser;

use burp_squeezer::cli::Cli;
use burp_squeezer::error::EXIT_OK;

fn main() -> ExitCode {
    match Cli::parse().execute() {
        Ok(()) => ExitCode::from(EXIT_OK as u8),
        Err(error) => {
            report(&error);
            ExitCode::from(error.exit_code() as u8)
        }
    }
}

/// Print the failure and its causes on stderr, regardless of `--quiet`.
///
/// Errors are the one thing an operator must always see: suppressing them would
/// leave a non-zero exit code with no explanation.
fn report(error: &burp_squeezer::Error) {
    eprintln!("error: {error}");
    let mut cause = error.source();
    while let Some(current) = cause {
        eprintln!("  caused by: {current}");
        cause = current.source();
    }
}
