//! Error taxonomy and the process exit codes derived from it.

use std::path::PathBuf;

/// Exit code returned when the run succeeded.
pub const EXIT_OK: i32 = 0;
/// The input could not be used (missing, unreadable, empty, devoid of items, or
/// past a limit in [`crate::config::Limits`]).
pub const EXIT_BAD_INPUT: i32 = 2;
/// The input was readable but is not well-formed Burp XML.
pub const EXIT_MALFORMED_XML: i32 = 3;
/// The report could not be written to the requested destination.
pub const EXIT_OUTPUT: i32 = 4;

/// Every failure mode `burpsqueezer` reports to its caller.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("input file is empty: {}", .0.display())]
    EmptyInput(PathBuf),

    #[error("cannot read input file {}: {source}", .path.display())]
    ReadInput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("malformed Burp XML at byte {offset}: {detail}")]
    MalformedXml { offset: u64, detail: String },

    #[error("input contains no Burp <item> entries: {}", .0.display())]
    NoTransactions(PathBuf),

    #[error(
        "input holds more than {limit} Burp <item> entries; \
         every figure in a report built from part of a dump would describe that part"
    )]
    TooManyTransactions { limit: usize },

    #[error("cannot write report to {}: {source}", .path.display())]
    WriteReport {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    /// Process exit code that corresponds to this failure.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::EmptyInput(_)
            | Error::ReadInput { .. }
            | Error::NoTransactions(_)
            | Error::TooManyTransactions { .. } => EXIT_BAD_INPUT,
            Error::MalformedXml { .. } => EXIT_MALFORMED_XML,
            Error::WriteReport { .. } => EXIT_OUTPUT,
        }
    }
}

/// Convenience alias used across the pipeline.
pub type Result<T> = std::result::Result<T, Error>;
