//! Command-line surface.
//!
//! One subcommand, no configuration files, no interactive behaviour. Argument
//! parsing lives here so `main` is left with nothing but exit-code mapping.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::Mode;
use crate::error::Result;
use crate::logging;

/// `burpsqueezer` — squeeze a Burp Suite XML dump into an LLM-ready report.
#[derive(Debug, Parser)]
#[command(name = "burpsqueezer", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Silence all progress output on stderr.
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Emit per-stage detail on stderr.
    #[arg(long, global = true, conflicts_with = "quiet")]
    pub verbose: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Analyse a Burp XML dump and write a Markdown report.
    Solve {
        /// Burp Suite XML dump to read.
        #[arg(value_name = "INPUT.XML")]
        input: PathBuf,

        /// Destination for the Markdown report.
        #[arg(short, long, value_name = "REPORT.MD")]
        output: PathBuf,

        /// Selectivity of the analysis; affects thresholds and limits only.
        #[arg(long, value_enum, default_value_t = Mode::Standard)]
        mode: Mode,
    },
}

impl Cli {
    /// Configure logging and dispatch the requested subcommand.
    pub fn execute(self) -> Result<()> {
        logging::configure(self.quiet, self.verbose);

        match self.command {
            Command::Solve {
                input,
                output,
                mode,
            } => {
                logging::info(&format!(
                    "burpsqueezer {} starting on {} (mode {mode})",
                    crate::VERSION,
                    input.display()
                ));
                crate::solve(&input, &output, mode)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn mode_defaults_to_standard() {
        let cli = Cli::parse_from(["burpsqueezer", "solve", "in.xml", "--output", "out.md"]);
        let Command::Solve { mode, .. } = cli.command;
        assert_eq!(mode, Mode::Standard);
    }

    #[test]
    fn accepts_every_mode_by_name() {
        for (name, expected) in [
            ("peaceful", Mode::Peaceful),
            ("standard", Mode::Standard),
            ("apocalyptic", Mode::Apocalyptic),
        ] {
            let cli = Cli::parse_from([
                "burpsqueezer",
                "solve",
                "in.xml",
                "--output",
                "out.md",
                "--mode",
                name,
            ]);
            let Command::Solve { mode, .. } = cli.command;
            assert_eq!(mode, expected);
        }
    }

    #[test]
    fn output_is_required() {
        let parsed = Cli::try_parse_from(["burpsqueezer", "solve", "in.xml"]);
        assert!(parsed.is_err());
    }
}
