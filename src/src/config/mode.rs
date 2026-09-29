//! Aggressiveness modes.

use std::fmt;

/// Controls how brutally the pipeline discards candidate signal.
///
/// The derived CLI values are `safe`, `standard`, `compact`, and `apocalyptic`: clap
/// kebab-cases variant names, which for single words is already lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Mode {
    /// Lower thresholds, fuller report, more tolerance for weak signal.
    Safe,
    /// Balanced default.
    #[default]
    Standard,
    /// AI-friendly compact mode: only high-signal values and endpoints.
    Compact,
    /// Maximum selectivity: essentially Core Signal only.
    Apocalyptic,
}

impl Mode {
    /// Stable lowercase identifier, used in the report's Meta section.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Safe => "safe",
            Mode::Standard => "standard",
            Mode::Compact => "compact",
            Mode::Apocalyptic => "apocalyptic",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
