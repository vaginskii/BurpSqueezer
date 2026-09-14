//! Aggressiveness modes.

use std::fmt;

/// Controls how brutally the pipeline discards candidate signal.
///
/// The derived CLI values are `peaceful`, `standard`, and `apocalyptic`: clap
/// kebab-cases variant names, which for single words is already lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Mode {
    /// Lower thresholds, fuller report, more tolerance for weak signal.
    Peaceful,
    /// Balanced default.
    #[default]
    Standard,
    /// Maximum selectivity: essentially Core Signal only.
    Apocalyptic,
}

impl Mode {
    /// Stable lowercase identifier, used in the report's Meta section.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Peaceful => "peaceful",
            Mode::Standard => "standard",
            Mode::Apocalyptic => "apocalyptic",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
