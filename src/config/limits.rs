//! Bounds on what the tool is willing to read from one input file.
//!
//! Separate from [`crate::config::Thresholds`] because these answer a different
//! question. A threshold decides what counts as signal, and every mode picks its
//! own; a limit decides how much input the tool will consume before it stops,
//! and no mode has any business relaxing that. Running `--mode peaceful` on a
//! hostile file must not buy the file more of the machine's memory.
//!
//! Each is set far above any real capture. They exist so that a malformed,
//! generated, or deliberately hostile dump fails predictably rather than by
//! exhausting memory, and hitting one is a statement about the input rather than
//! a judgement about the traffic.

/// Input bounds for one run.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Transactions accepted from one file before the input is rejected.
    ///
    /// A rejection, not a truncation: a dump this size is not a capture anyone
    /// took by hand, and quietly analysing the first slice of it would produce a
    /// report whose numbers describe an arbitrary prefix.
    pub max_transactions: usize,
    /// Largest request or response body kept for analysis, in bytes.
    ///
    /// A body over the cap is discarded and its message keeps its headers and
    /// status. Not an error: real captures do contain the occasional multi-
    /// megabyte download, and one of them must not cost the reader the other
    /// three hundred transactions.
    pub max_body_bytes: usize,
    /// Deepest JSON nesting level walked when extracting values.
    ///
    /// A body nested deeper than this is not truncated; the walk simply stops
    /// descending, and everything shallower is still mined.
    pub max_json_depth: usize,
    /// Scalars taken from one body before the walk stops.
    pub max_json_nodes: usize,
    /// Longest scalar kept as a candidate value, in bytes.
    ///
    /// Past this length a value is an encoded blob rather than an identifier,
    /// and no later stage could do anything with it but carry it.
    pub max_value_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_transactions: 200_000,
            max_body_bytes: 8 * 1024 * 1024,
            max_json_depth: 12,
            max_json_nodes: 2_000,
            max_value_bytes: 1_024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defaults have to clear any capture a person would actually take.
    /// A limit that fires on ordinary input is a bug report waiting to happen,
    /// and the checked-in Pachca dump — 323 transactions, 26 MB — is the
    /// largest real capture this project has seen.
    #[test]
    fn the_defaults_leave_real_captures_untouched() {
        let limits = Limits::default();
        assert!(limits.max_transactions > 100_000);
        assert!(limits.max_body_bytes >= 1024 * 1024);
        assert!(limits.max_json_depth >= 8, "ordinary APIs nest several deep");
        assert!(limits.max_json_nodes >= 1_000);
        assert!(
            limits.max_value_bytes >= 512,
            "a session JWT runs to several hundred bytes and is the signal, not the noise"
        );
    }
}
