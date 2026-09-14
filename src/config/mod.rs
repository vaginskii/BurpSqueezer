//! Every tunable number in the pipeline lives here.
//!
//! Two kinds, kept apart. [`Thresholds`] decide what counts as signal and are
//! chosen by [`Mode`]; [`Limits`] decide how much input the tool will read and
//! are the same in every mode. Mixing them would let `--mode peaceful` mean "and
//! also accept an unbounded file".

pub mod limits;
pub mod mode;
pub mod thresholds;

pub use limits::Limits;
pub use mode::Mode;
pub use thresholds::Thresholds;
