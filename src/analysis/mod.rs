//! Content-agnostic measurement helpers.
//!
//! Nothing in here knows what a field means. It only measures shape, spread,
//! and randomness, which is what keeps the pipeline free of business logic.

pub mod entropy;
pub mod fingerprint;
pub mod provenance;
pub mod salience;
pub mod stats;
pub mod tokens;
