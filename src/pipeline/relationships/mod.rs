//! Stage 5: relationships between transactions.
//!
//! Chains come first because sequences are only reported when they are anchored
//! to something a chain or a Strong Value already established.

pub mod dataflow;
pub mod sequences;

pub use dataflow::{Chain, Elision, Hop};
pub use sequences::Sequence;

use crate::config::Thresholds;
use crate::model::endpoint::EndpointTable;
use crate::model::transaction::TxId;
use crate::model::value::{ObservedValue, StrongValue};

/// Everything stage 5 produces.
#[derive(Debug, Default)]
pub struct Relationships {
    pub chains: Vec<Chain>,
    pub sequences: Vec<Sequence>,
}

/// Build chains, then the sequences they anchor.
pub fn build(
    values: &[StrongValue],
    observations: &[ObservedValue],
    table: &EndpointTable,
    kept: &[TxId],
    thresholds: &Thresholds,
) -> Relationships {
    let chains = dataflow::build(values, observations, table, thresholds);
    let sequences = sequences::build(kept, table, values, &chains, thresholds);
    Relationships { chains, sequences }
}
