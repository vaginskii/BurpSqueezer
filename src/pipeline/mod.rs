//! The pipeline orchestrator.
//!
//! This module owns sequence and nothing else. Every stage is a free function
//! taking its inputs and the thresholds, which keeps each one testable on its
//! own and keeps this file from turning into the place where logic accretes.

pub mod aggregator;
pub mod mining;
pub mod noise;
pub mod normalizer;
pub mod parser;
pub mod relationships;
pub mod variation;

use std::path::Path;

use crate::analysis::tokens;
use crate::config::{Limits, Mode, Thresholds};
use crate::error::Result;
use crate::logging;
use crate::model::report::ReportModel;
use crate::model::value::ObservedValue;

/// Run all eight stages and return the report model.
pub fn run(input: &Path, mode: Mode) -> Result<ReportModel> {
    let source = input
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| input.display().to_string());

    // Not derived from the mode. What counts as signal is a judgement call the
    // mode is entitled to make; how much of a file the tool will read is not.
    let limits = Limits::default();

    logging::stage(1, "parsing Burp XML");
    let parsed = parser::parse(input, &limits)?;
    let transactions = parsed.transactions;
    logging::info(&format!("{} transactions parsed", transactions.len()));
    if parsed.oversized_bodies > 0 {
        logging::warn(&format!(
            "{} bodies over {} bytes were discarded; their headers and statuses remain",
            parsed.oversized_bodies, limits.max_body_bytes
        ));
    }

    let mut thresholds = Thresholds::for_mode(mode);
    if thresholds.relax_for_small_dump(transactions.len()) {
        logging::warn(&format!(
            "small dump ({} transactions): thresholds relaxed",
            transactions.len()
        ));
    }

    logging::stage(2, "filtering noise");
    let filter = noise::apply(&transactions, &thresholds);
    logging::info(&format!(
        "{} kept, {} dropped",
        filter.kept.len(),
        filter.dropped_total()
    ));
    for (reason, count) in &filter.dropped_by_reason {
        logging::debug(&format!("{reason}: {count}"));
    }
    if filter.kept.is_empty() {
        logging::warn("every transaction was filtered as noise; report will be empty");
    }

    logging::stage(3, "normalizing paths");
    let mut table = normalizer::normalize(&transactions, &filter, &thresholds);
    logging::info(&format!("{} templated endpoints", table.len()));

    logging::stage(4, "mining strong values");
    let observations = extract_observations(&transactions, &filter.kept, &limits);
    normalizer::attach_field_stats(&mut table, &observations);
    let values = mining::mine(&observations, &table, &thresholds);
    logging::info(&format!(
        "{} candidate values observed, {} strong",
        observations.len(),
        values.len()
    ));

    logging::stage(5, "building relationships");
    let relationships =
        relationships::build(&values, &observations, &table, &filter.kept, &thresholds);
    logging::info(&format!(
        "{} chains, {} sequences",
        relationships.chains.len(),
        relationships.sequences.len()
    ));

    logging::stage(6, "detecting field variation");
    let indicators = variation::build(
        &observations,
        &table,
        &values,
        &relationships.chains,
        &thresholds,
    );
    logging::info(&format!("{} possible state indicators", indicators.len()));

    logging::stage(7, "prioritizing");
    let model = aggregator::aggregate(aggregator::Inputs {
        source: &source,
        transactions: &transactions,
        kept: &filter.kept,
        table: &table,
        values: &values,
        relationships: &relationships,
        indicators: &indicators,
        filter: &filter,
        thresholds: &thresholds,
        oversized_bodies: parsed.oversized_bodies,
    });
    for warning in &model.meta.warnings {
        logging::warn(warning);
    }

    Ok(model)
}

/// Extract candidate values from the surviving transactions only.
fn extract_observations(
    transactions: &[crate::model::transaction::RawTransaction],
    kept: &[usize],
    limits: &Limits,
) -> Vec<ObservedValue> {
    kept.iter()
        .filter_map(|id| transactions.get(*id))
        .flat_map(|tx| tokens::extract(tx, limits))
        .collect()
}
