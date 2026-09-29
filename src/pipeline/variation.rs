//! Stage 6: field variation signals.
//!
//! Looks for application fields that take a small, stable set of values on an
//! endpoint that already carries signal. Such fields plausibly encode state.
//! The report says "possible" and means it: this stage proposes candidates, it
//! does not name them or claim to know what they represent.
//!
//! Only body fields and query parameters are considered. Headers are excluded
//! because they describe transport rather than application data, and their
//! low-cardinality values would otherwise flood this section.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::relationships::Chain;
use crate::analysis::stats::distinct_ratio;
use crate::config::Thresholds;
use crate::model::endpoint::EndpointTable;
use crate::model::transaction::TxId;
use crate::model::value::{ObservedValue, StrongValue, ValueLocation};

/// A low-cardinality field observed alongside signal.
#[derive(Debug, Clone)]
pub struct StateIndicator {
    pub endpoint: String,
    pub field: String,
    /// Distinct values with occurrence counts, most frequent first.
    pub values: Vec<(String, usize)>,
    /// Share of the endpoint's transactions in which the field appeared.
    pub coverage: f64,
}

/// Per `(endpoint, field)` accumulator.
#[derive(Default)]
struct FieldStats {
    transactions: BTreeSet<TxId>,
    counts: BTreeMap<String, usize>,
}

/// Find candidate state fields on signal-bearing endpoints.
pub fn build(
    observations: &[ObservedValue],
    table: &EndpointTable,
    values: &[StrongValue],
    chains: &[Chain],
    thresholds: &Thresholds,
) -> Vec<StateIndicator> {
    let signal_endpoints = signal_endpoints(values, chains);
    if signal_endpoints.is_empty() {
        return Vec::new();
    }

    let mut fields: HashMap<(String, String), FieldStats> = HashMap::new();

    for observation in observations {
        let Some(field) = application_field(&observation.location) else {
            continue;
        };
        if observation.value.chars().count() > thresholds.variation_max_value_len {
            continue;
        }
        let Some(endpoint) = table.key_of_tx(observation.tx_id) else {
            continue;
        };
        if !signal_endpoints.contains(&endpoint) {
            continue;
        }

        let entry = fields.entry((endpoint, field.to_string())).or_default();
        entry.transactions.insert(observation.tx_id);
        *entry.counts.entry(observation.value.clone()).or_insert(0) += 1;
    }

    let mut indicators: Vec<StateIndicator> = fields
        .into_iter()
        .filter_map(|((endpoint, field), stats)| promote(endpoint, field, stats, table, thresholds))
        .collect();

    indicators.sort_by(|a, b| {
        b.coverage
            .partial_cmp(&a.coverage)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.values.len().cmp(&b.values.len()))
            .then_with(|| a.endpoint.cmp(&b.endpoint))
            .then_with(|| a.field.cmp(&b.field))
    });
    indicators
}

/// Endpoints that carry a Strong Value or take part in a chain.
fn signal_endpoints(values: &[StrongValue], chains: &[Chain]) -> BTreeSet<String> {
    let mut endpoints: BTreeSet<String> = BTreeSet::new();
    for value in values {
        endpoints.extend(value.endpoints.iter().cloned());
    }
    for chain in chains {
        endpoints.extend(chain.hops.iter().map(|hop| hop.endpoint.clone()));
    }
    endpoints
}

/// Field name, for locations that carry application data.
///
/// Cookies are application data too, but they are excluded here for the same
/// reason as headers: a cookie is a named slot in the transport envelope, and
/// its low-cardinality values (locale, consent flags, A/B buckets) would flood
/// this section without describing the application's own state.
fn application_field(location: &ValueLocation) -> Option<&str> {
    match location {
        ValueLocation::BodyField(name) | ValueLocation::QueryParam(name) => Some(name),
        ValueLocation::Header(_)
        | ValueLocation::Cookie(_)
        | ValueLocation::SetCookie(_)
        | ValueLocation::PathSegment(_) => None,
    }
}

/// Apply the selection rules to one candidate field.
fn promote(
    endpoint: String,
    field: String,
    stats: FieldStats,
    table: &EndpointTable,
    thresholds: &Thresholds,
) -> Option<StateIndicator> {
    let samples = stats.transactions.len();
    if samples < thresholds.variation_min_samples {
        return None;
    }

    let cardinality = stats.counts.len();
    // One value is a constant, not a state. Too many values is an identifier.
    if cardinality < 2 || cardinality > thresholds.variation_max_cardinality {
        return None;
    }

    // The ceiling alone cannot tell a small state machine from a small sample
    // of identifiers: four order references in four transactions sit under
    // every absolute limit. A state is a value that *recurs*, so the distinct
    // ratio has to be low as well, and unlike the ceiling it stays meaningful
    // as the endpoint's traffic grows.
    let total: usize = stats.counts.values().sum();
    if distinct_ratio(cardinality, total) > thresholds.variation_max_distinct_ratio {
        return None;
    }

    let hits = endpoint_hits(table, &endpoint)?;
    let coverage = samples as f64 / hits as f64;
    if coverage < thresholds.variation_min_coverage {
        return None;
    }

    let mut values: Vec<(String, usize)> = stats.counts.into_iter().collect();
    values.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    Some(StateIndicator {
        endpoint,
        field,
        values,
        coverage,
    })
}

fn endpoint_hits(table: &EndpointTable, key: &str) -> Option<usize> {
    table
        .endpoints
        .iter()
        .find(|stats| stats.endpoint.key() == key)
        .map(|stats| stats.hits())
        .filter(|hits| *hits > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;
    use crate::model::endpoint::Endpoint;
    use crate::model::value::Direction;

    fn table(entries: &[(TxId, &str)]) -> EndpointTable {
        let mut table = EndpointTable::new();
        for (tx_id, template) in entries {
            let slot = table.slot_for(Endpoint::new("GET", *template));
            table.assign(*tx_id, slot);
            table
                .stats_mut(slot)
                .expect("slot exists")
                .tx_ids
                .push(*tx_id);
        }
        table
    }

    /// `count` transactions against one signal-bearing endpoint.
    fn orders_table(count: usize) -> EndpointTable {
        let entries: Vec<(TxId, &str)> = (0..count).map(|id| (id, "/orders")).collect();
        table(&entries)
    }

    fn observation(tx_id: TxId, location: ValueLocation, value: &str) -> ObservedValue {
        ObservedValue {
            tx_id,
            direction: Direction::Response,
            location,
            value: value.to_string(),
        }
    }

    fn signal_value(endpoint: &str) -> StrongValue {
        let mut value = StrongValue::new("token-abcdef0123456789".to_string(), 0);
        value.score = 0.9;
        value.endpoints.insert(endpoint.to_string());
        value
    }

    fn field_observations(field: &str, values: &[&str]) -> Vec<ObservedValue> {
        values
            .iter()
            .enumerate()
            .map(|(tx_id, value)| observation(tx_id, ValueLocation::BodyField(field.into()), value))
            .collect()
    }

    #[test]
    fn promotes_a_low_cardinality_field_on_a_signal_endpoint() {
        let table = table(&[
            (0, "/orders"),
            (1, "/orders"),
            (2, "/orders"),
            (3, "/orders"),
        ]);
        let observations = field_observations("status", &["open", "open", "closed", "open"]);
        let values = vec![signal_value("GET /orders")];

        let indicators = build(
            &observations,
            &table,
            &values,
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );

        assert_eq!(indicators.len(), 1);
        let indicator = &indicators[0];
        assert_eq!(indicator.field, "status");
        assert_eq!(indicator.values[0], ("open".to_string(), 3));
        assert!((indicator.coverage - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ignores_constant_fields() {
        let table = table(&[
            (0, "/orders"),
            (1, "/orders"),
            (2, "/orders"),
            (3, "/orders"),
        ]);
        let observations = field_observations("kind", &["same", "same", "same", "same"]);
        let values = vec![signal_value("GET /orders")];

        let indicators = build(
            &observations,
            &table,
            &values,
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );
        assert!(indicators.is_empty());
    }

    #[test]
    fn ignores_fields_with_too_many_distinct_values() {
        // Six values, each seen three times. They recur, so the distinct ratio
        // is comfortably low and only the absolute ceiling can reject this.
        let labels = ["queued", "running", "paused", "failed", "done", "archived"];
        let observed: Vec<&str> = (0..18).map(|i| labels[i % labels.len()]).collect();
        let observations = field_observations("stage", &observed);
        let values = vec![signal_value("GET /orders")];

        let indicators = build(
            &observations,
            &orders_table(18),
            &values,
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );
        assert!(indicators.is_empty());
    }

    #[test]
    fn ignores_fields_whose_values_never_repeat() {
        // Four distinct values in four transactions sits under the cardinality
        // ceiling, but a field that is new every time is an identifier.
        let observations = field_observations("ref", &["a1", "b2", "c3", "d4"]);
        let values = vec![signal_value("GET /orders")];

        let indicators = build(
            &observations,
            &orders_table(4),
            &values,
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );
        assert!(indicators.is_empty());
    }

    #[test]
    fn ignores_endpoints_without_signal() {
        let table = table(&[
            (0, "/public"),
            (1, "/public"),
            (2, "/public"),
            (3, "/public"),
        ]);
        let observations = field_observations("status", &["on", "on", "off", "on"]);

        let indicators = build(
            &observations,
            &table,
            &[],
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );
        assert!(indicators.is_empty());
    }

    #[test]
    fn ignores_headers_and_cookies() {
        let table = table(&[
            (0, "/orders"),
            (1, "/orders"),
            (2, "/orders"),
            (3, "/orders"),
        ]);
        let observations: Vec<ObservedValue> = ["gzip", "gzip", "br", "gzip"]
            .iter()
            .enumerate()
            .map(|(tx_id, value)| {
                observation(
                    tx_id,
                    ValueLocation::Header("content-encoding".into()),
                    value,
                )
            })
            .collect();
        let values = vec![signal_value("GET /orders")];

        let indicators = build(
            &observations,
            &table,
            &values,
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );
        assert!(indicators.is_empty());
    }

    #[test]
    fn requires_systematic_coverage() {
        let table = table(&[
            (0, "/orders"),
            (1, "/orders"),
            (2, "/orders"),
            (3, "/orders"),
            (4, "/orders"),
            (5, "/orders"),
            (6, "/orders"),
            (7, "/orders"),
        ]);
        // Field present in only half of the endpoint's transactions.
        let observations = field_observations("status", &["open", "closed", "open", "closed"]);
        let values = vec![signal_value("GET /orders")];

        let indicators = build(
            &observations,
            &table,
            &values,
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );
        assert!(indicators.is_empty());
    }
}
