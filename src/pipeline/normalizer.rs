//! Stage 3: statistical path templating.
//!
//! A path position becomes `{id}` when the traffic itself shows it behaving
//! like an identifier: many distinct values under one shared prefix. No list of
//! known identifier names exists anywhere in this module.

use std::collections::{BTreeSet, HashMap};

use super::noise::FilterOutcome;
use crate::analysis::entropy::{self, CharShape};
use crate::config::Thresholds;
use crate::model::endpoint::{Endpoint, EndpointTable, ID_PLACEHOLDER};
use crate::model::transaction::{RawTransaction, TxId};
use crate::model::value::{Direction, ObservedValue, ValueLocation};

/// Values observed at one position under one prefix.
#[derive(Default)]
struct PositionStats {
    total: usize,
    distinct: BTreeSet<String>,
}

/// Build the endpoint table from the surviving transactions.
///
/// Takes the whole [`FilterOutcome`] rather than its `kept` list alone: what
/// filtering *removed* is part of an endpoint's history, and two adjacent
/// `&[TxId]` parameters would be a swap waiting to happen.
pub fn normalize(
    transactions: &[RawTransaction],
    filter: &FilterOutcome,
    thresholds: &Thresholds,
) -> EndpointTable {
    let survivors: Vec<&RawTransaction> = filter
        .kept
        .iter()
        .filter_map(|id| transactions.get(*id))
        .collect();

    let positions = measure_positions(&survivors);
    let mut table = EndpointTable::new();

    for tx in &survivors {
        let template = template_for(tx, &positions, thresholds);
        let slot = table.slot_for(Endpoint::new(tx.method.clone(), template));
        table.assign(tx.id, slot);

        let stats = table.stats_mut(slot).expect("slot just created");
        stats.tx_ids.push(tx.id);
        stats.observed += 1;
        *stats.statuses.entry(tx.status).or_insert(0) += 1;
        for (name, _) in tx.query_params() {
            *stats.query_params.entry(name).or_insert(0) += 1;
        }
    }

    count_filtered_calls(&mut table, transactions, filter, &positions, thresholds);
    table
}

/// Record the calls filtering removed against the endpoints that survived.
///
/// Only endpoints the retained traffic already established are counted, so a
/// route dropped outright — an image, a health probe — stays out of the report
/// entirely. What this recovers is the true call count of a route that *is*
/// reported but was sampled down for being repetitive, which is the one
/// question [`crate::model::endpoint::EndpointStats::calls`] exists to answer
/// honestly.
///
/// Collapsed repeat writes are counted a second time, into
/// [`crate::model::endpoint::EndpointStats::repeated_writes`]. A read replayed
/// fifty times only tells the reader the client polls; a write replayed twice
/// says the operation was performed twice, and that is a fact about the API.
fn count_filtered_calls(
    table: &mut EndpointTable,
    transactions: &[RawTransaction],
    filter: &FilterOutcome,
    positions: &HashMap<(String, String, usize), PositionStats>,
    thresholds: &Thresholds,
) {
    let retained: BTreeSet<TxId> = filter.kept.iter().copied().collect();
    let repeated: BTreeSet<TxId> = filter.repeated_writes.iter().copied().collect();

    for tx in transactions.iter().filter(|tx| !retained.contains(&tx.id)) {
        let template = template_for(tx, positions, thresholds);
        let key = Endpoint::new(tx.method.clone(), template).key();
        if let Some(slot) = table.slot_of_key(&key) {
            if let Some(stats) = table.stats_mut(slot) {
                stats.observed += 1;
                if repeated.contains(&tx.id) {
                    stats.repeated_writes += 1;
                }
            }
        }
    }
}

/// Map `(method, prefix, position) -> observed values`.
fn measure_positions(
    survivors: &[&RawTransaction],
) -> HashMap<(String, String, usize), PositionStats> {
    let mut positions: HashMap<(String, String, usize), PositionStats> = HashMap::new();

    for tx in survivors {
        let segments = tx.segments();
        for (index, segment) in segments.iter().enumerate() {
            let prefix = segments[..index].join("/");
            let entry = positions
                .entry((tx.method.clone(), prefix, index))
                .or_default();
            entry.total += 1;
            entry.distinct.insert((*segment).to_string());
        }
    }

    positions
}

/// Collapse identifier-like positions into `{id}`.
fn template_for(
    tx: &RawTransaction,
    positions: &HashMap<(String, String, usize), PositionStats>,
    thresholds: &Thresholds,
) -> String {
    let segments = tx.segments();
    let mut rendered: Vec<String> = Vec::with_capacity(segments.len());

    for (index, segment) in segments.iter().enumerate() {
        let prefix = segments[..index].join("/");
        let key = (tx.method.clone(), prefix, index);
        let collapse = positions
            .get(&key)
            .is_some_and(|stats| is_identifier_position(stats, segment, thresholds));

        rendered.push(if collapse {
            ID_PLACEHOLDER.to_string()
        } else {
            (*segment).to_string()
        });
    }

    format!("/{}", rendered.join("/"))
}

/// Decide whether one position varies the way an identifier varies.
fn is_identifier_position(stats: &PositionStats, segment: &str, thresholds: &Thresholds) -> bool {
    let shape = entropy::classify(segment);

    // A single unambiguous identifier shape is self-evident and needs no
    // corroborating frequency: one UUID in a path is already an id.
    if matches!(shape, CharShape::Uuid | CharShape::Jwt) {
        return true;
    }

    // Shape-based collapse for identifiers by character class and length only.
    // This handles numeric IDs and long hex strings that don't have frequency evidence.
    let shape_based_collapse = match shape {
        CharShape::Numeric => true,  // Pure digits are always identifiers
        CharShape::Hex => segment.len() >= 16,  // Long hex (≥16 chars) is an identifier
        CharShape::TokenLike => segment.len() >= 16,  // Very long tokens are identifiers
        _ => false,
    };

    if shape_based_collapse {
        return true;
    }

    // For remaining cases, require frequency evidence
    if stats.distinct.len() < thresholds.template_min_siblings {
        return false;
    }

    let ratio = stats.distinct.len() as f64 / stats.total as f64;
    if ratio < thresholds.template_distinct_ratio {
        return false;
    }

    match shape {
        CharShape::TokenLike => segment.len() >= 8 && has_digit(segment),
        // An address in a path names one account, but it is written by a human
        // and reads as itself; collapsing it would hide which account.
        CharShape::EmailLike
        | CharShape::Textual
        | CharShape::Wordlike => false,
        _ => false,
    }
}

fn has_digit(segment: &str) -> bool {
    segment.bytes().any(|b| b.is_ascii_digit())
}

/// Attach observed body field names to their endpoints.
///
/// Runs after value extraction because it reuses the same observations rather
/// than walking every body a second time.
pub fn attach_field_stats(table: &mut EndpointTable, observations: &[ObservedValue]) {
    for observation in observations {
        let ValueLocation::BodyField(field) = &observation.location else {
            continue;
        };
        let Some(slot) = table.slot_of_tx(observation.tx_id) else {
            continue;
        };
        let Some(stats) = table.stats_mut(slot) else {
            continue;
        };
        let bucket = match observation.direction {
            Direction::Request => &mut stats.request_fields,
            Direction::Response => &mut stats.response_fields,
        };
        *bucket.entry(field.clone()).or_insert(0) += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;
    use crate::model::http::HttpMessage;

    fn tx(id: usize, method: &str, path: &str) -> RawTransaction {
        RawTransaction {
            id,
            url: format!("https://x.test{path}"),
            host: "x.test".into(),
            port: "443".into(),
            protocol: "https".into(),
            method: method.into(),
            path: path.into(),
            query: String::new(),
            extension: String::new(),
            status: 200,
            mime_type: String::new(),
            request: HttpMessage::parse(b"GET / HTTP/1.1\r\n\r\n"),
            response: Some(HttpMessage::parse(b"HTTP/1.1 200 OK\r\n\r\nok")),
        }
    }

    /// A filter verdict that kept `kept` and dropped the rest as plain noise.
    fn dropped_all_but(kept: &[TxId]) -> FilterOutcome {
        FilterOutcome {
            kept: kept.to_vec(),
            ..FilterOutcome::default()
        }
    }

    fn normalize_all(transactions: &[RawTransaction]) -> EndpointTable {
        let kept: Vec<TxId> = transactions.iter().map(|t| t.id).collect();
        normalize(
            transactions,
            &dropped_all_but(&kept),
            &Thresholds::for_mode(Mode::Standard),
        )
    }

    #[test]
    fn collapses_varying_numeric_positions() {
        let transactions: Vec<RawTransaction> = (0..6)
            .map(|i| tx(i, "GET", &format!("/api/users/{}", 1000 + i)))
            .collect();
        let table = normalize_all(&transactions);

        assert_eq!(table.len(), 1);
        assert_eq!(table.endpoints[0].endpoint.template, "/api/users/{id}");
        assert_eq!(table.endpoints[0].hits(), 6);
    }

    /// Sampling is what the noise filter does to a route called constantly, so
    /// the retained count of exactly those routes understates them the most. The
    /// report still describes only the retained calls; it just knows how many
    /// there really were.
    #[test]
    fn calls_removed_by_filtering_still_count_towards_the_endpoint() {
        let mut transactions: Vec<RawTransaction> =
            (0..10).map(|i| tx(i, "GET", "/api/poll")).collect();
        transactions.push(tx(10, "PUT", "/api/users/812699/email"));

        let kept = vec![0, 1, 10];
        let table = normalize(
            &transactions,
            &dropped_all_but(&kept),
            &Thresholds::for_mode(Mode::Standard),
        );

        let poll = &table.endpoints[0];
        assert_eq!(poll.hits(), 2, "the report describes the retained calls");
        assert_eq!(poll.calls(), 10, "rarity has to see all ten");

        let write = &table.endpoints[1];
        assert_eq!(write.hits(), 1);
        assert_eq!(write.calls(), 1, "a route nothing was dropped from is exact");
    }

    /// The whole point of the repeat counter: a route sampled down for polling
    /// and a route whose write ran twice both lose transactions, and only the
    /// second one owes the reader an explanation.
    #[test]
    fn only_collapsed_writes_are_counted_as_repeats() {
        let mut transactions: Vec<RawTransaction> =
            (0..10).map(|i| tx(i, "GET", "/api/poll")).collect();
        transactions.push(tx(10, "POST", "/api/employees"));
        transactions.push(tx(11, "POST", "/api/employees"));
        transactions.push(tx(12, "POST", "/api/employees"));

        let filter = FilterOutcome {
            kept: vec![0, 1, 10],
            repeated_writes: vec![11, 12],
            ..FilterOutcome::default()
        };
        let table = normalize(&transactions, &filter, &Thresholds::for_mode(Mode::Standard));

        let poll = &table.endpoints[0];
        assert_eq!(poll.calls(), 10);
        assert_eq!(
            poll.repeated_writes, 0,
            "a replayed read is how a client polls, not an event"
        );

        let write = &table.endpoints[1];
        assert_eq!(write.hits(), 1, "the report still describes one call");
        assert_eq!(write.repeated_writes, 2, "but it ran three times in all");
    }

    /// A transaction the filter removed outright must not put its route back in
    /// the report, however many times it was called.
    #[test]
    fn a_wholly_filtered_route_stays_out_of_the_table() {
        let mut transactions: Vec<RawTransaction> =
            (0..4).map(|i| tx(i, "GET", "/assets/sprite.png")).collect();
        transactions.push(tx(4, "GET", "/api/orders"));

        let table = normalize(
            &transactions,
            &dropped_all_but(&[4]),
            &Thresholds::for_mode(Mode::Standard),
        );

        assert_eq!(table.len(), 1);
        assert_eq!(table.endpoints[0].endpoint.template, "/api/orders");
        assert_eq!(table.endpoints[0].calls(), 1);
    }

    #[test]
    fn keeps_stable_resource_names_intact() {
        let transactions: Vec<RawTransaction> =
            (0..6).map(|i| tx(i, "GET", "/api/users/profile")).collect();
        let table = normalize_all(&transactions);
        assert_eq!(table.endpoints[0].endpoint.template, "/api/users/profile");
    }

    #[test]
    fn a_lone_uuid_is_enough_to_collapse() {
        let transactions = vec![tx(
            0,
            "GET",
            "/api/orders/3f2504e0-4f89-11d3-9a0c-0305e82c3301",
        )];
        let table = normalize_all(&transactions);
        assert_eq!(table.endpoints[0].endpoint.template, "/api/orders/{id}");
    }

    #[test]
    fn distinguishes_methods_on_the_same_template() {
        let transactions = vec![
            tx(0, "GET", "/api/items/1"),
            tx(1, "GET", "/api/items/2"),
            tx(2, "GET", "/api/items/3"),
            tx(3, "DELETE", "/api/items/4"),
        ];
        let table = normalize_all(&transactions);
        let keys: Vec<String> = table.endpoints.iter().map(|s| s.endpoint.key()).collect();
        assert!(keys.contains(&"GET /api/items/{id}".to_string()));
        assert!(keys.iter().any(|k| k.starts_with("DELETE ")));
    }

    #[test]
    fn does_not_collapse_a_shallow_set_of_words() {
        let transactions = vec![
            tx(0, "GET", "/api/reports/daily"),
            tx(1, "GET", "/api/reports/weekly"),
            tx(2, "GET", "/api/reports/monthly"),
        ];
        let table = normalize_all(&transactions);
        let templates: BTreeSet<String> = table
            .endpoints
            .iter()
            .map(|s| s.endpoint.template.clone())
            .collect();
        assert_eq!(templates.len(), 3);
    }

    #[test]
    fn collapses_numeric_ids_by_shape_even_without_frequency() {
        // Single numeric ID should be collapsed based on shape alone
        let transactions = vec![tx(0, "PUT", "/api/users/812699/email")];
        let table = normalize_all(&transactions);
        assert_eq!(table.endpoints[0].endpoint.template, "/api/users/{id}/email");
    }

    #[test]
    fn collapses_long_hex_by_shape_even_without_frequency() {
        // Long hex (≥16 chars) should be collapsed based on shape alone
        let transactions = vec![tx(0, "GET", "/api/chats/deadbeefcafe1234/read")];
        let table = normalize_all(&transactions);
        assert_eq!(table.endpoints[0].endpoint.template, "/api/chats/{id}/read");
    }

    #[test]
    fn merges_endpoints_differing_only_by_numeric_id() {
        // Different numeric IDs should merge to same endpoint
        let transactions = vec![
            tx(0, "PUT", "/api/users/812699/email"),
            tx(1, "PUT", "/api/users/595931/email"),
            tx(2, "GET", "/api/users/123456/profile"),
        ];
        let table = normalize_all(&transactions);
        
        // Should have 2 endpoints: /api/users/{id}/email and /api/users/{id}/profile
        assert_eq!(table.len(), 2);
        
        let templates: BTreeSet<String> = table
            .endpoints
            .iter()
            .map(|s| s.endpoint.template.clone())
            .collect();
        
        assert!(templates.contains("/api/users/{id}/email"));
        assert!(templates.contains("/api/users/{id}/profile"));
    }

    #[test]
    fn keeps_static_segments_intact() {
        // Static segments like v3, api, signup should not be collapsed
        let transactions = vec![
            tx(0, "GET", "/api/v3/users/812699"),
            tx(1, "POST", "/api/v3/signup"),
        ];
        let table = normalize_all(&transactions);
        
        let templates: BTreeSet<String> = table
            .endpoints
            .iter()
            .map(|s| s.endpoint.template.clone())
            .collect();
        
        assert!(templates.contains("/api/v3/users/{id}"));
        assert!(templates.contains("/api/v3/signup"));
    }
}
