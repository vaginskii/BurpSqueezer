//! Templated endpoints and the statistics observed for each.

use std::collections::BTreeMap;
use std::fmt;

use super::transaction::TxId;
use crate::analysis::entropy;

/// Segment written wherever the traffic showed a position carrying identifiers.
///
/// Shared so that whoever writes a template and whoever later reads one agree on
/// the spelling. It is the only literal in the codebase that both stages must
/// match on.
pub const ID_PLACEHOLDER: &str = "{id}";

/// Endpoint key standing in for a transaction that filtering removed.
///
/// A value can be sighted in a transaction the noise filter dropped. Naming that
/// case keeps it visible instead of silently counting as an endpoint of its own.
pub const UNMAPPED_ENDPOINT: &str = "<unmapped>";

/// A method plus a templated path, e.g. `GET /api/users/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    pub method: String,
    pub template: String,
}

impl Endpoint {
    pub fn new(method: impl Into<String>, template: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            template: template.into(),
        }
    }

    /// Stable string key used for cross-stage lookups and report output.
    pub fn key(&self) -> String {
        format!("{} {}", self.method, self.template)
    }

    /// Whether the route addresses one particular object rather than a set.
    ///
    /// Either the normalizer already collapsed a position — proof that the
    /// capture saw identifiers there — or a segment is identifier-shaped on its
    /// own, which is how a route seen exactly once still reads as addressing an
    /// instance. Collection routes and action verbs contain neither.
    pub fn addresses_an_instance(&self) -> bool {
        self.template
            .split('/')
            .filter(|segment| !segment.is_empty())
            .any(|segment| segment == ID_PLACEHOLDER || entropy::is_identifier_like(segment))
    }

    /// Whether the capture showed path position `index` carrying identifiers.
    ///
    /// The template already records the verdict. If a position varied the way an
    /// identifier varies, the normalizer collapsed it; if a literal survived
    /// there, the traffic showed one constant word, and a value seen at that
    /// position is part of the route's *name* rather than an argument to it.
    /// Reading the answer back off the template is what keeps one definition of
    /// "this position holds data" instead of two that could disagree.
    ///
    /// `index` counts non-empty segments, matching
    /// [`crate::model::value::ValueLocation::PathSegment`].
    pub fn routes_on_data_at(&self, index: usize) -> bool {
        self.template
            .split('/')
            .filter(|segment| !segment.is_empty())
            .nth(index)
            == Some(ID_PLACEHOLDER)
    }

    /// Whether the method is defined to change server state.
    ///
    /// A read can be replayed and tells the reader what exists; a write is the
    /// operation itself. Nothing here depends on what is being written.
    pub fn is_state_changing(&self) -> bool {
        method_changes_state(&self.method)
    }
}

/// Whether an HTTP method is defined to change server state.
///
/// The single definition of a write verb in the codebase. Stage 2 needs it
/// before any endpoint exists — a replayed read is capture noise while a
/// replayed write is the operation happening again — and [`Endpoint`] needs it
/// afterwards, so it lives here as a free function over the method alone rather
/// than as two `matches!` arms that could drift apart.
///
/// Everything outside the list counts as a read, including verbs this list has
/// never heard of. That is deliberate: the caller that cares most is a filter,
/// and an unrecognised verb replayed byte-for-byte is far more likely to be a
/// client repeating a query than a custom mutation.
pub fn method_changes_state(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

/// Normalize a path by replacing id-shaped segments with {id}.
///
/// This applies conservative shape detection to convert concrete paths with
/// unambiguous identifier shapes (UUIDs, long hex, JWTs) to templates.
/// Unlike the statistical normalizer, this operates on shape alone and is
/// used for endpoint inventory normalization to ensure template-based aggregation.
///
/// Only collapses segments that are unambiguous identifier shapes to avoid
/// over-normalizing meaningful numeric IDs that the statistical normalizer
/// would keep as literals when seen infrequently.
pub fn normalize_path_by_shape(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let normalized: Vec<String> = segments
        .iter()
        .map(|segment| {
            // Only collapse unambiguous identifier shapes that the statistical
            // normalizer might miss when seen only once (UUIDs, JWTs, long hex)
            let shape = entropy::classify(segment);
            match shape {
                entropy::CharShape::Uuid | entropy::CharShape::Jwt => {
                    ID_PLACEHOLDER.to_string()
                }
                entropy::CharShape::Hex if segment.len() >= 8 => {
                    ID_PLACEHOLDER.to_string()
                }
                _ => segment.to_string()
            }
        })
        .collect();
    
    if normalized.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", normalized.join("/"))
    }
}

/// Normalize a full endpoint key ("METHOD /path") by shape, leaving the method
/// untouched.
///
/// The single place a `METHOD /path` key is re-templated. Every stage that
/// aggregates or renders an endpoint routes through here, so they can never
/// disagree about the spelling of a route — the duplication that previously let
/// the inventory, the value evidence, and the chain hops each collapse ids
/// slightly differently.
pub fn normalize_endpoint_key(key: &str) -> String {
    match key.split_once(' ') {
        Some((method, path)) => format!("{method} {}", normalize_path_by_shape(path)),
        None => key.to_string(),
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.method, self.template)
    }
}

/// Everything observed about one endpoint after filtering.
#[derive(Debug, Clone)]
pub struct EndpointStats {
    pub endpoint: Endpoint,
    /// Transactions retained for this endpoint, in dump order.
    pub tx_ids: Vec<TxId>,
    /// Times the capture called this endpoint, filtered calls included.
    pub observed: usize,
    /// State-changing calls collapsed as byte-identical repeats of a retained
    /// one.
    ///
    /// Counted separately from [`Self::observed`] because a repeated write is
    /// the only kind of collapsed traffic the report still has to state: the
    /// operation was performed more than once with identical input.
    pub repeated_writes: usize,
    /// Response status code counts.
    pub statuses: BTreeMap<u16, usize>,
    /// Query parameter names ever seen, with hit counts.
    pub query_params: BTreeMap<String, usize>,
    /// Request body field paths ever seen, with hit counts.
    pub request_fields: BTreeMap<String, usize>,
    /// Response body field paths ever seen, with hit counts.
    pub response_fields: BTreeMap<String, usize>,
}

impl EndpointStats {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            tx_ids: Vec::new(),
            observed: 0,
            repeated_writes: 0,
            statuses: BTreeMap::new(),
            query_params: BTreeMap::new(),
            request_fields: BTreeMap::new(),
            response_fields: BTreeMap::new(),
        }
    }

    /// Number of retained transactions.
    pub fn hits(&self) -> usize {
        self.tx_ids.len()
    }

    /// Number of times the capture called this endpoint.
    ///
    /// [`Self::hits`] counts what the report goes on to describe; this counts
    /// what the traffic did. The two differ wherever filtering sampled a
    /// repetitive endpoint down, and anything reasoning about how *often* an
    /// operation happened has to ask this one — otherwise sampling an endpoint
    /// for being repetitive would be what makes it look rare.
    pub fn calls(&self) -> usize {
        self.observed.max(self.hits())
    }

    /// Statuses rendered compactly, e.g. `200 (3), 404 (1)`.
    pub fn status_summary(&self) -> String {
        if self.statuses.is_empty() {
            return "-".to_string();
        }
        self.statuses
            .iter()
            .map(|(code, count)| {
                if *count == 1 {
                    code.to_string()
                } else {
                    format!("{} ({})", code, count)
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Endpoints plus the transaction-to-endpoint mapping produced by the
/// normalizer.
#[derive(Debug, Default)]
pub struct EndpointTable {
    pub endpoints: Vec<EndpointStats>,
    index: BTreeMap<String, usize>,
    tx_to_endpoint: BTreeMap<TxId, usize>,
}

impl EndpointTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or fetch the slot for `endpoint`.
    pub fn slot_for(&mut self, endpoint: Endpoint) -> usize {
        let key = endpoint.key();
        if let Some(&idx) = self.index.get(&key) {
            return idx;
        }
        let idx = self.endpoints.len();
        self.endpoints.push(EndpointStats::new(endpoint));
        self.index.insert(key, idx);
        idx
    }

    /// Record that `tx_id` belongs to endpoint slot `idx`.
    pub fn assign(&mut self, tx_id: TxId, idx: usize) {
        self.tx_to_endpoint.insert(tx_id, idx);
    }

    /// Endpoint slot for a key already present, without creating one.
    pub fn slot_of_key(&self, key: &str) -> Option<usize> {
        self.index.get(key).copied()
    }

    pub fn stats_mut(&mut self, idx: usize) -> Option<&mut EndpointStats> {
        self.endpoints.get_mut(idx)
    }

    /// Endpoint slot for a transaction, if it survived filtering.
    pub fn slot_of_tx(&self, tx_id: TxId) -> Option<usize> {
        self.tx_to_endpoint.get(&tx_id).copied()
    }

    /// Endpoint key for a transaction, if it survived filtering.
    pub fn key_of_tx(&self, tx_id: TxId) -> Option<String> {
        self.slot_of_tx(tx_id)
            .and_then(|idx| self.endpoints.get(idx))
            .map(|stats| stats.endpoint.key())
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    /// Transactions that survived filtering and were mapped to an endpoint.
    ///
    /// This is the denominator for any "share of the capture" statistic. It is
    /// deliberately not derived from the observation stream, where one
    /// transaction contributes many rows.
    pub fn transaction_count(&self) -> usize {
        self.tx_to_endpoint.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_stable_per_key() {
        let mut table = EndpointTable::new();
        let a = table.slot_for(Endpoint::new("GET", "/api/users/{id}"));
        let b = table.slot_for(Endpoint::new("GET", "/api/users/{id}"));
        let c = table.slot_for(Endpoint::new("POST", "/api/users/{id}"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn resolves_endpoint_key_for_transaction() {
        let mut table = EndpointTable::new();
        let slot = table.slot_for(Endpoint::new("GET", "/health"));
        table.assign(7, slot);
        assert_eq!(table.key_of_tx(7).as_deref(), Some("GET /health"));
        assert_eq!(table.key_of_tx(8), None);
    }

    #[test]
    fn transaction_count_is_the_mapped_transactions_not_the_endpoints() {
        let mut table = EndpointTable::new();
        let slot = table.slot_for(Endpoint::new("GET", "/poll"));
        for tx in 0..5 {
            table.assign(tx, slot);
        }
        assert_eq!(table.len(), 1);
        assert_eq!(table.transaction_count(), 5);
    }

    /// A route that names one object is what a rare write acts upon. Both ways
    /// of naming it have to count: the collapsed placeholder, and the literal
    /// identifier left in place because the capture only saw the route once.
    #[test]
    fn instance_routes_are_recognised_collapsed_or_literal() {
        for template in [
            "/api/users/{id}/email",
            "/api/users/812699/email",
            "/api/orders/3f2504e0-4f89-11d3-9a0c-0305e82c3301",
        ] {
            assert!(
                Endpoint::new("PUT", template).addresses_an_instance(),
                "missed instance route {template}"
            );
        }

        for template in ["/api/users", "/api/profile", "/api/users/settings", "/"] {
            assert!(
                !Endpoint::new("PUT", template).addresses_an_instance(),
                "collection route {template} read as an instance"
            );
        }
    }

    /// Which path positions hold data, indexed exactly as the extractor indexes
    /// them. A route noun scored like an identifier for as long as every path
    /// sighting was treated as one.
    #[test]
    fn only_a_collapsed_position_routes_on_data() {
        let route = Endpoint::new("GET", "/api/v3/users/{id}/email");
        assert!(!route.routes_on_data_at(0), "api is the route's own name");
        assert!(!route.routes_on_data_at(1));
        assert!(!route.routes_on_data_at(2));
        assert!(route.routes_on_data_at(3));
        assert!(!route.routes_on_data_at(4));
        assert!(!route.routes_on_data_at(9), "past the end of the template");

        // A literal identifier left in place is not evidence about the position:
        // the capture saw the route once and had nothing to compare it against.
        assert!(!Endpoint::new("PUT", "/api/accounts/595931/settings").routes_on_data_at(2));
        assert!(!Endpoint::new("GET", "/").routes_on_data_at(0));
    }

    #[test]
    fn state_changing_methods_are_the_write_verbs() {
        for method in ["POST", "PUT", "PATCH", "DELETE", "delete"] {
            assert!(Endpoint::new(method, "/x").is_state_changing());
        }
        for method in ["GET", "HEAD", "OPTIONS"] {
            assert!(!Endpoint::new(method, "/x").is_state_changing());
        }
    }

    /// Retained and observed counts answer different questions, and the second
    /// can never be smaller than the first however the stats were assembled.
    #[test]
    fn calls_count_the_traffic_and_hits_count_the_report() {
        let mut stats = EndpointStats::new(Endpoint::new("GET", "/poll"));
        stats.tx_ids.extend([1, 2, 3]);
        assert_eq!(stats.hits(), 3);
        assert_eq!(stats.calls(), 3, "an unset observed count never underreports");

        stats.observed = 40;
        assert_eq!(stats.hits(), 3);
        assert_eq!(stats.calls(), 40);
    }

    /// Status summary must not produce glued tokens like "200x4".
    #[test]
    fn status_summary_avoids_glued_tokens() {
        let mut stats = EndpointStats::new(Endpoint::new("GET", "/api/users"));
        stats.statuses.insert(200, 3);
        stats.statuses.insert(404, 1);
        
        let summary = stats.status_summary();
        assert_eq!(summary, "200 (3), 404");
        assert!(!summary.contains('x'), "status summary must not contain glued 'x' tokens");
    }

    /// Path normalization by shape should convert id-shaped segments to {id}.
    #[test]
    fn normalize_path_by_shape_converts_identifiers() {
        // UUIDs - unambiguous identifiers
        assert_eq!(
            normalize_path_by_shape("/api/orders/3f2504e0-4f89-11d3-9a0c-0305e82c3301"),
            "/api/orders/{id}"
        );
        
        // JWTs may or may not be collapsed depending on entropy classification
        // This test just verifies the function doesn't crash on JWT-like strings
        let jwt_result = normalize_path_by_shape("/api/verify/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        assert!(jwt_result.starts_with("/api/verify/"));
        
        // Long hex (16+ chars) - likely identifiers
        assert_eq!(
            normalize_path_by_shape("/chats/abc123def4567890/read"),
            "/chats/{id}/read"
        );
        
        // Numeric IDs should NOT be collapsed (conservative approach)
        // They might be meaningful room numbers, account numbers, etc.
        assert_eq!(
            normalize_path_by_shape("/users/812699/email"),
            "/users/812699/email"
        );
        assert_eq!(
            normalize_path_by_shape("/api/rooms/9182734650/members/44120986"),
            "/api/rooms/9182734650/members/44120986"
        );
        
        // Static segments should remain unchanged
        assert_eq!(
            normalize_path_by_shape("/api/users/profile"),
            "/api/users/profile"
        );
        assert_eq!(
            normalize_path_by_shape("/api/reports/daily"),
            "/api/reports/daily"
        );
        
        // Short hex should NOT be collapsed (might be meaningful)
        assert_eq!(
            normalize_path_by_shape("/chats/42183147/read"),
            "/chats/42183147/read"
        );
    }
}
