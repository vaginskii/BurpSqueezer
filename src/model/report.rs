//! The rendered report's data model.
//!
//! The aggregator decides what belongs here; the renderer only prints it. That
//! split is what keeps the section layout stable no matter how thin the data is.

use std::collections::BTreeMap;

use crate::config::Mode;

/// Fully resolved report, ready to render.
#[derive(Debug, Default)]
pub struct ReportModel {
    pub overview: Overview,
    pub strong_values: Vec<ValueRow>,
    pub chains: Vec<ChainRow>,
    pub core_endpoints: Vec<EndpointRow>,
    pub other_endpoints: Vec<EndpointRow>,
    pub sequences: Vec<SequenceRow>,
    pub state_indicators: Vec<StateRow>,
    pub meta: Meta,
}

/// Headline counts for the Overview section.
#[derive(Debug, Default)]
pub struct Overview {
    pub source: String,
    pub raw_transactions: usize,
    pub kept_transactions: usize,
    pub endpoints: usize,
    pub hosts: Vec<String>,
    pub methods: BTreeMap<String, usize>,
    pub strong_values: usize,
    pub chains: usize,
}

impl Overview {
    /// Share of transactions that survived filtering, as a percentage.
    pub fn retention_pct(&self) -> f64 {
        if self.raw_transactions == 0 {
            return 0.0;
        }
        (self.kept_transactions as f64 / self.raw_transactions as f64) * 100.0
    }
}

/// One Strong Value line.
#[derive(Debug)]
pub struct ValueRow {
    pub handle: String,
    pub masked: String,
    pub len: usize,
    pub entropy: f64,
    pub score: f64,
    pub occurrences: usize,
    /// Share of retained transactions carrying the value, `0.0..=1.0`.
    ///
    /// Reported because it is what separates an identifier from a constant, and
    /// the reader cannot recover it from the occurrence count alone.
    pub coverage: f64,
    pub endpoints: usize,
    pub propagates: bool,
    pub in_path: bool,
    /// Every distinct location the value was seen at, rendered clean and
    /// complete. Covers the hops shown for this value in the chains section.
    pub locations: Vec<String>,
    /// Whether the value appears synthetic/test-like based on shape analysis.
    /// Conservative detection to avoid false positives.
    pub synthetic: bool,
}

/// One data-flow chain.
#[derive(Debug)]
pub struct ChainRow {
    pub handle: String,
    pub masked: String,
    pub score: f64,
    /// Ordered hops, pre-formatted as `GET /a/{id} (resp body.token)`.
    pub hops: Vec<String>,
    /// Distinct endpoints the whole trail touched, unlisted hops included.
    ///
    /// A collapsed trail hides most of its hops, so this is what tells the
    /// reader how far the value actually reached.
    pub endpoints: usize,
    /// Hops the trail made beyond those listed, or `None` when all are listed.
    pub elided: Option<Elided>,
}

/// The hops a chain did not list, and where they fall among those it did.
#[derive(Debug, Clone, Copy)]
pub struct Elided {
    pub hops: usize,
    /// Listed hops preceding the gap; the rest follow it.
    pub after: usize,
}

impl ChainRow {
    /// Hops the value actually made, including any not listed.
    pub fn hop_count(&self) -> usize {
        self.hops.len() + self.elided_hops()
    }

    /// Hops omitted from the listing.
    pub fn elided_hops(&self) -> usize {
        self.elided.map_or(0, |elided| elided.hops)
    }
}

/// Why an endpoint earned its place in Core Signal.
///
/// Each variant names one of the two things the aggregator looks for, so a
/// reader can tell at a glance whether a route is there because the capture
/// mined identifiers from it or because it changed something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relevance {
    /// Values seen here were about here, rather than carried by every request.
    LocalIdentity,
    /// A rare state-changing call against one addressed object.
    DeliberateWrite,
}

impl Relevance {
    pub fn as_str(self) -> &'static str {
        match self {
            Relevance::LocalIdentity => "local identity",
            Relevance::DeliberateWrite => "deliberate write",
        }
    }
}

/// Evidence-based tags for why an endpoint is relevant.
///
/// These tags are derived from method, path shape, and slots rather than
/// hardcoded product-specific knowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhyTag {
    /// Login/code/token issuance patterns in path/slots
    Auth,
    /// Strong credential-like value in query
    TokenInQuery,
    /// Safe method + object id in path/query
    ObjectRead,
    /// Mutating method and/or deliberate write signal
    ObjectWrite,
    /// Generic privilege path segments (panel, admin, internal)
    Admin,
    /// Primary signal when actually the main reason
    LocalIdentity,
}

impl WhyTag {
    pub fn as_str(self) -> &'static str {
        match self {
            WhyTag::Auth => "auth",
            WhyTag::TokenInQuery => "token_in_query",
            WhyTag::ObjectRead => "object_read",
            WhyTag::ObjectWrite => "object_write",
            WhyTag::Admin => "admin",
            WhyTag::LocalIdentity => "local_identity",
        }
    }
}

/// One endpoint line.
#[derive(Debug, Clone)]
pub struct EndpointRow {
    pub endpoint: String,
    pub hits: usize,
    /// Identical state-changing calls collapsed into [`Self::hits`], if any.
    ///
    /// Rendered as `1 (+2 identical)`. A repeated read is collection noise and
    /// is not reported here; a repeated write means the operation ran again with
    /// the same input, which the reader cannot infer from anything else in the
    /// row.
    pub repeated_writes: usize,
    pub statuses: String,
    pub relevance: f64,
    /// What put the row in Core Signal, empty for any row that is not there.
    pub reasons: Vec<Relevance>,
    pub query_params: Vec<String>,
    pub request_fields: Vec<String>,
    pub response_fields: Vec<String>,
    /// Handles of Strong Values touching this endpoint.
    pub value_handles: Vec<String>,
    /// Evidence-based why tags derived from method, path shape, and slots.
    pub why_tags: Vec<WhyTag>,
}

impl EndpointRow {
    /// Call count as the report states it, noting collapsed identical writes.
    pub fn hit_summary(&self) -> String {
        if self.repeated_writes == 0 {
            return self.hits.to_string();
        }
        format!("{} (+{} identical)", self.hits, self.repeated_writes)
    }

    /// The row's reasons, as the report words them.
    pub fn reason_summary(&self) -> Vec<String> {
        self.reasons
            .iter()
            .map(|reason| reason.as_str().to_string())
            .collect()
    }
    
    /// The row's why tags, as the report words them.
    pub fn why_tag_summary(&self) -> Vec<String> {
        self.why_tags
            .iter()
            .map(|tag| tag.as_str().to_string())
            .collect()
    }
}

/// One observed endpoint sequence.
#[derive(Debug)]
pub struct SequenceRow {
    pub steps: Vec<String>,
    pub support: usize,
    pub linked_handles: Vec<String>,
}

/// One low-cardinality field that may encode state.
#[derive(Debug)]
pub struct StateRow {
    pub endpoint: String,
    pub field: String,
    /// Observed values with counts; values are short by construction.
    pub values: Vec<(String, usize)>,
    pub coverage: f64,
}

/// Run metadata and every warning raised along the way.
#[derive(Debug, Default)]
pub struct Meta {
    pub tool_version: String,
    pub mode: Option<Mode>,
    pub relaxed_for_small_dump: bool,
    pub dropped_by_reason: BTreeMap<String, usize>,
    pub truncations: Vec<String>,
    pub warnings: Vec<String>,
    pub value_masking_note: String,
    /// How values were selected, so a reader knows what the absence of a value
    /// means. Rendered alongside [`Meta::value_masking_note`].
    pub value_policy_note: String,
    /// Explanation of the (+N identical) marker used in hit counts.
    pub identical_marker_note: String,
}

impl Meta {
    /// Total transactions removed by the noise filter.
    pub fn dropped_total(&self) -> usize {
        self.dropped_by_reason.values().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_is_zero_for_empty_input() {
        let overview = Overview::default();
        assert_eq!(overview.retention_pct(), 0.0);
    }

    #[test]
    fn retention_tracks_kept_over_raw() {
        let overview = Overview {
            raw_transactions: 200,
            kept_transactions: 50,
            ..Overview::default()
        };
        assert!((overview.retention_pct() - 25.0).abs() < f64::EPSILON);
    }

    /// The row states collapsed writes and nothing else: a reader must not have
    /// to wonder whether `3` means three calls or three descriptions of one.
    #[test]
    fn only_a_row_with_collapsed_writes_annotates_its_count() {
        let row = |hits, repeated_writes| EndpointRow {
            endpoint: "POST /api/employees".into(),
            hits,
            repeated_writes,
            statuses: "200".into(),
            relevance: 1.0,
            reasons: Vec::new(),
            query_params: Vec::new(),
            request_fields: Vec::new(),
            response_fields: Vec::new(),
            value_handles: Vec::new(),
            why_tags: Vec::new(),
        };

        assert_eq!(row(3, 0).hit_summary(), "3");
        assert_eq!(row(1, 2).hit_summary(), "1 (+2 identical)");
    }
}
