//! Stage 7: prioritise everything and decide what the report will contain.
//!
//! This is the only stage that makes editorial choices. Every limit it applies
//! comes from [`Thresholds`], and every cut it makes is recorded in Meta so the
//! reader can tell a thin capture from an aggressive mode.

use std::collections::{BTreeMap, BTreeSet};

use super::noise::FilterOutcome;
use super::relationships::{Chain, Relationships, Sequence};
use super::variation::StateIndicator;
use crate::analysis::{entropy, provenance, stats};
use crate::config::Thresholds;
use crate::model::endpoint::{normalize_endpoint_key, Endpoint, EndpointStats, EndpointTable, UNMAPPED_ENDPOINT};
use crate::model::report::WhyTag;
use crate::model::report::{
    ChainRow, Elided, EndpointRow, Meta, Overview, Relevance, ReportModel, SequenceRow, StateRow,
    ValueRow,
};
use crate::model::transaction::{RawTransaction, TxId};
use crate::model::value::StrongValue;

/// Relative weights of the endpoint relevance terms. They sum to 1.0.
const W_VALUES: f64 = 0.40;
const W_CHAIN: f64 = 0.25;
const W_FIELDS: f64 = 0.15;
const W_METHOD: f64 = 0.10;
const W_STATUS: f64 = 0.10;

/// Count of local Strong Values at which an endpoint's value term reaches half
/// of what it can ever claim.
///
/// Below one deliberately. The first identifier a route handles is most of what
/// there is to learn about it; the fourth is a detail. A half point of one would
/// make a route with a single object id look half-evidenced, which it is not.
const LOCAL_EVIDENCE_HALF_POINT: f64 = 0.5;
/// All an endpoint may claim when every value ever seen on it was ubiquitous.
///
/// Not zero: the credential really was observed here, and the report still
/// cross-references it. But it is flat and does not accumulate, because three
/// session-wide credentials on one route are three restatements of one fact —
/// that the route is authenticated — and none of them is evidence about the
/// route itself.
const UBIQUITOUS_RESIDUE: f64 = 0.05;

/// Distinct field count at which the richness term saturates.
const FIELD_CEILING: f64 = 12.0;
/// Distinct extra status codes at which the status term saturates.
const STATUS_CEILING: f64 = 3.0;
/// Hosts listed in the Overview before the list is truncated.
const MAX_HOSTS_LISTED: usize = 10;

/// Everything the aggregator needs, gathered rather than passed positionally.
pub struct Inputs<'a> {
    pub source: &'a str,
    pub transactions: &'a [RawTransaction],
    pub kept: &'a [TxId],
    pub table: &'a EndpointTable,
    pub values: &'a [StrongValue],
    pub relationships: &'a Relationships,
    pub indicators: &'a [StateIndicator],
    pub filter: &'a FilterOutcome,
    pub thresholds: &'a Thresholds,
    /// Bodies stage 1 discarded for exceeding [`crate::config::Limits`].
    pub oversized_bodies: usize,
}

/// One endpoint with every judgement the report needs about it, made once.
///
/// `deliberate` and `locality` are computed alongside the score rather than
/// re-derived, because the decisions they feed — how high the endpoint ranks and
/// which section it lands in — must never be able to disagree.
#[derive(Debug, Clone, Copy)]
struct Ranked<'a> {
    relevance: f64,
    /// How strongly the endpoint reads as a deliberate write to one object.
    deliberate: f64,
    /// How much of the evidence seen here was about here, `0.0..=1.0`.
    locality: f64,
    stats: &'a EndpointStats,
}

impl Ranked<'_> {
    /// Why this endpoint belongs in Core Signal, strongest criterion first.
    ///
    /// Core Signal is what the reader should look at first, and there are two
    /// ways to earn a place in it. Holding enough evidence of its own is one: the
    /// endpoint is part of a flow that was reconstructed, and the bar is a
    /// quantity rather than a boolean precisely so that one session-wide
    /// credential cannot admit two thirds of the API. Being a rare write to one
    /// named object is the other, and it has to stay its own criterion, because
    /// such a request is often the only one of its kind in the capture and so has
    /// nothing to hand over and no traffic to rank on.
    ///
    /// An endpoint nothing was ever seen at has no evidence to clear any bar
    /// with, which matters because the small-dump relaxation drops the bar to
    /// zero: there it should admit every route a value touched, not every route.
    ///
    /// One list serves both the placement and the explanation, so the report can
    /// never print a reason that had no part in putting the row where it is.
    fn reasons(&self, thresholds: &Thresholds) -> Vec<Relevance> {
        let mut reasons = Vec::new();
        if self.locality > 0.0 && self.locality >= thresholds.core_min_local_evidence {
            reasons.push(Relevance::LocalIdentity);
        }
        if self.deliberate > 0.0 {
            reasons.push(Relevance::DeliberateWrite);
        }
        reasons
    }
}

/// Sightings at one endpoint, split by whether the value was local to the
/// capture's traffic or spread across all of it.
#[derive(Debug, Default, Clone, Copy)]
struct Tally {
    local: usize,
    ubiquitous: usize,
}

impl Tally {
    fn add(&mut self, is_local: bool) {
        if is_local {
            self.local += 1;
        } else {
            self.ubiquitous += 1;
        }
    }

    /// Credit these sightings earn an endpoint, `0.0..=1.0`.
    ///
    /// Local sightings accumulate with diminishing returns. Ubiquitous ones do
    /// not accumulate at all: they collapse to [`UBIQUITOUS_RESIDUE`] however
    /// many there were.
    fn credit(&self) -> f64 {
        if self.local == 0 {
            return if self.ubiquitous == 0 {
                0.0
            } else {
                UBIQUITOUS_RESIDUE
            };
        }
        stats::saturate(self.local, LOCAL_EVIDENCE_HALF_POINT)
    }
}

/// What the capture's mined values and chains say about one endpoint.
#[derive(Debug, Default, Clone, Copy)]
struct ValueEvidence {
    /// Strong Values sighted at the endpoint.
    values: Tally,
    /// Chains passing through it, counted once per chain.
    chains: Tally,
}

impl ValueEvidence {
    /// How strongly the endpoint's own evidence argues for reading it.
    ///
    /// The stronger of the two tallies rather than their sum. A chain hop and a
    /// value sighting at the same route are usually the same observation seen
    /// from two stages, so adding them would count it twice.
    fn locality(&self) -> f64 {
        self.values.credit().max(self.chains.credit())
    }
}

/// Ranked endpoints, most relevant first.
type ScoredEndpoints<'a> = Vec<Ranked<'a>>;

/// Build the final, fully decided report model.
pub fn aggregate(inputs: Inputs<'_>) -> ReportModel {
    let mut meta = base_meta(&inputs);

    let evidence = value_evidence(
        inputs.values,
        &inputs.relationships.chains,
        inputs.thresholds,
    );
    let handles_by_endpoint = handles_by_endpoint(inputs.values, &inputs.relationships.chains);

    let strong_values = build_value_rows(&inputs, &mut meta);

    // Limits are applied to Strong Values first, and every other section then
    // references only what survived. A handle the reader cannot look up is
    // noise, which is exactly what this tool exists to remove.
    let reported: BTreeSet<String> = strong_values
        .iter()
        .map(|value| value.handle.clone())
        .collect();

    let chains = build_chain_rows(&inputs, &reported, &mut meta);
    let (core_endpoints, other_endpoints) = build_endpoint_rows(
        &inputs,
        &evidence,
        &handles_by_endpoint,
        &reported,
        &mut meta,
    );
    let sequences = build_sequence_rows(&inputs, &reported, &mut meta);
    let state_indicators = build_state_rows(&inputs, &mut meta);

    let overview = build_overview(&inputs, &strong_values, &chains);

    let mut model = ReportModel {
        overview,
        strong_values,
        chains,
        core_endpoints,
        other_endpoints,
        sequences,
        state_indicators,
        meta,
    };
    add_quality_warnings(&mut model, &inputs);
    model
}

fn base_meta(inputs: &Inputs<'_>) -> Meta {
    Meta {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        mode: Some(inputs.thresholds.mode),
        relaxed_for_small_dump: inputs.thresholds.relaxed_for_small_dump,
        dropped_by_reason: inputs.filter.dropped_by_reason.clone(),
        truncations: Vec::new(),
        warnings: Vec::new(),
        value_masking_note:
            "Strong Values are shown truncated with a stable fingerprint. Chains were matched on \
             the full value in memory; full values are never written to this report. \
             propagates=yes when the same value is observed in a chain across more than one hop (any req/resp slot)."
                .to_string(),
        value_policy_note:
            "Values are judged by where they were seen, never by what a field is named. Path \
             segments, query parameters, cookies and JSON bodies carry application data; plain \
             headers carry protocol scaffolding and take no part in mining unless a value both \
             crossed from one slot into another and is long and random enough to be an issued \
             credential. Coverage is the share of retained transactions carrying the value: the \
             closer it is to 100%, the more the value behaves like a constant, and the harder it \
             is scored down."
                .to_string(),
        identical_marker_note: 
            "(+N identical) indicates extra identical retained transactions collapsed in display counts. \
             Only state-changing calls with identical input are collapsed; reads are not collapsed."
                .to_string(),
    }
}

fn build_overview(inputs: &Inputs<'_>, values: &[ValueRow], chains: &[ChainRow]) -> Overview {
    let kept: Vec<&RawTransaction> = inputs
        .kept
        .iter()
        .filter_map(|id| inputs.transactions.get(*id))
        .collect();

    let mut methods: BTreeMap<String, usize> = BTreeMap::new();
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    for tx in &kept {
        *methods.entry(tx.method.clone()).or_insert(0) += 1;
        if !tx.host.trim().is_empty() {
            hosts.insert(tx.host.clone());
        }
    }

    Overview {
        source: inputs.source.to_string(),
        raw_transactions: inputs.transactions.len(),
        kept_transactions: kept.len(),
        endpoints: inputs.table.len(),
        hosts: hosts.into_iter().take(MAX_HOSTS_LISTED).collect(),
        methods,
        strong_values: values.len(),
        chains: chains.len(),
    }
}

fn build_value_rows(inputs: &Inputs<'_>, meta: &mut Meta) -> Vec<ValueRow> {
    let limit = inputs.thresholds.max_strong_values;
    note_truncation(meta, "Strong Values", inputs.values.len(), limit);

    inputs
        .values
        .iter()
        .take(limit)
        .map(|value| {
            ValueRow {
                handle: value.handle(),
                masked: value.masked(),
                len: value.full().len(),
                entropy: value.entropy,
                score: value.score,
                occurrences: value.occurrences,
                coverage: value.coverage,
                endpoints: value.endpoints.len(),
                propagates: value.propagates,
                in_path: value.seen_in_path,
                // Already rendered by `render_location` in mining and complete;
                // the table shows exactly what feeds the chains, uncapped.
                locations: value.sightings.clone(),
                synthetic: entropy::is_synthetic(value.full()),
            }
        })
        .collect()
}

/// Chains, with genuine Multi-Data-Flow first.
///
/// Chains whose value did not make it into the Strong Values section are
/// dropped rather than shown with an unresolvable handle.
fn build_chain_rows(
    inputs: &Inputs<'_>,
    reported: &BTreeSet<String>,
    meta: &mut Meta,
) -> Vec<ChainRow> {
    let thresholds = inputs.thresholds;
    let mut ordered: Vec<(&Chain, &StrongValue)> = inputs
        .relationships
        .chains
        .iter()
        .filter_map(|chain| {
            let value = inputs.values.get(chain.value_index)?;
            reported.contains(&value.handle()).then_some((chain, value))
        })
        .collect();
    ordered.sort_by_key(|(chain, _)| !chain.is_multi(thresholds));

    note_truncation(meta, "chains", ordered.len(), thresholds.max_chains);

    ordered
        .into_iter()
        .take(thresholds.max_chains)
        .map(|(chain, value)| ChainRow {
            handle: value.handle(),
            masked: value.masked(),
            score: chain.score,
            hops: chain.hops.iter().map(|hop| hop.label()).collect(),
            endpoints: chain.endpoints,
            elided: chain.elision.map(|elision| Elided {
                hops: elision.count,
                after: elision.after,
            }),
        })
        .collect()
}

fn build_endpoint_rows(
    inputs: &Inputs<'_>,
    evidence: &BTreeMap<String, ValueEvidence>,
    handles: &BTreeMap<String, BTreeSet<String>>,
    reported: &BTreeSet<String>,
    meta: &mut Meta,
) -> (Vec<EndpointRow>, Vec<EndpointRow>) {
    let mut scored: ScoredEndpoints<'_> = inputs
        .table
        .endpoints
        .iter()
        .map(|stats| {
            let deliberate = deliberate_write(stats, inputs.thresholds);
            let normalized_key = normalize_endpoint_key(&stats.endpoint.key());
            let locality = evidence
                .get(&normalized_key)
                .map(ValueEvidence::locality)
                .unwrap_or(0.0);
            Ranked {
                relevance: lifted(
                    earned_relevance(stats, evidence),
                    deliberate,
                    inputs.thresholds.instance_mutation_lift,
                ),
                deliberate,
                locality,
                stats,
            }
        })
        .collect();
    scored.sort_by(|a, b| {
        b.relevance
            .partial_cmp(&a.relevance)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.stats.hits().cmp(&a.stats.hits()))
            .then_with(|| a.stats.endpoint.key().cmp(&b.stats.endpoint.key()))
    });

    // See [`Ranked::reasons`] for what earns a place here and why the bar is a
    // quantity rather than a boolean.
    let belongs_in_core = |row: &Ranked<'_>| !row.reasons(inputs.thresholds).is_empty();

    let (core_source, other_source): (ScoredEndpoints<'_>, ScoredEndpoints<'_>) =
        if scored.iter().any(belongs_in_core) {
            scored.iter().copied().partition(belongs_in_core)
        } else {
            // Nothing was mined and nothing was written, so relevance ranking is
            // all that is left. Those rows carry no reason, which is the honest
            // answer, and the warning in Meta says why.
            let split = scored.len().min(inputs.thresholds.max_core_endpoints);
            let (head, tail) = scored.split_at(split);
            (head.to_vec(), tail.to_vec())
        };

    note_truncation(
        meta,
        "high-relevance endpoints",
        core_source.len(),
        inputs.thresholds.max_core_endpoints,
    );
    note_truncation(
        meta,
        "other endpoints",
        other_source.len(),
        inputs.thresholds.max_other_endpoints,
    );

    let core = core_source
        .into_iter()
        .take(inputs.thresholds.max_core_endpoints)
        .map(|row| endpoint_row(row, inputs.thresholds, handles, reported))
        .collect();
    let other = other_source
        .into_iter()
        .take(inputs.thresholds.max_other_endpoints)
        .map(|row| endpoint_row(row, inputs.thresholds, handles, reported))
        .collect();

    (core, other)
}

fn endpoint_row(
    row: Ranked<'_>,
    thresholds: &Thresholds,
    handles: &BTreeMap<String, BTreeSet<String>>,
    reported: &BTreeSet<String>,
) -> EndpointRow {
    let stats = row.stats;
    let key = stats.endpoint.key();

    // Aggregate under a shape-normalized template so that, e.g.,
    // `/users/812699/email` and `/users/812700/email` collapse to
    // `/users/{id}/email` rather than splitting into separate endpoints.
    let normalized_key = normalize_endpoint_key(&key);

    EndpointRow {
        hits: stats.hits(),
        repeated_writes: stats.repeated_writes,
        statuses: stats.status_summary(),
        relevance: row.relevance,
        reasons: row.reasons(thresholds),
        query_params: top_names(&stats.query_params),
        request_fields: top_names(&stats.request_fields),
        response_fields: top_names(&stats.response_fields),
        value_handles: handles
            .get(&key)
            .map(|set| {
                set.iter()
                    .filter(|handle| reported.contains(*handle))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default(),
        endpoint: normalized_key,
        why_tags: generate_why_tags(&stats.endpoint, row.deliberate > 0.0, row.locality > 0.0),
    }
}

/// Generate evidence-based why tags from endpoint characteristics.
/// Rules are shape-based only - no hardcoded product-specific names.
fn generate_why_tags(endpoint: &Endpoint, is_deliberate_write: bool, has_local_evidence: bool) -> Vec<WhyTag> {
    let mut tags = Vec::new();
    
    // Check for auth patterns using shape-based criteria only
    // Look for common auth-related path segments (shape-based word detection)
    let path_lower = endpoint.template.to_lowercase();
    let auth_segments = ["login", "auth", "token", "session", "code", "signin", "signup", "verify", "password", "credential"];
    let has_auth_segment = auth_segments.iter().any(|seg| path_lower.contains(seg));
    
    // Strong auth signal: state-changing method + auth segment
    if endpoint.is_state_changing() && has_auth_segment {
        tags.push(WhyTag::Auth);
    }
    
    // Check for admin patterns using shape-based criteria
    let admin_segments = ["panel", "admin", "internal", "manage", "config", "settings", "system"];
    let segments: Vec<&str> = endpoint.template.split('/').filter(|s| !s.is_empty()).collect();
    let has_admin_segment = admin_segments.iter().any(|seg| 
        segments.iter().any(|s| s.to_lowercase() == *seg)
    );
    
    // Strong admin signal: admin segment + any method
    if has_admin_segment {
        tags.push(WhyTag::Admin);
    }
    
    // Method-based tags
    if endpoint.is_state_changing() {
        if is_deliberate_write {
            tags.push(WhyTag::ObjectWrite);
        }
    } else if endpoint.addresses_an_instance() {
        tags.push(WhyTag::ObjectRead);
    }
    
    // Local identity evidence - only when not already better classified
    // Reduced dominance: only apply when we have local evidence but no specific tags
    if has_local_evidence && tags.is_empty() {
        tags.push(WhyTag::LocalIdentity);
    }
    
    tags
}

/// Field names ordered by how often they were seen, then alphabetically.
/// Returns all field names to avoid losing information for analysis.
fn top_names(counts: &BTreeMap<String, usize>) -> Vec<String> {
    let mut names: Vec<(&String, &usize)> = counts.iter().collect();
    names.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    names
        .into_iter()
        .map(|(name, _)| name.clone())
        .collect()
}

/// How much attention an endpoint earned from what was observed of it.
///
/// Every term rewards evidence the capture supplied: values mined from it, a
/// chain passing through it, the breadth of its fields, whether HTTP calls its
/// method state-changing, and how many different outcomes it produced.
///
/// The first two terms are graded rather than boolean, and grading them is what
/// separates a route that handles identifiers from one that merely carried the
/// session. Under the old rule any endpoint touched by any mined value took the
/// full value weight, so a single ubiquitous cookie handed 0.40 — and through
/// its chain another 0.25 — to every authenticated route in the capture,
/// including static assets. See [`Tally::credit`] for what replaced it.
fn earned_relevance(stats: &EndpointStats, evidence: &BTreeMap<String, ValueEvidence>) -> f64 {
    let normalized_key = normalize_endpoint_key(&stats.endpoint.key());
    let here = evidence.get(&normalized_key).copied().unwrap_or_default();

    let value_term = here.values.credit();
    let chain_term = here.chains.credit();
    let field_count = stats.request_fields.len() + stats.response_fields.len();
    let field_term = stats::normalize(field_count as f64, FIELD_CEILING);
    let method_term = if stats.endpoint.is_state_changing() {
        1.0
    } else {
        0.0
    };
    let status_term = stats::normalize(
        stats.statuses.len().saturating_sub(1) as f64,
        STATUS_CEILING,
    );

    value_term * W_VALUES
        + chain_term * W_CHAIN
        + field_term * W_FIELDS
        + method_term * W_METHOD
        + status_term * W_STATUS
}

/// Raise a score by `share` of the headroom it has left, in proportion to
/// `target`.
///
/// Expressed as headroom rather than as another weighted term for two reasons.
/// It can only ever raise a score, so adding the rule cannot silently demote
/// anything that was already being reported. And its effect is largest exactly
/// where the earned terms are smallest, which is where the endpoints this exists
/// for always sit: one hit, one status, and whatever fields a single request
/// carried.
fn lifted(base: f64, target: f64, share: f64) -> f64 {
    base + (1.0 - base) * share * target
}

/// How strongly an endpoint reads as a deliberate write to one named object.
///
/// Three observations have to line up. The method is one HTTP defines as
/// changing state, so the request did something rather than reported something.
/// The route addresses an instance, so what it did, it did to one object rather
/// than to a collection. And it is rare, which is what separates an action a
/// human performed from one a client repeats on a timer.
///
/// Nothing here inspects the path beyond its shape. An endpoint that mutates one
/// object, once, is worth reading whatever the operation happens to be called.
fn deliberate_write(stats: &EndpointStats, thresholds: &Thresholds) -> f64 {
    if !stats.endpoint.is_state_changing() || !stats.endpoint.addresses_an_instance() {
        return 0.0;
    }
    rarity(stats.calls(), thresholds)
}

/// How rare an endpoint is, as `1.0` at a single call falling to `0.0` at
/// [`Thresholds::rare_endpoint_hits_ceiling`].
///
/// Counted over calls rather than retained transactions on purpose. Filtering
/// samples a repetitive endpoint down to a handful of examples, and reading
/// rarity off what survived would let the noise filter manufacture the very
/// signal this rule looks for.
fn rarity(calls: usize, thresholds: &Thresholds) -> f64 {
    let ceiling = thresholds.rare_endpoint_hits_ceiling;
    let headroom = ceiling.saturating_sub(1);
    if headroom == 0 {
        // A ceiling of one leaves no scale: an endpoint is either seen once or
        // it is not rare at all.
        return if calls <= 1 { 1.0 } else { 0.0 };
    }
    ceiling.saturating_sub(calls.max(1)) as f64 / headroom as f64
}

/// Sequences, keeping only those still anchored to a reported value.
/// Prefers higher-support and more-strongly-linked sequences when limiting.
fn build_sequence_rows(
    inputs: &Inputs<'_>,
    reported: &BTreeSet<String>,
    meta: &mut Meta,
) -> Vec<SequenceRow> {
    let sequences: &[Sequence] = &inputs.relationships.sequences;

    let mut anchored: Vec<SequenceRow> = sequences
        .iter()
        .filter_map(|sequence| {
            let linked_handles: Vec<String> = sequence
                .handles
                .iter()
                .filter(|handle| reported.contains(*handle))
                .cloned()
                .collect();
            (!linked_handles.is_empty()).then(|| SequenceRow {
                steps: sequence.steps.clone(),
                support: sequence.support,
                linked_handles,
            })
        })
        .collect();

    // Sort by support (descending), then by number of linked handles (descending)
    // This ensures we keep the most significant sequences when truncating
    anchored.sort_by(|a, b| {
        b.support
            .cmp(&a.support)
            .then_with(|| b.linked_handles.len().cmp(&a.linked_handles.len()))
    });

    note_truncation(
        meta,
        "sequences",
        anchored.len(),
        inputs.thresholds.max_sequences,
    );

    anchored
        .into_iter()
        .take(inputs.thresholds.max_sequences)
        .collect()
}

fn build_state_rows(inputs: &Inputs<'_>, meta: &mut Meta) -> Vec<StateRow> {
    note_truncation(
        meta,
        "state indicators",
        inputs.indicators.len(),
        inputs.thresholds.max_state_indicators,
    );

    inputs
        .indicators
        .iter()
        .take(inputs.thresholds.max_state_indicators)
        .map(|indicator| StateRow {
            endpoint: indicator.endpoint.clone(),
            field: indicator.field.clone(),
            values: indicator.values.clone(),
            coverage: indicator.coverage,
        })
        .collect()
}

/// Tally, per endpoint, the mined values and chains observed there, keeping
/// local evidence apart from the capture-wide kind.
///
/// The split is [`provenance::is_ubiquitous`] over the spread mining recorded on
/// each value, so this stage inherits one definition of session furniture rather
/// than inventing a second.
///
/// This now normalizes endpoint keys by shape to ensure that paths like
/// `/users/812699/email` and `/users/812700/email` are aggregated under the
/// same template `/users/{id}/email`.
fn value_evidence(
    values: &[StrongValue],
    chains: &[Chain],
    thresholds: &Thresholds,
) -> BTreeMap<String, ValueEvidence> {
    let mut evidence: BTreeMap<String, ValueEvidence> = BTreeMap::new();
    let is_local = |value: &StrongValue| !provenance::is_ubiquitous(value.spread, thresholds);

    for value in values {
        for endpoint in &value.endpoints {
            if endpoint == UNMAPPED_ENDPOINT {
                continue;
            }
            // Normalize endpoint key by shape for aggregation
            let normalized_key = normalize_endpoint_key(endpoint);
            evidence
                .entry(normalized_key)
                .or_default()
                .values
                .add(is_local(value));
        }
    }

    for chain in chains {
        let Some(value) = values.get(chain.value_index) else {
            continue;
        };
        // Once per endpoint per chain: a credential revisiting the same route
        // forty times is one fact about that route, not forty.
        let visited: BTreeSet<&str> = chain
            .hops
            .iter()
            .map(|hop| hop.endpoint.as_str())
            .filter(|endpoint| *endpoint != UNMAPPED_ENDPOINT)
            .collect();
        for endpoint in visited {
            // Normalize endpoint key by shape for aggregation
            let normalized_key = normalize_endpoint_key(endpoint);
            evidence
                .entry(normalized_key)
                .or_default()
                .chains
                .add(is_local(value));
        }
    }

    evidence
}

fn handles_by_endpoint(
    values: &[StrongValue],
    chains: &[Chain],
) -> BTreeMap<String, BTreeSet<String>> {
    let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for value in values {
        for endpoint in &value.endpoints {
            let normalized_key = normalize_endpoint_key(endpoint);
            map.entry(normalized_key)
                .or_default()
                .insert(value.handle());
        }
    }
    for chain in chains {
        if let Some(value) = values.get(chain.value_index) {
            for hop in &chain.hops {
                let normalized_key = normalize_endpoint_key(&hop.endpoint);
                map.entry(normalized_key)
                    .or_default()
                    .insert(value.handle());
            }
        }
    }
    map
}

fn note_truncation(meta: &mut Meta, label: &str, available: usize, limit: usize) {
    if available > limit {
        meta.truncations.push(format!(
            "{label}: showing {limit} of {available} (limited by --mode {})",
            meta.mode.map(|m| m.as_str()).unwrap_or("standard")
        ));
    }
}

/// Tell the reader plainly when the report is thin and why.
fn add_quality_warnings(model: &mut ReportModel, inputs: &Inputs<'_>) {
    if inputs.thresholds.relaxed_for_small_dump {
        model.meta.warnings.push(format!(
            "Small dump ({} transactions): thresholds were relaxed, so signal is less reliable \
             than usual.",
            inputs.transactions.len()
        ));
    }
    if model.overview.kept_transactions == 0 {
        model.meta.warnings.push(
            "Every transaction was filtered as noise. The report below is empty by construction, \
             not by failure."
                .to_string(),
        );
    }
    if model.strong_values.is_empty() {
        model.meta.warnings.push(
            "No Strong Values met the quality bar. Core Signal therefore rests on endpoint \
             relevance and observed writes alone; consider --mode peaceful."
                .to_string(),
        );
    }
    if model.chains.is_empty() && !model.strong_values.is_empty() {
        model.meta.warnings.push(
            "Strong Values were found but none propagated between transactions, so there are no \
             data-flow chains."
                .to_string(),
        );
    }
    if model.overview.raw_transactions > 0 && model.overview.retention_pct() < 5.0 {
        model.meta.warnings.push(format!(
            "Only {:.1}% of transactions survived filtering; consider --mode peaceful if the capture \
             was already clean.",
            model.overview.retention_pct()
        ));
    }
    if inputs.oversized_bodies > 0 {
        model.meta.warnings.push(format!(
            "{} request/response bodies exceeded the size limit and were discarded. Those \
             exchanges are still described in endpoint tables, but field lists are incomplete \
             (missing fields from the oversized bodies).",
            inputs.oversized_bodies
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;
    use crate::model::endpoint::Endpoint;
    use crate::model::http::HttpMessage;
    use crate::model::report::WhyTag;

    fn transaction(id: TxId, method: &str, path: &str) -> RawTransaction {
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

    fn table_of(entries: &[(TxId, &str, &str)]) -> EndpointTable {
        let mut table = EndpointTable::new();
        for (tx_id, method, template) in entries {
            let slot = table.slot_for(Endpoint::new(*method, *template));
            table.assign(*tx_id, slot);
            let stats = table.stats_mut(slot).expect("slot exists");
            stats.tx_ids.push(*tx_id);
            stats.observed += 1;
            *stats.statuses.entry(200).or_insert(0) += 1;
        }
        table
    }

    /// A mined value good enough to report, attributed to one endpoint.
    ///
    /// The secret is derived from the endpoint so that two helper values never
    /// share a fingerprint, which is what makes handle assertions meaningful.
    fn strong(endpoint: &str) -> StrongValue {
        let secret = format!(
            "token-0123456789abcdef-{}",
            endpoint.replace(['/', ' '], "-")
        );
        let mut value = StrongValue::new(secret, 0);
        value.score = 0.9;
        value.entropy = 3.9;
        value.occurrences = 2;
        value.endpoints.insert(endpoint.to_string());
        value
    }

    /// A mined value the capture carried almost everywhere: a session cookie,
    /// a bearer token, a CSRF header. Real, reported, and evidence about
    /// nothing in particular.
    fn ubiquitous(endpoints: &[&str]) -> StrongValue {
        let mut value = StrongValue::new("session-0123456789abcdef".to_string(), 0);
        value.score = 0.9;
        value.entropy = 3.9;
        value.occurrences = 40;
        value.coverage = 0.9;
        value.spread = 0.9;
        value.endpoints = endpoints.iter().map(|key| key.to_string()).collect();
        value
    }

    /// Owns everything [`Inputs`] borrows, so a case names only what it varies.
    ///
    /// [`Inputs`] is already a parameter object; wrapping it in a constructor
    /// that took one argument per stage would only restate it positionally.
    struct Capture {
        transactions: Vec<RawTransaction>,
        kept: Vec<TxId>,
        table: EndpointTable,
        values: Vec<StrongValue>,
        relationships: Relationships,
        filter: FilterOutcome,
        thresholds: Thresholds,
        oversized_bodies: usize,
    }

    impl Capture {
        /// The listed `(id, method, template)` transactions, all of which
        /// survived filtering, with nothing mined from them yet.
        fn of(entries: &[(TxId, &str, &str)]) -> Self {
            Capture {
                transactions: entries
                    .iter()
                    .map(|&(id, method, path)| transaction(id, method, path))
                    .collect(),
                kept: entries.iter().map(|&(id, _, _)| id).collect(),
                table: table_of(entries),
                values: Vec::new(),
                relationships: Relationships::default(),
                filter: FilterOutcome::default(),
                thresholds: Thresholds::for_mode(Mode::Standard),
                oversized_bodies: 0,
            }
        }

        fn mined(mut self, values: Vec<StrongValue>) -> Self {
            self.values = values;
            self
        }

        fn related(mut self, relationships: Relationships) -> Self {
            self.relationships = relationships;
            self
        }

        fn in_mode(mut self, mode: Mode) -> Self {
            self.thresholds = Thresholds::for_mode(mode);
            self
        }

        /// Cap the Strong Values that may be reported, to exercise truncation.
        fn reporting_at_most(mut self, values: usize) -> Self {
            self.thresholds.max_strong_values = values;
            self
        }

        /// Add transactions that filtering removed: present in the raw capture,
        /// absent from both `kept` and the endpoint table.
        fn dropped(mut self, reason: &str, count: usize) -> Self {
            let first = self.transactions.len();
            self.transactions
                .extend((0..count).map(|offset| transaction(first + offset, "GET", "/filtered")));
            self.filter
                .dropped_by_reason
                .insert(reason.to_string(), count);
            self
        }

        /// Bodies stage 1 threw away for being larger than the input limit.
        fn with_oversized_bodies(mut self, count: usize) -> Self {
            self.oversized_bodies = count;
            self
        }

        fn inputs(&self) -> Inputs<'_> {
            Inputs {
                source: "capture.xml",
                transactions: &self.transactions,
                kept: &self.kept,
                table: &self.table,
                values: &self.values,
                relationships: &self.relationships,
                indicators: &[],
                filter: &self.filter,
                thresholds: &self.thresholds,
                oversized_bodies: self.oversized_bodies,
            }
        }
    }

    #[test]
    fn separates_endpoints_that_hold_evidence_from_the_rest() {
        let capture = Capture::of(&[(0, "POST", "/login"), (1, "GET", "/assets/app")])
            .mined(vec![strong("POST /login")]);

        let model = aggregate(capture.inputs());

        assert_eq!(model.core_endpoints.len(), 1);
        assert_eq!(model.core_endpoints[0].endpoint, "POST /login");
        assert_eq!(model.other_endpoints.len(), 1);
        assert_eq!(model.overview.kept_transactions, 2);
        assert_eq!(model.overview.strong_values, 1);
    }

    /// The reason a row states and the judgement that placed it are one list,
    /// so a row can never be in Core for a reason the report does not give, nor
    /// give a reason that did not put it there.
    #[test]
    fn a_core_row_states_what_put_it_there() {
        let mined = aggregate(
            Capture::of(&[(0, "GET", "/api/orders/{id}"), (1, "GET", "/assets/app")])
                .mined(vec![strong("GET /api/orders/{id}")])
                .inputs(),
        );
        assert_eq!(
            mined.core_endpoints[0].reason_summary(),
            vec!["local identity"]
        );
        assert!(
            mined.other_endpoints[0].reasons.is_empty(),
            "an endpoint reaches Other precisely by having no reason"
        );

        let written = aggregate(Capture::of(&[(0, "PUT", "/api/users/{id}/email")]).inputs());
        assert_eq!(
            written.core_endpoints[0].reason_summary(),
            vec!["deliberate write"]
        );

        // Both criteria met: the row is in Core once, and says so twice.
        let both = aggregate(
            Capture::of(&[(0, "PUT", "/api/users/{id}/email")])
                .mined(vec![strong("PUT /api/users/{id}/email")])
                .inputs(),
        );
        assert_eq!(
            both.core_endpoints[0].reason_summary(),
            vec!["local identity", "deliberate write"]
        );
    }

    #[test]
    fn warns_and_falls_back_when_nothing_was_mined() {
        let capture = Capture::of(&[(0, "GET", "/a")]);

        let model = aggregate(capture.inputs());

        assert!(model.strong_values.is_empty());
        assert_eq!(model.core_endpoints.len(), 1);
        assert!(
            model.core_endpoints[0].reasons.is_empty(),
            "a row ranked into Core for want of anything better must not claim evidence"
        );
        assert!(model
            .meta
            .warnings
            .iter()
            .any(|w| w.contains("No Strong Values")));
    }

    #[test]
    fn records_truncation_when_limits_bite() {
        let paths: Vec<String> = (0..30).map(|i| format!("/api/e{i}")).collect();
        let entries: Vec<(TxId, &str, &str)> = paths
            .iter()
            .enumerate()
            .map(|(id, path)| (id, "GET", path.as_str()))
            .collect();
        let capture = Capture::of(&entries).in_mode(Mode::Apocalyptic);

        let model = aggregate(capture.inputs());

        assert!(model.core_endpoints.len() <= capture.thresholds.max_core_endpoints);
        assert!(!model.meta.truncations.is_empty());
    }

    #[test]
    fn a_chain_is_dropped_when_its_value_did_not_make_the_cut() {
        use crate::model::value::{Direction, ValueLocation};
        use crate::pipeline::relationships::Hop;

        // Two mined values, but the limit only allows the first to be reported.
        let values = vec![strong("POST /login"), strong("GET /me")];
        let relationships = Relationships {
            chains: vec![Chain {
                value_index: 1,
                hops: vec![
                    Hop {
                        tx_id: 0,
                        endpoint: "POST /login".into(),
                        direction: Direction::Response,
                        location: ValueLocation::BodyField("token".into()),
                    },
                    Hop {
                        tx_id: 1,
                        endpoint: "GET /me".into(),
                        direction: Direction::Request,
                        location: ValueLocation::Header("authorization".into()),
                    },
                ],
                elision: None,
                endpoints: 2,
                propagates: true,
                score: 1.2,
            }],
            sequences: vec![Sequence {
                steps: vec!["POST /login".into(), "GET /me".into()],
                support: 2,
                handles: vec![values[1].handle()],
                linking: vec![values[1].handle()],
            }],
        };
        let capture = Capture::of(&[(0, "POST", "/login"), (1, "GET", "/me")])
            .mined(values)
            .related(relationships)
            .reporting_at_most(1);

        let model = aggregate(capture.inputs());

        assert_eq!(model.strong_values.len(), 1);
        assert!(
            model.chains.is_empty(),
            "a chain must not survive its value being truncated away"
        );
        assert!(
            model.sequences.is_empty(),
            "a sequence loses its anchor when the value is not reported"
        );
        let dangling = model
            .core_endpoints
            .iter()
            .chain(model.other_endpoints.iter())
            .flat_map(|row| row.value_handles.iter())
            .any(|handle| *handle != model.strong_values[0].handle);
        assert!(!dangling, "endpoints referenced an unreported handle");
    }

    #[test]
    fn warns_when_filtering_removed_nearly_everything() {
        let capture =
            Capture::of(&[(0, "GET", "/api/poll")]).dropped("statistical: duplicate request", 99);

        let model = aggregate(capture.inputs());

        assert!(model
            .meta
            .warnings
            .iter()
            .any(|w| w.contains("survived filtering")));
        assert_eq!(model.meta.dropped_total(), 99);
    }

    /// A discarded body is not a discarded transaction, and the difference
    /// matters to a reader deciding whether a thin field list means the route
    /// carries little or that the tool declined to read it.
    #[test]
    fn warns_when_a_body_was_too_large_to_read() {
        let quiet = aggregate(Capture::of(&[(0, "GET", "/api/report")]).inputs());
        assert!(
            !quiet.meta.warnings.iter().any(|w| w.contains("size limit")),
            "an ordinary capture must not be told about a limit nothing hit"
        );

        let model = aggregate(
            Capture::of(&[(0, "GET", "/api/report")])
                .with_oversized_bodies(2)
                .inputs(),
        );
        assert!(model
            .meta
            .warnings
            .iter()
            .any(|w| w.contains("2 request/response bodies exceeded the size limit")));
    }

    /// Problem class this exists for: a write performed once against one object.
    /// It mines nothing, joins no chain and has no traffic behind it, so every
    /// ordinary term scores it near zero and it sank to the bottom of Other
    /// Endpoints — under the polling routes it should have been read instead of.
    #[test]
    fn a_write_to_one_object_reaches_core_even_at_a_single_hit() {
        let mut entries = vec![
            (0, "PUT", "/api/v3/users/{id}/email"),
            (1, "POST", "/api/v3/messages"),
        ];
        // Enough polling that the collection endpoint is the busy one.
        entries.extend((2..12).map(|id| (id, "GET", "/api/v3/feed")));

        let capture = Capture::of(&entries).mined(vec![strong("GET /api/v3/feed")]);
        let model = aggregate(capture.inputs());

        let core: Vec<&str> = model
            .core_endpoints
            .iter()
            .map(|row| row.endpoint.as_str())
            .collect();
        assert!(
            core.contains(&"PUT /api/v3/users/{id}/email"),
            "a rare write to an instance stayed out of Core Signal: {core:?}"
        );
        assert!(
            !core.contains(&"POST /api/v3/messages"),
            "a write to a collection was promoted on its method alone: {core:?}"
        );
    }

    /// The same operation, called constantly, is a background job rather than a
    /// deliberate act. Rarity is the whole difference between these two runs.
    #[test]
    fn the_same_write_repeated_stops_being_deliberate() {
        const ROUTE: &str = "/api/v3/users/{id}/email";

        let repeated: Vec<(TxId, &str, &str)> = (0..12).map(|id| (id, "PUT", ROUTE)).collect();
        let once = Capture::of(&[(0, "PUT", ROUTE)]);
        let often = Capture::of(&repeated);

        let relevance_of = |model: &ReportModel| {
            model
                .core_endpoints
                .iter()
                .chain(&model.other_endpoints)
                .find(|row| row.endpoint == format!("PUT {ROUTE}"))
                .expect("the endpoint is reported either way")
                .relevance
        };

        let rare = relevance_of(&aggregate(once.inputs()));
        let routine = relevance_of(&aggregate(often.inputs()));

        assert!(
            rare > routine,
            "a once-off write ({rare}) did not outrank the same route called twelve times \
             ({routine})"
        );
    }

    /// The lift spends headroom, so it can raise a score but never lower one.
    /// Without this, promoting rare writes would quietly demote the flows the
    /// report already got right.
    #[test]
    fn promoting_a_write_never_costs_another_endpoint_relevance() {
        let entries = vec![
            (0, "PUT", "/api/v3/users/{id}/email"),
            (1, "DELETE", "/api/v3/rooms/{id}"),
            (2, "POST", "/api/v3/sessions"),
            (3, "GET", "/api/v3/users/{id}"),
            (4, "GET", "/api/v3/feed"),
        ];
        let capture = Capture::of(&entries).mined(vec![strong("POST /api/v3/sessions")]);
        let table = &capture.table;

        let evidence = value_evidence(&capture.values, &[], &capture.thresholds);
        let model = aggregate(capture.inputs());

        for row in model.core_endpoints.iter().chain(&model.other_endpoints) {
            let stats = table
                .endpoints
                .iter()
                .find(|stats| stats.endpoint.key() == row.endpoint)
                .expect("every reported row came from the table");
            let earned = earned_relevance(stats, &evidence);
            assert!(
                row.relevance >= earned - f64::EPSILON,
                "{} lost relevance: {} < {earned}",
                row.endpoint,
                row.relevance
            );
            assert!(row.relevance <= 1.0, "{} exceeded 1.0", row.endpoint);
        }
    }

    /// A read is not an action, however rare, and a rare *read* of one object is
    /// the single most common thing in any capture.
    #[test]
    fn a_rare_read_of_one_object_is_not_promoted() {
        let capture = Capture::of(&[
            (0, "GET", "/api/v3/users/{id}"),
            (1, "POST", "/api/v3/sessions"),
        ])
        .mined(vec![strong("POST /api/v3/sessions")]);

        let model = aggregate(capture.inputs());

        assert_eq!(
            model
                .core_endpoints
                .iter()
                .map(|row| row.endpoint.as_str())
                .collect::<Vec<_>>(),
            vec!["POST /api/v3/sessions"]
        );
    }

    /// Problem class this exists for: a static asset with a large response and
    /// no business role held a High-Relevance slot, because the session cookie
    /// had been sent to it like it is sent to everything.
    #[test]
    fn a_credential_seen_everywhere_does_not_carry_an_endpoint_into_core() {
        const ASSET: &str = "GET /assets/emoji-data.json";
        const LOGIN: &str = "POST /api/v3/sessions";

        let capture = Capture::of(&[
            (0, "GET", "/assets/emoji-data.json"),
            (1, "POST", "/api/v3/sessions"),
        ])
        .mined(vec![ubiquitous(&[ASSET, LOGIN]), strong(LOGIN)]);

        let model = aggregate(capture.inputs());

        let core: Vec<&str> = model
            .core_endpoints
            .iter()
            .map(|row| row.endpoint.as_str())
            .collect();
        assert_eq!(
            core,
            vec![LOGIN],
            "an endpoint whose only evidence was the session reached Core Signal"
        );

        // The credential is not erased from the analysis, only from the claim
        // that it says something about the asset: the row still lists it.
        let asset = model
            .other_endpoints
            .iter()
            .find(|row| row.endpoint == ASSET)
            .expect("the asset is still reported, in Secondary Context");
        assert!(
            !asset.value_handles.is_empty(),
            "the asset lost its cross-reference to the credential it carried"
        );
    }

    /// The same endpoint, the same single mined value: only its reach differs.
    #[test]
    fn a_widespread_value_buys_less_relevance_than_a_local_one() {
        let entries = [(0, "GET", "/a"), (1, "GET", "/b")];
        let relevance_of = |values: Vec<StrongValue>| {
            let capture = Capture::of(&entries).mined(values);
            let model = aggregate(capture.inputs());
            model
                .core_endpoints
                .iter()
                .chain(&model.other_endpoints)
                .find(|row| row.endpoint == "GET /a")
                .expect("the endpoint is reported either way")
                .relevance
        };

        let local = relevance_of(vec![strong("GET /a")]);
        let global = relevance_of(vec![ubiquitous(&["GET /a", "GET /b"])]);

        assert!(
            global < local,
            "a capture-wide value ({global}) bought as much relevance as a local one ({local})"
        );
    }

    /// A ubiquitous credential revisits the same routes over and over. Counting
    /// each visit would let the longest chain in the capture decide which
    /// endpoints look important.
    #[test]
    fn revisiting_one_endpoint_does_not_accumulate_chain_evidence() {
        use crate::model::value::{Direction, ValueLocation};
        use crate::pipeline::relationships::Hop;

        const POLL: &str = "GET /api/v3/poll";
        const LOGIN: &str = "POST /api/v3/sessions";

        let mut entries: Vec<(TxId, &str, &str)> =
            (0..40).map(|id| (id, "GET", "/api/v3/poll")).collect();
        entries.push((40, "POST", "/api/v3/sessions"));

        let relationships = Relationships {
            chains: vec![Chain {
                value_index: 0,
                hops: (0..40)
                    .map(|tx_id| Hop {
                        tx_id,
                        endpoint: POLL.to_string(),
                        direction: Direction::Request,
                        location: ValueLocation::Cookie("sid".into()),
                    })
                    .collect(),
                elision: None,
                endpoints: 1,
                propagates: true,
                score: 1.4,
            }],
            sequences: Vec::new(),
        };

        // The login also holds a local identifier, so Core Signal is decided on
        // evidence rather than by the fallback that fires when nothing at all
        // qualifies.
        let capture = Capture::of(&entries)
            .mined(vec![ubiquitous(&[POLL, LOGIN]), strong(LOGIN)])
            .related(relationships);
        let model = aggregate(capture.inputs());

        let core: Vec<&str> = model
            .core_endpoints
            .iter()
            .map(|row| row.endpoint.as_str())
            .collect();
        assert_eq!(
            core,
            vec![LOGIN],
            "forty hops of one credential promoted a polling route into Core Signal"
        );
    }

    /// The invariant mechanism B rests on: session-only evidence has to sit
    /// below the Core bar, and one local identifier has to clear it, in every
    /// mode. Break either half and the bar stops meaning anything.
    #[test]
    fn session_only_evidence_falls_short_of_the_core_bar_in_every_mode() {
        for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
            let thresholds = Thresholds::for_mode(mode);

            let mut session = Tally::default();
            for _ in 0..5 {
                session.add(false);
            }
            assert!(
                session.credit() < thresholds.core_min_local_evidence,
                "{mode}: five capture-wide values ({}) cleared the Core bar ({})",
                session.credit(),
                thresholds.core_min_local_evidence
            );

            let mut identifier = Tally::default();
            identifier.add(true);
            assert!(
                identifier.credit() >= thresholds.core_min_local_evidence,
                "{mode}: one local identifier ({}) missed the Core bar ({})",
                identifier.credit(),
                thresholds.core_min_local_evidence
            );
        }
    }

    /// Rarity has to be a slope, not a cliff, or a mode threshold would only
    /// ever move one endpoint at a time.
    #[test]
    fn rarity_falls_off_smoothly_to_the_ceiling() {
        for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
            let thresholds = Thresholds::for_mode(mode);
            let ceiling = thresholds.rare_endpoint_hits_ceiling;

            assert_eq!(rarity(0, &thresholds), 1.0, "{mode}");
            assert_eq!(rarity(1, &thresholds), 1.0, "{mode}");
            assert_eq!(rarity(ceiling, &thresholds), 0.0, "{mode}");
            assert_eq!(rarity(ceiling + 100, &thresholds), 0.0, "{mode}");

            let mut previous = 1.0;
            for hits in 1..=ceiling {
                let now = rarity(hits, &thresholds);
                assert!(
                    (0.0..=1.0).contains(&now),
                    "{mode} rarity {now} out of range"
                );
                assert!(now <= previous, "{mode} rarity rose at {hits} hits");
                previous = now;
            }
        }

        // A ceiling of one leaves no room for a slope, and the ratio it would
        // otherwise compute divides by zero.
        let mut knife_edge = Thresholds::for_mode(Mode::Standard);
        knife_edge.rare_endpoint_hits_ceiling = 1;
        assert_eq!(rarity(1, &knife_edge), 1.0);
        assert_eq!(rarity(2, &knife_edge), 0.0);
    }

    /// Test that evidence-based why tags are generated correctly.
    #[test]
    fn why_tags_are_derived_from_endpoint_characteristics() {
        use crate::model::endpoint::Endpoint;
        
        // Auth pattern should generate auth tag
        let auth_endpoint = Endpoint::new("POST", "/api/auth/login");
        let auth_tags = generate_why_tags(&auth_endpoint, false, false);
        assert!(auth_tags.contains(&WhyTag::Auth));
        
        // Admin path should generate admin tag
        let admin_endpoint = Endpoint::new("GET", "/admin/panel/users");
        let admin_tags = generate_why_tags(&admin_endpoint, false, false);
        assert!(admin_tags.contains(&WhyTag::Admin));
        
        // Object read should generate object_read tag
        let read_endpoint = Endpoint::new("GET", "/api/users/{id}");
        let read_tags = generate_why_tags(&read_endpoint, false, false);
        assert!(read_tags.contains(&WhyTag::ObjectRead));
        
        // Deliberate write should generate object_write tag
        let write_endpoint = Endpoint::new("PUT", "/api/users/{id}/email");
        let write_tags = generate_why_tags(&write_endpoint, true, false);
        assert!(write_tags.contains(&WhyTag::ObjectWrite));
        
        // Local identity without other tags should generate local_identity tag
        let local_endpoint = Endpoint::new("GET", "/api/reports/daily");
        let local_tags = generate_why_tags(&local_endpoint, false, true);
        assert!(local_tags.contains(&WhyTag::LocalIdentity));
    }
}
