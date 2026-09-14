//! Endpoint sequence detection.
//!
//! A window of consecutive calls is reported for one of two reasons, and the
//! distinction is what separates a flow from a record of what the browser
//! happened to load.
//!
//! It **repeated**: the same steps in the same order, often enough to clear
//! [`Thresholds::sequence_min_support`]. Repetition is the evidence, so the
//! window is collapsed to its longest form — one five-step flow rather than its
//! seven fragments.
//!
//! Or it is **linked**: one value that is *not* spread across the whole capture
//! was sighted at two or more of its steps. The link is the evidence, so the
//! window is collapsed to its tightest form and admitted on as little as a
//! single occurrence. Most real flows happen once.
//!
//! Anchors are local values only. A session cookie sent to two thirds of the
//! API anchors two thirds of all windows, which is anchoring that filters
//! nothing — and it was why this stage used to emit a handful of polling n-grams
//! and call them sequences.

use std::collections::{BTreeSet, HashMap};

use super::dataflow::Chain;
use crate::analysis::provenance;
use crate::config::Thresholds;
use crate::model::endpoint::EndpointTable;
use crate::model::transaction::TxId;
use crate::model::value::StrongValue;

/// A repeated, signal-anchored window of consecutive endpoint calls.
#[derive(Debug, Clone)]
pub struct Sequence {
    pub steps: Vec<String>,
    /// How many times this exact window occurred.
    pub support: usize,
    /// Handles of Strong Values anchoring it.
    pub handles: Vec<String>,
    /// Handles of values sighted at two or more of the steps.
    ///
    /// These are why the window is worth reading: the same identifier was seen
    /// at both ends of it, so the steps are related rather than merely adjacent.
    pub linking: Vec<String>,
}

/// Endpoints carrying local signal, mapped to the handles involved.
type Anchors = HashMap<String, BTreeSet<String>>;

/// A window under consideration, with the evidence found for it.
struct Candidate {
    steps: Vec<String>,
    support: usize,
    linking: Vec<String>,
}

impl Candidate {
    /// Repetitions this window needs to be worth reporting.
    ///
    /// A linked window needs fewer, because the shared value is already
    /// evidence that its steps belong together — evidence repetition can only
    /// approximate.
    fn required_support(&self, thresholds: &Thresholds) -> usize {
        if self.linking.is_empty() {
            thresholds.sequence_min_support
        } else {
            thresholds.sequence_linked_min_support
        }
    }
}

/// Find repeated or value-linked windows of consecutive endpoint calls.
pub fn build(
    kept: &[TxId],
    table: &EndpointTable,
    values: &[StrongValue],
    chains: &[Chain],
    thresholds: &Thresholds,
) -> Vec<Sequence> {
    let stream: Vec<String> = kept
        .iter()
        .filter_map(|tx_id| table.key_of_tx(*tx_id))
        .collect();
    if stream.len() < thresholds.sequence_min_len {
        return Vec::new();
    }

    let anchors = anchor_handles(values, chains, thresholds);
    if anchors.is_empty() {
        return Vec::new();
    }

    let mut windows: HashMap<Vec<String>, usize> = HashMap::new();
    let max_len = thresholds.sequence_max_len.min(stream.len());

    for length in thresholds.sequence_min_len..=max_len {
        for window in stream.windows(length) {
            if !is_anchored(window, &anchors) {
                continue;
            }
            *windows.entry(window.to_vec()).or_insert(0) += 1;
        }
    }

    let supported: Vec<Candidate> = windows
        .into_iter()
        .map(|(steps, support)| Candidate {
            linking: linking_handles(&steps, &anchors),
            steps,
            support,
        })
        .filter(|candidate| candidate.support >= candidate.required_support(thresholds))
        .collect();

    let mut sequences: Vec<Sequence> = supported
        .iter()
        .filter(|candidate| survives_collapse(candidate, &supported))
        .map(|candidate| Sequence {
            handles: handles_for(&candidate.steps, &anchors),
            steps: candidate.steps.clone(),
            support: candidate.support,
            linking: candidate.linking.clone(),
        })
        .collect();

    // Linked windows first: a shared identifier is stronger evidence than any
    // amount of repetition, and repetition is what a polling client produces
    // most of.
    sequences.sort_by(|a, b| {
        b.linking
            .len()
            .cmp(&a.linking.len())
            .then_with(|| b.support.cmp(&a.support))
            .then_with(|| b.steps.len().cmp(&a.steps.len()))
            .then_with(|| a.steps.cmp(&b.steps))
    });
    sequences
}

/// Endpoints that carry local signal, mapped to the value handles involved.
///
/// Ubiquitous values are skipped. They are still mined, still reported and
/// still chained; they simply cannot vouch for a window, because a value seen
/// nearly everywhere vouches for nearly everything.
fn anchor_handles(values: &[StrongValue], chains: &[Chain], thresholds: &Thresholds) -> Anchors {
    let mut anchors: Anchors = HashMap::new();

    let local = |value: &StrongValue| !provenance::is_ubiquitous(value.spread, thresholds);

    for value in values.iter().filter(|value| local(value)) {
        for endpoint in &value.endpoints {
            anchors
                .entry(endpoint.clone())
                .or_default()
                .insert(value.handle());
        }
    }
    for chain in chains {
        let Some(value) = values.get(chain.value_index).filter(|value| local(value)) else {
            continue;
        };
        for hop in &chain.hops {
            anchors
                .entry(hop.endpoint.clone())
                .or_default()
                .insert(value.handle());
        }
    }

    anchors
}

fn is_anchored(window: &[String], anchors: &Anchors) -> bool {
    window.iter().any(|step| anchors.contains_key(step))
}

fn handles_for(steps: &[String], anchors: &Anchors) -> Vec<String> {
    let mut handles: BTreeSet<String> = BTreeSet::new();
    for step in steps {
        if let Some(found) = anchors.get(step) {
            handles.extend(found.iter().cloned());
        }
    }
    handles.into_iter().collect()
}

/// Handles sighted at two or more *distinct* steps of the window.
///
/// Distinct steps, not distinct positions: a route that repeats inside a window
/// carries the same value to itself, which says nothing about how the window
/// hangs together.
fn linking_handles(steps: &[String], anchors: &Anchors) -> Vec<String> {
    let mut seen_at: HashMap<&str, usize> = HashMap::new();
    let distinct: BTreeSet<&String> = steps.iter().collect();
    for step in distinct {
        let Some(found) = anchors.get(step) else {
            continue;
        };
        for handle in found {
            *seen_at.entry(handle.as_str()).or_insert(0) += 1;
        }
    }

    let mut linking: Vec<String> = seen_at
        .into_iter()
        .filter(|(_, steps)| *steps >= 2)
        .map(|(handle, _)| handle.to_string())
        .collect();
    linking.sort();
    linking
}

/// Drop a window that is a contiguous part of a better-evidenced longer one, or
/// that contains a better-evidenced shorter one.
///
/// Repetition and linkage pull in opposite directions here, and deliberately so.
/// A window that repeats is collapsed *outwards*: the longest equally-repeated
/// form is the real flow, and its fragments are artefacts of counting. A window
/// held together by a shared value is collapsed *inwards*: the shortest form
/// that still carries the link is the actual hand-off, and padding it with
/// whatever the client happened to call next only dilutes it.
///
/// Each rule looks only at windows admitted on its own basis. Letting them cross
/// would make the outcome depend on candidates that the other rule is about to
/// discard, and a repeated window could vanish behind a longer one that is
/// itself never reported.
fn survives_collapse(candidate: &Candidate, all: &[Candidate]) -> bool {
    let linked = !candidate.linking.is_empty();
    !all.iter().any(|other| {
        if linked != !other.linking.is_empty() {
            return false;
        }
        if linked {
            other.steps.len() < candidate.steps.len()
                && contains_window(&candidate.steps, &other.steps)
        } else {
            other.steps.len() > candidate.steps.len()
                && other.support >= candidate.support
                && contains_window(&other.steps, &candidate.steps)
        }
    })
}

fn contains_window(haystack: &[String], needle: &[String]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;
    use crate::model::endpoint::Endpoint;

    fn table(entries: &[(TxId, &str)]) -> EndpointTable {
        let mut table = EndpointTable::new();
        for (tx_id, key) in entries {
            let slot = table.slot_for(Endpoint::new("GET", *key));
            table.assign(*tx_id, slot);
        }
        table
    }

    fn value_on(endpoints: &[&str]) -> StrongValue {
        named_value_on("token-value-abcdef123456", endpoints)
    }

    /// A local value with a distinct secret, so two helpers never collide on
    /// one fingerprint.
    fn named_value_on(secret: &str, endpoints: &[&str]) -> StrongValue {
        let mut value = StrongValue::new(secret.to_string(), 0);
        value.score = 0.8;
        for endpoint in endpoints {
            value.endpoints.insert((*endpoint).to_string());
        }
        value
    }

    /// The same value, but carried by so much of the capture that it identifies
    /// nothing: a session cookie or bearer token.
    fn everywhere_on(endpoints: &[&str]) -> StrongValue {
        let mut value = value_on(endpoints);
        value.coverage = 0.95;
        value.spread = 0.95;
        value
    }

    #[test]
    fn reports_a_repeated_anchored_window() {
        let table = table(&[(0, "/login"), (1, "/me"), (2, "/login"), (3, "/me")]);
        let kept = vec![0, 1, 2, 3];
        let values = vec![value_on(&["GET /login"])];

        let sequences = build(
            &kept,
            &table,
            &values,
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );

        assert_eq!(sequences.len(), 1);
        assert_eq!(sequences[0].steps, vec!["GET /login", "GET /me"]);
        assert_eq!(sequences[0].support, 2);
        assert!(!sequences[0].handles.is_empty());
    }

    #[test]
    fn returns_nothing_without_an_anchor() {
        let table = table(&[(0, "/a"), (1, "/b"), (2, "/a"), (3, "/b")]);
        let sequences = build(
            &[0, 1, 2, 3],
            &table,
            &[],
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );
        assert!(sequences.is_empty());
    }

    #[test]
    fn keeps_only_the_maximal_window() {
        let table = table(&[
            (0, "/login"),
            (1, "/me"),
            (2, "/orders"),
            (3, "/login"),
            (4, "/me"),
            (5, "/orders"),
        ]);
        let values = vec![value_on(&["GET /login"])];

        let sequences = build(
            &[0, 1, 2, 3, 4, 5],
            &table,
            &values,
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );

        assert_eq!(sequences.len(), 1);
        assert_eq!(
            sequences[0].steps,
            vec!["GET /login", "GET /me", "GET /orders"]
        );
    }

    #[test]
    fn ignores_windows_seen_only_once() {
        let table = table(&[(0, "/login"), (1, "/me"), (2, "/orders")]);
        let values = vec![value_on(&["GET /login"])];
        let sequences = build(
            &[0, 1, 2],
            &table,
            &values,
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );
        assert!(sequences.is_empty());
    }

    /// Problem class this exists for: most real flows happen once. Demanding
    /// repetition meant the report showed polling loops and missed the
    /// hand-offs, which is the opposite of useful.
    #[test]
    fn one_value_seen_at_two_steps_earns_a_sequence_on_a_single_pass() {
        let table = table(&[(0, "/orders"), (1, "/orders/{id}/pay"), (2, "/receipts")]);
        let values = vec![value_on(&["GET /orders", "GET /orders/{id}/pay"])];

        let sequences = build(
            &[0, 1, 2],
            &table,
            &values,
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );

        let linked = sequences
            .iter()
            .find(|sequence| !sequence.linking.is_empty())
            .expect("a value crossing two steps is a sequence even seen once");
        assert_eq!(
            linked.steps,
            vec!["GET /orders", "GET /orders/{id}/pay"],
            "the link was padded with a step it says nothing about"
        );
        assert_eq!(linked.support, 1);
        assert_eq!(linked.linking, vec![values[0].handle()]);
    }

    /// A session cookie reaches most of the API, so letting it anchor windows
    /// anchors nearly all of them — which is filtering that filters nothing.
    #[test]
    fn a_capture_wide_credential_anchors_nothing() {
        let table = table(&[(0, "/a"), (1, "/b"), (2, "/a"), (3, "/b")]);
        let thresholds = Thresholds::for_mode(Mode::Standard);

        let session = build(
            &[0, 1, 2, 3],
            &table,
            &[everywhere_on(&["GET /a", "GET /b"])],
            &[],
            &thresholds,
        );
        assert!(
            session.is_empty(),
            "a capture-wide credential anchored a window on its own: {session:?}"
        );

        // The identical traffic, anchored by a value local to it, still works.
        let local = build(
            &[0, 1, 2, 3],
            &table,
            &[value_on(&["GET /a", "GET /b"])],
            &[],
            &thresholds,
        );
        assert!(!local.is_empty(), "a local value stopped anchoring windows");
    }

    /// Repetition collapses outward to the longest flow; a shared value
    /// collapses inward to the tightest hand-off. Both directions in one
    /// stream, so neither rule can quietly swallow the other.
    #[test]
    fn repetition_collapses_outward_and_a_link_collapses_inward() {
        let table = table(&[
            (0, "/login"),
            (1, "/me"),
            (2, "/feed"),
            (3, "/login"),
            (4, "/me"),
            (5, "/feed"),
        ]);
        // One value repeats across /login and /me; another sits only on /feed,
        // so the three-step window repeats but is not linked end to end.
        let values = vec![
            named_value_on("token-value-abcdef123456", &["GET /login", "GET /me"]),
            named_value_on("other-value-987654fedcba", &["GET /feed"]),
        ];

        let sequences = build(
            &[0, 1, 2, 3, 4, 5],
            &table,
            &values,
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );

        let steps: Vec<&[String]> = sequences.iter().map(|s| s.steps.as_slice()).collect();
        assert!(
            steps.iter().any(|s| *s == ["GET /login", "GET /me"]),
            "the linked hand-off was lost: {steps:?}"
        );
        assert!(
            !steps
                .iter()
                .any(|s| *s == ["GET /login", "GET /me", "GET /feed"]),
            "a linked window was padded with an unrelated step: {steps:?}"
        );
    }

    /// Linked windows are what the reader came for; repeated ones are context.
    #[test]
    fn linked_sequences_are_reported_before_merely_repeated_ones() {
        let table = table(&[
            (0, "/poll"),
            (1, "/status"),
            (2, "/poll"),
            (3, "/status"),
            (4, "/poll"),
            (5, "/status"),
            (6, "/checkout"),
            (7, "/pay"),
        ]);
        let values = vec![
            named_value_on("poll-value-abcdef123456", &["GET /poll"]),
            named_value_on("cart-value-987654fedcba", &["GET /checkout", "GET /pay"]),
        ];

        let sequences = build(
            &(0..8).collect::<Vec<_>>(),
            &table,
            &values,
            &[],
            &Thresholds::for_mode(Mode::Standard),
        );

        let first = sequences.first().expect("both windows qualify");
        assert_eq!(
            first.steps,
            vec!["GET /checkout", "GET /pay"],
            "a thrice-repeated polling loop outranked a real hand-off: {:?}",
            sequences.iter().map(|s| &s.steps).collect::<Vec<_>>()
        );
    }

    /// Apocalyptic mode may only ever tighten. If a linked window could clear a
    /// bar there that it misses under Standard, the modes would not be ordered.
    #[test]
    fn the_linked_allowance_never_loosens_with_the_mode() {
        for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
            let thresholds = Thresholds::for_mode(mode);
            assert!(
                thresholds.sequence_linked_min_support <= thresholds.sequence_min_support,
                "{mode}: a linked window needs more repetition than an unlinked one"
            );
            assert!(
                thresholds.sequence_linked_min_support >= 1,
                "{mode}: a window would qualify without occurring"
            );
        }
    }
}
