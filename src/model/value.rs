//! Observed values, where they were seen, and the promoted Strong Values.
//!
//! The full value is kept in memory so chains can be matched exactly, but it
//! is never rendered: [`StrongValue::masked`] is what reaches the report.

use std::collections::BTreeSet;

use super::endpoint::normalize_endpoint_key;
use super::transaction::TxId;
use crate::analysis::fingerprint;

/// Whether a value was observed travelling out or coming back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    Request,
    Response,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Request => "req",
            Direction::Response => "resp",
        }
    }
}

/// Where inside a message a value was found.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueLocation {
    /// Path segment at the given zero-based index.
    PathSegment(usize),
    QueryParam(String),
    Header(String),
    /// Cookie a request sent, from `Cookie`.
    Cookie(String),
    /// Cookie a response assigned, from `Set-Cookie`.
    ///
    /// Held apart from [`ValueLocation::Cookie`] because the two are different
    /// headers travelling in opposite directions. Collapsing them would hide
    /// the most common handover in any web application: the server issues a
    /// cookie and the client starts returning it.
    SetCookie(String),
    /// Dotted JSON path, e.g. `data.session.token`.
    BodyField(String),
}

impl ValueLocation {
    /// Compact, readable slot name for the report.
    ///
    /// A path sighting renders as the bare slot `path`: the segment index is a
    /// positional detail the reader cannot act on, and splicing the concrete
    /// segment back in is what produced the `path.{id}` artefact — a normalized
    /// route already shows `{id}` in the path itself. The index still matters
    /// upstream (it decides whether a position routes on data), so it is kept on
    /// the variant and only dropped here, at the point of display.
    pub fn label(&self) -> String {
        match self {
            ValueLocation::PathSegment(_) => "path".to_string(),
            ValueLocation::QueryParam(name) => format!("query.{name}"),
            ValueLocation::Header(name) => format!("header.{name}"),
            ValueLocation::Cookie(name) => format!("cookie.{name}"),
            ValueLocation::SetCookie(name) => format!("set-cookie.{name}"),
            ValueLocation::BodyField(path) => format!("body.{path}"),
        }
    }
}

/// The one rendering of "where a value was seen", shared by the Strong Values
/// locations column and the data-flow chain hops.
///
/// Both sections describe the same sightings, so both build their strings here:
/// the endpoint key is normalized once by shape, and the slot comes from
/// [`ValueLocation::label`]. Having a single function is what guarantees the
/// two sections can never drift into different spellings of the same location.
///
/// Form: `METHOD /normalized/path (dir slot)`, e.g.
/// `GET /api/v3/chats/{id}/memberships (req path)`.
pub fn render_location(endpoint_key: &str, direction: Direction, location: &ValueLocation) -> String {
    format!(
        "{} ({} {})",
        normalize_endpoint_key(endpoint_key),
        direction.as_str(),
        location.label()
    )
}

/// A single sighting of a value.
#[derive(Debug, Clone)]
pub struct ObservedValue {
    pub tx_id: TxId,
    pub direction: Direction,
    pub location: ValueLocation,
    pub value: String,
}

/// A value that survived quality mining.
#[derive(Debug, Clone)]
pub struct StrongValue {
    /// Full value. Never rendered; used for exact chain matching.
    full: String,
    /// Short stable identifier, safe to print and to cross-reference.
    pub fingerprint: String,
    pub occurrences: usize,
    pub entropy: f64,
    pub score: f64,
    pub seen_in_path: bool,
    /// True when a response emitted the value and a later request sent it back
    /// from a different slot.
    pub propagates: bool,
    /// Share of the capture's retained transactions the value appeared in.
    ///
    /// Near 1.0 marks a constant rather than an identifier: a value carried by
    /// every exchange distinguishes none of them.
    pub coverage: f64,
    /// How far the value reaches, over transactions and over routes together.
    ///
    /// [`Self::coverage`] alone under-reads a credential that rides half the
    /// exchanges but two thirds of the API, so mining records the composed
    /// figure and every later stage — endpoint relevance, sequence anchoring,
    /// chain rendering — asks this rather than re-deriving its own.
    pub spread: f64,
    pub endpoints: BTreeSet<String>,
    /// Every distinct location the value was seen at, pre-rendered by
    /// [`render_location`] and de-duplicated. The single source of truth for the
    /// Strong Values `locations` column; the chain hops render the same way, so
    /// the column always covers the hops. No cap — completeness is required.
    pub sightings: Vec<String>,
    pub first_seen: TxId,
}

impl StrongValue {
    pub fn new(full: String, first_seen: TxId) -> Self {
        let fingerprint = fingerprint::fingerprint(&full);
        Self {
            full,
            fingerprint,
            occurrences: 0,
            entropy: 0.0,
            score: 0.0,
            seen_in_path: false,
            propagates: false,
            coverage: 0.0,
            spread: 0.0,
            endpoints: BTreeSet::new(),
            sightings: Vec::new(),
            first_seen,
        }
    }

    /// Full value, for in-process use only: chain matching and length
    /// statistics. Never write the result to the report — use [`Self::masked`].
    pub fn full(&self) -> &str {
        &self.full
    }

    /// Redacted rendering: head and tail plus the fingerprint.
    pub fn masked(&self) -> String {
        fingerprint::mask(&self.full, &self.fingerprint)
    }

    /// Short handle used to reference this value from chains and sequences.
    pub fn handle(&self) -> String {
        format!("fp:{}", self.fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masked_output_hides_the_middle_of_the_value() {
        let value = StrongValue::new("eyJhbGciOiJIUzI1NiJ9.super.secret.9k4A".to_string(), 0);
        let masked = value.masked();
        assert!(!masked.contains("super.secret"));
        assert!(masked.contains(&value.fingerprint));
        assert!(value.full().contains("super.secret"));
    }

    #[test]
    fn location_labels_are_compact() {
        // A path sighting renders as the bare slot `path`: the index is a
        // positional detail the reader cannot use, and re-splicing the concrete
        // segment is what produced the old `path.{id}` / `path[N]` artefacts.
        assert_eq!(ValueLocation::PathSegment(2).label(), "path");
        assert_eq!(
            ValueLocation::BodyField("data.token".into()).label(),
            "body.data.token"
        );
    }

    #[test]
    fn a_location_renders_endpoint_slot_and_direction_together() {
        // The one shared rendering both the table and the chains use. The path
        // is normalized by shape, and the slot never leaks a segment index.
        let rendered = render_location(
            "GET /api/v3/users/3f2504e0-4f89-11d3-9a0c-0305e82c3301",
            Direction::Request,
            &ValueLocation::PathSegment(3),
        );
        assert_eq!(rendered, "GET /api/v3/users/{id} (req path)");
        assert!(!rendered.contains("path."));
        assert!(!rendered.contains('['));
    }

    #[test]
    fn a_sent_cookie_and_an_assigned_cookie_are_different_locations() {
        let sent = ValueLocation::Cookie("sid".into());
        let assigned = ValueLocation::SetCookie("sid".into());
        assert_ne!(sent, assigned);
        assert_eq!(assigned.label(), "set-cookie.sid");
    }
}
