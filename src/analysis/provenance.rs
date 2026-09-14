//! The value-source policy, shared by mining and data-flow.
//!
//! This module is the single place that decides what a value's *origin* means:
//! where a value was seen determines how far it may be trusted. The rules are
//! deliberately name-free — nothing here knows or cares what an application
//! calls its fields. It knows only HTTP structure and statistics.
//!
//! The centrepiece is a split between **application** slots (path, query, body,
//! cookies) and the **transport** envelope (plain headers). A header is
//! protocol scaffolding: `Host`, `Content-Type`, `Cache-Control`,
//! `Referrer-Policy` and their dozens of cousins repeat in every exchange, say
//! nothing about the application, and must not be allowed to pass as business
//! identifiers. Header-borne values are admitted only through a strict gate.

use std::collections::{BTreeMap, BTreeSet};

use super::entropy;
use crate::config::Thresholds;
use crate::model::endpoint::UNMAPPED_ENDPOINT;
use crate::model::transaction::TxId;
use crate::model::value::{Direction, ObservedValue, ValueLocation};

/// Whether a value's origin is application data or transport scaffolding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceClass {
    Application,
    Transport,
}

/// Classify a slot for the shared source rules.
pub fn source_class(location: &ValueLocation) -> SourceClass {
    match location {
        ValueLocation::Header(_) => SourceClass::Transport,
        ValueLocation::PathSegment(_)
        | ValueLocation::QueryParam(_)
        | ValueLocation::Cookie(_)
        | ValueLocation::SetCookie(_)
        | ValueLocation::BodyField(_) => SourceClass::Application,
    }
}

/// How strongly a sighting in this slot anchors a value as application data.
///
/// A path segment is definitive: if the server routes on it, it identifies
/// something. A body field is nearly as good. A query parameter or a cookie is
/// application state too, but weaker, since either also carries generic
/// plumbing. A plain header, on its own, earns nothing.
fn anchor(location: &ValueLocation) -> f64 {
    match location {
        ValueLocation::PathSegment(_) => 1.0,
        ValueLocation::BodyField(_) => 0.9,
        ValueLocation::QueryParam(_) => 0.75,
        ValueLocation::Cookie(_) | ValueLocation::SetCookie(_) => 0.75,
        ValueLocation::Header(_) => 0.0,
    }
}

/// What a value looks like, independent of where it was seen.
#[derive(Debug, Clone, Copy)]
pub struct ValueShape {
    pub len: usize,
    pub entropy: f64,
    /// How much the character makeup resembles an identifier, `0.0..=1.0`.
    pub identifier_weight: f64,
}

impl ValueShape {
    pub fn of(value: &str) -> Self {
        Self {
            len: value.chars().count(),
            entropy: entropy::shannon_bits_str(value),
            identifier_weight: entropy::classify(value).identifier_weight(),
        }
    }
}

/// One sighting, reduced to what the source policy actually judges.
///
/// Mining feeds this from raw observations and data-flow feeds it from the hops
/// of a trail. Borrowing the location keeps both callers allocation-free and,
/// more importantly, keeps this module ignorant of either stage's own types.
#[derive(Debug, Clone, Copy)]
pub struct Sighting<'a> {
    pub tx_id: TxId,
    pub direction: Direction,
    pub location: &'a ValueLocation,
}

impl<'a> From<&'a ObservedValue> for Sighting<'a> {
    fn from(observation: &'a ObservedValue) -> Self {
        Self {
            tx_id: observation.tx_id,
            direction: observation.direction,
            location: &observation.location,
        }
    }
}

/// What a value's provenance says about it.
///
/// Accumulated in one pass by both mining (from raw sightings) and data-flow
/// (from the hops of a trail). The stronger the anchoring, and the more
/// genuinely the value crossed from a response into a later request, the more
/// it looks like live application state rather than protocol furniture.
#[derive(Debug, Clone, Default)]
pub struct Provenance {
    /// The best slot type the value was seen in.
    anchor: f64,
    /// Set once the value was seen in an application slot.
    has_application: bool,
    /// Earliest response transaction per slot.
    response_firsts: BTreeMap<ValueLocation, TxId>,
    /// Latest request transaction per slot.
    request_lasts: BTreeMap<ValueLocation, TxId>,
    /// Distinct transactions the value appeared in.
    transactions: BTreeSet<TxId>,
}

impl Provenance {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accumulate the provenance of a group of sightings.
    pub fn of<'a>(sightings: impl IntoIterator<Item = Sighting<'a>>) -> Self {
        let mut provenance = Self::new();
        for sighting in sightings {
            provenance.observe(sighting);
        }
        provenance
    }

    /// Record one sighting.
    pub fn observe(&mut self, sighting: Sighting<'_>) {
        let slot = sighting.location;
        self.anchor = self.anchor.max(anchor(slot));
        if source_class(slot) == SourceClass::Application {
            self.has_application = true;
        }
        self.transactions.insert(sighting.tx_id);

        let (extremes, keep): (&mut BTreeMap<ValueLocation, TxId>, fn(TxId, TxId) -> TxId) =
            match sighting.direction {
                Direction::Response => (&mut self.response_firsts, TxId::min),
                Direction::Request => (&mut self.request_lasts, TxId::max),
            };
        let entry = extremes.entry(slot.clone()).or_insert(sighting.tx_id);
        *entry = keep(*entry, sighting.tx_id);
    }

    /// The strongest slot type the value was seen in, `0.0..=1.0`.
    pub fn anchoring(&self) -> f64 {
        self.anchor
    }

    /// True when every sighting was inside a plain header.
    pub fn is_transport_only(&self) -> bool {
        !self.has_application
    }

    /// Whether a response emitted the value and a later request sent it back.
    ///
    /// Comparing only the extremes of each slot is exact: if any ordered
    /// qualifying pair exists, then the earliest response and the latest
    /// request of those slots already form one.
    pub fn has_handover(&self) -> bool {
        self.request_lasts.iter().any(|(request_slot, request_tx)| {
            self.response_firsts
                .iter()
                .any(|(response_slot, response_tx)| {
                    request_tx > response_tx && crossed(response_slot, request_slot)
                })
        })
    }

    /// Whether the value was ever used to address a request.
    ///
    /// A path segment or a query parameter is the client saying *which* thing it
    /// wants. Only a reusable handle can play that part, so a value seen there
    /// has demonstrated it is one — which is exactly what a catalogue string
    /// returned inside a body never does, however often it is returned.
    pub fn addresses_a_request(&self) -> bool {
        self.slots().any(|slot| {
            matches!(
                slot,
                ValueLocation::PathSegment(_) | ValueLocation::QueryParam(_)
            )
        })
    }

    /// Distinct transactions the value appeared in.
    pub fn sighted_transactions(&self) -> usize {
        self.transactions.len()
    }

    /// Every slot the value was ever seen in, in either direction.
    fn slots(&self) -> impl Iterator<Item = &ValueLocation> {
        self.response_firsts.keys().chain(self.request_lasts.keys())
    }
}

/// Whether an ordered response-to-request pair is a handover rather than a
/// protocol echo.
///
/// Inside the transport envelope the slot must change. A header sent back under
/// the name it arrived in — `content-type`, `te`, a cached `etag` — is HTTP
/// doing its job, not the application handing data over.
///
/// Application slots carry no such rule, because there the stable name is the
/// evidence. A server that answers with `challenge_id` and a client that posts
/// `challenge_id` back is the canonical flow, and demanding it change slots
/// would reject precisely the propagation worth reporting.
fn crossed(response_slot: &ValueLocation, request_slot: &ValueLocation) -> bool {
    response_slot != request_slot || source_class(request_slot) == SourceClass::Application
}

/// Share of the capture's mapped endpoints a value was seen at, `0.0..=1.0`.
///
/// The unmapped bucket is not an endpoint and is excluded from both sides, so a
/// value seen only there scores zero rather than dividing by a phantom route.
pub fn endpoint_share(endpoints: &BTreeSet<String>, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let mapped = endpoints
        .iter()
        .filter(|key| *key != UNMAPPED_ENDPOINT)
        .count();
    (mapped as f64 / total as f64).min(1.0)
}

/// How far a value is spread, as the stronger of its two independent evidences.
///
/// A value can be everywhere in two different senses, and either one alone is
/// enough to stop it distinguishing anything. It can ride most of the
/// *transactions*, which is what coverage measures; or it can appear at most of
/// the *routes*, which is what endpoint share measures. The two come apart in
/// practice, and taking the maximum is what stops one hiding behind the other.
///
/// This is not hypothetical. The session cookie that dominated the reference
/// capture sat at 52.5% coverage — comfortably under every mode's onset, so it
/// was damped by exactly nothing — while touching 41 of 59 endpoints, 69% of the
/// API. Measured on coverage alone it looked like an ordinary identifier;
/// measured on either evidence it is plainly a constant.
pub fn ubiquity(coverage: f64, endpoint_share: f64) -> f64 {
    coverage.max(endpoint_share)
}

/// Whether a spread is wide enough that the value stopped identifying anything.
///
/// The single definition of "ubiquitous" in the codebase, taking the figure
/// [`ubiquity`] produces. Mining reaches it through [`ubiquity_damping`] to
/// discount score and records the spread on the value; the aggregator, sequences
/// and data-flow then ask this predicate directly to decide how much a shared
/// value is worth as endpoint evidence, whether it may anchor a sequence, and
/// whether its trail is printed in full. One predicate rather than four
/// re-derivations is what keeps those stages agreeing about which values are
/// session furniture.
pub fn is_ubiquitous(spread: f64, thresholds: &Thresholds) -> bool {
    spread > thresholds.ubiquity_onset
}

/// The complete source-policy verdict on a candidate value.
///
/// A value anchored anywhere in application data is judged on its score like
/// any other. A value that only ever rode inside plain headers has to earn its
/// place: it must be long, random and identifier-shaped, *and* it must have
/// genuinely crossed slots. The last condition is what separates an issued
/// credential from "the same header in every request", which is the case this
/// gate exists to reject.
pub fn admissible(provenance: &Provenance, shape: &ValueShape, thresholds: &Thresholds) -> bool {
    if !provenance.is_transport_only() {
        return true;
    }
    provenance.has_handover()
        && shape.len >= thresholds.transport_min_len
        && shape.entropy >= thresholds.transport_min_entropy_bits
        && shape.identifier_weight >= thresholds.transport_min_shape_weight
}

/// Penalty for values carried by nearly every exchange.
///
/// A value present in a modest share of transactions identifies something. The
/// same value carried by everything is a constant: it distinguishes nothing.
/// The multiplier stays at full strength up to [`Thresholds::ubiquity_onset`],
/// then ramps linearly down to [`Thresholds::ubiquity_floor`] at total
/// spread. A ramp rather than a cliff is deliberate — a session token is
/// legitimately present on every authenticated request, and a hard rarity
/// ceiling would delete exactly the value the reader most wants.
///
/// Spread is [`ubiquity`], not coverage alone, so a credential that rides half
/// the transactions but two thirds of the routes is damped for what it is.
///
/// Public only to [`super::salience`], which composes every score multiplier
/// into the single figure mining applies.
pub(super) fn ubiquity_damping(spread: f64, thresholds: &Thresholds) -> f64 {
    let onset = thresholds.ubiquity_onset;
    let floor = thresholds.ubiquity_floor;
    // The two knobs are measured in different units and are not comparable with
    // one another: `onset` is a share of the capture's transactions, `floor` is
    // a score multiplier. Each is bounded in its own space.
    debug_assert!(
        (0.0..1.0).contains(&onset),
        "ubiquity_onset is a coverage share and must leave room to ramp: {onset}"
    );
    debug_assert!(
        floor > 0.0 && floor < 1.0,
        "ubiquity_floor is a multiplier that damps without erasing: {floor}"
    );
    if spread <= onset {
        return 1.0;
    }
    let progress = ((spread - onset) / (1.0 - onset)).min(1.0);
    floor + (1.0 - floor) * (1.0 - progress)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;

    fn at(tx: TxId, direction: Direction, location: &ValueLocation) -> Sighting<'_> {
        Sighting {
            tx_id: tx,
            direction,
            location,
        }
    }

    fn header(name: &str) -> ValueLocation {
        ValueLocation::Header(name.to_string())
    }

    fn body(field: &str) -> ValueLocation {
        ValueLocation::BodyField(field.to_string())
    }

    #[test]
    fn headers_are_transport_but_cookies_are_application() {
        assert_eq!(
            source_class(&ValueLocation::Header("host".into())),
            SourceClass::Transport
        );
        assert_eq!(
            source_class(&ValueLocation::Cookie("sid".into())),
            SourceClass::Application
        );
        assert_eq!(
            source_class(&ValueLocation::SetCookie("sid".into())),
            SourceClass::Application
        );
        assert_eq!(
            source_class(&ValueLocation::PathSegment(0)),
            SourceClass::Application
        );
    }

    #[test]
    fn anchoring_prefers_path_then_body_and_ignores_headers() {
        let host = header("host");
        let id = body("id");
        let path = ValueLocation::PathSegment(0);

        let mut provenance = Provenance::new();
        provenance.observe(at(0, Direction::Request, &host));
        assert_eq!(provenance.anchoring(), 0.0);
        assert!(provenance.is_transport_only());

        provenance.observe(at(1, Direction::Response, &id));
        assert_eq!(provenance.anchoring(), 0.9);
        assert!(!provenance.is_transport_only());

        provenance.observe(at(2, Direction::Request, &path));
        assert_eq!(provenance.anchoring(), 1.0);
    }

    #[test]
    fn handover_requires_different_slots_inside_the_transport_envelope() {
        // The classic protocol echo: the client sends `te: trailers`, the
        // server answers with the same header. No handover has happened.
        let te = header("te");
        let echo = Provenance::of([
            at(0, Direction::Request, &te),
            at(1, Direction::Response, &te),
        ]);
        assert!(!echo.has_handover());

        // Even correctly ordered, one header name repeating is still an echo.
        let ordered_echo = Provenance::of([
            at(0, Direction::Response, &te),
            at(1, Direction::Request, &te),
        ]);
        assert!(!ordered_echo.has_handover());

        // A server-issued session cookie that the client starts returning.
        let issued = ValueLocation::SetCookie("sid".into());
        let returned = ValueLocation::Cookie("sid".into());
        let session = Provenance::of([
            at(0, Direction::Response, &issued),
            at(1, Direction::Request, &returned),
        ]);
        assert!(session.has_handover());
    }

    /// The shape the transport rule must not swallow: an application field
    /// answered by the server and posted straight back under its own name.
    #[test]
    fn an_application_field_returned_under_its_own_name_is_a_handover() {
        let challenge = body("challenge_id");
        let flow = Provenance::of([
            at(0, Direction::Response, &challenge),
            at(1, Direction::Request, &challenge),
        ]);
        assert!(flow.has_handover());

        // Ordering still rules: a field posted first and echoed back is not.
        let echoed_back = Provenance::of([
            at(0, Direction::Request, &challenge),
            at(1, Direction::Response, &challenge),
        ]);
        assert!(!echoed_back.has_handover());
    }

    #[test]
    fn handover_needs_the_request_after_the_response() {
        let issued = body("k");
        let sent_back = ValueLocation::QueryParam("k".into());

        let too_early = Provenance::of([
            at(0, Direction::Request, &sent_back),
            at(1, Direction::Response, &issued),
        ]);
        assert!(!too_early.has_handover());

        let in_order = Provenance::of([
            at(0, Direction::Response, &issued),
            at(1, Direction::Request, &sent_back),
        ]);
        assert!(in_order.has_handover());
    }

    /// Being sent back as part of the address is the proof that a value is a
    /// reusable handle rather than a string the server happened to print.
    #[test]
    fn addressing_counts_only_the_path_and_the_query() {
        let in_path = Provenance::of([at(0, Direction::Request, &ValueLocation::PathSegment(2))]);
        assert!(in_path.addresses_a_request());

        let selector = ValueLocation::QueryParam("chat_id".into());
        assert!(Provenance::of([at(0, Direction::Request, &selector)]).addresses_a_request());

        let printed = body("data.items.name");
        assert!(!Provenance::of([at(0, Direction::Response, &printed)]).addresses_a_request());

        let carried = header("authorization");
        assert!(!Provenance::of([at(0, Direction::Request, &carried)]).addresses_a_request());
    }

    #[test]
    fn coverage_counts_distinct_transactions() {        let slot = ValueLocation::QueryParam("k".into());
        let mut provenance = Provenance::new();
        for tx in 0..3 {
            provenance.observe(at(tx, Direction::Request, &slot));
            provenance.observe(at(tx, Direction::Request, &slot));
        }
        assert_eq!(provenance.sighted_transactions(), 3);
    }

    #[test]
    fn transport_values_need_every_gate_condition() {
        let thresholds = Thresholds::for_mode(Mode::Standard);
        let issued = body("t");
        let carried = header("authorization");
        let anchored = Provenance::of([
            at(0, Direction::Response, &issued),
            at(1, Direction::Request, &carried),
        ]);
        assert!(!anchored.is_transport_only());

        // The same travel, but never once touching application data. The
        // handover holds, so the value is not simply "the same header in every
        // request" — yet every shape gate still has to pass for admission.
        let emitted = header("x-token");
        let echoed = Provenance::of([
            at(0, Direction::Response, &emitted),
            at(1, Direction::Request, &carried),
        ]);
        assert!(echoed.is_transport_only());
        assert!(echoed.has_handover());

        let long_random = ValueShape::of("9f3aa1bd7c2e4f5a8b6d00001111");
        let prose = ValueShape::of("strict-origin-when-cross-origin");
        let short_random = ValueShape::of("a1b2c3d4e5f6");

        assert!(admissible(&echoed, &long_random, &thresholds));
        assert!(!admissible(&echoed, &prose, &thresholds));
        assert!(!admissible(&echoed, &short_random, &thresholds));
        assert!(admissible(&anchored, &prose, &thresholds));

        // Without the crossing, no shape is good enough.
        let pinned = Provenance::of([
            at(0, Direction::Request, &carried),
            at(1, Direction::Request, &carried),
        ]);
        assert!(!admissible(&pinned, &long_random, &thresholds));
    }

    #[test]
    fn damping_is_flat_below_onset_and_ramps_to_the_floor() {
        let thresholds = Thresholds::for_mode(Mode::Standard);
        assert_eq!(ubiquity_damping(0.3, &thresholds), 1.0);
        assert!(
            (ubiquity_damping(1.0, &thresholds) - thresholds.ubiquity_floor).abs() < 1e-9
        );
        let mid = ubiquity_damping((thresholds.ubiquity_onset + 1.0) / 2.0, &thresholds);
        assert!(mid < 1.0 && mid > thresholds.ubiquity_floor);
    }

    /// The measured failure this predicate exists for: the reference capture's
    /// session cookie rode 52.5% of transactions — under every mode's onset, so
    /// coverage alone damped it by nothing — while appearing at 41 of 59
    /// endpoints. Either evidence on its own has to be enough.
    #[test]
    fn spread_is_the_stronger_of_transactions_and_routes() {
        let thresholds = Thresholds::for_mode(Mode::Standard);
        let session = ubiquity(0.525, 41.0 / 59.0);

        assert!(
            ubiquity_damping(0.525, &thresholds) == 1.0,
            "coverage alone provably misses it"
        );
        assert!(ubiquity_damping(session, &thresholds) < 1.0);
        assert!(is_ubiquitous(session, &thresholds));

        // Neither evidence is allowed to hide behind the other.
        assert_eq!(ubiquity(0.9, 0.1), 0.9);
        assert_eq!(ubiquity(0.1, 0.9), 0.9);

        // A value confined to a couple of routes stays undamped on both counts.
        assert!(!is_ubiquitous(ubiquity(0.2, 2.0 / 59.0), &thresholds));

        // The predicate and the discount agree on where the line falls.
        assert!(!is_ubiquitous(thresholds.ubiquity_onset, &thresholds));
        assert_eq!(ubiquity_damping(thresholds.ubiquity_onset, &thresholds), 1.0);
    }

    #[test]
    fn endpoint_share_ignores_the_unmapped_bucket() {
        let mut endpoints = BTreeSet::from(["GET /a".to_string(), "GET /b".to_string()]);
        assert!((endpoint_share(&endpoints, 4) - 0.5).abs() < 1e-9);

        endpoints.insert(UNMAPPED_ENDPOINT.to_string());
        assert!(
            (endpoint_share(&endpoints, 4) - 0.5).abs() < 1e-9,
            "the unmapped bucket is not a route"
        );

        assert_eq!(endpoint_share(&BTreeSet::new(), 4), 0.0);
        assert_eq!(endpoint_share(&endpoints, 0), 0.0);
    }

    #[test]
    fn apocalyptic_damps_harder_than_peaceful_everywhere() {
        let peaceful = Thresholds::for_mode(Mode::Peaceful);
        let standard = Thresholds::for_mode(Mode::Standard);
        let apocalyptic = Thresholds::for_mode(Mode::Apocalyptic);
        for coverage in (0..=20).map(|i| i as f64 / 20.0) {
            let p = ubiquity_damping(coverage, &peaceful);
            let st = ubiquity_damping(coverage, &standard);
            let a = ubiquity_damping(coverage, &apocalyptic);
            assert!(
                p >= st && st >= a,
                "damping not monotone across modes at coverage {coverage}"
            );
        }
    }
}
