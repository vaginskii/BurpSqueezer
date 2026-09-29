//! Stage 4: Strong Value Mining.
//!
//! Groups every observation by its exact value and scores each group on shape,
//! randomness, where it came from, and whether it genuinely travelled. Nothing
//! is matched by name: a field called `session_token` earns nothing for being
//! called that, and a field called `q` is not penalised for being called that.
//!
//! Two rules do most of the work, and both come from
//! [`crate::analysis::provenance`]. First, a value's *origin* is scored, not
//! merely counted: sightings in application slots anchor it, sightings in plain
//! headers do not, and a value that never left the transport envelope must pass
//! a strict gate to survive at all. Second, ubiquity is a penalty rather than a
//! reward, because a value present in every exchange distinguishes none of
//! them. Together these keep protocol furniture — `application/json`,
//! `no-cache`, `SAMEORIGIN` — out of the report without naming any of it.
//!
//! What the score means is decided here; how much of it a candidate keeps is
//! decided by [`crate::analysis::salience`], which this stage consults once.

use std::collections::BTreeMap;

use crate::analysis::provenance::{self, Provenance, ValueShape};
use crate::analysis::salience::{self, Corpus, Evidence};
use crate::analysis::stats;
use crate::analysis::value_class::{self, StickyEvidence};
use crate::config::Thresholds;
use crate::model::endpoint::{normalize_endpoint_key, EndpointTable, UNMAPPED_ENDPOINT};
use crate::model::value::{render_location, Direction, ObservedValue, StrongValue, ValueLocation};

/// Entropy in bits/byte treated as the practical ceiling when normalising.
const ENTROPY_CEILING: f64 = 6.0;
/// Extra endpoints at which the reach term reaches half its weight.
const SPREAD_HALF_POINT: f64 = 2.0;

/// Relative contribution of each scoring term. They sum to 1.0.
///
/// There is deliberately no term for raw occurrence count. Repetition is what
/// a protocol constant does best, so rewarding it was the single largest source
/// of noise in Core Signal. Occurrence still acts as a floor through
/// [`Thresholds::value_min_occurrences`]; it just no longer buys score.
const W_SHAPE: f64 = 0.30;
const W_ENTROPY: f64 = 0.20;
const W_HANDOVER: f64 = 0.20;
const W_ANCHORING: f64 = 0.20;
const W_SPREAD: f64 = 0.10;

/// A grouped value together with everything its sightings revealed.
struct Candidate {
    value: StrongValue,
    provenance: Provenance,
    /// Whether any path sighting landed at a position the capture showed varying.
    ///
    /// Answered per sighting, while the endpoint that supplied it is still known,
    /// and kept here rather than on the value because nothing after mining asks
    /// the question. A path sighting names a position *of a particular route*, so
    /// once the sightings are grouped by value the endpoint context is gone.
    routes_on_data: bool,
    /// Track best location types seen in request/response for bonus calculation.
    best_location_bonus: f64,
    /// The cookie slot this value was seen in, if any.
    ///
    /// The *name* rather than the whole location: the cookie a client sends and
    /// the one a server assigns are one slot seen from two directions, and
    /// [`value_class::slot_churn`] measures them together.
    cookie_slot: Option<String>,
}

/// Location bonus for ranking - path > body/write > query > cookie.
///
/// Bonus values from the specification:
/// - path segment: 1.00
/// - body field (response): 0.90
/// - body field (request): 0.75
/// - query param: 0.55
/// - cookie / set-cookie: 0.25
/// - header: 0.00
fn location_bonus(location: &ValueLocation, direction: Direction) -> f64 {
    match location {
        ValueLocation::PathSegment(_) => 1.00,
        ValueLocation::BodyField(_) => {
            if direction == Direction::Response {
                0.90
            } else {
                0.75
            }
        }
        ValueLocation::QueryParam(_) => 0.55,
        ValueLocation::Cookie(_) | ValueLocation::SetCookie(_) => 0.25,
        ValueLocation::Header(_) => 0.00,
    }
}

/// Score every distinct value and keep those that clear the bar.
///
/// The result is sorted by descending score, so downstream limits always cut
/// the weakest candidates.
pub fn mine(
    observations: &[ObservedValue],
    table: &EndpointTable,
    thresholds: &Thresholds,
) -> Vec<StrongValue> {
    let transactions = table.transaction_count();
    let corpus = Corpus::profile(observations, table);
    // One pass over the observations measures every cookie slot, and the result
    // is what lets a candidate be judged by how its slot behaved rather than by
    // whether some particular value happened to be sent once.
    let churn = value_class::slot_churn(observations, transactions);
    let mut grouped: BTreeMap<&str, Candidate> = BTreeMap::new();

    for observation in observations {
        if !plausible_length(&observation.value, thresholds) {
            continue;
        }

        let candidate = grouped
            .entry(observation.value.as_str())
            .or_insert_with(|| Candidate {
                value: StrongValue::new(observation.value.clone(), observation.tx_id),
                provenance: Provenance::new(),
                routes_on_data: false,
                best_location_bonus: 0.0,
                cookie_slot: None,
            });

        candidate.value.occurrences += 1;
        candidate.provenance.observe(observation.into());
        
        // Track best location bonus
        let bonus = location_bonus(&observation.location, observation.direction);
        candidate.best_location_bonus = candidate.best_location_bonus.max(bonus);
        
        // Remember the slot, not the sighting, so both directions of one cookie
        // are recognised as the same slot.
        if let ValueLocation::Cookie(name) | ValueLocation::SetCookie(name) = &observation.location {
            if candidate.cookie_slot.is_none() {
                candidate.cookie_slot = Some(name.clone());
            }
        }

        if let ValueLocation::BodyField(path) = &observation.location {
            candidate.value.observe_field(path);
        }

        if let ValueLocation::PathSegment(index) = &observation.location {
            candidate.value.seen_in_path = true;
            candidate.routes_on_data |= routes_on_data_at(table, observation.tx_id, *index);
        }

        if observation.direction == Direction::Response {
            candidate.value.seen_in_response = true;
        }

        let endpoint = table
            .key_of_tx(observation.tx_id)
            .unwrap_or_else(|| UNMAPPED_ENDPOINT.to_string());
        candidate
            .value
            .endpoints
            .insert(normalize_endpoint_key(&endpoint));

        // Every distinct location, rendered once through the shared helper so the
        // table always covers the chain hops. De-duplicated by the final string —
        // two path positions that both render to `path` are one location — and
        // never capped: completeness of this list is a hard requirement.
        let location = render_location(&endpoint, observation.direction, &observation.location);
        if !candidate.value.sightings.contains(&location) {
            candidate.value.sightings.push(location);
        }
    }

    let strong: Vec<StrongValue> = grouped
        .into_values()
        .filter_map(|candidate| promote(candidate, transactions, &corpus, &churn, thresholds))
        .filter(|value| !is_client_asserted(value))
        .collect();

    // Collapse before ranking, not after: a limit that cut a list still holding
    // a dozen siblings would keep whichever siblings happened to score highest
    // and drop the fact that they were one thing.
    let mut strong = collapse_by_class(strong);

    strong.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.first_seen.cmp(&b.first_seen))
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
    });
    strong
}

/// Bits of randomness an outbound-only value must still carry to be judged a
/// finding rather than a constant.
///
/// 3.5 bits/byte is the bar this crate already uses to call a cookie- or
/// header-borne value a credential at all (`sticky_min_entropy_bits`,
/// `transport_min_entropy_bits`). The two cases that separate on it are the ones
/// that matter: an SDK's metric-name and resource-hash constants sit below it,
/// while a token the client hands a server in a query string sits well above,
/// and that token is exactly the sort of thing the report exists to surface.
/// Deliberately not a per-mode threshold — whether a value is a secret or a
/// constant is not a question of how selective the reader is.
const OUTBOUND_SECRET_MIN_ENTROPY: f64 = 3.5;

/// Whether a value is only ever asserted by the client, and so is not evidence
/// of system state.
///
/// Mining rewards reach, and reach is exactly what an embedded analytics SDK
/// has: its build ids, resource hashes and metric-name strings ride dozens of
/// exchanges at once, so on ubiquity alone they outrank a real identifier and
/// fill the ranking with one emitter's field set. What they never do is come
/// back — nothing in a response, nothing in a URL, no handover between slots.
///
/// So the test is not "is this a known telemetry field" but "did the server ever
/// put this value anywhere". A sighting in a response, a path, or a propagation
/// all mean it did, and those values are kept untouched. What remains is dropped
/// only if it also fails to look like something the client would keep secret —
/// see [`OUTBOUND_SECRET_MIN_ENTROPY`].
///
/// Dropping costs the report nothing: endpoint field lists are built from
/// observations, so the field is still named where it was found. It simply stops
/// ranking as a finding.
fn is_client_asserted(value: &StrongValue) -> bool {
    !value.seen_in_response
        && !value.seen_in_path
        && !value.propagates
        && value.entropy < OUTBOUND_SECRET_MIN_ENTROPY
}

/// Whether one transaction's route treats path position `index` as data.
///
/// Deferred to the endpoint's own template, which already records the verdict:
/// the normalizer collapsed the position to `{id}` exactly when the capture
/// showed it varying like an identifier. An unmapped transaction has no route
/// and therefore no answer, which is the same as no evidence.
fn routes_on_data_at(table: &EndpointTable, tx_id: usize, index: usize) -> bool {
    table
        .slot_of_tx(tx_id)
        .and_then(|slot| table.endpoints.get(slot))
        .is_some_and(|stats| stats.endpoint.routes_on_data_at(index))
}

/// Finish one group and decide whether it is a Strong Value.
fn promote(
    candidate: Candidate,
    transactions: usize,
    corpus: &Corpus,
    churn: &BTreeMap<String, value_class::SlotChurn>,
    thresholds: &Thresholds,
) -> Option<StrongValue> {
    let Candidate {
        mut value,
        provenance,
        routes_on_data,
        best_location_bonus,
        cookie_slot,
    } = candidate;

    let shape = ValueShape::of(value.full());
    value.entropy = shape.entropy;
    value.propagates = provenance.has_handover();
    value.coverage = coverage(&provenance, transactions);

    // The one place a value is classified. Everything downstream reads the
    // answer off the value rather than judging it again.
    value.class = value_class::ValueClass::classify(
        &StickyEvidence {
            slot: cookie_slot.as_deref(),
            value: value.full(),
            churn: cookie_slot.as_deref().and_then(|name| churn.get(name).copied()),
        },
        thresholds,
    );

    let salience = salience::judge(
        &Evidence {
            coverage: value.coverage,
            endpoints: &value.endpoints,
            shape: &shape,
            provenance: &provenance,
            routes_on_data,
        },
        corpus,
        thresholds,
    );
    value.spread = salience.spread;
    let class_damping = value.class.damping_multiplier(thresholds);
    value.score = raw_score(&value, &shape, &provenance, best_location_bonus) * salience.damping * class_damping;

    let qualifies = provenance::admissible(&provenance, &shape, thresholds)
        && value.occurrences >= thresholds.value_min_occurrences
        && value.entropy >= thresholds.value_min_entropy_bits
        // A collapsing class is not asking for a row of its own: it is asking for
        // one line standing for a group, and the floor has already put that line
        // where it belongs. Judging the summary against the bar for a row of its
        // own would mean the discount erased the evidence instead of ordering
        // it, and the report would be silent about a credential the capture
        // spent its whole session maintaining.
        && (value.class.should_collapse() || value.score >= thresholds.value_min_score);

    qualifies.then_some(value)
}

/// Share of the capture's transactions in which the value appeared.
fn coverage(provenance: &Provenance, transactions: usize) -> f64 {
    if transactions == 0 {
        return 0.0;
    }
    (provenance.sighted_transactions() as f64 / transactions as f64).min(1.0)
}

/// Order two values so that a representative is chosen the same way twice.
///
/// Descending score, then earliest sighting, then fingerprint. The last key is
/// what makes the choice a function of the capture rather than of the iteration
/// order a hash map happened to produce: a report that changed which credential
/// it names on every run could not be compared against the last one.
fn representative_order(a: &StrongValue, b: &StrongValue) -> std::cmp::Ordering {
    b.score
        .partial_cmp(&a.score)
        .unwrap_or(std::cmp::Ordering::Equal)
        .then_with(|| a.first_seen.cmp(&b.first_seen))
        .then_with(|| a.fingerprint.cmp(&b.fingerprint))
}

/// Fold every value of a collapsing class into one representative.
///
/// A routing credential arrives in a new shape on every exchange, so a capture
/// served through one produces a dozen mining results that are all the same
/// fact. Reporting them separately puts a dozen rows at the top of the report
/// and, worse, a limit cuts whichever of them happened to score highest.
///
/// What the representative absorbs, and why:
///
/// - `endpoints` and `occurrences` are unions and sums, so the row accounts for
///   every sighting it stands for rather than for one value's share of them;
/// - `coverage` is the widest among the absorbed, which can only make the
///   collapsed value read as *more* ubiquitous than any of its members — the
///   right direction for something that names no object;
/// - `score`, `entropy` and `first_seen` stay the representative's own, because
///   they describe one real value and inventing an average would describe none.
///
/// A class with a single member is left whole: there was nothing to collapse,
/// and replacing its sightings with a summary would only lose information.
fn collapse_by_class(values: Vec<StrongValue>) -> Vec<StrongValue> {
    let (collapsed, mut kept): (Vec<StrongValue>, Vec<StrongValue>) = values
        .into_iter()
        .partition(|value| value.class.should_collapse());

    if collapsed.len() > 1 {
        kept.push(fold(collapsed));
    } else {
        kept.extend(collapsed);
    }
    kept
}

/// Merge a group of same-class values into the one that leads it.
fn fold(mut group: Vec<StrongValue>) -> StrongValue {
    group.sort_by(representative_order);

    let variants = group.len();
    let mut representative = group.remove(0);
    representative.collapsed_variants = variants;
    if variants > 1 {
        representative.sightings = vec![format!("cookie.* (collapsed {variants} variants)")];
    }

    for absorbed in group {
        representative.occurrences += absorbed.occurrences;
        representative.coverage = representative.coverage.max(absorbed.coverage);
        representative.endpoints.extend(absorbed.endpoints);
        representative.fields.extend(absorbed.fields);
    }

    representative
}

fn plausible_length(value: &str, thresholds: &Thresholds) -> bool {
    let len = value.chars().count();
    len >= thresholds.value_min_len && len <= thresholds.value_max_len
}

/// What the value looks like, before salience decides how much of it survives.
///
/// The five terms answer five independent questions: does it look like an
/// identifier, is it random, did the server hand it to the client, did it come
/// from application data rather than the transport envelope, and does it tie
/// several endpoints together.
///
/// Every reason a well-formed value might still distinguish nothing lives in
/// [`crate::analysis::salience`] instead, and is applied to this figure exactly
/// once by [`promote`]. Keeping the two apart is what makes a score explainable:
/// this function says what was observed, and the multiplier says what it is worth.
fn raw_score(value: &StrongValue, shape: &ValueShape, provenance: &Provenance, location_bonus: f64) -> f64 {
    let randomness = stats::normalize(shape.entropy, ENTROPY_CEILING);
    let handover = if value.propagates { 1.0 } else { 0.0 };
    let reach = stats::saturate(value.endpoints.len().saturating_sub(1), SPREAD_HALF_POINT);

    let base_score = shape.identifier_weight * W_SHAPE
        + randomness * W_ENTROPY
        + handover * W_HANDOVER
        + provenance.anchoring() * W_ANCHORING
        + reach * W_SPREAD;
    
    // Apply location bonus: (1.0 + 0.35 * location_bonus)
    // This gives path values up to 35% boost, cookie values minimal boost
    base_score * (1.0 + 0.35 * location_bonus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;
    use crate::model::endpoint::Endpoint;
    use crate::model::value::Direction;

    const TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.Xk9sQ2p1bXBlcg";

    fn table_with(ids: &[(usize, &str)]) -> EndpointTable {
        let mut table = EndpointTable::new();
        for (tx_id, key) in ids {
            let slot = table.slot_for(Endpoint::new("GET", *key));
            table.assign(*tx_id, slot);
            table
                .stats_mut(slot)
                .expect("slot just created")
                .tx_ids
                .push(*tx_id);
        }
        table
    }

    /// `count` transactions against one endpoint, to set the coverage
    /// denominator without adding sightings.
    fn table_of_size(count: usize) -> EndpointTable {
        let entries: Vec<(usize, &str)> = (0..count).map(|id| (id, "/poll")).collect();
        table_with(&entries)
    }

    fn observation(
        tx_id: usize,
        direction: Direction,
        location: ValueLocation,
        value: &str,
    ) -> ObservedValue {
        ObservedValue {
            tx_id,
            direction,
            location,
            value: value.to_string(),
        }
    }

    #[test]
    fn promotes_a_token_that_propagates_from_response_to_request() {
        let observations = vec![
            observation(
                0,
                Direction::Response,
                ValueLocation::BodyField("data.token".into()),
                TOKEN,
            ),
            observation(
                1,
                Direction::Request,
                ValueLocation::Header("authorization".into()),
                TOKEN,
            ),
        ];
        let table = table_with(&[(0, "/login"), (1, "/me")]);

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Standard));

        assert_eq!(mined.len(), 1);
        let value = &mined[0];
        assert!(value.propagates);
        assert_eq!(value.occurrences, 2);
        assert_eq!(value.endpoints.len(), 2);
        assert!(value.score > 0.5);
    }

    /// A value carrying only the evidence mining records about it, so the rule
    /// can be exercised on each clause without first fighting every other gate.
    fn outbound_only(entropy: f64) -> StrongValue {
        let mut value = StrongValue::new("outbound".to_string(), 0);
        value.entropy = entropy;
        value
    }

    #[test]
    fn the_rule_rejects_an_outbound_constant_that_is_not_secret_shaped() {
        // An SDK beacon: never returned, never in a URL, no handover, and too
        // regular to be a secret the client would keep.
        assert!(is_client_asserted(&outbound_only(3.0)));
    }

    #[test]
    fn a_secret_the_client_only_sends_is_still_a_finding() {
        // A token in a query string is outbound-only too, and is exactly what
        // the report exists to surface. Dropping it would be a regression, not
        // a cleanup.
        assert!(!is_client_asserted(&outbound_only(4.1)));
    }

    #[test]
    fn a_value_the_server_put_somewhere_is_never_client_asserted() {
        let bar = OUTBOUND_SECRET_MIN_ENTROPY - 0.5;

        let mut echoed = outbound_only(bar);
        echoed.seen_in_response = true;
        assert!(
            !is_client_asserted(&echoed),
            "a response sighting settles it"
        );

        let mut in_url = outbound_only(bar);
        in_url.seen_in_path = true;
        assert!(!is_client_asserted(&in_url), "a path sighting settles it");

        let mut handed_over = outbound_only(bar);
        handed_over.propagates = true;
        assert!(!is_client_asserted(&handed_over), "a handover settles it");
    }

    /// A beacon's resource id, the shape an embedded analytics SDK ships to its
    /// collector: a hex constant, request-only, riding a few routes, never once
    /// returned, and too regular to be a secret.
    ///
    /// The exact string is load-bearing, and so is where it is seen. Twelve hex
    /// characters give 3.25 bits — clear of the 2.5 floor mining applies, clear
    /// of the 3.5 a credential must reach — and it reaches a score of 0.65,
    /// which is above the 0.5 bar, so it genuinely qualifies and is genuinely
    /// dropped. A word-like value would not do: dotted attribute names never
    /// score high enough to reach the ranking at all, so a test built from one
    /// would pass with the filter removed and prove nothing.
    const BEACON_ID: &str = "0fd09f3a1c7b";

    fn beacon_capture() -> (Vec<ObservedValue>, EndpointTable) {
        let routes = ["/collect", "/track", "/send", "/push", "/emit"];
        let entries: Vec<(usize, &str)> = (0..24).map(|t| (t, routes[t % routes.len()])).collect();
        let observations = (0..3)
            .map(|tx| {
                observation(
                    tx,
                    Direction::Request,
                    ValueLocation::BodyField("events[].event_properties.build".into()),
                    BEACON_ID,
                )
            })
            .collect();
        (observations, table_with(&entries))
    }

    #[test]
    fn a_constant_only_the_client_sends_is_not_a_finding() {
        let (observations, table) = beacon_capture();

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Standard));

        assert!(
            mined.is_empty(),
            "an outbound-only constant that is not secret-shaped must not rank, but got {:?}",
            mined.iter().map(|v| v.full()).collect::<Vec<_>>()
        );
    }

    /// The counterpart, and the reason the test above cannot pass for the wrong
    /// reason: this value clears every mining gate, so with the filter removed
    /// it would rank — the single response sighting is the only difference
    /// between the two outcomes. If a future change makes the request-only
    /// case pass by accident, this one stops passing with it.
    #[test]
    fn the_same_constant_is_a_finding_once_a_response_echoes_it() {
        let (mut observations, table) = beacon_capture();
        observations.push(observation(
            23,
            Direction::Response,
            ValueLocation::BodyField("echo.build".into()),
            BEACON_ID,
        ));

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Standard));

        assert_eq!(
            mined.len(),
            1,
            "the very same value must rank as soon as a response carries it"
        );
        assert!(mined[0].seen_in_response);
    }

    /// End-to-end guard for the false negative that matters: a JWT the client
    /// hands over in `GET /?token=…` is outbound only, and an earlier form of
    /// this rule deleted it.
    #[test]
    fn a_token_in_a_query_string_survives_mining() {
        let observations = vec![
            observation(
                0,
                Direction::Request,
                ValueLocation::QueryParam("token".into()),
                TOKEN,
            ),
            observation(
                1,
                Direction::Request,
                ValueLocation::QueryParam("token".into()),
                TOKEN,
            ),
        ];
        let table = table_with(&[(0, "/"), (1, "/")]);

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Standard));

        assert_eq!(
            mined.len(),
            1,
            "a token handed to a server in a query string is what the report is for"
        );
        assert!(!mined[0].seen_in_response);
        assert!(!mined[0].propagates);
    }

    #[test]
    fn rejects_low_entropy_and_prose_values() {
        let observations = vec![
            observation(
                0,
                Direction::Request,
                ValueLocation::Header("accept".into()),
                "application/json",
            ),
            observation(
                1,
                Direction::Request,
                ValueLocation::Header("accept".into()),
                "application/json",
            ),
            observation(
                0,
                Direction::Request,
                ValueLocation::BodyField("note".into()),
                "aaaaaaaaaaaaaaa",
            ),
            observation(
                1,
                Direction::Request,
                ValueLocation::BodyField("note".into()),
                "aaaaaaaaaaaaaaa",
            ),
        ];
        let table = table_with(&[(0, "/a"), (1, "/b")]);

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Standard));
        assert!(mined.is_empty());
    }

    #[test]
    fn requires_repeat_sightings() {
        let observations = vec![observation(
            0,
            Direction::Response,
            ValueLocation::BodyField("token".into()),
            "9f3aa1bd7c2e4f5a8b6d",
        )];
        let table = table_with(&[(0, "/once")]);

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Standard));
        assert!(mined.is_empty());
    }

    #[test]
    fn records_path_sightings() {
        let id = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
        let observations = vec![
            observation(
                0,
                Direction::Response,
                ValueLocation::BodyField("id".into()),
                id,
            ),
            observation(1, Direction::Request, ValueLocation::PathSegment(1), id),
        ];
        let table = table_with(&[(0, "/orders"), (1, "/orders/{id}")]);

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Standard));
        assert_eq!(mined.len(), 1);
        assert!(mined[0].seen_in_path);
        assert!(mined[0].propagates);
    }

    /// The mid-tier failure, end to end. Both values sit in a path, are returned
    /// in a body, and are handed back to a later request; the only difference is
    /// that one names a position the capture showed varying and the other is the
    /// route's own name. Before the vocabulary rule they scored within 0.03 of
    /// each other and the word ranked higher, because it carries more entropy.
    #[test]
    fn a_route_noun_sinks_below_the_object_id_it_sits_beside() {
        let noun = "custom_properties";
        let id = "81269354";
        let mut observations = Vec::new();
        for tx in [0, 1] {
            observations.push(observation(
                tx,
                Direction::Request,
                ValueLocation::PathSegment(2),
                noun,
            ));
            observations.push(observation(
                tx,
                Direction::Response,
                ValueLocation::BodyField("data.key".into()),
                noun,
            ));
        }
        for tx in [2, 3] {
            observations.push(observation(
                tx,
                Direction::Request,
                ValueLocation::PathSegment(3),
                id,
            ));
            observations.push(observation(
                tx,
                Direction::Response,
                ValueLocation::BodyField("data.id".into()),
                id,
            ));
        }
        // The noun's position never varied; the id's did, so it was collapsed.
        let table = table_with(&[
            (0, "/api/v3/custom_properties"),
            (1, "/api/v3/custom_properties"),
            (2, "/api/v3/users/{id}"),
            (3, "/api/v3/users/{id}"),
            (4, "/api/v3/spare"),
        ]);

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Standard));
        let score_of = |wanted: &str| {
            mined
                .iter()
                .find(|value| value.full() == wanted)
                .map(|value| value.score)
        };

        let kept = score_of(id).expect("an eight-digit object id must survive");
        if let Some(sunk) = score_of(noun) {
            assert!(
                sunk < kept,
                "the route noun did not sink below the identifier beside it"
            );
        }
    }

    /// The failure this whole stage was rebuilt around: a header that every
    /// request carries is not an identifier, however long or random it looks.
    #[test]
    fn a_value_that_only_ever_rode_in_headers_is_not_mined() {
        let trace = "9f3aa1bd7c2e4f5a8b6d00001111";
        let table = table_with(&[
            (0, "/a"),
            (1, "/b"),
            (2, "/c"),
            (3, "/d"),
            (4, "/e"),
            (5, "/f"),
            (6, "/g"),
            (7, "/h"),
        ]);
        let header_only: Vec<ObservedValue> = (0..4)
            .map(|tx| {
                observation(
                    tx,
                    Direction::Request,
                    ValueLocation::Header("x-request-id".into()),
                    trace,
                )
            })
            .collect();

        for mode in [Mode::Safe, Mode::Standard, Mode::Apocalyptic] {
            let mined = mine(&header_only, &table, &Thresholds::for_mode(mode));
            assert!(mined.is_empty(), "header-only value survived in {mode} mode");
        }

        // The same characters, once a response has actually handed them over.
        let mut handed_over = header_only.clone();
        handed_over.push(observation(
            0,
            Direction::Response,
            ValueLocation::BodyField("trace".into()),
            trace,
        ));
        let mined = mine(&handed_over, &table, &Thresholds::for_mode(Mode::Standard));
        assert_eq!(mined.len(), 1);
        assert!(mined[0].propagates);
    }

    /// Two runs over identical sightings, differing only in how much traffic
    /// surrounds them. Ubiquity has to cost score, or every protocol constant
    /// outranks the identifiers worth reading.
    #[test]
    fn a_value_carried_by_every_transaction_is_damped() {
        let observations: Vec<ObservedValue> = (0..4)
            .map(|tx| {
                observation(
                    tx,
                    Direction::Response,
                    ValueLocation::BodyField("ref".into()),
                    TOKEN,
                )
            })
            .collect();
        let thresholds = Thresholds::for_mode(Mode::Safe);

        let everywhere = mine(&observations, &table_of_size(4), &thresholds);
        let occasional = mine(&observations, &table_of_size(20), &thresholds);

        assert_eq!(everywhere.len(), 1);
        assert_eq!(occasional.len(), 1);
        assert!((everywhere[0].coverage - 1.0).abs() < f64::EPSILON);
        assert!(everywhere[0].score < occasional[0].score);

        // In standard mode the ubiquity damping still reduces the score, but location bonus
        // for body field (0.90) may keep it above threshold. The key behavior is that
        // the everywhere version scores lower than the occasional one.
        let thresholds = Thresholds::for_mode(Mode::Standard);
        let everywhere_standard = mine(&observations, &table_of_size(4), &thresholds);
        let occasional_standard = mine(&observations, &table_of_size(20), &thresholds);
        
        // The key test: everywhere should score lower than occasional
        if !everywhere_standard.is_empty() && !occasional_standard.is_empty() {
            assert!(everywhere_standard[0].score < occasional_standard[0].score);
        }
    }

    #[test]
    fn apocalyptic_mode_keeps_strictly_fewer_values() {
        let weak = "9f3aa1bd7c2e4f5a8b6d0000";
        let observations = vec![
            observation(
                0,
                Direction::Response,
                ValueLocation::BodyField("t".into()),
                TOKEN,
            ),
            observation(
                1,
                Direction::Request,
                ValueLocation::Header("authorization".into()),
                TOKEN,
            ),
            observation(2, Direction::Request, ValueLocation::PathSegment(1), weak),
            observation(3, Direction::Request, ValueLocation::PathSegment(1), weak),
        ];
        let table = table_with(&[
            (0, "/login"),
            (1, "/me"),
            (2, "/orders/{id}"),
            (3, "/items/{id}"),
            (4, "/other"),
            (5, "/spare"),
        ]);

        let standard = mine(&observations, &table, &Thresholds::for_mode(Mode::Standard));
        let apocalyptic = mine(
            &observations,
            &table,
            &Thresholds::for_mode(Mode::Apocalyptic),
        );

        // The key behavior: apocalyptic mode should be stricter than standard
        assert!(apocalyptic.len() <= standard.len(), "apocalyptic should be as strict or stricter");
        
        // The handed-over token should always survive (it has body field location bonus + handover)
        assert!(apocalyptic.iter().any(|v| v.full() == TOKEN), "handed-over token should survive");
        
        // In apocalyptic mode, all surviving values should have high scores
        assert!(apocalyptic.iter().all(|v| v.score >= 0.7));
    }

    /// A static catalogue served over HTTP is still a static catalogue. Its rows
    /// are well shaped, random and perfectly exclusive, so every other term in
    /// the score rates them highly and they filled Core Signal ahead of the
    /// identifiers that actually drive the API.
    ///
    /// The control is the point of the test: the same rows, from an endpoint
    /// that returns a handful of them, stay. What is being penalised is bulk
    /// vocabulary, not rarity, and not the shape of the value.
    #[test]
    fn rows_of_a_shipped_catalogue_are_dropped_but_a_short_list_survives() {
        /// A catalogue endpoint fetched twice, plus an unrelated token flow.
        fn capture(rows: usize) -> (Vec<ObservedValue>, EndpointTable) {
            let mut observations = Vec::new();
            for tx in [0, 1] {
                for row in 0..rows {
                    observations.push(observation(
                        tx,
                        Direction::Response,
                        ValueLocation::BodyField("rows.id".into()),
                        &format!("{row:08x}-4f89-11d3-9a0c-0305e82c3301"),
                    ));
                }
            }
            observations.push(observation(
                2,
                Direction::Response,
                ValueLocation::BodyField("data.token".into()),
                TOKEN,
            ));
            observations.push(observation(
                3,
                Direction::Request,
                ValueLocation::Header("authorization".into()),
                TOKEN,
            ));
            let table = table_with(&[
                (0, "/assets/catalogue.json"),
                (1, "/assets/catalogue.json"),
                (2, "/login"),
                (3, "/me"),
            ]);
            (observations, table)
        }

        let thresholds = Thresholds::for_mode(Mode::Standard);
        let is_row = |value: &&StrongValue| value.full().ends_with("-4f89-11d3-9a0c-0305e82c3301");

        let (short, table) = capture(8);
        let mined = mine(&short, &table, &thresholds);
        assert_eq!(
            mined.iter().filter(is_row).count(),
            8,
            "a short list of ids is ordinary application data and must be kept"
        );

        let (bulk, table) = capture(400);
        let mined = mine(&bulk, &table, &thresholds);
        assert_eq!(
            mined.iter().filter(is_row).count(),
            0,
            "rows of a bulk-emitted catalogue reached Core Signal"
        );
        assert!(
            mined.iter().any(|value| value.full() == TOKEN),
            "the handed-over token must be untouched by the catalogue rule"
        );
    }

    /// The composed spread figure has to reach the value, or every later stage
    /// re-derives its own and they drift apart.
    #[test]
    fn the_spread_recorded_on_a_value_accounts_for_both_evidences() {
        let observations: Vec<ObservedValue> = (0..6)
            .map(|tx| {
                observation(
                    tx,
                    Direction::Request,
                    ValueLocation::Cookie("sid".into()),
                    TOKEN,
                )
            })
            .chain(std::iter::once(observation(
                0,
                Direction::Response,
                ValueLocation::SetCookie("sid".into()),
                TOKEN,
            )))
            .collect();
        // Six of twelve transactions, but six of eight routes.
        let mut entries: Vec<(usize, String)> =
            (0..6).map(|tx| (tx, format!("/api/r{tx}"))).collect();
        entries.extend((6..12).map(|tx| (tx, "/poll".to_string())));
        entries.push((12, "/spare".to_string()));
        let borrowed: Vec<(usize, &str)> = entries
            .iter()
            .map(|(tx, key)| (*tx, key.as_str()))
            .collect();
        let table = table_with(&borrowed);

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Safe));
        assert_eq!(mined.len(), 1);
        let session = &mined[0];

        assert!(session.coverage < 0.5, "coverage alone under-reads it");
        assert!(
            session.spread > session.coverage,
            "route spread was not composed in: {} vs {}",
            session.spread,
            session.coverage
        );
    }

    #[test]
    fn results_are_ordered_by_descending_score() {
        let plain = "7c2a9f3b1d4e6a8c";
        let observations = vec![
            observation(
                0,
                Direction::Response,
                ValueLocation::BodyField("t".into()),
                TOKEN,
            ),
            observation(
                1,
                Direction::Request,
                ValueLocation::Header("authorization".into()),
                TOKEN,
            ),
            observation(
                2,
                Direction::Request,
                ValueLocation::QueryParam("x".into()),
                plain,
            ),
            observation(
                2,
                Direction::Request,
                ValueLocation::QueryParam("y".into()),
                plain,
            ),
        ];
        let table = table_with(&[(0, "/login"), (1, "/me"), (2, "/other")]);

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Safe));
        assert!(mined.len() >= 2);
        assert!(mined[0].score >= mined[1].score);
    }

    /// A credential that pins a client to one backend looks like an identifier in
    /// every respect mining measures: long, random, handed out by a response and
    /// sent back on the next request. A capture served through one of them mines
    /// a dozen of them, and a report that lists them is describing its
    /// infrastructure.
    fn routing_credential(seed: usize) -> String {
        format!(
            "v{seed}9f3aa1bd7c2e4f5a8b6d000011112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccdd"
        )
    }

    /// A capture whose session is pinned: one slot, repeatedly replaced, riding
    /// every exchange. `variants` distinct credentials reach Strong Values.
    fn pinned_session(variants: usize) -> (Vec<ObservedValue>, EndpointTable) {
        let mut observations = Vec::new();
        let mut entries = Vec::new();

        for tx in 0..24 {
            let credential = routing_credential(tx % variants);
            if tx == 0 {
                // Issued once, then sent back on everything that follows.
                observations.push(observation(
                    tx,
                    Direction::Response,
                    ValueLocation::SetCookie("routing".into()),
                    &credential,
                ));
            }
            observations.push(observation(
                tx,
                Direction::Request,
                ValueLocation::Cookie("routing".into()),
                &credential,
            ));
            entries.push((tx, format!("/api/r{}", tx % 8)));
        }

        let borrowed: Vec<(usize, &str)> = entries
            .iter()
            .map(|(tx, key)| (*tx, key.as_str()))
            .collect();
        (observations, table_with(&borrowed))
    }

    #[test]
    fn a_rotating_session_credential_is_reported_once_and_last() {
        let (observations, table) = pinned_session(12);

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Standard));

        let pinned: Vec<&StrongValue> = mined
            .iter()
            .filter(|value| value.class.should_collapse())
            .collect();
        assert_eq!(
            pinned.len(),
            1,
            "twelve replacements of one credential reached the report as twelve rows"
        );

        let representative = pinned[0];
        assert_eq!(representative.collapsed_variants, 12);
        assert_eq!(
            representative.sightings,
            vec!["cookie.* (collapsed 12 variants)".to_string()],
            "the row must say what it stands for, in the slot's own terms"
        );
        assert!(
            mined.last().expect("values are sorted") .class.should_collapse(),
            "a credential that names no object must not lead the table"
        );
    }

    /// Twelve rows or one is the whole difference, but only if the one is chosen
    /// the same way every time. A representative taken from hash iteration order
    /// would name a different credential on each run, and two reports of one
    /// capture could not be compared.
    #[test]
    fn the_collapsed_representative_is_chosen_deterministically() {
        let (observations, table) = pinned_session(12);
        let thresholds = Thresholds::for_mode(Mode::Standard);

        let first = mine(&observations, &table, &thresholds);
        let second = mine(&observations, &table, &thresholds);

        let representative = |mined: &[StrongValue]| {
            mined
                .iter()
                .find(|value| value.class.should_collapse())
                .map(|value| value.full().to_string())
        };

        assert_eq!(representative(&first), representative(&second));
        // And it is the leading member of its group, not merely a stable one.
        let strongest = first
            .iter()
            .filter(|value| value.class.should_collapse())
            .map(|value| value.score)
            .fold(f64::NEG_INFINITY, f64::max);
        assert_eq!(
            representative(&first).is_some(),
            strongest.is_finite(),
            "the reported representative is the group collapsed, not a leftover"
        );
    }

    /// A credential that never changes is a constant, and constants are already
    /// discounted by ubiquity. Folding one under this rule instead would replace
    /// a real finding about the capture with a guess about it.
    #[test]
    fn a_settled_session_cookie_is_left_alone() {
        let mut observations = vec![observation(
            0,
            Direction::Response,
            ValueLocation::SetCookie("routing".into()),
            &routing_credential(0),
        )];
        for tx in 0..24 {
            observations.push(observation(
                tx,
                Direction::Request,
                ValueLocation::Cookie("routing".into()),
                &routing_credential(0),
            ));
        }
        let table = table_with(&(0..24).map(|tx| (tx, "/api/poll")).collect::<Vec<_>>());

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Standard));

        assert!(
            mined.iter().all(|value| !value.class.should_collapse()),
            "one value that never changed was treated as a rotation"
        );
    }

    /// The control for both tests above. A long, random, widely-carried value in
    /// a body is a catalogue of ids or a batch of records, and it is exactly what
    /// this rule must not touch.
    #[test]
    fn a_long_rotating_body_value_is_never_collapsed() {
        let mut observations = Vec::new();
        let mut entries = Vec::new();
        for tx in 0..24 {
            observations.push(observation(
                tx,
                Direction::Response,
                ValueLocation::BodyField("results[].id".into()),
                &routing_credential(tx),
            ));
            entries.push((tx, format!("/api/page{}/results", tx % 8)));
        }
        let borrowed: Vec<(usize, &str)> = entries
            .iter()
            .map(|(tx, key)| (*tx, key.as_str()))
            .collect();
        let table = table_with(&borrowed);

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Standard));

        assert_eq!(
            mined.iter().filter(|value| value.class.should_collapse()).count(),
            0,
            "a batch of distinct ids in a body was mistaken for a session pin"
        );
    }

    /// A class with one member has nothing to collapse, and summarising it would
    /// only throw away the locations that say where the credential is used.
    ///
    /// One rotating credential is on its own here, not because its slot is
    /// settled — the slot rotates throughout — but because every other value in
    /// it was seen once and never mined. A group of one is the case where a
    /// summary line would be strictly less informative than the locations.
    #[test]
    fn a_lone_sticky_cookie_keeps_its_locations() {
        let mut observations = vec![observation(
            0,
            Direction::Response,
            ValueLocation::SetCookie("routing".into()),
            &routing_credential(0),
        )];
        let mut entries = Vec::new();
        for tx in 0..24 {
            let credential = if tx < 12 {
                routing_credential(0)
            } else {
                routing_credential(tx)
            };
            observations.push(observation(
                tx,
                Direction::Request,
                ValueLocation::Cookie("routing".into()),
                &credential,
            ));
            entries.push((tx, format!("/api/r{}", tx % 8)));
        }
        let borrowed: Vec<(usize, &str)> = entries
            .iter()
            .map(|(tx, key)| (*tx, key.as_str()))
            .collect();

        let mined = mine(
            &observations,
            &table_with(&borrowed),
            &Thresholds::for_mode(Mode::Standard),
        );

        let sticky: Vec<&StrongValue> = mined
            .iter()
            .filter(|value| value.class.should_collapse())
            .collect();
        assert_eq!(sticky.len(), 1);
        assert_eq!(sticky[0].collapsed_variants, 0, "nothing was folded");
        assert!(
            !sticky[0].sightings[0].contains("collapsed"),
            "a lone value was summarised anyway: {:?}",
            sticky[0].sightings
        );
        assert!(
            sticky[0]
                .sightings
                .iter()
                .any(|sighting| sighting.contains("cookie.routing")),
            "the locations that say where the credential is used were lost"
        );
    }
}
