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

use std::collections::HashMap;

use crate::analysis::provenance::{self, Provenance, ValueShape};
use crate::analysis::salience::{self, Corpus, Evidence};
use crate::analysis::stats;
use crate::config::Thresholds;
use crate::model::endpoint::{normalize_endpoint_key, EndpointTable, UNMAPPED_ENDPOINT};
use crate::model::value::{render_location, ObservedValue, StrongValue, ValueLocation};

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
    let mut grouped: HashMap<&str, Candidate> = HashMap::new();

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
            });

        candidate.value.occurrences += 1;
        candidate.provenance.observe(observation.into());
        if let ValueLocation::PathSegment(index) = &observation.location {
            candidate.value.seen_in_path = true;
            candidate.routes_on_data |= routes_on_data_at(table, observation.tx_id, *index);
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

    let mut strong: Vec<StrongValue> = grouped
        .into_values()
        .filter_map(|candidate| promote(candidate, transactions, &corpus, thresholds))
        .collect();

    strong.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.first_seen.cmp(&b.first_seen))
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
    });
    strong
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
    thresholds: &Thresholds,
) -> Option<StrongValue> {
    let Candidate {
        mut value,
        provenance,
        routes_on_data,
    } = candidate;

    let shape = ValueShape::of(value.full());
    value.entropy = shape.entropy;
    value.propagates = provenance.has_handover();
    value.coverage = coverage(&provenance, transactions);

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
    value.score = raw_score(&value, &shape, &provenance) * salience.damping;

    let qualifies = provenance::admissible(&provenance, &shape, thresholds)
        && value.occurrences >= thresholds.value_min_occurrences
        && value.entropy >= thresholds.value_min_entropy_bits
        && value.score >= thresholds.value_min_score;

    qualifies.then_some(value)
}

/// Share of the capture's transactions in which the value appeared.
fn coverage(provenance: &Provenance, transactions: usize) -> f64 {
    if transactions == 0 {
        return 0.0;
    }
    (provenance.sighted_transactions() as f64 / transactions as f64).min(1.0)
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
fn raw_score(value: &StrongValue, shape: &ValueShape, provenance: &Provenance) -> f64 {
    let randomness = stats::normalize(shape.entropy, ENTROPY_CEILING);
    let handover = if value.propagates { 1.0 } else { 0.0 };
    let reach = stats::saturate(value.endpoints.len().saturating_sub(1), SPREAD_HALF_POINT);

    shape.identifier_weight * W_SHAPE
        + randomness * W_ENTROPY
        + handover * W_HANDOVER
        + provenance.anchoring() * W_ANCHORING
        + reach * W_SPREAD
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

        for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
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
        let thresholds = Thresholds::for_mode(Mode::Peaceful);

        let everywhere = mine(&observations, &table_of_size(4), &thresholds);
        let occasional = mine(&observations, &table_of_size(20), &thresholds);

        assert_eq!(everywhere.len(), 1);
        assert_eq!(occasional.len(), 1);
        assert!((everywhere[0].coverage - 1.0).abs() < f64::EPSILON);
        assert!(everywhere[0].score < occasional[0].score);

        // In standard mode the same penalty is enough to reject it outright.
        let thresholds = Thresholds::for_mode(Mode::Standard);
        assert!(mine(&observations, &table_of_size(4), &thresholds).is_empty());
        assert_eq!(mine(&observations, &table_of_size(20), &thresholds).len(), 1);
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

        assert_eq!(standard.len(), 2, "both values clear the standard bar");
        assert_eq!(
            apocalyptic.len(),
            1,
            "only the handed-over token clears the apocalyptic bar"
        );
        assert_eq!(apocalyptic[0].full(), TOKEN);
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

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Peaceful));
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

        let mined = mine(&observations, &table, &Thresholds::for_mode(Mode::Peaceful));
        assert!(mined.len() >= 2);
        assert!(mined[0].score >= mined[1].score);
    }
}
