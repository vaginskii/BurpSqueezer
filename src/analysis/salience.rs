//! How much a value's presence actually distinguishes anything.
//!
//! Mining scores a value on what it looks like and where it came from. That is
//! necessary but not sufficient: a string can be long, well-shaped and anchored
//! in application data and still be worthless to read, because it is one row of
//! a catalogue the server ships wholesale. This module is the single place that
//! decides how much a candidate's score survives that judgement, and mining
//! applies its verdict exactly once.
//!
//! Three effects compose here, and they are three different ways for a
//! well-formed value to distinguish nothing.
//! [`provenance::ubiquity_damping`] handles a value spread across *too much* of
//! the capture to identify any part of it. [`Corpus`] handles the reverse: a
//! value confined to one endpoint that emits vocabulary in bulk. And
//! [`label_damping`] handles the value that was never a handle at all, but a word.
//! None of them needs to know what an application calls anything.

use std::collections::{BTreeSet, HashMap, HashSet};

use super::provenance::{self, Provenance, SourceClass, ValueShape};
use crate::config::Thresholds;
use crate::model::endpoint::{EndpointTable, UNMAPPED_ENDPOINT};
use crate::model::value::ObservedValue;

/// Smallest capture in which confinement to one endpoint means anything.
///
/// With a single endpoint every value is confined to it by definition, so the
/// rule would fire on the whole capture. Below this it abstains entirely.
const MIN_ENDPOINTS_TO_JUDGE: usize = 2;

/// What each endpoint's application slots emit, measured across the capture.
///
/// Built once from the same observation stream mining consumes, so no message is
/// walked twice.
#[derive(Debug, Default)]
pub struct Corpus {
    endpoints: usize,
    vocabularies: HashMap<String, Vocabulary>,
}

/// One endpoint's output, reduced to the two figures that identify a catalogue.
#[derive(Debug, Default)]
struct Vocabulary {
    /// Distinct values per retained transaction.
    ///
    /// Per transaction rather than in total, because otherwise the figure would
    /// grow with how often the endpoint happened to be captured, and the same
    /// endpoint would be judged differently in a long dump than in a short one.
    per_transaction: f64,
    /// Share of those values seen at no other endpoint.
    ///
    /// A catalogue is self-contained: its rows exist nowhere else in the API. A
    /// busy endpoint that reports live state shares most of its values with the
    /// endpoints that produced them, and this is what tells the two apart.
    exclusivity: f64,
}

impl Corpus {
    /// Profile every endpoint's application-slot vocabulary.
    pub fn profile(observations: &[ObservedValue], table: &EndpointTable) -> Self {
        let mut emitted: HashMap<usize, HashSet<&str>> = HashMap::new();
        let mut origins: HashMap<&str, HashSet<usize>> = HashMap::new();

        for observation in observations {
            if provenance::source_class(&observation.location) != SourceClass::Application {
                continue;
            }
            let Some(slot) = table.slot_of_tx(observation.tx_id) else {
                continue;
            };
            emitted
                .entry(slot)
                .or_default()
                .insert(observation.value.as_str());
            origins
                .entry(observation.value.as_str())
                .or_default()
                .insert(slot);
        }

        let vocabularies = emitted
            .into_iter()
            .filter_map(|(slot, values)| {
                let stats = table.endpoints.get(slot)?;
                let hits = stats.hits();
                if hits == 0 {
                    return None;
                }
                let exclusive = values
                    .iter()
                    .copied()
                    .filter(|value| origins.get(value).is_some_and(|places| places.len() == 1))
                    .count();
                let vocabulary = Vocabulary {
                    per_transaction: values.len() as f64 / hits as f64,
                    exclusivity: exclusive as f64 / values.len() as f64,
                };
                Some((stats.endpoint.key(), vocabulary))
            })
            .collect();

        Self {
            endpoints: table.len(),
            vocabularies,
        }
    }

    /// Whether an endpoint ships vocabulary in bulk rather than reporting state.
    fn emits_in_bulk(&self, key: &str, thresholds: &Thresholds) -> bool {
        self.vocabularies.get(key).is_some_and(|vocabulary| {
            vocabulary.per_transaction >= thresholds.dictionary_min_vocabulary_per_hit
                && vocabulary.exclusivity >= thresholds.dictionary_min_exclusivity
        })
    }
}

/// Everything the salience rules judge about one candidate.
///
/// Gathered at the single call site that has all of it to hand. Passing the
/// evidence rather than five positional numbers is what stops a later rule from
/// needing another parameter threaded through, and makes it impossible to swap
/// two `f64`s at the call site without the compiler noticing.
#[derive(Debug, Clone, Copy)]
pub struct Evidence<'a> {
    /// Share of the capture's retained transactions the value appeared in.
    pub coverage: f64,
    /// Endpoint keys the value was seen at.
    pub endpoints: &'a BTreeSet<String>,
    /// What the value's characters look like.
    pub shape: &'a ValueShape,
    /// Where the value was seen, and how it travelled.
    pub provenance: &'a Provenance,
    /// Whether the value ever named a path position the capture showed varying.
    ///
    /// The distinction a route noun cannot survive: `settings` in
    /// `/api/{id}/settings` sits in the path exactly as an object id does, but
    /// the position never varied, so the value is part of the route's name
    /// rather than an argument to it.
    pub routes_on_data: bool,
}

/// The salience verdict on one candidate.
#[derive(Debug, Clone, Copy)]
pub struct Salience {
    /// How far the value is spread, as [`provenance::ubiquity`] measures it.
    ///
    /// Returned rather than kept private because later stages — endpoint
    /// relevance, sequence anchoring, chain rendering — all need to know how
    /// ubiquitous a value is, and re-deriving it in each of them is how four
    /// stages come to disagree about which values are session furniture.
    pub spread: f64,
    /// The multiplier mining applies to the candidate's raw score.
    pub damping: f64,
}

/// Weigh one candidate's presence. One call, one verdict.
///
/// Composing the effects here rather than at the call site is what keeps "how
/// much is this presence worth" answerable in a single place.
pub fn judge(evidence: &Evidence<'_>, corpus: &Corpus, thresholds: &Thresholds) -> Salience {
    let spread = spread(evidence, corpus);
    Salience {
        spread,
        damping: provenance::ubiquity_damping(spread, thresholds)
            * dictionary_damping(evidence, corpus, thresholds)
            * label_damping(evidence, thresholds),
    }
}

/// How far the value reaches, over transactions and over routes together.
///
/// Below [`MIN_ENDPOINTS_TO_JUDGE`] the route evidence is abstained from for the
/// same reason the catalogue rule abstains: with one endpoint in the capture
/// every value sits at 100% of the routes by definition, and letting that count
/// would mark the whole dump ubiquitous.
fn spread(evidence: &Evidence<'_>, corpus: &Corpus) -> f64 {
    if corpus.endpoints < MIN_ENDPOINTS_TO_JUDGE {
        return evidence.coverage;
    }
    provenance::ubiquity(
        evidence.coverage,
        provenance::endpoint_share(evidence.endpoints, corpus.endpoints),
    )
}

/// Penalty for a value that is a word rather than a handle.
///
/// Two conditions hold together. The characters are vocabulary — letter runs in
/// one case, joined by nothing more than a separator, which is not how anything
/// mints an identifier. And the value never named a path position the capture
/// showed varying, so wherever it sat in a route it sat there as the route's own
/// name.
///
/// The gate is on *shape*, not entropy, and the reference capture is why. The
/// word `custom_properties` carries 3.38 bits per byte; a real eight-digit chat
/// id carries 2.50. An entropy rule would rank the noise above the signal and
/// delete the wrong one. Shape separates them cleanly: bare digits are still a
/// generated form and sit above the ceiling, prose does not.
///
/// Handover is deliberately not a third condition. An enum member legitimately
/// round-trips — the server prints it in a response body, the client posts it
/// back — so sparing anything that crossed once would spare most of the
/// vocabulary this exists to sink, which is exactly what the measurements showed.
///
/// This is a discount, not a ban-list. A word that does name a varying position,
/// or that turns out to be a token after all, keeps its full score.
fn label_damping(evidence: &Evidence<'_>, thresholds: &Thresholds) -> f64 {
    let is_vocabulary = evidence.shape.identifier_weight < thresholds.label_max_shape_weight;
    if is_vocabulary && !evidence.routes_on_data {
        return thresholds.label_floor;
    }
    1.0
}

/// Penalty for a value that is one row of a static catalogue.
///
/// Four conditions have to hold together, and each one on its own is innocent.
/// The value is confined to a single endpoint, so it ties nothing together. No
/// response ever handed it to a later request, so it drives no flow. It was
/// never used to address a request, so it is not a handle. And the endpoint it
/// came from emits vocabulary in bulk, exclusively its own. A value that meets
/// all four was read out of a fixed table that happens to be served over HTTP:
/// there is nothing for a reader to do with it, and there are usually hundreds
/// more exactly like it queued behind it.
///
/// Requiring all four is what makes the rule safe. An identifier fails the first
/// or the third, live state fails the fourth, and a credential fails the second.
fn dictionary_damping(
    evidence: &Evidence<'_>,
    corpus: &Corpus,
    thresholds: &Thresholds,
) -> f64 {
    if corpus.endpoints < MIN_ENDPOINTS_TO_JUDGE {
        return 1.0;
    }
    let mut mapped = evidence
        .endpoints
        .iter()
        .filter(|key| *key != UNMAPPED_ENDPOINT);
    let Some(sole) = mapped.next() else {
        return 1.0;
    };
    if mapped.next().is_some() {
        return 1.0;
    }
    if evidence.provenance.has_handover() || evidence.provenance.addresses_a_request() {
        return 1.0;
    }
    if !corpus.emits_in_bulk(sole, thresholds) {
        return 1.0;
    }
    thresholds.dictionary_floor
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::entropy::CharShape;
    use crate::config::Mode;
    use crate::model::endpoint::Endpoint;
    use crate::model::transaction::TxId;
    use crate::model::value::{Direction, ValueLocation};

    const CATALOGUE: &str = "GET /assets/catalogue.json";
    const RESOURCE: &str = "GET /api/items/{id}";

    /// A capture in which one endpoint ships a big exclusive catalogue and
    /// another reports ordinary state.
    fn capture(rows: usize) -> (Vec<ObservedValue>, EndpointTable) {
        let mut table = EndpointTable::new();
        let mut observations = Vec::new();

        let catalogue = table.slot_for(Endpoint::new("GET", "/assets/catalogue.json"));
        table.assign(0, catalogue);
        table
            .stats_mut(catalogue)
            .expect("slot just created")
            .tx_ids
            .push(0);
        for row in 0..rows {
            observations.push(seen(
                0,
                Direction::Response,
                ValueLocation::BodyField("rows.name".into()),
                &format!("row-{row:04}"),
            ));
        }

        let items = table.slot_for(Endpoint::new("GET", "/api/items/{id}"));
        for tx in 1..4 {
            table.assign(tx, items);
            table
                .stats_mut(items)
                .expect("slot just created")
                .tx_ids
                .push(tx);
            observations.push(seen(
                tx,
                Direction::Response,
                ValueLocation::BodyField("item.state".into()),
                "settled",
            ));
        }

        (observations, table)
    }

    fn seen(
        tx_id: TxId,
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

    fn keys(key: &str) -> BTreeSet<String> {
        BTreeSet::from([key.to_string()])
    }

    fn body(field: &str) -> ValueLocation {
        ValueLocation::BodyField(field.to_string())
    }

    /// Evidence with an identifier-shaped value, so the vocabulary rule abstains
    /// and a test of one effect measures only that effect.
    fn evidence<'a>(
        coverage: f64,
        endpoints: &'a BTreeSet<String>,
        provenance: &'a Provenance,
        shape: &'a ValueShape,
    ) -> Evidence<'a> {
        Evidence {
            coverage,
            endpoints,
            shape,
            provenance,
            routes_on_data: false,
        }
    }

    fn handle_shape() -> ValueShape {
        ValueShape::of("3f2504e0-4f89-11d3-9a0c-0305e82c3301")
    }

    #[test]
    fn a_bulk_emitter_is_told_apart_from_a_busy_endpoint() {
        let thresholds = Thresholds::for_mode(Mode::Standard);
        let (observations, table) = capture(400);
        let corpus = Corpus::profile(&observations, &table);

        assert!(corpus.emits_in_bulk(CATALOGUE, &thresholds));
        assert!(!corpus.emits_in_bulk(RESOURCE, &thresholds));
        assert!(!corpus.emits_in_bulk("GET /never/seen", &thresholds));
    }

    /// The whole point: a row of a shipped table is damped, and every kind of
    /// value that merely resembles one is not.
    #[test]
    fn only_a_confined_unanchored_catalogue_row_is_damped() {
        let thresholds = Thresholds::for_mode(Mode::Standard);
        let (observations, table) = capture(400);
        let corpus = Corpus::profile(&observations, &table);
        let printed = body("rows.name");
        let shape = handle_shape();

        let row = Provenance::of([provenance::Sighting {
            tx_id: 0,
            direction: Direction::Response,
            location: &printed,
        }]);
        assert_eq!(
            dictionary_damping(
                &evidence(0.1, &keys(CATALOGUE), &row, &shape),
                &corpus,
                &thresholds
            ),
            thresholds.dictionary_floor
        );

        // Handed over to a later request: it drives a flow, whatever it is.
        let returned = ValueLocation::QueryParam("code".into());
        let handed_over = Provenance::of([
            provenance::Sighting {
                tx_id: 0,
                direction: Direction::Response,
                location: &printed,
            },
            provenance::Sighting {
                tx_id: 1,
                direction: Direction::Request,
                location: &returned,
            },
        ]);
        assert_eq!(
            dictionary_damping(
                &evidence(0.1, &keys(CATALOGUE), &handed_over, &shape),
                &corpus,
                &thresholds
            ),
            1.0
        );

        // Seen at a second endpoint: it ties two places together.
        let mut spread = keys(CATALOGUE);
        spread.insert(RESOURCE.to_string());
        assert_eq!(
            dictionary_damping(&evidence(0.1, &spread, &row, &shape), &corpus, &thresholds),
            1.0
        );

        // From an endpoint that reports state rather than shipping a table.
        assert_eq!(
            dictionary_damping(
                &evidence(0.1, &keys(RESOURCE), &row, &shape),
                &corpus,
                &thresholds
            ),
            1.0
        );
    }

    /// An endpoint too small to be a catalogue must not be treated as one, or
    /// the rule would quietly become "values seen once, in a body".
    #[test]
    fn a_small_vocabulary_is_not_a_catalogue() {
        let thresholds = Thresholds::for_mode(Mode::Standard);
        let (observations, table) = capture(8);
        let corpus = Corpus::profile(&observations, &table);
        let printed = body("rows.name");
        let shape = handle_shape();
        let row = Provenance::of([provenance::Sighting {
            tx_id: 0,
            direction: Direction::Response,
            location: &printed,
        }]);

        assert!(!corpus.emits_in_bulk(CATALOGUE, &thresholds));
        assert_eq!(
            dictionary_damping(
                &evidence(0.1, &keys(CATALOGUE), &row, &shape),
                &corpus,
                &thresholds
            ),
            1.0
        );
    }

    /// With nothing to compare against, confinement carries no information.
    #[test]
    fn a_single_endpoint_capture_is_never_judged() {
        let thresholds = Thresholds::for_mode(Mode::Standard);
        let mut table = EndpointTable::new();
        let slot = table.slot_for(Endpoint::new("GET", "/assets/catalogue.json"));
        table.assign(0, slot);
        table
            .stats_mut(slot)
            .expect("slot just created")
            .tx_ids
            .push(0);
        let observations: Vec<ObservedValue> = (0..400)
            .map(|row| {
                seen(
                    0,
                    Direction::Response,
                    ValueLocation::BodyField("rows.name".into()),
                    &format!("row-{row:04}"),
                )
            })
            .collect();
        let corpus = Corpus::profile(&observations, &table);
        let printed = body("rows.name");
        let shape = handle_shape();
        let row = Provenance::of([provenance::Sighting {
            tx_id: 0,
            direction: Direction::Response,
            location: &printed,
        }]);
        let at_catalogue = keys(CATALOGUE);
        let only_row = evidence(0.1, &at_catalogue, &row, &shape);

        assert_eq!(dictionary_damping(&only_row, &corpus, &thresholds), 1.0);

        // Route spread abstains for the same reason: one endpoint means every
        // value sits at all of them, which is not evidence of anything.
        assert_eq!(spread(&only_row, &corpus), 0.1);
    }

    /// Measured per transaction, so capturing the same endpoint more often
    /// cannot turn a live endpoint into a catalogue or spare a real one.
    #[test]
    fn bulk_is_measured_per_transaction_not_per_dump() {
        let thresholds = Thresholds::for_mode(Mode::Standard);
        let mut table = EndpointTable::new();
        let slot = table.slot_for(Endpoint::new("GET", "/api/feed"));
        let other = table.slot_for(Endpoint::new("GET", "/api/other"));
        table.assign(999, other);

        let mut observations = Vec::new();
        for tx in 0..50 {
            table.assign(tx, slot);
            table
                .stats_mut(slot)
                .expect("slot just created")
                .tx_ids
                .push(tx);
            for item in 0..4 {
                observations.push(seen(
                    tx,
                    Direction::Response,
                    ValueLocation::BodyField("feed.id".into()),
                    &format!("tx{tx}-item{item}"),
                ));
            }
        }

        // 200 distinct values in total, but only four per call.
        let corpus = Corpus::profile(&observations, &table);
        assert!(!corpus.emits_in_bulk("GET /api/feed", &thresholds));
    }

    #[test]
    fn every_mode_damps_a_catalogue_row_without_erasing_it() {
        let (observations, table) = capture(400);
        let printed = body("rows.name");
        let row = Provenance::of([provenance::Sighting {
            tx_id: 0,
            direction: Direction::Response,
            location: &printed,
        }]);

        let mut previous = 1.0;
        let shape = handle_shape();
        for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
            let thresholds = Thresholds::for_mode(mode);
            let corpus = Corpus::profile(&observations, &table);
            let damped = dictionary_damping(
                &evidence(0.1, &keys(CATALOGUE), &row, &shape),
                &corpus,
                &thresholds,
            );
            assert!(
                damped > 0.0 && damped < 1.0,
                "{mode} damping is not a usable multiplier: {damped}"
            );
            assert!(
                damped <= previous,
                "{mode} damps a catalogue row less than the gentler mode"
            );
            previous = damped;
        }
    }

    /// Composition, not any one effect alone, is what mining applies.
    #[test]
    fn every_effect_multiplies_into_one_verdict() {
        let thresholds = Thresholds::for_mode(Mode::Standard);
        let (observations, table) = capture(400);
        let corpus = Corpus::profile(&observations, &table);
        let printed = body("rows.name");
        let row = Provenance::of([provenance::Sighting {
            tx_id: 0,
            direction: Direction::Response,
            location: &printed,
        }]);
        let shape = handle_shape();

        let rare = judge(
            &evidence(0.1, &keys(CATALOGUE), &row, &shape),
            &corpus,
            &thresholds,
        );
        let everywhere = judge(
            &evidence(1.0, &keys(CATALOGUE), &row, &shape),
            &corpus,
            &thresholds,
        );

        assert!((rare.damping - thresholds.dictionary_floor).abs() < 1e-9);
        assert!(
            (everywhere.damping - thresholds.dictionary_floor * thresholds.ubiquity_floor).abs()
                < 1e-9
        );

        // A word on top of the catalogue row takes the third discount as well.
        let word = ValueShape::of("scheduled_drafts");
        let labelled = judge(
            &evidence(0.1, &keys(CATALOGUE), &row, &word),
            &corpus,
            &thresholds,
        );
        assert!(
            (labelled.damping - thresholds.dictionary_floor * thresholds.label_floor).abs() < 1e-9
        );
    }

    /// The mid-tier failure this rule exists for. Every value here passed length,
    /// entropy and anchoring, and every one of them is a word: an enum member, a
    /// region label, a settings key, a protocol name. Meanwhile the values that
    /// must survive carry *less* entropy than the noise, which is why the gate is
    /// on shape.
    #[test]
    fn a_word_is_discounted_and_an_identifier_is_not() {
        let thresholds = Thresholds::for_mode(Mode::Standard);
        let endpoints = keys(RESOURCE);
        let printed = body("rows.name");
        let anywhere = Provenance::of([provenance::Sighting {
            tx_id: 0,
            direction: Direction::Response,
            location: &printed,
        }]);

        for word in [
            "custom_properties",
            "Europe/Moscow",
            "chat_subtype",
            "websocket",
            "scheduled_drafts",
            "light-slate-gray",
        ] {
            let shape = ValueShape::of(word);
            assert_eq!(
                label_damping(&evidence(0.1, &endpoints, &anywhere, &shape), &thresholds),
                thresholds.label_floor,
                "{word} kept a handle's score"
            );
        }

        for identifier in [
            "81269913",
            "595931",
            "someone@example.com",
            "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.Xk9sQ2p1bXBlcg",
            "deadbeefcafe1234",
        ] {
            let shape = ValueShape::of(identifier);
            assert_eq!(
                label_damping(&evidence(0.1, &endpoints, &anywhere, &shape), &thresholds),
                1.0,
                "{identifier} was discounted as vocabulary"
            );
        }

        // The measured inversion an entropy rule would get backwards.
        assert!(
            ValueShape::of("custom_properties").entropy > ValueShape::of("81269913").entropy,
            "the noise really does carry more entropy than the signal"
        );
    }

    /// A word that names a varying route position is an identifier that happens
    /// to be pronounceable — a slug — and keeps its score.
    #[test]
    fn a_word_that_names_a_varying_position_is_spared() {
        let thresholds = Thresholds::for_mode(Mode::Standard);
        let endpoints = keys(RESOURCE);
        let slug = ValueShape::of("acme-corp");
        let in_path = ValueLocation::PathSegment(2);
        let addressed = Provenance::of([provenance::Sighting {
            tx_id: 0,
            direction: Direction::Request,
            location: &in_path,
        }]);

        let mut spared = evidence(0.1, &endpoints, &addressed, &slug);
        spared.routes_on_data = true;
        assert_eq!(label_damping(&spared, &thresholds), 1.0);

        // The same word at a position the capture never varied is a route noun.
        let noun = evidence(0.1, &endpoints, &addressed, &slug);
        assert_eq!(label_damping(&noun, &thresholds), thresholds.label_floor);
    }

    /// The discount tracks the mode like every other, and never erases.
    #[test]
    fn the_vocabulary_rule_only_ever_tightens_with_the_mode() {
        let endpoints = keys(RESOURCE);
        let word = ValueShape::of("multi_select");
        let printed = body("rows.name");
        let anywhere = Provenance::of([provenance::Sighting {
            tx_id: 0,
            direction: Direction::Response,
            location: &printed,
        }]);

        let mut previous = 1.0;
        for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
            let thresholds = Thresholds::for_mode(mode);
            let damped =
                label_damping(&evidence(0.1, &endpoints, &anywhere, &word), &thresholds);
            assert!(
                damped > 0.0 && damped < 1.0,
                "{mode} vocabulary damping is not a usable multiplier: {damped}"
            );
            assert!(damped <= previous, "{mode} damps a word less than a gentler mode");
            previous = damped;
        }
    }

    /// The gate is a line drawn between two known shape weights, and it is only
    /// meaningful while it stays between them. If [`CharShape`] weights are ever
    /// retuned, this is what says so before a report does.
    #[test]
    fn the_vocabulary_gate_sits_between_words_and_bare_digits() {
        for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
            let gate = Thresholds::for_mode(mode).label_max_shape_weight;
            assert!(
                gate > CharShape::Wordlike.identifier_weight(),
                "{mode} gate {gate} lets vocabulary through"
            );
            assert!(
                gate <= CharShape::Numeric.identifier_weight(),
                "{mode} gate {gate} would discount a bare numeric id"
            );
        }
    }
}
