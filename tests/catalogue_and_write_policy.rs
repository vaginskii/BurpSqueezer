//! Regression tests for the catalogue and deliberate-write policies.
//!
//! One capture drives both, because both failures come from the same habit of
//! ranking traffic by how much of it there is. An endpoint that ships a static
//! table produces three hundred perfectly shaped identifiers that mean nothing,
//! and they crowd out the four values the capture is actually about. Meanwhile
//! the call worth reading most — one write, to one object, never repeated —
//! carries the least evidence of any kind and sinks to the bottom. A separate
//! test states that shared cause on its own: repetition buys no rank.
//!
//! Each test below checks both directions. Suppressing a catalogue is easy if
//! one is willing to suppress every identifier; promoting a rare write is easy
//! if one is willing to promote every rare thing. So the fixture pairs each
//! case with its control: a short list of ids in the same shape from the same
//! kind of endpoint, one catalogue row the client actually sent back, and a
//! rare *read* of one object alongside the rare write.
//!
//! One thing is deliberately *not* claimed: that the write outranks every read
//! in the capture. The promotion spends the headroom an endpoint has left, so it
//! lifts a write that earned nothing a long way and one that earned plenty
//! hardly at all — and it can never carry a write past a read that earned more
//! on its own. That ceiling is the whole point of
//! `aggregator::tests::promoting_a_write_never_costs_another_endpoint_relevance`:
//! the rule adds attention rather than taking it from somewhere else. This
//! capture shows it in Apocalyptic, where the mode's ubiquity damping rejects the
//! session token, the write is left with nothing of its own, and the account read
//! — which carries the identifier the whole capture is about, and a chain hop
//! besides — ranks a shade higher. Forcing the other order would take a lift of
//! 0.634 fitted to this one fixture, and the next read to earn 0.7 would defeat
//! it again. What the tests below pin instead is what holds by arithmetic in any
//! capture: the write reaches Core Signal, beats the matched read that only
//! looks, and beats every route the capture left empty-handed.
//!
//! What is isolated here is the outcome, not the arithmetic. The unit tests in
//! `analysis::salience` and `pipeline::aggregator` pin each mechanism on its
//! own; these say what the report must end up saying.

mod common;

use std::collections::HashSet;

use burpsqueezer::analysis::fingerprint::fingerprint;
use burpsqueezer::config::Mode;
use burpsqueezer::model::report::{EndpointRow, ReportModel, ValueRow};
use common::fixture;

const MODES: [Mode; 3] = [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic];

/// Modes whose score bar admits an identifier the client never sent back.
///
/// Apocalyptic rejects those outright, so a catalogue it drops proves nothing
/// about the catalogue rule — it would have dropped a two-row list just the
/// same. Comparing bulk against a short list is only meaningful where a short
/// list can survive at all.
const MODES_ADMITTING_UNRETURNED_IDS: [Mode; 2] = [Mode::Peaceful, Mode::Standard];

// The fixture's two catalogues, restated by formula rather than by three
// hundred literals. Drift between generator and test surfaces immediately:
// every row the report is required to *keep* is named the same way.
const PALETTE_NAMESPACE: u64 = 0x0050_414C;
const TIER_NAMESPACE: u64 = 0x5449_4552;
const PALETTE_ROWS: u64 = 300;
const TIER_ROWS: u64 = 6;
/// The single palette row the capture shows a client choosing and sending back.
const CHOSEN_PALETTE_ROW: u64 = 17;
/// The same, from the short catalogue.
const CHOSEN_TIER_ROW: u64 = 3;

/// The identifier the whole capture is about: issued once, then addressed.
const ACCOUNT: &str = "acct_9Xq2Lm4Rt7Kd";

/// One write, to one object, seen once and never again.
/// Path normalization now collapses numeric IDs to {id} based on shape.
const DELIBERATE_WRITE: &str = "DELETE /api/rooms/{id}/members/{id}";
/// The control: as rare, as instance-shaped, but it only reads.
/// Path normalization now collapses numeric IDs to {id} based on shape.
const RARE_READ: &str = "GET /api/rooms/{id}/members";

fn squeeze(mode: Mode) -> ReportModel {
    burpsqueezer::squeeze(&fixture("catalogue.xml"), mode).expect("fixture must analyse")
}

fn splitmix64(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The generator behind the fixture's catalogue rows: a canonical UUID.
fn catalogue_row(namespace: u64, index: u64) -> String {
    let high = splitmix64(namespace.wrapping_add(index));
    let low = splitmix64(high);
    let digits = format!("{high:016x}{low:016x}");
    format!(
        "{}-{}-{}-{}-{}",
        &digits[0..8],
        &digits[8..12],
        &digits[12..16],
        &digits[16..20],
        &digits[20..32]
    )
}

/// Values are reported by handle, so that is what identifies them.
fn handle_of(value: &str) -> String {
    format!("fp:{}", fingerprint(value))
}

fn reported_values(model: &ReportModel) -> HashSet<&str> {
    model
        .strong_values
        .iter()
        .map(|value| value.handle.as_str())
        .collect()
}

/// The report in reading order: Core Signal first, then Secondary Context.
///
/// Rank is position in this sequence, which is what a reader actually meets —
/// an endpoint's place in the report is set by its section first and its
/// relevance second, and comparing relevance alone would miss a row promoted
/// past another by the split.
fn as_read(model: &ReportModel) -> impl Iterator<Item = &EndpointRow> {
    model.core_endpoints.iter().chain(&model.other_endpoints)
}

/// Where the reader meets an endpoint, and what the report says about it.
fn listed<'a>(model: &'a ReportModel, endpoint: &str) -> (usize, &'a EndpointRow) {
    as_read(model)
        .enumerate()
        .find(|(_, row)| row.endpoint == endpoint)
        .unwrap_or_else(|| panic!("{endpoint} is missing from the report"))
}

// --- The catalogue rule -----------------------------------------------------

/// The headline symptom: three hundred rows of a shipped table, every one of
/// them a well-formed UUID handed over by the server, filling Core Signal.
#[test]
fn rows_of_a_bulk_catalogue_never_become_strong_values() {
    for mode in MODES {
        let model = squeeze(mode);
        let reported = reported_values(&model);

        for index in (0..PALETTE_ROWS).filter(|index| *index != CHOSEN_PALETTE_ROW) {
            let handle = handle_of(&catalogue_row(PALETTE_NAMESPACE, index));
            assert!(
                !reported.contains(handle.as_str()),
                "{mode:?}: catalogue row {index} reached Strong Values as {handle}"
            );
        }
    }
}

/// The other direction, and the sharpest case in the fixture: one row of that
/// same table is chosen by a client and sent back. Nothing about the value
/// changed — same endpoint, same body slot, same shape as its 299 siblings —
/// only its use. That is what the rule keys on, so that row must survive.
#[test]
fn a_catalogue_row_the_client_sends_back_is_kept() {
    for mode in MODES {
        let model = squeeze(mode);

        for (label, handle) in [
            (
                "palette",
                handle_of(&catalogue_row(PALETTE_NAMESPACE, CHOSEN_PALETTE_ROW)),
            ),
            (
                "tier",
                handle_of(&catalogue_row(TIER_NAMESPACE, CHOSEN_TIER_ROW)),
            ),
        ] {
            let value = model
                .strong_values
                .iter()
                .find(|value| value.handle == handle)
                .unwrap_or_else(|| panic!("{mode:?}: the chosen {label} row was suppressed"));
            assert!(
                value.propagates,
                "{mode:?}: the chosen {label} row is only interesting because it travelled"
            );
        }
    }
}

/// Bulk is the whole charge. The fixture serves a six-row table from a second
/// endpoint of exactly the same kind, and those rows are ordinary application
/// data: nothing about being a list, being exclusive to one endpoint, or never
/// being sent back may suppress them on its own.
#[test]
fn a_short_list_of_the_same_ids_is_left_alone() {
    for mode in MODES_ADMITTING_UNRETURNED_IDS {
        let model = squeeze(mode);
        let reported = reported_values(&model);

        for index in 0..TIER_ROWS {
            let handle = handle_of(&catalogue_row(TIER_NAMESPACE, index));
            assert!(
                reported.contains(handle.as_str()),
                "{mode:?}: short-list row {index} was lost, expected handle {handle}"
            );
        }
    }
}

/// Suppression must not be achieved by suppressing everything.
#[test]
fn the_identifier_the_capture_is_about_survives_every_mode() {
    for mode in MODES {
        let model = squeeze(mode);
        let handle = handle_of(ACCOUNT);
        assert!(
            reported_values(&model).contains(handle.as_str()),
            "{mode:?}: the account identifier was lost, expected handle {handle}"
        );
    }
}

// --- Ranking by worth rather than by volume -----------------------------------

/// The rule underneath both of the above, stated where a reader would see it:
/// how much a value is worth is not how often it turned up.
///
/// This capture's most repeated application value is a room id the client puts
/// in sixteen paths, which no response ever handed over. Score it on repetition
/// and it leads Strong Values; it must instead rank below every value a server
/// issued and a client sent back, several of which were seen four times.
///
/// Checked in Safe alone, because Safe is the only mode whose bar admits the
/// weak value at all — and being admitted yet ranked last is precisely what
/// distinguishes a penalty from a rejection. Nothing here is hardcoded: the
/// capture is asked which of its values repeat and which travel.
#[test]
fn repetition_alone_does_not_buy_rank() {
    let model = squeeze(Mode::Peaceful);
    let ranked: Vec<(usize, &ValueRow)> = model.strong_values.iter().enumerate().collect();

    let (weakest_rank, repeated) = ranked
        .iter()
        .filter(|(_, value)| !value.propagates)
        .max_by_key(|(_, value)| value.occurrences)
        .copied()
        .expect("the capture must report a value nobody handed over");

    let handed_over: Vec<(usize, &ValueRow)> = ranked
        .iter()
        .filter(|(_, value)| value.propagates)
        .copied()
        .collect();
    assert!(
        !handed_over.is_empty(),
        "the capture must report values that travelled, or there is nothing to compare"
    );

    for (rank, value) in &handed_over {
        assert!(
            *rank < weakest_rank,
            "a value seen {} times outranked {}, which travelled and was seen {}",
            repeated.occurrences,
            value.handle,
            value.occurrences
        );
    }

    assert!(
        handed_over
            .iter()
            .any(|(_, value)| value.occurrences < repeated.occurrences),
        "the comparison is vacuous unless the repeated value really is the more repeated one"
    );
}

// --- The deliberate-write rule ----------------------------------------------

/// A single DELETE against one object, in a capture whose busiest route was
/// called twelve times. Ranked on evidence alone it has almost none: one hit,
/// one status, no mined value of its own.
#[test]
fn a_rare_write_to_one_object_reaches_core_signal() {
    for mode in MODES {
        let model = squeeze(mode);
        assert!(
            model
                .core_endpoints
                .iter()
                .any(|row| row.endpoint == DELIBERATE_WRITE),
            "{mode:?}: the capture's one deliberate write is not in Core Signal"
        );
    }
}

/// The floor under the promotion, and the one ordering that holds by arithmetic
/// rather than by luck.
///
/// A read that yielded nothing scores on its fields and its status spread and
/// nothing else, which caps it at `W_FIELDS + W_STATUS` = 0.25. A write seen
/// once is rare by definition, so it takes the full lift on top of `W_METHOD`:
/// 0.46 even in Safe, whose lift is the gentlest of the three. The gap is a
/// property of the weights, so no capture can close it — which is exactly what
/// makes this worth asserting where the ranking against well-evidenced reads is
/// not.
///
/// Only Apocalyptic leaves a read empty-handed here. The milder modes mine the
/// session token, and every route in the capture carries it, so every route has
/// something to show. Hence the tally: if a change ever gives every route a
/// value in every mode, this test must fail rather than quietly stop testing.
#[test]
fn a_deliberate_write_outranks_a_read_that_yielded_nothing() {
    let mut compared = 0;

    for mode in MODES {
        let model = squeeze(mode);
        let (write_rank, _) = listed(&model, DELIBERATE_WRITE);

        for (rank, row) in as_read(&model).enumerate() {
            if !row.endpoint.starts_with("GET ") || !row.value_handles.is_empty() {
                continue;
            }
            compared += 1;
            assert!(
                write_rank < rank,
                "{mode:?}: {} yielded nothing and still outranked the capture's one \
                 deliberate write",
                row.endpoint
            );
        }
    }

    assert!(
        compared > 0,
        "no mode left a read empty-handed, so this compared nothing"
    );
}

/// The control that keeps the rule from being "anything seen once", and the
/// tightest comparison the capture can make. These two routes are matched on
/// everything the report shows: one hit each, each naming one object, neither
/// carrying traffic the other lacks. The verb is the only thing left that can
/// separate them, so whatever separates them in the report is the verb.
#[test]
fn a_rare_read_of_one_object_is_not_promoted_with_the_write() {
    for mode in MODES {
        let model = squeeze(mode);
        let (write_rank, write) = listed(&model, DELIBERATE_WRITE);
        let (read_rank, read) = listed(&model, RARE_READ);

        assert_eq!(
            write.hits, read.hits,
            "{mode:?}: the pair is only matched for as long as the traffic is"
        );
        assert!(
            write.relevance > read.relevance,
            "{mode:?}: a rare read scored {} against a rare write's {}",
            read.relevance,
            write.relevance
        );
        assert!(
            write_rank < read_rank,
            "{mode:?}: a rare read outranked a rare write on the same shape of route"
        );

        if model.other_endpoints.is_empty() {
            continue;
        }
        assert!(
            !model
                .core_endpoints
                .iter()
                .any(|row| row.endpoint == RARE_READ),
            "{mode:?}: a rare read reached Core Signal alongside the write"
        );
    }
}
