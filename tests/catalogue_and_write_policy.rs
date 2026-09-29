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
//! One thing is deliberately *not* claimed of the catalogue rule: that a bulk
//! row is erased. It is discounted, and the code says so where the rule lives —
//! `thresholds::tests::the_catalogue_rule_only_ever_tightens_with_the_mode`
//! ("a discount, never an erasure") and `salience::label_damping` ("a discount,
//! not a ban-list"). A multiplier cannot promise absence, only a lower price, so
//! what the test below pins is the property a multiplier really has: where the
//! discount is decisive the rows are gone, and where it is not, every row that
//! survives ranks below the one row of the same table that earned its place.
//!
//! The ceiling on the write promotion is stated the same way. The promotion
//! spends the headroom an endpoint has left, so it can never carry a write past
//! a read that earned more on its own — that is the point of
//! `aggregator::tests::promoting_a_write_never_costs_another_endpoint_relevance`.
//! What the tests below claim is narrower and true of this capture: the write
//! reaches Core Signal, beats the matched read that only looks, and outranks
//! every read the capture contains.
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

/// Modes whose discount is decisive on a catalogue this size.
///
/// Peaceful is excluded, and its exclusion is the contract rather than an
/// exception. Peaceful pairs the lowest score bar of the three with the mildest
/// catalogue discount, so a well-shaped catalogue row can still clear the bar
/// after being marked down. The stricter modes ask for less evidence before
/// discounting and then discount harder, which on this fixture is the difference
/// between a row being reported and not.
const MODES_DISCOUNTING_BULK_AWAY: [Mode; 2] = [Mode::Standard, Mode::Apocalyptic];

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
    burpsqueezer::squeeze(&fixture("catalogue.xml"), mode, true).expect("fixture must analyse")
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

/// The score the report gave a handle, if it reported it at all.
fn score_of(model: &ReportModel, handle: &str) -> Option<f64> {
    model
        .strong_values
        .iter()
        .find(|value| value.handle == handle)
        .map(|value| value.score)
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
///
/// What the rule owes the reader is a price, not a purge, so this asks for the
/// two things a discount can actually deliver. Where the mark-down is decisive
/// the rows are gone. Everywhere, including the mode where they are not, a row
/// that nobody ever sent back ranks below the one row of its own table that was
/// — same endpoint, same body slot, same shape as its 299 siblings, differing
/// only in use. That is what the rule keys on, and it is the property that
/// survives being a multiplier.
#[test]
fn rows_of_a_bulk_catalogue_are_priced_below_the_row_a_client_sent_back() {
    let chosen = handle_of(&catalogue_row(PALETTE_NAMESPACE, CHOSEN_PALETTE_ROW));
    let bulk: Vec<String> = (0..PALETTE_ROWS)
        .filter(|index| *index != CHOSEN_PALETTE_ROW)
        .map(|index| handle_of(&catalogue_row(PALETTE_NAMESPACE, index)))
        .collect();

    for mode in MODES {
        let model = squeeze(mode);
        let chosen_score = score_of(&model, &chosen)
            .unwrap_or_else(|| panic!("{mode:?}: the chosen palette row was suppressed, so \
                there is nothing for the bulk rows to rank below"));
        let reported = reported_values(&model);

        for handle in &bulk {
            match score_of(&model, handle) {
                None => {}
                Some(score) => assert!(
                    score < chosen_score,
                    "{mode:?}: {handle} scored {score} against the chosen row's {chosen_score}, \
                     so a row nobody sent back outranked the one that was"
                ),
            }
        }

        if MODES_DISCOUNTING_BULK_AWAY.contains(&mode) {
            for (index, handle) in bulk.iter().enumerate() {
                assert!(
                    !reported.contains(handle.as_str()),
                    "{mode:?}: catalogue row {index} reached Strong Values as {handle}, but \
                     this mode's discount is decisive and should have left nothing to report"
                );
            }
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
/// Checked in Peaceful alone, because Peaceful is the only mode whose bar admits the
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

/// The floor under the promotion, stated against every read the capture
/// contains rather than against an idealised one.
///
/// This used to compare the write against reads that yielded nothing, on the
/// strength of Apocalyptic's ubiquity damping rejecting the session token. That
/// premise was never true: a value the server issued and the client sends back
/// is a credential, and every damping rule abstains from a credential by design
/// — it is the one value in the capture worth having. So the token rides along on
/// every route, no read is ever empty-handed, and the comparison quietly stopped
/// testing anything.
///
/// What is left is the claim the fixture can actually support, and it is the
/// useful one: the capture's single deliberate write is never below a read. Not
/// merely above the matched control, and not merely in Core Signal — above every
/// GET in the report, by rank and by relevance, in all three modes. If a change
/// ever lets a read pass a write this rare, this fails.
#[test]
fn a_deliberate_write_outranks_every_read_in_the_capture() {
    for mode in MODES {
        let model = squeeze(mode);
        let (write_rank, write) = listed(&model, DELIBERATE_WRITE);

        let reads: Vec<(usize, &EndpointRow)> = as_read(&model)
            .enumerate()
            .filter(|(_, row)| row.endpoint.starts_with("GET "))
            .collect();
        assert!(
            !reads.is_empty(),
            "{mode:?}: the capture reported no reads, so there was nothing to compare"
        );

        for (rank, read) in reads {
            assert!(
                write.relevance > read.relevance,
                "{mode:?}: {} scored {} against the capture's one deliberate write's {}",
                read.endpoint,
                read.relevance,
                write.relevance
            );
            assert!(
                write_rank < rank,
                "{mode:?}: {} outranked the capture's one deliberate write",
                read.endpoint
            );
        }
    }
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
