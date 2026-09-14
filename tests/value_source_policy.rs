//! Regression tests for the value-source policy.
//!
//! The capture behind these tests is the shape that broke Core Signal on a real
//! dump: every exchange carries the same nine request headers and seven response
//! headers, so the most frequent, most widely spread, most reliably repeated
//! values in the file are all protocol furniture. Ranked on repetition alone
//! they win every time, and the identifiers worth reading — issued once, then
//! carried — are buried underneath them.
//!
//! What is asserted here is therefore two-sided. Suppressing noise is easy if
//! one is willing to suppress everything; keeping signal is easy if one is
//! willing to keep everything. Every test below checks both directions, in all
//! three modes.

mod common;

use burpsqueezer::analysis::fingerprint::fingerprint;
use burpsqueezer::config::Mode;
use burpsqueezer::model::report::ReportModel;
use common::fixture;

const MODES: [Mode; 3] = [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic];

/// Constants repeated by the capture's transport envelope.
///
/// Each is rejected for its own reason — too short, response-only,
/// request-only, or never crossing slots — which is the point: one blanket rule
/// would not cover them, and no rule here names any of them.
const TRANSPORT_NOISE: [&str; 13] = [
    "application/json",
    "no-cache",
    "SAMEORIGIN",
    "strict-origin-when-cross-origin",
    "trailers",
    "max-age=31536000",
    "keep-alive",
    "gzip, deflate, br",
    "nginx",
    "ru-RU,ru;q=0.9,en-US;q=0.8",
    "app.example.com",
    // A CSRF token: 32 hex characters, so every shape gate passes. Only the
    // absence of a handover keeps it out, which makes it the sharpest case.
    "7b2e91d05a4c6f8e3d1b0a9c5e7f2d84",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
];

/// Identifiers the capture genuinely issues and reuses.
const BUSINESS_VALUES: [&str; 6] = [
    "c1f4a9b28e7d4f6ab3125e9d77aa0c31", // session token, body -> header
    "wks_8Hq2Lm4Rt9",                   // workspace id, body -> path
    "usr_5Zp7Kd3Wn1",                   // user id, body -> path
    "chn_2Vb6Xy8Qs4",                   // channel id, body -> path
    "inv_9Tk1Nc7Rw3",                   // invite id, body -> path
    "chg_4Jm8Pf2Bd6",                   // challenge id, body -> body
];

fn squeeze(mode: Mode) -> ReportModel {
    burpsqueezer::squeeze(&fixture("header_noise.xml"), mode).expect("fixture must analyse")
}

/// Values are reported by handle, so that is what identifies them.
fn handle_of(value: &str) -> String {
    format!("fp:{}", fingerprint(value))
}

fn reported_handles(model: &ReportModel) -> Vec<&str> {
    model
        .strong_values
        .iter()
        .map(|value| value.handle.as_str())
        .chain(model.chains.iter().map(|chain| chain.handle.as_str()))
        .collect()
}

/// The headline symptom: repeated headers crowding out everything else.
#[test]
fn repeated_transport_headers_never_become_strong_values() {
    for mode in MODES {
        let model = squeeze(mode);
        let handles = reported_handles(&model);
        for noise in TRANSPORT_NOISE {
            let handle = handle_of(noise);
            assert!(
                !handles.contains(&handle.as_str()),
                "{mode:?}: transport constant {noise:?} reached the report as {handle}"
            );
        }
    }
}

/// The other half of the symptom: those same constants built the longest
/// chains in the capture, because a value in every exchange travels everywhere.
#[test]
fn transport_constants_do_not_build_chains() {
    for mode in MODES {
        let model = squeeze(mode);
        let noise_handles: Vec<String> = TRANSPORT_NOISE.iter().copied().map(handle_of).collect();
        for chain in &model.chains {
            assert!(
                !noise_handles.contains(&chain.handle),
                "{mode:?}: a transport constant produced a {}-hop chain",
                chain.hop_count()
            );
        }
    }
}

/// Suppression must not be achieved by reporting nothing.
#[test]
fn genuine_identifiers_survive_the_policy() {
    for mode in MODES {
        let model = squeeze(mode);
        let handles = reported_handles(&model);
        for value in BUSINESS_VALUES {
            let handle = handle_of(value);
            assert!(
                handles.contains(&handle.as_str()),
                "{mode:?}: identifier {value:?} was lost, expected handle {handle}"
            );
        }
    }
}

/// Every business identifier here is issued by a response and sent back later,
/// including the one returned under the field name it was issued under — the
/// case a strict cross-slot rule would silently discard.
#[test]
fn response_to_request_propagation_is_recognised() {
    for mode in MODES {
        let model = squeeze(mode);
        for value in BUSINESS_VALUES {
            let handle = handle_of(value);
            let row = model
                .strong_values
                .iter()
                .find(|row| row.handle == handle)
                .unwrap_or_else(|| panic!("{mode:?}: {value:?} missing from Strong Values"));
            assert!(
                row.propagates,
                "{mode:?}: {value:?} travels response-to-request but was not flagged"
            );
            assert!(
                model.chains.iter().any(|chain| chain.handle == handle),
                "{mode:?}: {value:?} propagates but produced no chain"
            );
        }
    }
}

/// Core Signal is ranked, so the first row is the strongest claim the report
/// makes. It must be an identifier, not a constant.
#[test]
fn the_leading_strong_value_is_an_identifier() {
    for mode in MODES {
        let model = squeeze(mode);
        let leader = model
            .strong_values
            .first()
            .unwrap_or_else(|| panic!("{mode:?}: Core Signal is empty"));
        let business: Vec<String> = BUSINESS_VALUES.iter().copied().map(handle_of).collect();
        assert!(
            business.contains(&leader.handle),
            "{mode:?}: the top Strong Value is not one of the capture's identifiers"
        );
    }
}

/// Route nouns are path segments, so they anchor as strongly as an id does.
/// Only their shape separates them, and they must never outrank a real one.
#[test]
fn route_nouns_never_outrank_identifiers() {
    for mode in MODES {
        let model = squeeze(mode);
        let business: Vec<String> = BUSINESS_VALUES.iter().copied().map(handle_of).collect();
        let last_identifier = model
            .strong_values
            .iter()
            .rposition(|row| business.contains(&row.handle))
            .expect("identifiers are reported");
        let first_other = model
            .strong_values
            .iter()
            .position(|row| !business.contains(&row.handle));
        if let Some(first_other) = first_other {
            assert!(
                first_other > last_identifier,
                "{mode:?}: a non-identifier outranks an identifier in Core Signal"
            );
        }
    }
}

/// Core Signal shows all hops, no truncation for any mode.
#[test]
fn long_trails_show_all_hops() {
    for mode in MODES {
        let model = squeeze(mode);
        for chain in &model.chains {
            // All hops are shown, no truncation
            assert_eq!(
                chain.hop_count(),
                chain.hops.len(),
                "{mode:?}: all hops must be shown, no truncation"
            );
            assert_eq!(
                chain.elided_hops(),
                0,
                "{mode:?}: no hops should be elided"
            );
            assert!(
                chain.elided.is_none(),
                "{mode:?}: elision should be None when all hops are shown"
            );
        }
    }
}

/// Stricter modes must cut noise before signal.
#[test]
fn stricter_modes_keep_the_identifiers_and_shed_the_rest() {
    let peaceful = squeeze(Mode::Peaceful);
    let standard = squeeze(Mode::Standard);
    let apocalyptic = squeeze(Mode::Apocalyptic);

    assert!(peaceful.strong_values.len() >= standard.strong_values.len());
    assert!(standard.strong_values.len() >= apocalyptic.strong_values.len());

    // Whatever else is dropped on the way, the identifiers are still there.
    let business: Vec<String> = BUSINESS_VALUES.iter().copied().map(handle_of).collect();
    let survivors = apocalyptic
        .strong_values
        .iter()
        .filter(|row| business.contains(&row.handle))
        .count();
    assert_eq!(
        survivors,
        BUSINESS_VALUES.len(),
        "the strictest mode should still report every genuine identifier"
    );
}

/// The masking rule applies here too: this capture's secrets must not appear.
#[test]
fn no_transport_or_business_secret_is_printed_in_full() {
    for mode in MODES {
        let model = squeeze(mode);
        let rendered = burpsqueezer::render::markdown::render(&model);
        for secret in [BUSINESS_VALUES[0], TRANSPORT_NOISE[11]] {
            assert!(
                !rendered.contains(secret),
                "{mode:?}: {secret:?} was printed in full"
            );
        }
    }
}

