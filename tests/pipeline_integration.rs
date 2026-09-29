//! End-to-end behaviour of stages 1–7 against checked-in Burp dumps.

mod common;

use burpsqueezer::config::{Mode, Thresholds};
use burpsqueezer::error::Error;
use burpsqueezer::model::report::ReportModel;

use common::fixture;

fn squeeze(name: &str, mode: Mode) -> ReportModel {
    burpsqueezer::squeeze(&fixture(name), mode, true).expect("fixture must analyse")
}

#[test]
fn an_empty_file_is_rejected() {
    let error = burpsqueezer::squeeze(&fixture("empty.xml"), Mode::Standard, true)
        .expect_err("an empty file cannot be analysed");
    assert!(matches!(error, Error::EmptyInput(_)));
    assert_eq!(error.exit_code(), burpsqueezer::error::EXIT_BAD_INPUT);
}

#[test]
fn malformed_xml_is_rejected_with_its_own_exit_code() {
    let error = burpsqueezer::squeeze(&fixture("malformed.xml"), Mode::Standard, true)
        .expect_err("unclosed item must fail");
    assert!(matches!(error, Error::MalformedXml { .. }));
    assert_eq!(error.exit_code(), burpsqueezer::error::EXIT_MALFORMED_XML);
}

#[test]
fn a_missing_file_is_a_bad_input_not_a_panic() {
    let error = burpsqueezer::squeeze(&fixture("does-not-exist.xml"), Mode::Standard, true)
        .expect_err("missing file must fail");
    assert!(matches!(error, Error::ReadInput { .. }));
}

#[test]
fn parsing_accounts_for_every_transaction() {
    let model = squeeze("noisy.xml", Mode::Standard);
    assert_eq!(
        model.overview.kept_transactions + model.meta.dropped_total(),
        model.overview.raw_transactions,
        "kept plus dropped must equal the raw count"
    );
}

#[test]
fn infrastructure_and_asset_noise_is_removed() {
    let model = squeeze("noisy.xml", Mode::Standard);
    let reasons: Vec<&String> = model.meta.dropped_by_reason.keys().collect();

    assert!(
        reasons.iter().any(|r| r.contains("infrastructure path")),
        "health/ping/favicon probes should be dropped, saw {reasons:?}"
    );
    assert!(
        reasons.iter().any(|r| r.contains("opaque asset")),
        "images and fonts should be dropped, saw {reasons:?}"
    );

    let listed: Vec<&str> = model
        .core_endpoints
        .iter()
        .chain(model.other_endpoints.iter())
        .map(|e| e.endpoint.as_str())
        .collect();
    for probe in [
        "/health",
        "/healthz",
        "/ping",
        "/favicon.ico",
        "/robots.txt",
        "/tunnel",
    ] {
        assert!(
            !listed.iter().any(|endpoint| endpoint.ends_with(probe)),
            "{probe} must not reach the report, saw {listed:?}"
        );
    }
}

#[test]
fn business_endpoints_survive_a_noisy_capture() {
    let model = squeeze("noisy.xml", Mode::Standard);
    let listed: Vec<&str> = model
        .core_endpoints
        .iter()
        .chain(model.other_endpoints.iter())
        .map(|e| e.endpoint.as_str())
        .collect();
    assert!(
        listed.iter().any(|endpoint| endpoint.contains("/api/")),
        "the API traffic should survive, saw {listed:?}"
    );
}

/// The whole point of method-aware deduplication, stated end to end.
///
/// `repeated_write.xml` sends one refund three times byte for byte, and reads
/// the same order three times byte for byte. Both collapse — neither repeat
/// carries a field or a value the first one did not — but only one of them is an
/// event. A reader who is told the refund ran once has been misinformed; a reader
/// who is told the order was fetched three times has learned that a client polls.
#[test]
fn a_repeated_write_is_collapsed_but_still_counted() {
    let model = squeeze("repeated_write.xml", Mode::Standard);
    let row = |endpoint: &str| {
        model
            .core_endpoints
            .iter()
            .chain(model.other_endpoints.iter())
            .find(|e| e.endpoint == endpoint)
            .unwrap_or_else(|| panic!("{endpoint} is missing from the report"))
    };

    let refund = row("POST /api/orders/{id}/refund");
    assert_eq!(refund.repeated_writes, 2);
    assert_eq!(
        refund.hit_summary(),
        "1 (+2 identical)",
        "the mutation recurred, and the row has to say so"
    );

    let read = row("GET /api/orders/{id}");
    assert_eq!(
        read.repeated_writes, 0,
        "a replayed read is collection noise and is owed no account"
    );
    assert_eq!(read.hit_summary(), "1");

    let dropped = |reason: &str| model.meta.dropped_by_reason.get(reason).copied();
    assert_eq!(
        dropped("statistical: repeated identical write"),
        Some(2),
        "the Filtering Breakdown names a collapsed mutation apart from a duplicate"
    );
    assert_eq!(dropped("statistical: duplicate request"), Some(2));
    assert_eq!(
        model.overview.kept_transactions + model.meta.dropped_total(),
        model.overview.raw_transactions,
        "naming a drop must not stop it being counted as one"
    );
}

#[test]
fn paths_are_templated_from_observed_variation() {
    let model = squeeze("dataflow.xml", Mode::Standard);
    let listed: Vec<&str> = model
        .core_endpoints
        .iter()
        .chain(model.other_endpoints.iter())
        .map(|e| e.endpoint.as_str())
        .collect();

    assert!(
        listed.iter().any(|endpoint| endpoint.contains("{id}")),
        "numeric user ids should collapse into a template, saw {listed:?}"
    );
    assert!(
        !listed.iter().any(|endpoint| endpoint.contains("812696")),
        "no concrete identifier should remain in a template, saw {listed:?}"
    );
}

#[test]
fn the_session_token_is_mined_and_chained() {
    let model = squeeze("dataflow.xml", Mode::Standard);

    assert!(
        !model.strong_values.is_empty(),
        "the session token and user refs should be mined"
    );
    assert!(
        model.strong_values.iter().any(|v| v.propagates),
        "a token returned by the server and later sent back must be flagged as propagating"
    );
    assert!(
        !model.chains.is_empty(),
        "propagating values should produce at least one data-flow chain"
    );
    assert!(
        model.chains.iter().any(|chain| chain.hop_count() >= 2),
        "a chain needs at least two hops to be worth reporting"
    );
}

#[test]
fn every_chain_handle_resolves_to_a_reported_value() {
    let model = squeeze("dataflow.xml", Mode::Peaceful);
    let handles: Vec<&str> = model
        .strong_values
        .iter()
        .map(|v| v.handle.as_str())
        .collect();
    for chain in &model.chains {
        assert!(
            handles.contains(&chain.handle.as_str()),
            "chain {} references a value that was not reported",
            chain.handle
        );
    }
}

#[test]
fn a_tiny_dump_relaxes_thresholds_and_says_so() {
    let model = squeeze("tiny.xml", Mode::Standard);
    assert!(model.meta.relaxed_for_small_dump);
    assert!(
        model
            .meta
            .warnings
            .iter()
            .any(|warning| warning.contains("Small dump")),
        "the reader must be told the thresholds were relaxed"
    );
}

#[test]
fn peaceful_mode_is_never_less_generous_than_standard() {
    let peaceful = squeeze("noisy.xml", Mode::Peaceful);
    let standard = squeeze("noisy.xml", Mode::Standard);
    assert!(peaceful.overview.kept_transactions >= standard.overview.kept_transactions);
}

#[test]
fn apocalyptic_mode_reports_no_more_than_standard() {
    // Only the selectively mined sections are compared. The endpoint split is not
    // monotone by design: when a strict mode mines fewer values the signal set
    // shrinks, which moves endpoints into Other rather than removing them.
    let standard = squeeze("dataflow.xml", Mode::Standard);
    let apocalyptic = squeeze("dataflow.xml", Mode::Apocalyptic);

    assert!(apocalyptic.strong_values.len() <= standard.strong_values.len());
    assert!(apocalyptic.chains.len() <= standard.chains.len());
    assert!(apocalyptic.sequences.len() <= standard.sequences.len());
    assert!(apocalyptic.state_indicators.len() <= standard.state_indicators.len());
}

#[test]
fn overview_and_meta_agree_with_the_sections() {
    for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
        let model = squeeze("dataflow.xml", mode);
        assert_eq!(model.overview.strong_values, model.strong_values.len());
        assert_eq!(model.overview.chains, model.chains.len());
        assert_eq!(Some(mode), model.meta.mode);
        assert!(!model.meta.tool_version.is_empty());
    }
}

#[test]
fn sequences_are_anchored_to_reported_signal() {
    let model = squeeze("dataflow.xml", Mode::Peaceful);
    for sequence in &model.sequences {
        assert!(
            sequence.steps.len() >= 2,
            "a single endpoint is not a sequence"
        );
        assert!(
            !sequence.linked_handles.is_empty(),
            "sequences must be anchored to a Strong Value or a chain"
        );
    }
}

#[test]
fn state_indicators_stay_low_cardinality() {
    // The bound is read from the mode rather than written as a literal: rows are
    // passed through untruncated, so the promotion rule in stage 6 is the only
    // thing that limits cardinality, and that is what this asserts.
    for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
        let ceiling = Thresholds::for_mode(mode).variation_max_cardinality;
        let model = squeeze("dataflow.xml", mode);
        for indicator in &model.state_indicators {
            assert!(
                indicator.values.len() >= 2,
                "{} has one value, which is a constant and not a state hint",
                indicator.field
            );
            assert!(
                indicator.values.len() <= ceiling,
                "{} has {} distinct values, over the {mode:?} ceiling of {ceiling}",
                indicator.field,
                indicator.values.len()
            );
            assert!(indicator.coverage > 0.0 && indicator.coverage <= 1.0);
        }
    }
}

/// The three structural rules against a capture built to defeat all of them.
///
/// `background_noise.xml` is a login, thirty heartbeat reads, a telemetry
/// collector and three order reads. The heartbeat rotates a routing cookie every
/// two calls, so the name is stable and the value never is; the collector is
/// called sixteen times and returns nothing; both endpoints vary their field
/// names, which is what makes folding a judgement rather than a guess.
///
/// None of the three rules is allowed to look at the names in this capture. A
/// rule that fired here because it knew about `routing` or `/api/feed` would be
/// worth nothing on the next one.
#[test]
fn a_rotating_routing_cookie_is_one_row_not_fifteen() {
    let model = squeeze("background_noise.xml", Mode::Standard);

    let collapsed: Vec<String> = model
        .strong_values
        .iter()
        .map(|value| value.locations.join(" "))
        .filter(|location| location.contains("cookie.*"))
        .collect();
    assert_eq!(
        collapsed.len(),
        1,
        "fifteen replaced values are one piece of plumbing, saw {collapsed:?}"
    );
    assert!(
        model.strong_values.iter().any(|v| v
            .locations
            .iter()
            .any(|l| l.contains("collapsed 15 variants"))),
        "the row must still say how many values it stands for, saw {:?}",
        model
            .strong_values
            .iter()
            .map(|v| &v.locations)
            .collect::<Vec<_>>()
    );

    for value in &model.strong_values {
        assert!(
            value.locations.iter().all(|l| !l.contains("/api/feed (req")),
            "a collapsed value owes no account of where its variants were, saw {:?}",
            value.locations
        );
    }
}

#[test]
fn a_collector_endpoint_is_damped_below_the_telemetry_it_carries() {
    let model = squeeze("background_noise.xml", Mode::Standard);
    let row = |endpoint: &str| {
        model
            .core_endpoints
            .iter()
            .chain(model.other_endpoints.iter())
            .find(|e| e.endpoint == endpoint)
            .unwrap_or_else(|| panic!("{endpoint} is missing from the report"))
    };

    let collector = row("GET /api/feed");
    let telemetry = row("POST /api/collect/events");
    assert_eq!(collector.hits, 30);
    assert!(
        collector.relevance < telemetry.relevance,
        "thirty heartbeats carrying a cookie are worth less than the call that \
         carries an identifier: {} vs {}",
        collector.relevance,
        telemetry.relevance
    );
    assert!(
        !model.core_endpoints.iter().any(|e| e.endpoint == "GET /api/feed"),
        "a damped endpoint stays out of Core Signal"
    );
}

#[test]
fn varied_telemetry_fields_fold_and_the_identifier_does_not() {
    let model = squeeze("background_noise.xml", Mode::Standard);
    let row = |endpoint: &str| {
        model
            .core_endpoints
            .iter()
            .chain(model.other_endpoints.iter())
            .find(|e| e.endpoint == endpoint)
            .unwrap_or_else(|| panic!("{endpoint} is missing from the report"))
    };

    let telemetry = row("POST /api/collect/events");
    assert!(
        telemetry.request_fields.iter().any(|f| f.contains("(8 keys)")),
        "eight varying event properties are one line, saw {:?}",
        telemetry.request_fields
    );
    assert!(
        telemetry.request_fields.iter().any(|f| f == "event.device_id"),
        "a field a Strong Value lives in is never folded away, saw {:?}",
        telemetry.request_fields
    );

    // A query is already a summary of what varied, so folding one would say
    // nothing and cost the reader the parameter names. The order is the
    // report's own: most-seen first, then the order first seen.
    let feed = row("GET /api/feed");
    assert_eq!(
        feed.query_params,
        ["cursor", "page", "sort", "filter", "view", "from"],
        "query parameters are listed, never folded"
    );
    assert!(
        feed.request_fields.is_empty(),
        "a GET with no body has no fields to report"
    );
}

#[test]
fn a_heartbeat_does_not_produce_a_sequence_of_itself() {
    let model = squeeze("background_noise.xml", Mode::Standard);

    // The fixture produces four windows of `/feed` calling itself, each with
    // support in the twenties, all anchored to the routing cookie. They are the
    // one thing the cookie summary already said, said at greater length, and
    // the summary is the row that survives.
    let collapsed_handle = model
        .strong_values
        .iter()
        .find(|value| value.locations.iter().any(|l| l.contains("cookie.*")))
        .map(|value| value.handle.clone())
        .expect("the routing cookie is summarised as one row");

    for sequence in &model.sequences {
        let mut endpoints: Vec<&str> = sequence.steps.iter().map(|s| s.as_str()).collect();
        endpoints.sort_unstable();
        endpoints.dedup();
        if endpoints.len() == 1 {
            assert!(
                !sequence.linked_handles.contains(&collapsed_handle),
                "one endpoint calling itself, carried by plumbing, is not a \
                 flow: {:?} on {collapsed_handle}",
                sequence.steps
            );
        }
    }
    assert!(
        !model.sequences.is_empty(),
        "the fixture does contain a real window, and it must survive"
    );
}

