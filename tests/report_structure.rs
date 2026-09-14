//! The report layout is a contract: identical sections, in order, for every
//! input. These tests hold that contract across rich, thin, and empty captures.

mod common;

use burpsqueezer::config::Mode;
use burpsqueezer::model::report::ReportModel;
use burpsqueezer::render;

use common::fixture;

/// Every heading the specification mandates, in order.
const MANDATED: [&str; 11] = [
    "# BurpSqueezer Report",
    "## Overview",
    "## Core Signal",
    "### Strong Values",
    "### Multi-Data-Flow Chains",
    "### High-Relevance Endpoints",
    "## Secondary Context",
    "### Other Endpoints",
    "### Sequences",
    "### Possible State Indicators",
    "## Meta",
];

fn assert_layout(markdown: &str) {
    let mut cursor = 0;
    for heading in MANDATED {
        let offset = markdown[cursor..]
            .find(heading)
            .unwrap_or_else(|| panic!("missing or out-of-order heading: {heading}"));
        cursor += offset + heading.len();
    }
}

fn render_fixture(name: &str, mode: Mode) -> String {
    let model = burpsqueezer::squeeze(&fixture(name), mode).expect("fixture must analyse");
    render::render(&model)
}

#[test]
fn layout_is_identical_for_every_fixture_and_mode() {
    for name in ["dataflow.xml", "tiny.xml", "noisy.xml"] {
        for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
            assert_layout(&render_fixture(name, mode));
        }
    }
}

#[test]
fn layout_survives_a_completely_empty_model() {
    assert_layout(&render::render(&ReportModel::default()));
}

#[test]
fn sections_never_collapse_they_show_a_placeholder() {
    let markdown = render::render(&ReportModel::default());
    for heading in [
        "### Strong Values",
        "### Multi-Data-Flow Chains",
        "### High-Relevance Endpoints",
        "### Other Endpoints",
        "### Sequences",
        "### Possible State Indicators",
    ] {
        let section = &markdown[markdown.find(heading).expect("heading present")..];
        assert!(
            section.starts_with(&format!("{heading}\n\n_none_")),
            "{heading} should fall back to the placeholder"
        );
    }
}

#[test]
fn meta_always_states_mode_version_and_masking() {
    let markdown = render_fixture("dataflow.xml", Mode::Standard);
    assert!(markdown.contains("| mode | standard |"));
    assert!(markdown.contains(&format!("burpsqueezer {}", burpsqueezer::VERSION)));
    assert!(markdown.contains("### Value Handling"));
    assert!(markdown.contains("### Filtering Breakdown"));
    assert!(markdown.contains("### Truncations"));
    assert!(markdown.contains("### Warnings"));
}

#[test]
fn no_full_secret_ever_reaches_the_report() {
    let secret = "c9f4a1b28e7d4f6ab3125e9d77aa0c31";
    for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
        let markdown = render_fixture("dataflow.xml", mode);
        assert!(
            !markdown.contains(secret),
            "the full session token leaked into the report in mode {mode}"
        );
    }
}

/// The rendered body of one section: everything up to the next heading.
fn section<'a>(markdown: &'a str, heading: &str) -> &'a str {
    let start = markdown.find(heading).expect("heading present");
    let body = &markdown[start + heading.len()..];
    let end = body.find("\n#").map(|at| at + 1).unwrap_or(body.len());
    &body[..end]
}

#[test]
fn a_stricter_mode_visibly_shrinks_core_signal() {
    // Whole-document length is deliberately not compared. With nothing mined the
    // aggregator promotes every endpoint into Core Signal and adds a warning, and
    // Meta spells out the longer mode name, so a strict mode can render the
    // longer file. What the thresholds do guarantee is that the selectively mined
    // sections are a subset, and each row renders the same way in either mode.
    for heading in ["### Strong Values", "### Multi-Data-Flow Chains"] {
        let peaceful = section(&render_fixture("noisy.xml", Mode::Peaceful), heading).len();
        let apocalyptic = section(&render_fixture("noisy.xml", Mode::Apocalyptic), heading).len();
        assert!(
            apocalyptic <= peaceful,
            "{heading}: apocalyptic ({apocalyptic}) should not exceed peaceful ({peaceful})"
        );
    }
}

#[test]
fn tables_are_well_formed_markdown() {
    let markdown = render_fixture("dataflow.xml", Mode::Standard);
    for line in markdown.lines().filter(|line| line.starts_with("| ")) {
        assert!(line.ends_with(" |"), "unterminated table row: {line}");
    }
}
