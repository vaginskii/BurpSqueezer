//! Whole-report snapshots.
//!
//! The other integration tests pin one property each: the layout is stable, a
//! header never reaches Core, a rare write survives. Between them they still let
//! a change slip through that alters *what the report says* without breaking any
//! single rule — an identity value quietly dropping out of Core Signal, a
//! transport artefact reappearing in a field list, a section going empty. These
//! tests pin the whole output, so any such change shows up as a diff and has to
//! be looked at.
//!
//! A snapshot is not a specification. It records what the pipeline currently
//! does, and a diff here is a question, not a verdict: read it, decide whether
//! the new output is better, then bless it. What must never happen is blessing
//! it unread, which is why the version line is scrubbed and why the failure
//! message points at one located difference rather than dumping two reports.
//!
//! Deliberately small fixtures. The Pachca capture is 26 MB and its report runs
//! to hundreds of lines: pinning it would cost more to read than the regressions
//! it would catch, and every stage it exercises is exercised here too.

mod common;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use burpsqueezer::config::Mode;
use burpsqueezer::render;

use common::fixture;

/// Environment variable that rewrites every snapshot from the current output.
const BLESS: &str = "BLESS_GOLDEN";

/// Lines of leading context shown around a difference.
const CONTEXT_LINES: usize = 3;

/// Captures whose whole report is pinned, and the mode each is pinned in.
///
/// Standard is the mode users get by default and the one worth guarding first.
/// `header_noise` is additionally pinned in Apocalyptic because that fixture
/// sits right on the ubiquity threshold, where the strictest mode takes a
/// different branch — the one place where pinning a second mode buys anything.
const PINNED: [(&str, Mode); 5] = [
    ("dataflow.xml", Mode::Standard),
    ("catalogue.xml", Mode::Standard),
    ("header_noise.xml", Mode::Standard),
    ("header_noise.xml", Mode::Apocalyptic),
    ("tiny.xml", Mode::Standard),
];

#[test]
fn reports_match_their_snapshots() {
    let blessing = std::env::var_os(BLESS).is_some();
    let mut complaints: Vec<String> = Vec::new();
    let mut created: Vec<String> = Vec::new();

    for (name, mode) in PINNED {
        let report = scrub_version(&render_fixture(name, mode));
        let path = snapshot_path(name, mode);

        // A snapshot that does not exist yet is guarding nothing, so writing it
        // costs no coverage and keeps a fresh checkout's first `cargo test`
        // green. A snapshot that exists and disagrees is a different matter
        // entirely, and no flag short of BLESS makes that pass.
        if blessing || !path.exists() {
            write_snapshot(&path, &report);
            if !blessing {
                created.push(path.display().to_string());
            }
            continue;
        }

        match fs::read_to_string(&path) {
            Ok(snapshot) if snapshot == report => {}
            Ok(snapshot) => complaints.push(format!(
                "{} no longer renders as {}:\n{}",
                name,
                path.display(),
                first_difference(&snapshot, &report)
            )),
            Err(error) => complaints.push(format!(
                "{} has a snapshot at {} that cannot be read: {error}",
                name,
                path.display()
            )),
        }
    }

    if !created.is_empty() {
        // Not a failure, but the reader has to know these were written rather
        // than checked, and that nothing has reviewed them yet.
        println!(
            "wrote {} new snapshot(s), unreviewed:\n  {}",
            created.len(),
            created.join("\n  ")
        );
    }

    assert!(
        complaints.is_empty(),
        "{}\n\nEach difference above is either a regression or an improvement, \
         and only a person can tell which. Once you have decided they are all \
         improvements, re-run with {BLESS}=1 to rewrite the snapshots, then read \
         the resulting diff before committing it.",
        complaints.join("\n\n")
    );
}

fn render_fixture(name: &str, mode: Mode) -> String {
    let model = burpsqueezer::squeeze(&fixture(name), mode)
        .unwrap_or_else(|error| panic!("{name} must analyse in {mode:?}: {error}"));
    render::render(&model)
}

fn snapshot_path(fixture: &str, mode: Mode) -> PathBuf {
    let stem = fixture.strip_suffix(".xml").unwrap_or(fixture);
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(format!("{stem}.{}.md", mode.as_str()))
}

fn write_snapshot(path: &Path, report: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("snapshot directory");
    }
    fs::write(path, report).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

/// Replace the tool's own version with a placeholder.
///
/// It is the one line in a report that changes without the analysis changing at
/// all. Pinning it would make every release a snapshot update, and a reader who
/// has learned that snapshot diffs are usually noise is a reader who will bless
/// the one that matters without looking at it.
fn scrub_version(markdown: &str) -> String {
    markdown.replace(
        concat!("burpsqueezer ", env!("CARGO_PKG_VERSION")),
        "burpsqueezer {version}",
    )
}

/// The first line where two reports disagree, with a little context.
///
/// A full diff of two multi-kilobyte reports is unreadable in test output, and
/// `assert_eq!` on them is worse. One located line is enough to tell a
/// deliberate change from a regression; the snapshot file holds the rest.
fn first_difference(snapshot: &str, report: &str) -> String {
    let snapshot: Vec<&str> = snapshot.lines().collect();
    let report: Vec<&str> = report.lines().collect();
    let at = snapshot
        .iter()
        .zip(&report)
        .position(|(pinned, rendered)| pinned != rendered)
        .unwrap_or_else(|| snapshot.len().min(report.len()));

    let mut out = String::new();
    for index in at.saturating_sub(CONTEXT_LINES)..at {
        let _ = writeln!(out, "  {:>4} | {}", index + 1, snapshot[index]);
    }
    let line = at + 1;
    let missing_from = |side: &str| format!("<nothing: the {side} ends here>");
    let _ = writeln!(
        out,
        "- {line:>4} | {}",
        snapshot
            .get(at)
            .map_or_else(|| missing_from("snapshot"), |text| text.to_string())
    );
    let _ = writeln!(
        out,
        "+ {line:>4} | {}",
        report
            .get(at)
            .map_or_else(|| missing_from("report"), |text| text.to_string())
    );
    let _ = writeln!(
        out,
        "  ({} snapshot lines, {} rendered)",
        snapshot.len(),
        report.len()
    );
    out
}

/// Regression test: Core Signal chain render must list ALL hops.
/// No "… and N further hops" in Multi-Data-Flow Chains for any current mode.
#[test]
fn core_signal_chains_must_not_truncate_hops() {
    for (name, mode) in PINNED {
        let report = render_fixture(name, mode);
        // Find the Multi-Data-Flow Chains section
        if let Some(chains_start) = report.find("### Multi-Data-Flow Chains") {
            // Get the section (until next ### or end of file)
            let chains_section = if let Some(next_section) = report[chains_start..].find("\n### ") {
                &report[chains_start..chains_start + next_section]
            } else {
                &report[chains_start..]
            };

            assert!(
                !chains_section.contains("further hops"),
                "Core Signal must not show 'further hops' in Multi-Data-Flow Chains. \
                 Found in {name:?} with mode {mode:?}:\n{chains_section}"
            );
        }
    }
}

/// Regression test: header hop count must equal listed hop count.
/// Ensures that chain headers don't claim more hops than are actually rendered.
#[test]
fn chain_header_hop_count_must_equal_listed_hop_count() {
    for (name, mode) in PINNED {
        let report = render_fixture(name, mode);
        // Find the Multi-Data-Flow Chains section
        if let Some(chains_start) = report.find("### Multi-Data-Flow Chains") {
            // Get the section (until next ### or end of file)
            let chains_section = if let Some(next_section) = report[chains_start..].find("\n### ") {
                &report[chains_start..chains_start + next_section]
            } else {
                &report[chains_start..]
            };

            // Check each chain header and its hop list
            for line in chains_section.lines() {
                if line.starts_with("- **") {
                    // Extract hop count from header: "... — N hops across ..."
                    // Use character-based indexing to handle multi-byte characters like em dash
                    let line_chars: Vec<char> = line.chars().collect();
                    if let Some(dash_pos) = line_chars.iter().position(|&c| c == '—') {
                        if dash_pos + 2 < line_chars.len() {
                            let after_dash: String = line_chars[dash_pos + 2..].iter().collect();
                            if let Some(hops_end) = after_dash.find(" hops") {
                                let header_hops_str = &after_dash[..hops_end];
                                if let Ok(header_hops) = header_hops_str.parse::<usize>() {
                                    // Count the numbered hop items for this chain
                                    // Start from the next line after the header
                                    let chain_start = chains_section.find(line).unwrap() + line.len();
                                    let chain_end = chains_section[chain_start..]
                                        .find("- **")
                                        .unwrap_or(chains_section[chain_start..].len());
                                    let chain_block = &chains_section[chain_start..chain_start + chain_end];

                                    let listed_hops = chain_block
                                        .lines()
                                        .filter(|l| l.trim().starts_with(|c: char| c.is_numeric()))
                                        .count();

                                    assert_eq!(
                                        header_hops, listed_hops,
                                        "Chain header claims {} hops but only {} are listed for {name:?} mode {mode:?}:\n{}\nChain block:\n{}",
                                        header_hops, listed_hops, line, chain_block
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
