//! The contract the binary offers to whatever script is driving it.
//!
//! Everything here is observed from the outside: arguments in, files and exit
//! codes out. Nothing links against the library, because a caller cannot.

mod common;

use std::path::Path;
use std::process::{Command, Output};

use burpsqueezer::error::{EXIT_BAD_INPUT, EXIT_MALFORMED_XML, EXIT_OK};

use common::{fixture, Scratch};

/// Run the real binary with the given arguments.
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_burpsqueezer"))
        .args(args)
        .output()
        .expect("the binary must be runnable")
}

/// Run `solve` on a fixture, writing into a scratch directory.
fn solve(fixture_name: &str, report: &Path, extra: &[&str]) -> Output {
    let input = fixture(fixture_name);
    let mut args = vec![
        "solve",
        input.to_str().expect("fixture path is UTF-8"),
        "--output",
        report.to_str().expect("scratch path is UTF-8"),
    ];
    args.extend_from_slice(extra);
    run(&args)
}

/// Exit code, failing loudly if the process died from a signal instead.
fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("the process must exit normally, not by signal")
}

#[test]
fn solve_writes_a_report_and_exits_zero() {
    let scratch = Scratch::new("happy");
    let report = scratch.join("report.md");

    let output = solve("noisy.xml", &report, &[]);

    assert_eq!(code(&output), EXIT_OK, "stderr: {}", stderr(&output));
    assert!(report.exists(), "the report must be written where asked");

    let markdown = std::fs::read_to_string(&report).expect("report is readable");
    assert!(markdown.starts_with("# BurpSqueezer Report"));
    assert!(markdown.contains("## Core Signal"));
}

#[test]
fn progress_goes_to_stderr_and_stdout_stays_empty() {
    let scratch = Scratch::new("streams");
    let report = scratch.join("report.md");

    let output = solve("noisy.xml", &report, &[]);

    assert!(
        output.stdout.is_empty(),
        "stdout must stay clean so the report is the only artefact, saw {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let logged = stderr(&output);
    assert!(
        logged.contains("burpsqueezer"),
        "the run should announce itself on stderr, saw {logged:?}"
    );
}

#[test]
fn quiet_silences_progress_but_never_errors() {
    let scratch = Scratch::new("quiet");

    let ok = solve("noisy.xml", &scratch.join("ok.md"), &["--quiet"]);
    assert_eq!(code(&ok), EXIT_OK);
    assert!(
        stderr(&ok).trim().is_empty(),
        "--quiet must suppress progress, saw {:?}",
        stderr(&ok)
    );

    let failed = solve("empty.xml", &scratch.join("never.md"), &["--quiet"]);
    assert_eq!(code(&failed), EXIT_BAD_INPUT);
    assert!(
        stderr(&failed).contains("error:"),
        "a failure must always be explained, even when quiet"
    );
}

#[test]
fn every_mode_is_accepted_and_the_report_names_the_one_used() {
    let scratch = Scratch::new("modes");

    for mode in ["peaceful", "standard", "apocalyptic"] {
        let report = scratch.join(&format!("{mode}.md"));
        let output = solve("dataflow.xml", &report, &["--mode", mode]);

        assert_eq!(
            code(&output),
            EXIT_OK,
            "mode {mode} failed: {}",
            stderr(&output)
        );

        // Proves the flag reached the pipeline rather than being parsed and
        // dropped. Relative report sizes are asserted in the library tests,
        // which can compare sections instead of whole files.
        let markdown = std::fs::read_to_string(&report).expect("report is readable");
        assert!(markdown.starts_with("# BurpSqueezer Report"), "mode {mode}");
        assert!(
            markdown.contains(&format!("| mode | {mode} |")),
            "mode {mode} is not recorded in Meta"
        );
    }
}

#[test]
fn an_unknown_mode_is_rejected_before_any_work_happens() {
    let scratch = Scratch::new("bad-mode");
    let report = scratch.join("report.md");

    let output = solve("noisy.xml", &report, &["--mode", "gentle"]);

    assert_ne!(code(&output), EXIT_OK);
    assert!(!report.exists(), "a rejected run must not write anything");
}

#[test]
fn an_empty_input_exits_with_the_bad_input_code() {
    let scratch = Scratch::new("empty");
    let report = scratch.join("report.md");

    let output = solve("empty.xml", &report, &[]);

    assert_eq!(code(&output), EXIT_BAD_INPUT);
    assert!(stderr(&output).contains("empty"));
    assert!(!report.exists(), "a failed run must not write a report");
}

#[test]
fn malformed_xml_exits_with_its_own_code() {
    let scratch = Scratch::new("malformed");
    let report = scratch.join("report.md");

    let output = solve("malformed.xml", &report, &[]);

    assert_eq!(code(&output), EXIT_MALFORMED_XML);
    assert!(!report.exists());
}

#[test]
fn a_missing_input_file_is_reported_not_panicked_over() {
    let scratch = Scratch::new("missing");
    let report = scratch.join("report.md");

    let output = solve("nope.xml", &report, &[]);

    assert_eq!(code(&output), EXIT_BAD_INPUT);
    let logged = stderr(&output);
    assert!(logged.contains("error:"), "saw {logged:?}");
    assert!(
        !logged.contains("panicked"),
        "a missing file is an expected condition, saw {logged:?}"
    );
}

#[test]
fn the_output_directory_is_created_on_demand() {
    let scratch = Scratch::new("nested");
    let report = scratch.join("reports").join("2026").join("report.md");

    let output = solve("tiny.xml", &report, &[]);

    assert_eq!(code(&output), EXIT_OK, "stderr: {}", stderr(&output));
    assert!(report.exists(), "intermediate directories must be created");
}

#[test]
fn output_is_mandatory_and_solve_is_the_only_subcommand() {
    let input = fixture("tiny.xml");
    let path = input.to_str().expect("fixture path is UTF-8");

    assert_ne!(code(&run(&["solve", path])), EXIT_OK);
    assert_ne!(code(&run(&["squeeze", path])), EXIT_OK);
    assert_ne!(code(&run(&[])), EXIT_OK);
}

#[test]
fn version_and_help_are_answered_on_stdout() {
    let version = run(&["--version"]);
    assert_eq!(code(&version), EXIT_OK);
    assert!(String::from_utf8_lossy(&version.stdout).contains(burpsqueezer::VERSION));

    let help = run(&["--help"]);
    assert_eq!(code(&help), EXIT_OK);
    assert!(String::from_utf8_lossy(&help.stdout).contains("solve"));
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
