//! Minimal stderr logging: stage progress, warnings, and final statistics.
//!
//! stdout is never touched, so the report can be piped without contamination.

use std::sync::atomic::{AtomicBool, Ordering};

static QUIET: AtomicBool = AtomicBool::new(false);
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Configure global verbosity once, at startup.
pub fn configure(quiet: bool, verbose: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
    VERBOSE.store(verbose && !quiet, Ordering::Relaxed);
}

fn enabled() -> bool {
    !QUIET.load(Ordering::Relaxed)
}

/// Announce entry into a pipeline stage.
pub fn stage(index: usize, name: &str) {
    if enabled() {
        eprintln!("[{index}/8] {name}");
    }
}

/// Report a stage outcome or run-level fact.
pub fn info(message: &str) {
    if enabled() {
        eprintln!("      {message}");
    }
}

/// Surface something the operator should know about the quality of the report.
pub fn warn(message: &str) {
    if enabled() {
        eprintln!("warn: {message}");
    }
}

/// Detail suppressed unless `--verbose` was requested.
pub fn debug(message: &str) {
    if VERBOSE.load(Ordering::Relaxed) {
        eprintln!("debug: {message}");
    }
}
