//! Shared helpers for the integration tests.
//!
//! Every integration test binary compiles this module separately, so a helper
//! only one of them needs still looks unused to the others.
#![allow(dead_code)]

use std::path::PathBuf;

/// Absolute path to a checked-in fixture.
pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// A scratch directory unique to one test, removed when the guard drops.
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub fn new(label: &str) -> Self {
        let unique = format!(
            "burpsqueezer-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        );
        let path = std::env::temp_dir().join(unique.replace(['(', ')', ' '], ""));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        Self { path }
    }

    /// Path inside the scratch directory. The file need not exist yet.
    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
