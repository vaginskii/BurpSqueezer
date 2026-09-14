//! `burpsqueezer` turns a raw Burp Suite XML dump into a compact Markdown
//! report intended to be read by a language model rather than by a person.
//!
//! The whole tool is one strictly sequential pipeline:
//!
//! 1. [`pipeline::parser`] — read Burp XML into transactions
//! 2. [`pipeline::noise`] — hybrid statistical + gross noise filtering
//! 3. [`pipeline::normalizer`] — statistical path templating
//! 4. [`pipeline::mining`] — strong value (identifier) mining
//! 5. [`pipeline::relationships`] — data-flow chains and sequences
//! 6. [`pipeline::variation`] — low-cardinality field variation signals
//! 7. [`pipeline::aggregator`] — prioritization into a report model
//! 8. [`render`] — Markdown rendering
//!
//! Stages 1–7 are orchestrated by [`pipeline::run`]; stage 8 is invoked by
//! [`write_report`]. Nothing in this crate searches for vulnerabilities or
//! attaches semantic meaning to what it observes.

pub mod analysis;
pub mod cli;
pub mod config;
pub mod error;
pub mod logging;
pub mod model;
pub mod pipeline;
pub mod render;

use std::fs;
use std::path::Path;

pub use config::Mode;
pub use error::{Error, Result};
pub use model::report::ReportModel;

/// Version reported in the CLI and in the report's Meta section.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run the analysis pipeline and write the report: the whole `solve` command.
pub fn solve(input: &Path, output: &Path, mode: Mode) -> Result<()> {
    let model = squeeze(input, mode)?;
    write_report(&model, output)
}

/// Run stages 1–7 and return the report model without rendering it.
///
/// Exposed separately so the analysis can be exercised in tests, and so future
/// front-ends do not have to go through the filesystem.
pub fn squeeze(input: &Path, mode: Mode) -> Result<ReportModel> {
    pipeline::run(input, mode)
}

/// Render a report model and write it to disk (stage 8).
pub fn write_report(model: &ReportModel, output: &Path) -> Result<()> {
    logging::stage(8, "rendering Markdown");
    let markdown = render::render(model);

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| Error::WriteReport {
                path: output.to_path_buf(),
                source,
            })?;
        }
    }

    fs::write(output, markdown.as_bytes()).map_err(|source| Error::WriteReport {
        path: output.to_path_buf(),
        source,
    })?;

    logging::info(&format!(
        "wrote {} ({} bytes)",
        output.display(),
        markdown.len()
    ));
    Ok(())
}
