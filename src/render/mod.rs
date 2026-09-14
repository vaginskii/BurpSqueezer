//! Stage 8: rendering.
//!
//! `format` holds the Markdown primitives, `markdown` the section layout. The
//! split exists so the layout can be read in one screen without escaping and
//! truncation rules getting in the way.

pub mod format;
pub mod markdown;

pub use markdown::render;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::report::ReportModel;

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

    #[test]
    fn an_empty_model_still_renders_every_section_in_order() {
        let rendered = render(&ReportModel::default());
        let mut cursor = 0;
        for heading in MANDATED {
            let found = rendered[cursor..]
                .find(heading)
                .unwrap_or_else(|| panic!("missing heading: {heading}"));
            cursor += found + heading.len();
        }
    }

    #[test]
    fn empty_sections_carry_the_placeholder() {
        let rendered = render(&ReportModel::default());
        assert!(rendered.contains("### Strong Values\n\n_none_"));
        assert!(rendered.contains("### Sequences\n\n_none_"));
        assert!(rendered.contains("### Possible State Indicators\n\n_none_"));
    }

    #[test]
    fn overview_is_present_even_without_transactions() {
        let rendered = render(&ReportModel::default());
        assert!(rendered.contains("| raw transactions | 0 |"));
        assert!(rendered.contains("0 (0.0% retained)"));
    }
}
