//! Stage 8: the Markdown renderer.
//!
//! Deliberately dumb. It never filters, sorts, or recomputes anything; the
//! aggregator already decided. That is what guarantees the section layout is
//! identical for a rich capture and an empty one.
//!
//! The one exception is hop numbering, which has to place a chain's gap and
//! renumber what follows it. That is presentation arithmetic over what the
//! aggregator already decided to omit, not a second opinion about it — but it
//! is arithmetic, so it is tested at the bottom of this file.

use std::fmt::Write as _;

use super::format;
use crate::model::report::{ChainRow, EndpointRow, ReportModel};

/// Render the full report.
pub fn render(model: &ReportModel) -> String {
    let mut out = String::with_capacity(8 * 1024);
    out.push_str("# BurpSqueezer Report\n\n");
    overview(&mut out, model);
    core_signal(&mut out, model);
    secondary_context(&mut out, model);
    meta(&mut out, model);
    out
}

fn overview(out: &mut String, model: &ReportModel) {
    let o = &model.overview;
    out.push_str("## Overview\n\n");

    let methods = if o.methods.is_empty() {
        "-".to_string()
    } else {
        o.methods
            .iter()
            .map(|(method, count)| format::method_count(method, *count))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let rows = vec![
        vec!["source".into(), o.source.clone()],
        vec!["raw transactions".into(), o.raw_transactions.to_string()],
        vec![
            "after filtering".into(),
            format!(
                "{} ({:.1}% retained)",
                o.kept_transactions,
                o.retention_pct()
            ),
        ],
        vec!["endpoints".into(), o.endpoints.to_string()],
        vec!["hosts".into(), format::list(&o.hosts)],
        vec!["methods".into(), methods],
        vec!["strong values".into(), o.strong_values.to_string()],
        vec!["data-flow chains".into(), o.chains.to_string()],
    ];
    out.push_str(&format::table(&["metric", "value"], &rows));
    out.push('\n');
}

fn core_signal(out: &mut String, model: &ReportModel) {
    out.push_str("## Core Signal\n\n");
    // Add fp: legend before Strong Values
    out.push_str("fp:HHHH = stable short fingerprint of a full value; matching uses the full value in memory; full values are not printed in this report by default\n\n");
    strong_values(out, model);
    chains(out, model);
    endpoints(
        out,
        "High-Relevance Endpoints",
        &model.core_endpoints,
        Reasons::Shown,
    );
}

fn strong_values(out: &mut String, model: &ReportModel) {
    out.push_str("### Strong Values\n\n");
    let rows: Vec<Vec<String>> = model
        .strong_values
        .iter()
        .map(|v| {
            // Format all cells individually to escape pipes and control chars
            let handle_cell = format::cell(&v.handle);
            let value_cell = format::cell(&v.masked);
            let len_cell = format::cell(&v.len.to_string());
            let entropy_cell = format::cell(&format::score(v.entropy));
            let score_cell = format::cell(&format::score(v.score));
            let seen_cell = format::cell(&v.occurrences.to_string());
            let coverage_cell = format::cell(&format::percent(v.coverage));
            let endpoints_cell = format::cell(&v.endpoints.to_string());
            let propagates_cell = format::cell(&format::flag(v.propagates).to_string());
            let in_path_cell = format::cell(&format::flag(v.in_path).to_string());
            
            // Format synthetic indicator (optional hint)
            let synthetic_cell = if v.synthetic {
                format::cell("(test?)")
            } else {
                format::cell("-")
            };

            // Locations are already rendered clean and complete upstream. The
            // table renderer escapes pipes and control chars, so join and hand
            // it over whole — never truncated.
            let locations_cell = v.locations.join(", ");
            
            vec![
                handle_cell,
                value_cell,
                len_cell,
                entropy_cell,
                score_cell,
                seen_cell,
                coverage_cell,
                endpoints_cell,
                propagates_cell,
                in_path_cell,
                synthetic_cell,
                locations_cell,
            ]
        })
        .collect();
    out.push_str(&format::table_with_preformatted_cells(
        &[
            "handle",
            "value",
            "len",
            "entropy",
            "score",
            "seen",
            "coverage",
            "endpoints",
            "propagates",
            "in path",
            "synthetic?",
            "locations",
        ],
        &rows,
    ));
    out.push('\n');
}

fn chains(out: &mut String, model: &ReportModel) {
    out.push_str("### Multi-Data-Flow Chains\n\n");
    if model.chains.is_empty() {
        out.push_str(format::none());
        out.push_str("\n\n");
        return;
    }
    for chain in &model.chains {
        let _ = writeln!(
            out,
            "- **{}** {} — {} hops across {} endpoints, score {}",
            chain.handle,
            chain.masked,
            chain.hop_count(),
            chain.endpoints,
            format::score(chain.score)
        );
        hops(out, chain);
    }
    out.push('\n');
}

/// List a chain's hops, numbered by their place along the whole trail.
///
/// The gap goes where the hops were dropped, which for a truncated trail is the
/// end and for a collapsed one the middle. Numbering what follows it by real
/// positions is what keeps a collapsed listing readable as one trail.
fn hops(out: &mut String, chain: &ChainRow) {
    let dropped = chain.elided_hops();
    let listed = chain.hops.len();
    let (head, tail) = chain
        .hops
        .split_at(chain.elided.map_or(listed, |elided| elided.after.min(listed)));

    for (index, hop) in head.iter().enumerate() {
        let _ = writeln!(out, "  {}. {}", index + 1, hop);
    }
    // Core Signal must not show "… and N further hops" - all hops are listed
    for (index, hop) in tail.iter().enumerate() {
        let _ = writeln!(out, "  {}. {}", head.len() + dropped + index + 1, hop);
    }
}

/// Whether an endpoint table carries the `why` column.
///
/// Fixed per section rather than inferred from the rows, so that the layout of
/// a section never depends on what happened to be in it. Only Core rows can
/// carry a reason: an endpoint reaches Other precisely by having none.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reasons {
    Shown,
    Omitted,
}

fn endpoints(out: &mut String, heading: &str, rows: &[EndpointRow], reasons: Reasons) {
    let _ = writeln!(out, "### {heading}\n");
    let explained = reasons == Reasons::Shown;

    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|e| {
            // Format all cells individually to escape pipes and control chars
            let endpoint_cell = format::cell(&e.endpoint);
            let hits_cell = format::cell(&e.hit_summary());
            let statuses_cell = format::cell(&e.statuses.clone());
            let relevance_cell = format::cell(&format::score(e.relevance));
            
            let mut cells = vec![
                endpoint_cell,
                hits_cell,
                statuses_cell,
                relevance_cell,
            ];
            if explained {
                // Show evidence-based why tags instead of the old reasons
                let why_cell = format::cell(&format::list(&e.why_tag_summary()));
                cells.push(why_cell);
            }
            
            // Field lists are joined whole and handed to the table renderer,
            // which escapes pipes and control chars without truncating — a
            // clipped field name would be worse than a wide column.
            cells.extend([
                format::list(&e.query_params),
                format::list(&e.request_fields),
                format::list(&e.response_fields),
                format::list(&e.value_handles),
            ]);
            cells
        })
        .collect();

    let mut headers = vec!["endpoint", "hits", "statuses", "relevance"];
    if explained {
        headers.push("why");
    }
    headers.extend(["query", "req fields", "resp fields", "values"]);

    out.push_str(&format::table_with_preformatted_cells(&headers, &table_rows));
    out.push('\n');
}

fn secondary_context(out: &mut String, model: &ReportModel) {
    out.push_str("## Secondary Context\n\n");
    
    // Filter out obvious static/asset endpoints from other_endpoints based on shape
    // Static assets typically have: GET method, no path parameters, common extensions
    let filtered_other_endpoints: Vec<EndpointRow> = model.other_endpoints
        .iter()
        .filter(|endpoint| {
            // Keep endpoints that show meaningful activity
            // Filter out very low-hit static-like endpoints
            let is_static_like = {
                let method = endpoint.endpoint.split(' ').next().unwrap_or("");
                let path = endpoint.endpoint.split(' ').nth(1).unwrap_or("");
                let has_extension = path.contains('.') && 
                    (path.ends_with(".js") || path.ends_with(".css") || 
                     path.ends_with(".png") || path.ends_with(".jpg") || 
                     path.ends_with(".svg") || path.ends_with(".ico") ||
                     path.ends_with(".woff") || path.ends_with(".ttf"));
                let has_id_placeholder = path.contains("{id}");
                
                // Static-like: GET method, has extension, no id placeholder, low hit count
                method == "GET" && has_extension && !has_id_placeholder && endpoint.hits <= 2
            };
            
            !is_static_like
        })
        .cloned()
        .collect();
    
    endpoints(
        out,
        "Other Endpoints",
        &filtered_other_endpoints,
        Reasons::Omitted,
    );
    sequences(out, model);
    state_indicators(out, model);
}

fn sequences(out: &mut String, model: &ReportModel) {
    out.push_str("### Sequences\n\n");
    let rows: Vec<Vec<String>> = model
        .sequences
        .iter()
        .map(|s| {
            vec![
                s.steps.join(" \u{2192} "),
                s.support.to_string(),
                format::list(&s.linked_handles),
            ]
        })
        .collect();
    out.push_str(&format::table(
        &["sequence", "support", "linked values"],
        &rows,
    ));
    out.push('\n');
}

fn state_indicators(out: &mut String, model: &ReportModel) {
    out.push_str("### Possible State Indicators\n\n");
    let rows: Vec<Vec<String>> = model
        .state_indicators
        .iter()
        .map(|s| {
            let values = s
                .values
                .iter()
                .map(|(value, count)| format::count_with_value(value, *count))
                .collect::<Vec<_>>()
                .join(", ");
            vec![
                s.endpoint.clone(),
                s.field.clone(),
                values,
                format::percent(s.coverage),
            ]
        })
        .collect();
    out.push_str(&format::table(
        &["endpoint", "field", "observed values", "coverage"],
        &rows,
    ));
    out.push('\n');
}

fn meta(out: &mut String, model: &ReportModel) {
    let m = &model.meta;
    out.push_str("## Meta\n\n");

    let mode = m.mode.map(|mode| mode.as_str()).unwrap_or("standard");
    let rows = vec![
        vec!["tool".into(), format!("burpsqueezer {}", m.tool_version)],
        vec!["mode".into(), mode.to_string()],
        vec![
            "relaxed for small dump".into(),
            format::flag(m.relaxed_for_small_dump).to_string(),
        ],
        vec!["transactions dropped".into(), m.dropped_total().to_string()],
    ];
    out.push_str(&format::table(&["field", "value"], &rows));
    out.push('\n');

    out.push_str("### Value Handling\n\n");
    paragraphs(out, [&m.value_masking_note, &m.value_policy_note]);
    
    if !m.identical_marker_note.is_empty() {
        out.push_str("### Display Notes\n\n");
        out.push_str(&format!("{}\n", m.identical_marker_note));
    }

    out.push_str("### Filtering Breakdown\n\n");
    let drop_rows: Vec<Vec<String>> = m
        .dropped_by_reason
        .iter()
        .map(|(reason, count)| vec![reason.clone(), count.to_string()])
        .collect();
    out.push_str(&format::table(&["reason", "count"], &drop_rows));
    out.push('\n');

    out.push_str("### Truncations\n\n");
    bullets(out, &m.truncations);

    out.push_str("### Warnings\n\n");
    bullets(out, &m.warnings);
}

/// Print the non-empty notes as paragraphs, or the placeholder if there are
/// none. Keeps `### Value Handling` present and shaped the same either way.
fn paragraphs<'a>(out: &mut String, notes: impl IntoIterator<Item = &'a String>) {
    let present: Vec<&str> = notes
        .into_iter()
        .map(String::as_str)
        .filter(|note| !note.is_empty())
        .collect();
    if present.is_empty() {
        out.push_str(format::none());
        out.push_str("\n\n");
        return;
    }
    for note in present {
        let _ = writeln!(out, "{note}\n");
    }
}

fn bullets(out: &mut String, items: &[String]) {
    if items.is_empty() {
        out.push_str(format::none());
        out.push_str("\n\n");
        return;
    }
    for item in items {
        let _ = writeln!(out, "- {item}");
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::report::Elided;

    /// A chain listing `hops` of a `total`-hop trail, with the gap after
    /// `after` of them.
    fn chain(listed: usize, total: usize, after: usize) -> ChainRow {
        ChainRow {
            handle: "fp:abcd".into(),
            masked: "abc…xyz".into(),
            score: 1.0,
            hops: (0..listed).map(|index| format!("hop-{index}")).collect(),
            endpoints: 3,
            elided: (total > listed).then_some(Elided {
                hops: total - listed,
                after,
            }),
        }
    }

    fn listing(chain: &ChainRow) -> String {
        let mut out = String::new();
        hops(&mut out, chain);
        out
    }

    #[test]
    fn a_whole_trail_is_numbered_straight_through() {
        let rendered = listing(&chain(3, 3, 3));
        assert_eq!(rendered, "  1. hop-0\n  2. hop-1\n  3. hop-2\n");
    }

    #[test]
    fn a_truncated_trail_shows_all_hops() {
        let rendered = listing(&chain(2, 9, 2));
        assert_eq!(rendered, "  1. hop-0\n  2. hop-1\n");
    }

    /// The collapsed listing is only readable if the tail keeps the positions
    /// it actually held: hops 12 and 13 of thirteen, not 3 and 4.
    #[test]
    fn a_collapsed_trail_renumbers_the_tail_by_its_real_positions() {
        let rendered = listing(&chain(4, 13, 2));
        assert_eq!(
            rendered,
            "  1. hop-0\n  2. hop-1\n  12. hop-2\n  13. hop-3\n"
        );
    }

    /// Regression test: Core Signal must never show "further hops" in chain listings.
    /// This test ensures the render layer does not omit hops in Multi-Data-Flow Chains.
    #[test]
    fn core_signal_must_not_show_further_hops() {
        // Test with various chain configurations
        let test_cases = vec![
            (2, 9, 2),   // truncated
            (4, 13, 2),  // collapsed
            (5, 25, 3),  // larger collapsed
            (10, 40, 5), // very large collapsed
        ];

        for (listed, total, after) in test_cases {
            let rendered = listing(&chain(listed, total, after));
            assert!(
                !rendered.contains("further hops"),
                "Core Signal must not show 'further hops' in chain listings. \
                 Found in: {rendered}"
            );
        }
    }
}
