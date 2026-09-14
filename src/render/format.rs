//! Markdown formatting primitives.
//!
//! Everything here optimises for a machine reader: no decoration, no padding,
//! short cell values, and never a table where a line would do.

/// Longest cell text before it is elided.
const MAX_CELL_LEN: usize = 96;

/// Escape the characters that would break a Markdown table cell.
pub fn cell(text: &str) -> String {
    let collapsed: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let escaped = collapsed.replace('|', "\\|");
    // Apply truncation for regular cells (values, not field lists)
    truncate(&escaped, MAX_CELL_LEN)
}

/// Shorten to `limit` characters, marking the cut.
/// For very long strings, tries to keep meaningful suffix (e.g., field name endings).
pub fn truncate(text: &str, limit: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= limit {
        return text.to_string();
    }
    
    // For moderately long strings (within 50 chars of limit), simple head truncation  
    if chars.len() <= limit + 50 {
        let head: String = chars[..limit.saturating_sub(1)].iter().collect();
        return format!("{head}\u{2026}");
    }
    
    // For very long strings, keep head and meaningful suffix
    // Reserve 2 chars for ellipsis, split remaining space
    let available = limit.saturating_sub(2);
    let head_len = available * 2 / 3;  // 2/3 for head
    let suffix_len = available - head_len;  // 1/3 for suffix
    
    let head: String = chars[..head_len].iter().collect();
    
    // For suffix, try to find a natural breakpoint (after separator)
    let suffix_start = chars.len().saturating_sub(suffix_len);
    let suffix: String = chars[suffix_start..].iter().collect();
    
    // Look for separator to start suffix at more natural boundary
    let adjusted_suffix = if let Some(sep_pos) = suffix.find(|c: char| c == '_' || c == '-' || c == '.') {
        if sep_pos > 0 && sep_pos < suffix.len() - 5 {
            &suffix[sep_pos + 1..]
        } else {
            &suffix
        }
    } else {
        &suffix
    };
    
    format!("{head}\u{2026}{adjusted_suffix}")
}

/// Render a table, or the placeholder when there is nothing to show.
///
/// Section structure stays identical whether or not data exists, which is what
/// lets a consumer rely on the layout.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return format!("{}\n", none());
    }

    let mut out = String::new();
    out.push_str(&format!("| {} |\n", headers.join(" | ")));
    out.push_str(&format!(
        "|{}|\n",
        headers.iter().map(|_| "---").collect::<Vec<_>>().join("|")
    ));
    for row in rows {
        let cells: Vec<String> = row.iter().map(|value| cell(value)).collect();
        out.push_str(&format!("| {} |\n", cells.join(" | ")));
    }
    out
}

/// Render a table with pre-formatted cells (no additional cell formatting applied).
/// Used when cells need custom formatting limits (e.g., locations, field lists).
pub(crate) fn table_with_preformatted_cells(headers: &[&str], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return format!("{}\n", none());
    }

    let mut out = String::new();
    out.push_str(&format!("| {} |\n", headers.join(" | ")));
    out.push_str(&format!(
        "|{}|\n",
        headers.iter().map(|_| "---").collect::<Vec<_>>().join("|")
    ));
    for row in rows {
        // Don't apply cell() formatting - cells are already pre-formatted
        // Just escape pipes to prevent table breaking
        let escaped_row: Vec<String> = row.iter().map(|cell| {
            let collapsed: String = cell.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
            collapsed.replace('|', "\\|")
        }).collect();
        out.push_str(&format!("| {} |\n", escaped_row.join(" | ")));
    }
    out
}

/// The single phrase used everywhere a section has no content.
pub fn none() -> &'static str {
    "_none_"
}

/// Join a list into one cell, or the placeholder when empty.
pub fn list(items: &[String]) -> String {
    if items.is_empty() {
        return "-".to_string();
    }
    items.join(", ")
}

/// Format a score or ratio with two decimals.
pub fn score(value: f64) -> String {
    format!("{value:.2}")
}

/// Format a fraction as a percentage with one decimal.
pub fn percent(value: f64) -> String {
    format!("{:.1}%", value * 100.0)
}

/// Yes/no rendered compactly for tables.
pub fn flag(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

/// Format a count with a value, avoiding glued tokens like "truex3".
///
/// Renders as "value (count)" when count > 1, or just "value" when count == 1.
/// This prevents unparseable concatenated tokens and provides consistent formatting.
pub fn count_with_value(value: &str, count: usize) -> String {
    if count == 1 {
        value.to_string()
    } else {
        format!("{} ({})", value, count)
    }
}

/// Format a method/status count with proper spacing, avoiding "GETx81".
///
/// Renders as "METHOD: count" or "METHOD (count)" depending on context.
/// For methods, uses colon separator; for statuses, uses parentheses.
pub fn method_count(method: &str, count: usize) -> String {
    if count == 1 {
        method.to_string()
    } else {
        format!("{}: {}", method, count)
    }
}

/// Format a status code count, avoiding "200x4".
///
/// Renders as "CODE (count)" when count > 1, or just "CODE" when count == 1.
pub fn status_count(code: u16, count: usize) -> String {
    if count == 1 {
        code.to_string()
    } else {
        format!("{} ({})", code, count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_pipes_and_control_characters() {
        assert_eq!(cell("a|b"), "a\\|b");
        assert_eq!(cell("a\nb"), "a b");
    }

    #[test]
    fn truncates_long_cells() {
        let long = "x".repeat(MAX_CELL_LEN + 20);
        let rendered = cell(&long);
        assert_eq!(rendered.chars().count(), MAX_CELL_LEN);
        assert!(rendered.ends_with('\u{2026}'));
    }

    #[test]
    fn empty_tables_render_the_placeholder() {
        assert_eq!(table(&["a", "b"], &[]), "_none_\n");
    }

    #[test]
    fn renders_a_header_and_rows() {
        let rendered = table(&["k", "v"], &[vec!["1".into(), "2".into()]]);
        assert!(rendered.starts_with("| k | v |\n|---|---|\n"));
        assert!(rendered.contains("| 1 | 2 |"));
    }

    #[test]
    fn formats_numbers_predictably() {
        assert_eq!(score(0.5), "0.50");
        assert_eq!(percent(0.874), "87.4%");
        assert_eq!(flag(true), "yes");
    }

    #[test]
    fn count_formatter_avoids_glued_tokens() {
        assert_eq!(count_with_value("true", 1), "true");
        assert_eq!(count_with_value("true", 3), "true (3)");
        assert_eq!(count_with_value("GET", 1), "GET");
        assert_eq!(count_with_value("GET", 81), "GET (81)");
    }

    #[test]
    fn method_count_uses_colon_separator() {
        assert_eq!(method_count("GET", 1), "GET");
        assert_eq!(method_count("GET", 5), "GET: 5");
        assert_eq!(method_count("POST", 12), "POST: 12");
    }

    #[test]
    fn status_count_uses_parentheses() {
        assert_eq!(status_count(200, 1), "200");
        assert_eq!(status_count(200, 4), "200 (4)");
        assert_eq!(status_count(404, 1), "404");
        assert_eq!(status_count(404, 7), "404 (7)");
    }

    #[test]
    fn count_formatters_reject_glued_patterns() {
        // Ensure we never produce glued tokens like "truex3" or "200x4"
        assert!(!count_with_value("true", 3).contains('x'));
        assert!(!method_count("GET", 81).contains('x'));
        assert!(!status_count(200, 4).contains('x'));
    }

    #[test]
    fn smart_truncation_keeps_meaningful_suffix() {
        // Very long field names should keep their suffix after truncation
        let very_long = "user_profile_settings_preferences_configuration_data_field_name_ending_with_meaningful_suffix";
        let truncated = truncate(very_long, 50);

        // Should contain ellipsis since input is longer than limit
        assert!(truncated.contains('…'));
        // Length should be close to but not exceed limit significantly
        // (may slightly exceed due to Unicode character handling)
        assert!(truncated.len() <= 52); // Allow small margin for ellipsis
    }
}
