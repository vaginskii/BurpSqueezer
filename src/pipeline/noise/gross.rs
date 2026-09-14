//! The only place in the codebase allowed to hardcode anything.
//!
//! Every list here is deliberately short and closed. Nothing may be added to it
//! that encodes an assumption about an application's domain; these entries
//! describe transport-level noise that is noise in every application.

use crate::config::Thresholds;
use crate::model::transaction::RawTransaction;

/// Content-type prefixes that carry no API semantics.
const OPAQUE_CONTENT_TYPES: &[&str] = &[
    "image/",
    "font/",
    "audio/",
    "video/",
    "application/wasm",
    "application/font-woff",
    "application/font-woff2",
    "application/x-font-ttf",
    "application/x-font-otf",
    "application/vnd.ms-fontobject",
];

/// Content type dropped only when the body is decisively large.
const BULK_CONTENT_TYPE: &str = "application/octet-stream";
/// Multiplier applied to the body-size floor for [`BULK_CONTENT_TYPE`].
const BULK_SIZE_FACTOR: usize = 4;

/// Infrastructure paths that never describe business behaviour.
const INFRA_PATHS: &[&str] = &[
    "/tunnel",
    "/health",
    "/healthz",
    "/ready",
    "/readiness",
    "/live",
    "/liveness",
    "/ping",
    "/favicon.ico",
    "/robots.txt",
];

/// Query parameter names typical of cache busting.
///
/// Their presence is only ever a demotion signal. It is never sufficient on its
/// own to discard a transaction, because these names are also legitimate
/// business parameters in plenty of APIs.
const CACHE_BUSTER_PARAMS: &[&str] = &["_", "callback", "v", "t", "ts", "timestamp"];

/// Why the gross filter rejected a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrossReason {
    /// Body is an opaque binary asset.
    OpaqueAsset,
    /// Path is an infrastructure probe.
    InfraPath,
}

impl GrossReason {
    pub fn as_str(self) -> &'static str {
        match self {
            GrossReason::OpaqueAsset => "gross: opaque asset body",
            GrossReason::InfraPath => "gross: infrastructure path",
        }
    }
}

/// Judge one transaction against the closed lists.
pub fn evaluate(tx: &RawTransaction, th: &Thresholds) -> Option<GrossReason> {
    if matches_infra_path(&tx.path) {
        return Some(GrossReason::InfraPath);
    }
    if is_opaque_asset(tx, th) {
        return Some(GrossReason::OpaqueAsset);
    }
    None
}

/// Exact match, or a match on a full leading path segment.
///
/// Segment-boundary matching is what stops `/livestream` from being mistaken
/// for `/live`.
fn matches_infra_path(path: &str) -> bool {
    let path = path.trim_end_matches('/');
    let lowered = path.to_ascii_lowercase();
    let candidate = if lowered.is_empty() { "/" } else { &lowered };

    INFRA_PATHS.iter().any(|probe| {
        candidate == *probe
            || candidate.starts_with(&format!("{probe}/"))
            || candidate.starts_with(&format!("{probe}?"))
    })
}

/// True when the response body is opaque binary content of a meaningful size.
fn is_opaque_asset(tx: &RawTransaction, th: &Thresholds) -> bool {
    let Some(content_type) = tx.response_content_type() else {
        return false;
    };
    let body_len = tx.response_len();

    if content_type.starts_with(BULK_CONTENT_TYPE) {
        return body_len >= th.gross_body_min_len.saturating_mul(BULK_SIZE_FACTOR);
    }
    if body_len < th.gross_body_min_len {
        return false;
    }
    OPAQUE_CONTENT_TYPES
        .iter()
        .any(|prefix| content_type.starts_with(prefix))
}

/// Count of cache-buster-looking query parameters on this transaction.
pub fn cache_buster_hits(tx: &RawTransaction) -> usize {
    tx.query_params()
        .iter()
        .filter(|(name, _)| {
            let lowered = name.to_ascii_lowercase();
            CACHE_BUSTER_PARAMS.iter().any(|probe| lowered == *probe)
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;
    use crate::model::http::HttpMessage;

    fn tx(path: &str, query: &str, content_type: &str, body_len: usize) -> RawTransaction {
        let response = HttpMessage::parse(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n\r\n{}",
                "x".repeat(body_len)
            )
            .as_bytes(),
        );
        RawTransaction {
            id: 0,
            url: format!("https://x.test{path}"),
            host: "x.test".into(),
            port: "443".into(),
            protocol: "https".into(),
            method: "GET".into(),
            path: path.into(),
            query: query.into(),
            extension: String::new(),
            status: 200,
            mime_type: String::new(),
            request: HttpMessage::parse(b"GET / HTTP/1.1\r\n\r\n"),
            response: Some(response),
        }
    }

    fn thresholds() -> Thresholds {
        Thresholds::for_mode(Mode::Standard)
    }

    #[test]
    fn drops_infrastructure_probes() {
        let th = thresholds();
        for path in ["/health", "/HEALTHZ", "/ping/", "/favicon.ico", "/live/x"] {
            assert_eq!(
                evaluate(&tx(path, "", "application/json", 10), &th),
                Some(GrossReason::InfraPath),
                "{path} should be treated as infrastructure"
            );
        }
    }

    #[test]
    fn does_not_drop_paths_that_merely_share_a_prefix() {
        let th = thresholds();
        for path in ["/livestream", "/healthcheck-report", "/tunnels-config"] {
            assert_eq!(
                evaluate(&tx(path, "", "application/json", 10), &th),
                None,
                "{path} must survive"
            );
        }
    }

    #[test]
    fn drops_large_binary_assets_only() {
        let th = thresholds();
        let large = tx("/img/a.png", "", "image/png", th.gross_body_min_len + 1);
        assert_eq!(evaluate(&large, &th), Some(GrossReason::OpaqueAsset));

        let small = tx("/img/a.png", "", "image/png", 8);
        assert_eq!(evaluate(&small, &th), None);
    }

    #[test]
    fn octet_stream_needs_to_be_decisively_large() {
        let th = thresholds();
        let modest = tx(
            "/blob",
            "",
            "application/octet-stream",
            th.gross_body_min_len,
        );
        assert_eq!(evaluate(&modest, &th), None);

        let huge = tx(
            "/blob",
            "",
            "application/octet-stream",
            th.gross_body_min_len * 4,
        );
        assert_eq!(evaluate(&huge, &th), Some(GrossReason::OpaqueAsset));
    }

    #[test]
    fn cache_busters_are_counted_not_dropped() {
        let th = thresholds();
        let candidate = tx("/api/list", "_=1699999&page=2", "application/json", 20);
        assert_eq!(cache_buster_hits(&candidate), 1);
        assert_eq!(evaluate(&candidate, &th), None);
    }
}
