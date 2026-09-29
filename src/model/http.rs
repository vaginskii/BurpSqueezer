//! A parsed HTTP message: start line, headers, and raw body.

use std::borrow::Cow;

/// One side of an HTTP exchange, decoded from Burp's base64 blob.
#[derive(Debug, Clone, Default)]
pub struct HttpMessage {
    pub start_line: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpMessage {
    /// Split raw message bytes into a start line, headers, and body.
    ///
    /// Tolerant by design: Burp dumps are frequently truncated or contain
    /// binary tails, so anything unparseable degrades into an empty field
    /// rather than an error.
    pub fn parse(raw: &[u8]) -> Self {
        let split = find_body_offset(raw);
        let (head, body) = match split {
            Some((head_end, body_start)) => (&raw[..head_end], raw[body_start..].to_vec()),
            None => (raw, Vec::new()),
        };

        let head = String::from_utf8_lossy(head);
        let mut lines = head.split("\r\n").flat_map(|l| l.split('\n'));
        let start_line = lines.next().unwrap_or_default().trim().to_string();

        let headers = lines
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.trim().to_string(), value.trim().to_string()))
            })
            .collect();

        Self {
            start_line,
            headers,
            body,
        }
    }

    /// First header matching `name`, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All headers matching `name`, case-insensitively (e.g. `Set-Cookie`).
    pub fn headers_all(&self, name: &str) -> impl Iterator<Item = &str> {
        let needle = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter_map(move |(k, v)| k.to_ascii_lowercase().eq(&needle).then_some(v.as_str()))
    }

    /// Content type with any parameters stripped and lowercased.
    pub fn content_type(&self) -> Option<String> {
        self.header("content-type").map(|ct| {
            ct.split(';')
                .next()
                .unwrap_or(ct)
                .trim()
                .to_ascii_lowercase()
        })
    }

    /// Body as text, replacing invalid UTF-8 rather than failing.
    pub fn body_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    /// Body parsed as JSON, if it plausibly is JSON.
    pub fn json(&self) -> Option<serde_json::Value> {
        let text = self.body_str();
        let trimmed = text.trim_start();
        if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
            return None;
        }
        serde_json::from_str(trimmed).ok()
    }

    /// Cookie pairs sent by the client.
    pub fn cookies(&self) -> Vec<(String, String)> {
        self.header("cookie")
            .map(|raw| {
                raw.split(';')
                    .filter_map(|pair| pair.split_once('='))
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                    .filter(|(k, v)| !k.is_empty() && !v.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Cookie pairs set by the server, ignoring attributes such as `Path`.
    pub fn set_cookies(&self) -> Vec<(String, String)> {
        self.headers_all("set-cookie")
            .filter_map(|raw| raw.split(';').next())
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .filter(|(k, v)| !k.is_empty() && !v.is_empty())
            .collect()
    }
}

/// Locate the header/body boundary, returning `(head_end, body_start)`.
fn find_body_offset(raw: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        return Some((pos, pos + 4));
    }
    find_subslice(raw, b"\n\n").map(|pos| (pos, pos + 2))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_headers_and_body() {
        let raw = b"POST /api/login HTTP/1.1\r\nHost: x.test\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{\"a\":1}";
        let msg = HttpMessage::parse(raw);
        assert_eq!(msg.start_line, "POST /api/login HTTP/1.1");
        assert_eq!(msg.header("host"), Some("x.test"));
        assert_eq!(msg.content_type().as_deref(), Some("application/json"));
        assert_eq!(msg.body_str(), "{\"a\":1}");
        assert!(msg.json().is_some());
    }

    #[test]
    fn handles_missing_body_and_lf_only_separators() {
        let msg = HttpMessage::parse(b"GET / HTTP/1.1\nHost: x.test\n\n");
        assert_eq!(msg.header("Host"), Some("x.test"));
        assert!(msg.body.is_empty());

        let headerless = HttpMessage::parse(b"GET / HTTP/1.1");
        assert_eq!(headerless.start_line, "GET / HTTP/1.1");
        assert!(headerless.headers.is_empty());
    }

    #[test]
    fn extracts_cookies_from_both_directions() {
        let req = HttpMessage::parse(b"GET / HTTP/1.1\r\nCookie: sid=abc; theme=dark\r\n\r\n");
        assert_eq!(
            req.cookies(),
            vec![
                ("sid".to_string(), "abc".to_string()),
                ("theme".to_string(), "dark".to_string())
            ]
        );

        let resp = HttpMessage::parse(
            b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=xyz; Path=/; HttpOnly\r\nSet-Cookie: csrf=q1\r\n\r\n",
        );
        assert_eq!(
            resp.set_cookies(),
            vec![
                ("sid".to_string(), "xyz".to_string()),
                ("csrf".to_string(), "q1".to_string())
            ]
        );
    }
}
