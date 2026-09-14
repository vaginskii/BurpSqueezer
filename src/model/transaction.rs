//! One request/response pair as it appeared in the dump.

use super::http::HttpMessage;

/// Index of a transaction in dump order. Dump order is capture order, which
/// the data-flow stage relies on to tell sources from sinks.
pub type TxId = usize;

/// A single Burp `<item>`, decoded but not yet interpreted.
#[derive(Debug, Clone)]
pub struct RawTransaction {
    pub id: TxId,
    pub url: String,
    pub host: String,
    pub port: String,
    pub protocol: String,
    pub method: String,
    /// Path as captured, query string excluded.
    pub path: String,
    /// Raw query string without the leading `?`.
    pub query: String,
    pub extension: String,
    pub status: u16,
    pub mime_type: String,
    pub request: HttpMessage,
    pub response: Option<HttpMessage>,
}

impl RawTransaction {
    /// Decoded query parameters in order of appearance.
    pub fn query_params(&self) -> Vec<(String, String)> {
        parse_query(&self.query)
    }

    /// Sorted, de-duplicated parameter names. Used as the low-variation key.
    pub fn param_signature(&self) -> String {
        let mut names: Vec<String> = self.query_params().into_iter().map(|(k, _)| k).collect();
        names.sort();
        names.dedup();
        names.join(",")
    }

    /// Non-empty path segments.
    pub fn segments(&self) -> Vec<&str> {
        self.path.split('/').filter(|s| !s.is_empty()).collect()
    }

    /// Effective content type of the response, preferring the parsed header
    /// over Burp's own `mimetype` hint.
    pub fn response_content_type(&self) -> Option<String> {
        self.response
            .as_ref()
            .and_then(|r| r.content_type())
            .or_else(|| {
                let hint = self.mime_type.trim();
                (!hint.is_empty()).then(|| hint.to_ascii_lowercase())
            })
    }

    /// Response body length, zero when there is no response.
    pub fn response_len(&self) -> usize {
        self.response.as_ref().map_or(0, |r| r.body.len())
    }
}

/// Split a query string into decoded key/value pairs.
pub fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

/// Decode `%XX` escapes and `+` as space; invalid escapes are left verbatim.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match hex_pair(bytes[i + 1], bytes[i + 2]) {
                Some(byte) => {
                    out.push(byte);
                    i += 3;
                }
                None => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_pair(high: u8, low: u8) -> Option<u8> {
    Some(hex_digit(high)? << 4 | hex_digit(low)?)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_query_pairs() {
        let pairs = parse_query("a=1&b=hello+world&c=%2Fx&flag");
        assert_eq!(
            pairs,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "hello world".to_string()),
                ("c".to_string(), "/x".to_string()),
                ("flag".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn leaves_broken_escapes_alone() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
