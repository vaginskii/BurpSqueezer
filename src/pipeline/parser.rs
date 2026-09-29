//! Stage 1: Burp XML into [`RawTransaction`]s.
//!
//! Streams `<item>` elements so that memory scales with retained data rather
//! than with file size.
//!
//! Two [`Limits`] are enforced here, and they behave differently on purpose. An
//! oversized body is dropped and the run continues, because a real capture may
//! well contain one download and the reader would rather lose it than the other
//! three hundred transactions. An oversized *dump* stops the run outright,
//! because analysing an arbitrary prefix of it would produce coverage figures,
//! ubiquity shares and retention rates that describe the prefix rather than the
//! API — every statistic downstream is a ratio over the whole input.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::config::Limits;
use crate::error::{Error, Result};
use crate::model::http::HttpMessage;
use crate::model::transaction::RawTransaction;

/// A parsed dump, together with what the input limits did to it.
#[derive(Debug, Default)]
pub struct Parsed {
    pub transactions: Vec<RawTransaction>,
    /// Bodies discarded for exceeding [`Limits::max_body_bytes`].
    ///
    /// Carried out of the parser rather than merely logged: a report built
    /// without those bodies is missing fields it would otherwise have listed,
    /// and Meta has to be able to say so.
    pub oversized_bodies: usize,
}

/// Parse a Burp XML export.
///
/// Fails when the file is empty, unreadable, malformed, devoid of items, or
/// larger than [`Limits::max_transactions`] allows.
pub fn parse(path: &Path, limits: &Limits) -> Result<Parsed> {
    let metadata = std::fs::metadata(path).map_err(|source| Error::ReadInput {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() == 0 {
        return Err(Error::EmptyInput(path.to_path_buf()));
    }

    let file = File::open(path).map_err(|source| Error::ReadInput {
        path: path.to_path_buf(),
        source,
    })?;
    let parsed = parse_reader(BufReader::new(file), limits)?;

    if parsed.transactions.is_empty() {
        return Err(Error::NoTransactions(path.to_path_buf()));
    }
    Ok(parsed)
}

/// Parse from any reader. Exposed for tests and for future input sources.
pub fn parse_reader<R: std::io::BufRead>(source: R, limits: &Limits) -> Result<Parsed> {
    let mut reader = Reader::from_reader(source);
    // Set as two fields rather than through the `trim_text` convenience method:
    // these are the primitive knobs quick-xml exposes, and being explicit says
    // that both ends are trimmed. Pretty-printed dumps indent the contents of
    // <request>, and that indentation is not part of the HTTP message.
    let config = reader.config_mut();
    config.trim_text_start = true;
    config.trim_text_end = true;

    let mut buffer = Vec::new();
    let mut parsed = Parsed::default();
    let mut item: Option<ItemBuilder> = None;
    let mut field: Option<String> = None;
    let mut text = String::new();
    let mut base64_field = false;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|error| Error::MalformedXml {
                offset: reader.buffer_position(),
                detail: error.to_string(),
            })?;

        match event {
            Event::Start(start) => {
                let name = local_name(start.name().as_ref());
                if name == "item" {
                    item = Some(ItemBuilder::default());
                } else if item.is_some() {
                    base64_field = has_base64_attribute(&start);
                    field = Some(name);
                    text.clear();
                }
            }
            Event::Text(bytes) => {
                if field.is_some() {
                    let decoded = bytes.unescape().map_err(|error| Error::MalformedXml {
                        offset: reader.buffer_position(),
                        detail: error.to_string(),
                    })?;
                    text.push_str(decoded.as_ref());
                }
            }
            Event::CData(bytes) => {
                if field.is_some() {
                    let raw = bytes.into_inner();
                    text.push_str(&String::from_utf8_lossy(&raw));
                }
            }
            Event::End(end) => {
                let name = local_name(end.name().as_ref());
                if name == "item" {
                    if let Some(builder) = item.take() {
                        if parsed.transactions.len() == limits.max_transactions {
                            return Err(Error::TooManyTransactions {
                                limit: limits.max_transactions,
                            });
                        }
                        parsed.oversized_bodies += builder.oversized_bodies;
                        parsed
                            .transactions
                            .push(builder.build(parsed.transactions.len()));
                    }
                } else if let (Some(builder), Some(current)) = (item.as_mut(), field.take()) {
                    if current == name {
                        builder.set(&current, &text, base64_field, limits);
                    }
                    text.clear();
                    base64_field = false;
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    Ok(parsed)
}

/// Strip any namespace prefix and lowercase the tag name.
fn local_name(raw: &[u8]) -> String {
    let name = String::from_utf8_lossy(raw);
    let local = name.rsplit(':').next().unwrap_or(&name);
    local.to_ascii_lowercase()
}

fn has_base64_attribute(start: &quick_xml::events::BytesStart<'_>) -> bool {
    start.attributes().flatten().any(|attr| {
        attr.key.as_ref().eq_ignore_ascii_case(b"base64")
            && attr.value.as_ref().eq_ignore_ascii_case(b"true")
    })
}

/// Accumulates one `<item>` before it becomes a [`RawTransaction`].
#[derive(Default)]
struct ItemBuilder {
    url: String,
    host: String,
    port: String,
    protocol: String,
    method: String,
    path: String,
    extension: String,
    status: String,
    mime_type: String,
    request: HttpMessage,
    response: Option<HttpMessage>,
    oversized_bodies: usize,
}

impl ItemBuilder {
    fn set(&mut self, field: &str, text: &str, base64_encoded: bool, limits: &Limits) {
        match field {
            "url" => self.url = text.to_string(),
            "host" => self.host = text.to_string(),
            "port" => self.port = text.to_string(),
            "protocol" => self.protocol = text.to_string(),
            "method" => self.method = text.trim().to_ascii_uppercase(),
            "path" => self.path = text.to_string(),
            "extension" => self.extension = normalize_extension(text),
            "status" => self.status = text.to_string(),
            "mimetype" => self.mime_type = text.to_string(),
            "request" => self.request = self.message(text, base64_encoded, limits),
            "response" => self.response = Some(self.message(text, base64_encoded, limits)),
            _ => {}
        }
    }

    /// Decode one side of the exchange, dropping a body past the cap.
    ///
    /// The start line and headers always survive, so an oversized download
    /// still tells the report which route served it, with what status and what
    /// content type. Only the payload nobody was going to mine goes.
    fn message(&mut self, text: &str, base64_encoded: bool, limits: &Limits) -> HttpMessage {
        let mut message = HttpMessage::parse(&decode_body(text, base64_encoded));
        if message.body.len() > limits.max_body_bytes {
            message.body = Vec::new();
            self.oversized_bodies += 1;
        }
        message
    }

    fn build(self, id: usize) -> RawTransaction {
        let (path, query) = split_path(&self.path, &self.url);

        RawTransaction {
            id,
            url: self.url,
            host: self.host,
            port: self.port,
            protocol: self.protocol,
            method: if self.method.is_empty() {
                "GET".to_string()
            } else {
                self.method
            },
            path,
            query,
            extension: self.extension,
            status: self.status.trim().parse().unwrap_or(0),
            mime_type: self.mime_type,
            request: self.request,
            response: self.response,
        }
    }
}

/// Burp writes the literal string `null` when there is no extension.
fn normalize_extension(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.eq_ignore_ascii_case("null") {
        return String::new();
    }
    trimmed.to_ascii_lowercase()
}

fn decode_body(text: &str, base64_encoded: bool) -> Vec<u8> {
    if !base64_encoded {
        return text.as_bytes().to_vec();
    }
    let compact: String = text.split_whitespace().collect();
    STANDARD
        .decode(compact.as_bytes())
        .unwrap_or_else(|_| text.as_bytes().to_vec())
}

/// Split a captured path into path and query, falling back to the URL.
fn split_path(path: &str, url: &str) -> (String, String) {
    let candidate = if path.trim().is_empty() {
        path_from_url(url)
    } else {
        path.trim().to_string()
    };
    match candidate.split_once('?') {
        Some((head, tail)) => (head.to_string(), tail.to_string()),
        None => (candidate, String::new()),
    }
}

fn path_from_url(url: &str) -> String {
    let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    match without_scheme.find('/') {
        Some(index) => without_scheme[index..].to_string(),
        None => "/".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    fn dump(items: &str) -> String {
        format!(r#"<?xml version="1.0"?><items burpVersion="2024.1">{items}</items>"#)
    }

    /// Parse under the shipped limits: what an ordinary run sees.
    fn read(xml: &str) -> Vec<RawTransaction> {
        parse_reader(xml.as_bytes(), &Limits::default())
            .expect("well-formed dump")
            .transactions
    }

    fn item(path: &str, request: &str, response: &str) -> String {
        format!(
            r#"<item><url>https://x.test{path}</url><host ip="10.0.0.1">x.test</host>
               <port>443</port><protocol>https</protocol><method>get</method>
               <path>{path}</path><extension>null</extension><status>200</status>
               <mimetype>JSON</mimetype>
               <request base64="true">{}</request>
               <response base64="true">{}</response></item>"#,
            STANDARD.encode(request),
            STANDARD.encode(response),
        )
    }

    #[test]
    fn decodes_base64_bodies_and_normalizes_fields() {
        let xml = dump(&item(
            "/api/users/7?page=2",
            "GET /api/users/7?page=2 HTTP/1.1\r\nHost: x.test\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":7}",
        ));
        let parsed = read(&xml);

        assert_eq!(parsed.len(), 1);
        let tx = &parsed[0];
        assert_eq!(tx.id, 0);
        assert_eq!(tx.method, "GET");
        assert_eq!(tx.path, "/api/users/7");
        assert_eq!(tx.query, "page=2");
        assert_eq!(tx.extension, "");
        assert_eq!(tx.status, 200);
        assert_eq!(tx.request.header("host"), Some("x.test"));
        assert_eq!(tx.response.as_ref().unwrap().body_str(), "{\"id\":7}");
    }

    #[test]
    fn accepts_plaintext_bodies_without_base64_attribute() {
        let xml = dump(
            r#"<item><url>https://x.test/a</url><host>x.test</host><method>POST</method>
               <path>/a</path><status>201</status>
               <request>POST /a HTTP/1.1&#13;&#10;Host: x.test&#13;&#10;&#13;&#10;</request></item>"#,
        );
        let parsed = read(&xml);
        assert_eq!(parsed[0].method, "POST");
        assert_eq!(parsed[0].request.header("host"), Some("x.test"));
        assert!(parsed[0].response.is_none());
    }

    #[test]
    fn assigns_sequential_ids_in_dump_order() {
        let xml = dump(&format!(
            "{}{}",
            item(
                "/first",
                "GET /first HTTP/1.1\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\n"
            ),
            item(
                "/second",
                "GET /second HTTP/1.1\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\n"
            ),
        ));
        let parsed = read(&xml);
        assert_eq!(parsed.iter().map(|t| t.id).collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(parsed[1].path, "/second");
    }

    #[test]
    fn falls_back_to_the_url_when_path_is_absent() {
        let xml = dump(
            r#"<item><url>https://x.test/from/url?q=1</url><method>GET</method><status>200</status>
               <request>GET /from/url?q=1 HTTP/1.1</request></item>"#,
        );
        let parsed = read(&xml);
        assert_eq!(parsed[0].path, "/from/url");
        assert_eq!(parsed[0].query, "q=1");
    }

    #[test]
    fn rejects_malformed_xml() {
        let error = parse_reader(
            b"<items><item><url>oops</items>".as_slice(),
            &Limits::default(),
        )
        .expect_err("unclosed tag must fail");
        assert!(matches!(error, Error::MalformedXml { .. }));
    }

    /// A dump past the cap is refused outright. Every figure the report prints
    /// — coverage, ubiquity, retention — is a ratio over the whole input, so
    /// silently analysing a prefix would describe a file nobody supplied.
    #[test]
    fn rejects_a_dump_past_the_transaction_limit() {
        let one = item("/a", "GET /a HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n");
        let xml = dump(&one.repeat(3));
        let limits = Limits {
            max_transactions: 2,
            ..Limits::default()
        };

        let error = parse_reader(xml.as_bytes(), &limits).expect_err("three items exceeds two");
        assert!(matches!(error, Error::TooManyTransactions { limit: 2 }));

        let limits = Limits {
            max_transactions: 3,
            ..Limits::default()
        };
        let parsed = parse_reader(xml.as_bytes(), &limits).expect("exactly at the limit is fine");
        assert_eq!(parsed.transactions.len(), 3);
    }

    /// The opposite call: one oversized body must not cost the reader the
    /// transaction it belongs to, nor the ones that follow it.
    #[test]
    fn drops_an_oversized_body_and_keeps_its_transaction() {
        let huge = "x".repeat(64);
        let xml = dump(&format!(
            "{}{}",
            item(
                "/download",
                &format!("POST /download HTTP/1.1\r\nHost: x.test\r\n\r\n{huge}"),
                &format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{huge}"),
            ),
            item(
                "/small",
                "GET /small HTTP/1.1\r\n\r\n",
                "HTTP/1.1 204 No Content\r\n\r\n",
            ),
        ));
        let limits = Limits {
            max_body_bytes: 16,
            ..Limits::default()
        };

        let parsed = parse_reader(xml.as_bytes(), &limits).expect("well-formed dump");

        assert_eq!(parsed.transactions.len(), 2, "both items survive");
        assert_eq!(
            parsed.oversized_bodies, 2,
            "the request and the response are each counted"
        );

        let big = &parsed.transactions[0];
        assert!(big.request.body.is_empty(), "the payload is gone");
        assert_eq!(
            big.request.header("host"),
            Some("x.test"),
            "but the exchange still says which route served it"
        );
        assert_eq!(
            big.response.as_ref().unwrap().start_line,
            "HTTP/1.1 200 OK",
            "and what the server answered"
        );
        assert_eq!(parsed.transactions[1].path, "/small");
    }
}
