//! Extraction of candidate values from HTTP messages.
//!
//! This is the only module that knows how to reach into an HTTP exchange. It
//! extracts every scalar it can reach and judges none of them; quality
//! filtering happens later, in mining and variation analysis.

use serde_json::Value as Json;

use crate::config::Limits;
use crate::model::http::HttpMessage;
use crate::model::transaction::RawTransaction;
use crate::model::value::{Direction, ObservedValue, ValueLocation};

/// Shortest trailing word worth splitting out of a `<scheme> <credential>` header.
const MIN_CREDENTIAL_LEN: usize = 8;
/// Longest leading word still shaped like an auth scheme.
const MAX_SCHEME_LEN: usize = 12;

/// Extract every candidate value from one transaction, request first.
pub fn extract(tx: &RawTransaction, limits: &Limits) -> Vec<ObservedValue> {
    let mut out = Vec::new();
    extract_request(tx, limits, &mut out);
    if let Some(response) = tx.response.as_ref() {
        extract_response(tx, response, limits, &mut out);
    }
    out
}

fn extract_request(tx: &RawTransaction, limits: &Limits, out: &mut Vec<ObservedValue>) {
    let id = tx.id;

    for (index, segment) in tx.segments().iter().enumerate() {
        push(
            out,
            id,
            Direction::Request,
            ValueLocation::PathSegment(index),
            (*segment).to_string(),
            limits,
        );
    }

    for (name, value) in tx.query_params() {
        push(
            out,
            id,
            Direction::Request,
            ValueLocation::QueryParam(name),
            value,
            limits,
        );
    }

    for (name, value) in &tx.request.headers {
        push_header(out, id, Direction::Request, name, value, limits);
    }

    for (name, value) in tx.request.cookies() {
        push(
            out,
            id,
            Direction::Request,
            ValueLocation::Cookie(name),
            value,
            limits,
        );
    }

    collect_body_fields(&tx.request, id, Direction::Request, limits, out);
}

fn extract_response(
    tx: &RawTransaction,
    response: &HttpMessage,
    limits: &Limits,
    out: &mut Vec<ObservedValue>,
) {
    let id = tx.id;

    for (name, value) in &response.headers {
        push_header(out, id, Direction::Response, name, value, limits);
    }

    for (name, value) in response.set_cookies() {
        push(
            out,
            id,
            Direction::Response,
            ValueLocation::SetCookie(name),
            value,
            limits,
        );
    }

    collect_body_fields(response, id, Direction::Response, limits, out);
}

fn collect_body_fields(
    message: &HttpMessage,
    tx_id: usize,
    direction: Direction,
    limits: &Limits,
    out: &mut Vec<ObservedValue>,
) {
    let Some(json) = message.json() else {
        return;
    };
    let mut budget = limits.max_json_nodes;
    walk_json(
        &json,
        &mut String::new(),
        0,
        &mut budget,
        limits,
        &mut |path, value| {
            push(
                out,
                tx_id,
                direction,
                ValueLocation::BodyField(path.to_string()),
                value,
                limits,
            );
        },
    );
}

/// Depth-first walk emitting `(dotted_path, scalar)` for every leaf.
///
/// Array indices collapse to `[]` so that `items[0].id` and `items[1].id`
/// aggregate into a single observed field.
fn walk_json(
    node: &Json,
    path: &mut String,
    depth: usize,
    budget: &mut usize,
    limits: &Limits,
    emit: &mut impl FnMut(&str, String),
) {
    if depth > limits.max_json_depth || *budget == 0 {
        return;
    }
    match node {
        Json::Object(map) => {
            for (key, child) in map {
                let restore = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
                walk_json(child, path, depth + 1, budget, limits, emit);
                path.truncate(restore);
            }
        }
        Json::Array(items) => {
            let restore = path.len();
            path.push_str("[]");
            for child in items {
                if *budget == 0 {
                    break;
                }
                walk_json(child, path, depth + 1, budget, limits, emit);
            }
            path.truncate(restore);
        }
        Json::String(text) => {
            *budget -= 1;
            emit(path, text.clone());
        }
        Json::Number(number) => {
            *budget -= 1;
            emit(path, number.to_string());
        }
        Json::Bool(flag) => {
            *budget -= 1;
            emit(path, flag.to_string());
        }
        Json::Null => {
            *budget -= 1;
        }
    }
}

/// Emit a header, plus its credential part when the value is a two-word pair.
///
/// Header values of the form `<scheme> <credential>` are a transport-level
/// convention, so the trailing word is emitted as well. No scheme name is
/// recognised: the rule is purely shape-based, which is what lets a token
/// carried this way still match the same token seen in a body or a cookie.
fn push_header(
    out: &mut Vec<ObservedValue>,
    tx_id: usize,
    direction: Direction,
    name: &str,
    value: &str,
    limits: &Limits,
) {
    let location = ValueLocation::Header(name.to_ascii_lowercase());
    push(
        out,
        tx_id,
        direction,
        location.clone(),
        value.to_string(),
        limits,
    );

    let mut words = value.split_whitespace();
    if let (Some(scheme), Some(credential), None) = (words.next(), words.next(), words.next()) {
        if looks_like_scheme(scheme) && credential.len() >= MIN_CREDENTIAL_LEN {
            push(
                out,
                tx_id,
                direction,
                location,
                credential.to_string(),
                limits,
            );
        }
    }
}

/// A short, purely alphabetic first word: the shape an auth scheme has.
fn looks_like_scheme(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= MAX_SCHEME_LEN
        && word.chars().all(|c| c.is_ascii_alphabetic())
}

fn push(
    out: &mut Vec<ObservedValue>,
    tx_id: usize,
    direction: Direction,
    location: ValueLocation,
    value: String,
    limits: &Limits,
) {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > limits.max_value_bytes {
        return;
    }
    out.push(ObservedValue {
        tx_id,
        direction,
        location,
        value: trimmed.to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::http::HttpMessage;

    /// Extract under the shipped limits: what an ordinary run sees.
    fn extract(tx: &RawTransaction) -> Vec<ObservedValue> {
        super::extract(tx, &Limits::default())
    }

    fn transaction(path: &str, query: &str, req_body: &str, resp_body: &str) -> RawTransaction {
        let request = HttpMessage::parse(
            format!(
                "POST {path} HTTP/1.1\r\nHost: x.test\r\nCookie: sid=abc123\r\nContent-Type: application/json\r\n\r\n{req_body}"
            )
            .as_bytes(),
        );
        let response = HttpMessage::parse(
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{resp_body}")
                .as_bytes(),
        );
        RawTransaction {
            id: 1,
            url: format!("https://x.test{path}"),
            host: "x.test".into(),
            port: "443".into(),
            protocol: "https".into(),
            method: "POST".into(),
            path: path.into(),
            query: query.into(),
            extension: String::new(),
            status: 200,
            mime_type: "JSON".into(),
            request,
            response: Some(response),
        }
    }

    #[test]
    fn extracts_from_every_part_of_the_exchange() {
        let tx = transaction(
            "/api/users/812696",
            "page=2",
            r#"{"name":"ann"}"#,
            r#"{"data":{"token":"tok_9f3a"}}"#,
        );
        let values = extract(&tx);

        let has = |loc: ValueLocation, val: &str| {
            values.iter().any(|o| o.location == loc && o.value == val)
        };

        assert!(has(ValueLocation::PathSegment(2), "812696"));
        assert!(has(ValueLocation::QueryParam("page".into()), "2"));
        assert!(has(ValueLocation::Cookie("sid".into()), "abc123"));
        assert!(has(ValueLocation::Header("host".into()), "x.test"));
        assert!(has(ValueLocation::BodyField("name".into()), "ann"));
        assert!(has(
            ValueLocation::BodyField("data.token".into()),
            "tok_9f3a"
        ));
    }

    #[test]
    fn array_indices_collapse_into_one_field_path() {
        let tx = transaction(
            "/api/items",
            "",
            "{}",
            r#"{"items":[{"id":"a1"},{"id":"b2"}]}"#,
        );
        let values = extract(&tx);
        let ids: Vec<&str> = values
            .iter()
            .filter(|o| o.location == ValueLocation::BodyField("items[].id".into()))
            .map(|o| o.value.as_str())
            .collect();
        assert_eq!(ids, vec!["a1", "b2"]);
    }

    #[test]
    fn response_values_are_tagged_as_responses() {
        let tx = transaction("/api/login", "", "{}", r#"{"token":"zzz"}"#);
        let token = extract(&tx)
            .into_iter()
            .find(|o| o.value == "zzz")
            .expect("token extracted");
        assert_eq!(token.direction, Direction::Response);
    }

    #[test]
    fn splits_the_credential_out_of_a_scheme_prefixed_header() {
        let mut tx = transaction("/api/x", "", "{}", "{}");
        tx.request = HttpMessage::parse(
            b"GET /api/x HTTP/1.1\r\nAuthorization: Bearer c9f4a1b28e7d4f6ab3125e9d77aa0c31\r\n\r\n",
        );
        let values = extract(&tx);
        let seen: Vec<&str> = values
            .iter()
            .filter(|o| o.location == ValueLocation::Header("authorization".into()))
            .map(|o| o.value.as_str())
            .collect();

        assert!(seen.contains(&"Bearer c9f4a1b28e7d4f6ab3125e9d77aa0c31"));
        assert!(
            seen.contains(&"c9f4a1b28e7d4f6ab3125e9d77aa0c31"),
            "the bare credential must be observable so it can match the same value elsewhere"
        );
    }

    #[test]
    fn leaves_ordinary_two_word_headers_alone() {
        let mut tx = transaction("/api/x", "", "{}", "{}");
        tx.request =
            HttpMessage::parse(b"GET /api/x HTTP/1.1\r\nAccept: text/html;q=0.9 */*\r\n\r\n");
        let split_out = extract(&tx)
            .into_iter()
            .filter(|o| o.location == ValueLocation::Header("accept".into()))
            .count();
        assert_eq!(split_out, 1, "a short trailing word is not a credential");
    }

    #[test]
    fn an_assigned_cookie_is_a_different_slot_from_a_sent_one() {
        let mut tx = transaction("/api/login", "", "{}", "{}");
        tx.response = Some(HttpMessage::parse(
            b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc123; Path=/; HttpOnly\r\n\r\n",
        ));
        let values = extract(&tx);

        assert!(values
            .iter()
            .any(|o| o.location == ValueLocation::SetCookie("sid".into()) && o.value == "abc123"));
        assert!(
            values
                .iter()
                .any(|o| o.location == ValueLocation::Cookie("sid".into())),
            "the request's own cookie stays a Cookie slot"
        );
    }

    #[test]
    fn skips_blank_and_oversized_scalars() {
        let limits = Limits::default();
        let huge = "x".repeat(limits.max_value_bytes + 1);
        let body = format!(r#"{{"blank":"   ","huge":"{huge}"}}"#);
        let tx = transaction("/api/x", "", &body, "{}");
        let values = extract(&tx);
        assert!(!values
            .iter()
            .any(|o| o.value.len() > limits.max_value_bytes));
        assert!(!values
            .iter()
            .any(|o| o.location == ValueLocation::BodyField("blank".into())));
    }

    /// The depth limit stops the descent; it does not discard the body. A
    /// pathological nest costs the walk nothing beyond the level it stops at,
    /// and every field above that level is still mined.
    #[test]
    fn stops_descending_past_the_depth_limit_without_losing_shallow_fields() {
        let deep = r#"{"a":{"b":{"c":{"d":"buried"}}},"top":"visible"}"#;
        let tx = transaction("/api/x", "", "{}", deep);
        let limits = Limits {
            max_json_depth: 2,
            ..Limits::default()
        };

        let found = |values: &[ObservedValue], field: &str| {
            values
                .iter()
                .any(|o| o.location == ValueLocation::BodyField(field.into()))
        };

        let capped = super::extract(&tx, &limits);
        assert!(found(&capped, "top"), "a shallow field is unaffected");
        assert!(!found(&capped, "a.b.c.d"), "the deep one is out of reach");

        assert!(
            found(&extract(&tx), "a.b.c.d"),
            "and the shipped limit is nowhere near tight enough to lose it"
        );
    }

    /// The node budget bounds how much one body can cost, whatever its shape.
    #[test]
    fn stops_collecting_past_the_node_limit() {
        let items: Vec<String> = (0..50).map(|i| format!(r#""v{i}""#)).collect();
        let tx = transaction("/api/x", "", "{}", &format!("{{\"xs\":[{}]}}", items.join(",")));
        let limits = Limits {
            max_json_nodes: 5,
            ..Limits::default()
        };

        let collected = super::extract(&tx, &limits)
            .into_iter()
            .filter(|o| o.location == ValueLocation::BodyField("xs[]".into()))
            .count();
        assert_eq!(collected, 5);
    }
}
