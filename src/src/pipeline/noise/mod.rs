//! Stage 2: the hybrid noise filter.
//!
//! Gross rules run first because they are cheap and certain; whatever survives
//! is then judged statistically. Every drop is attributed to a reason so the
//! Meta section can account for the whole input.
//!
//! A drop is not always a deletion. A repeated state-changing request carries
//! nothing the report has not already read off the first one — the same fields,
//! the same values — so it is collapsed like any other repeat, but the fact that
//! it happened again is recorded in [`FilterOutcome::repeated_writes`] and
//! travels on to the endpoint that performed it.

pub mod gross;
pub mod statistical;

use std::collections::BTreeMap;

use crate::config::Thresholds;
use crate::model::transaction::{RawTransaction, TxId};

use statistical::StatisticalReason;

/// Outcome of filtering an entire dump.
#[derive(Debug, Default)]
pub struct FilterOutcome {
    /// Ids of surviving transactions, in dump order.
    pub kept: Vec<TxId>,
    /// Drop counts keyed by human-readable reason.
    pub dropped_by_reason: BTreeMap<String, usize>,
    /// Ids of state-changing transactions collapsed as exact repeats.
    ///
    /// Kept apart from the other drops because these are the one kind the
    /// report must still account for: the operation really was performed again.
    /// Stage 3 attributes each to the endpoint that served it.
    pub repeated_writes: Vec<TxId>,
}

impl FilterOutcome {
    pub fn dropped_total(&self) -> usize {
        self.dropped_by_reason.values().sum()
    }
}

/// Apply the gross filter, then the statistical filter.
pub fn apply(transactions: &[RawTransaction], thresholds: &Thresholds) -> FilterOutcome {
    let mut outcome = FilterOutcome::default();

    let survivors: Vec<&RawTransaction> = transactions
        .iter()
        .filter(|tx| match gross::evaluate(tx, thresholds) {
            Some(reason) => {
                record(&mut outcome, reason.as_str());
                false
            }
            None => true,
        })
        .collect();

    let mut filter = statistical::StatisticalFilter::build(&survivors, thresholds);
    for tx in survivors {
        match filter.evaluate(tx) {
            Some(reason) => {
                record(&mut outcome, reason.as_str());
                if reason == StatisticalReason::RepeatedWrite {
                    outcome.repeated_writes.push(tx.id);
                }
            }
            None => outcome.kept.push(tx.id),
        }
    }

    outcome
}

fn record(outcome: &mut FilterOutcome, reason: &str) {
    *outcome
        .dropped_by_reason
        .entry(reason.to_string())
        .or_insert(0) += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;
    use crate::model::http::HttpMessage;

    fn tx(id: usize, path: &str, content_type: &str, body: &str) -> RawTransaction {
        RawTransaction {
            id,
            url: format!("https://x.test{path}"),
            host: "x.test".into(),
            port: "443".into(),
            protocol: "https".into(),
            method: "GET".into(),
            path: path.into(),
            query: String::new(),
            extension: String::new(),
            status: 200,
            mime_type: String::new(),
            request: HttpMessage::parse(b"GET / HTTP/1.1\r\n\r\n"),
            response: Some(HttpMessage::parse(
                format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n\r\n{body}").as_bytes(),
            )),
        }
    }

    /// Which transactions were collapsed as repeat writes, and which as noise
    /// the report owes no account of.
    #[test]
    fn collapsed_writes_are_carried_out_of_the_filter_by_id() {
        let th = Thresholds::for_mode(Mode::Standard);
        let write = |id| RawTransaction {
            method: "POST".into(),
            ..tx(id, "/api/employees", "application/json", r#"{"a":1}"#)
        };
        let transactions = vec![
            tx(0, "/api/orders", "application/json", r#"{"a":1}"#),
            tx(1, "/api/orders", "application/json", r#"{"a":1}"#),
            write(2),
            write(3),
        ];

        let outcome = apply(&transactions, &th);

        assert_eq!(outcome.kept, vec![0, 2]);
        assert_eq!(
            outcome.repeated_writes,
            vec![3],
            "the replayed read is noise; the replayed write is an event"
        );
        assert_eq!(
            outcome.kept.len() + outcome.dropped_total(),
            transactions.len(),
            "naming a drop must not stop it being counted as one"
        );
    }

    #[test]
    fn accounts_for_every_input_transaction() {
        let th = Thresholds::for_mode(Mode::Standard);
        let png = "p".repeat(th.gross_body_min_len + 1);
        let transactions = vec![
            tx(0, "/api/orders", "application/json", r#"{"a":1}"#),
            tx(1, "/health", "application/json", "ok"),
            tx(2, "/logo.png", "image/png", &png),
            tx(3, "/api/orders", "application/json", r#"{"a":1}"#),
        ];

        let outcome = apply(&transactions, &th);

        assert_eq!(outcome.kept, vec![0]);
        assert_eq!(
            outcome.kept.len() + outcome.dropped_total(),
            transactions.len()
        );
        assert_eq!(outcome.dropped_by_reason.values().sum::<usize>(), 3);
    }

    #[test]
    fn keeps_dump_order_for_survivors() {
        let th = Thresholds::for_mode(Mode::Standard);
        let transactions = vec![
            tx(0, "/api/a", "application/json", "1"),
            tx(1, "/health", "application/json", "ok"),
            tx(2, "/api/b", "application/json", "2"),
            tx(3, "/api/c", "application/json", "3"),
        ];
        assert_eq!(apply(&transactions, &th).kept, vec![0, 2, 3]);
    }
}
