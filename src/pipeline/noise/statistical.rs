//! Statistical noise filtering: no domain knowledge, only observed shape.
//!
//! Runs before templating, so it groups transactions by a *coarse* endpoint key
//! computed from segment shape alone. The normalizer later derives the real,
//! frequency-driven templates; this key exists only so that frequency is
//! measured per endpoint rather than per URL.
//!
//! One rule here reads the HTTP method, and only through
//! [`method_changes_state`]. A byte-identical request means two different things
//! depending on the verb: repeating a read is how clients poll, while repeating
//! a write is the operation happening twice. Both are collapsed, because
//! neither repetition adds a field or a value the report has not already seen —
//! but a collapsed write is *counted*, so the fact that it recurred survives
//! into the report instead of being silently deleted.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use super::gross;
use crate::analysis::entropy;
use crate::analysis::stats;
use crate::config::Thresholds;
use crate::model::endpoint::method_changes_state;
use crate::model::transaction::RawTransaction;

/// Why the statistical filter rejected a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatisticalReason {
    /// Byte-identical repeat of an earlier read.
    Duplicate,
    /// Byte-identical repeat of an earlier state-changing request.
    ///
    /// Separate from [`Self::Duplicate`] so the Filtering Breakdown can say
    /// that a mutation recurred rather than reporting it as a duplicate
    /// request, which reads as a collection artefact.
    RepeatedWrite,
    /// Large response body that is almost entirely uniform.
    LowEntropyBody,
    /// A frequent endpoint called over and over with the same parameter shape.
    LowVariation,
}

impl StatisticalReason {
    pub fn as_str(self) -> &'static str {
        match self {
            StatisticalReason::Duplicate => "statistical: duplicate request",
            StatisticalReason::RepeatedWrite => "statistical: repeated identical write",
            StatisticalReason::LowEntropyBody => "statistical: low-entropy body",
            StatisticalReason::LowVariation => "statistical: low variation on frequent endpoint",
        }
    }
}

/// Per-group aggregates gathered in the first pass.
#[derive(Default)]
struct GroupStats {
    hits: usize,
    signatures: HashSet<String>,
}

/// Two-pass statistical filter: measure everything, then judge each item.
pub struct StatisticalFilter<'a> {
    thresholds: &'a Thresholds,
    groups: HashMap<String, GroupStats>,
    seen_requests: HashSet<u64>,
    kept_per_group: HashMap<String, usize>,
}

impl<'a> StatisticalFilter<'a> {
    /// First pass: accumulate per-endpoint frequency and parameter spread.
    pub fn build(transactions: &[&RawTransaction], thresholds: &'a Thresholds) -> Self {
        let mut groups: HashMap<String, GroupStats> = HashMap::new();
        for tx in transactions {
            let entry = groups.entry(coarse_key(tx)).or_default();
            entry.hits += 1;
            entry.signatures.insert(tx.param_signature());
        }
        Self {
            thresholds,
            groups,
            seen_requests: HashSet::new(),
            kept_per_group: HashMap::new(),
        }
    }

    /// Second pass: judge one transaction, in dump order.
    ///
    /// Stateful by design — duplicate detection and per-endpoint sampling both
    /// depend on what has already been kept.
    pub fn evaluate(&mut self, tx: &RawTransaction) -> Option<StatisticalReason> {
        if !self.seen_requests.insert(request_hash(tx)) {
            return Some(if method_changes_state(&tx.method) {
                StatisticalReason::RepeatedWrite
            } else {
                StatisticalReason::Duplicate
            });
        }
        if self.has_low_entropy_body(tx) {
            return Some(StatisticalReason::LowEntropyBody);
        }
        if let Some(reason) = self.judge_variation(tx) {
            return Some(reason);
        }
        *self.kept_per_group.entry(coarse_key(tx)).or_insert(0) += 1;
        None
    }

    fn has_low_entropy_body(&self, tx: &RawTransaction) -> bool {
        let Some(response) = tx.response.as_ref() else {
            return false;
        };
        if response.body.len() < self.thresholds.entropy_min_body_len {
            return false;
        }
        entropy::shannon_bits(&response.body) < self.thresholds.low_entropy_bits
    }

    /// Sample down endpoints that are called constantly with the same shape.
    fn judge_variation(&self, tx: &RawTransaction) -> Option<StatisticalReason> {
        let key = coarse_key(tx);
        let group = self.groups.get(&key)?;

        if group.hits < self.thresholds.frequent_endpoint_hits {
            return None;
        }
        let spread = stats::distinct_ratio(group.signatures.len(), group.hits);
        if spread > self.thresholds.low_variation_ratio {
            return None;
        }

        // Cache-buster parameters never justify a drop on their own; here they
        // only tighten the sampling budget of an endpoint already judged
        // repetitive.
        let mut allowance = self.thresholds.low_variation_keep;
        if gross::cache_buster_hits(tx) > 0 {
            allowance = (allowance / 2).max(1);
        }

        let kept = self.kept_per_group.get(&key).copied().unwrap_or(0);
        (kept >= allowance).then_some(StatisticalReason::LowVariation)
    }
}

/// Method plus a path whose identifier-shaped segments collapse to `*`.
fn coarse_key(tx: &RawTransaction) -> String {
    let collapsed: Vec<&str> = tx
        .segments()
        .into_iter()
        .map(|segment| {
            if entropy::is_identifier_like(segment) {
                "*"
            } else {
                segment
            }
        })
        .collect();
    format!("{} /{}", tx.method, collapsed.join("/"))
}

fn request_hash(tx: &RawTransaction) -> u64 {
    let mut hasher = DefaultHasher::new();
    tx.method.hash(&mut hasher);
    tx.path.hash(&mut hasher);
    tx.query.hash(&mut hasher);
    tx.request.body.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;
    use crate::model::http::HttpMessage;

    fn tx(id: usize, path: &str, query: &str, body: &str) -> RawTransaction {
        RawTransaction {
            id,
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
            response: Some(HttpMessage::parse(
                format!("HTTP/1.1 200 OK\r\n\r\n{body}").as_bytes(),
            )),
        }
    }

    fn run(transactions: &[RawTransaction], th: &Thresholds) -> Vec<Option<StatisticalReason>> {
        let refs: Vec<&RawTransaction> = transactions.iter().collect();
        let mut filter = StatisticalFilter::build(&refs, th);
        transactions.iter().map(|t| filter.evaluate(t)).collect()
    }

    /// One request sent twice, byte for byte, under the given method.
    fn sent_twice(method: &str) -> Vec<RawTransaction> {
        (0..2)
            .map(|i| RawTransaction {
                method: method.into(),
                ..tx(i, "/api/employees", "", "{}")
            })
            .collect()
    }

    #[test]
    fn collapses_identifier_segments_into_one_group() {
        let a = tx(0, "/api/users/812696/posts", "", "");
        let b = tx(1, "/api/users/40771/posts", "", "");
        let c = tx(2, "/api/users/3f2504e0-4f89-11d3-9a0c-0305e82c3301", "", "");
        assert_eq!(coarse_key(&a), coarse_key(&b));
        assert_eq!(coarse_key(&a), "GET /api/users/*/posts");
        assert_eq!(coarse_key(&c), "GET /api/users/*");
    }

    #[test]
    fn keeps_the_first_occurrence_and_drops_repeats() {
        let th = Thresholds::for_mode(Mode::Standard);
        let transactions = vec![
            tx(0, "/api/a", "x=1", "body"),
            tx(1, "/api/a", "x=1", "body"),
            tx(2, "/api/a", "x=2", "body"),
        ];
        let verdicts = run(&transactions, &th);
        assert_eq!(verdicts[0], None);
        assert_eq!(verdicts[1], Some(StatisticalReason::Duplicate));
        assert_eq!(verdicts[2], None);
    }

    /// Both verbs collapse — the second request carries no field the first did
    /// not — but they collapse under different names, because only one of them
    /// means the operation happened again.
    #[test]
    fn a_repeated_write_is_named_apart_from_a_repeated_read() {
        let th = Thresholds::for_mode(Mode::Standard);

        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            assert_eq!(
                run(&sent_twice(method), &th)[1],
                Some(StatisticalReason::RepeatedWrite),
                "{method} repeat read as a collection artefact"
            );
        }

        for method in ["GET", "HEAD", "OPTIONS", "PROPFIND"] {
            assert_eq!(
                run(&sent_twice(method), &th)[1],
                Some(StatisticalReason::Duplicate),
                "{method} repeat read as a mutation"
            );
        }
    }

    /// Naming the reason must not change the verdict: the first call survives
    /// and the repeat is still removed, whichever verb sent it.
    #[test]
    fn a_repeated_write_is_still_collapsed() {
        let th = Thresholds::for_mode(Mode::Standard);
        let verdicts = run(&sent_twice("POST"), &th);
        assert_eq!(verdicts[0], None);
        assert!(verdicts[1].is_some());
    }

    #[test]
    fn drops_large_uniform_bodies() {
        let th = Thresholds::for_mode(Mode::Standard);
        let filler = "a".repeat(th.entropy_min_body_len + 10);
        let transactions = vec![tx(0, "/api/pad", "", &filler)];
        assert_eq!(
            run(&transactions, &th)[0],
            Some(StatisticalReason::LowEntropyBody)
        );
    }

    #[test]
    fn samples_down_repetitive_frequent_endpoints() {
        let th = Thresholds::for_mode(Mode::Standard);
        // The cursor varies so that no two requests are byte-identical: this
        // test is about the sampling rule, and duplicate detection runs first
        // and would otherwise decide every case before sampling is reached. The
        // parameter *name* stays constant, which is what keeps the spread low.
        let transactions: Vec<RawTransaction> = (0..20)
            .map(|i| tx(i, "/api/poll", &format!("cursor={i}"), &format!("tick {i}")))
            .collect();
        let verdicts = run(&transactions, &th);

        let kept = verdicts.iter().filter(|v| v.is_none()).count();
        assert_eq!(kept, th.low_variation_keep);
        assert!(verdicts
            .iter()
            .skip(th.low_variation_keep)
            .all(|v| *v == Some(StatisticalReason::LowVariation)));
    }

    #[test]
    fn rare_endpoints_are_never_sampled_down() {
        let th = Thresholds::for_mode(Mode::Standard);
        let transactions: Vec<RawTransaction> = (0..3)
            .map(|i| {
                tx(
                    i,
                    "/api/rare",
                    &format!("cursor={i}"),
                    &format!("payload {i}"),
                )
            })
            .collect();
        assert!(run(&transactions, &th).iter().all(|v| v.is_none()));
    }

    #[test]
    fn varied_parameters_protect_a_frequent_endpoint() {
        let th = Thresholds::for_mode(Mode::Standard);
        let transactions: Vec<RawTransaction> = (0..20)
            .map(|i| tx(i, "/api/search", &format!("f{i}=1"), &format!("r{i}")))
            .collect();
        assert!(run(&transactions, &th).iter().all(|v| v.is_none()));
    }
}
