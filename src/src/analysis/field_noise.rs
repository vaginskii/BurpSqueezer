//! Which body fields deserve a line of their own, and which are structure.
//!
//! An endpoint's field list is the one part of the report that is a raw
//! enumeration: everything the extractor saw, in order of how often it was seen.
//! For most routes that is exactly right — eight field names tell a reader what
//! the route carries. For some it is a wall: a single telemetry envelope can
//! contribute forty sibling paths, all of them constants, all of them the same
//! few keys copied into every event, and they push the fields that matter off
//! the end of the cell.
//!
//! The fix cannot be a list of field names. `featureFlags` is a real name in one
//! application and a real name in a hundred others, and a rule keyed on it
//! misses the next one and deletes a field that mattered. So the rule is
//! structural, and it has exactly two shapes to detect:
//!
//! - **fan-out** — one prefix holds enough keys on this route that the keys say
//!   less than the prefix does;
//! - **repetition** — one prefix shows up at many endpoints of the capture, so
//!   the list is a template being filled rather than this route's own shape.
//!
//! What is deliberately *not* thrown away is the route back to a reported Strong
//! Value. That is why values carry their field paths in typed form: a summary
//! that folded up the field an identifier arrives in would hide the only place
//! the reader can look for it. It is not a reason to keep a group open, though.
//! Twenty-three siblings around the one field that matters is still a wall, and
//! the reader still cannot use it. So a bucket is folded regardless, and the
//! protected fields inside it are named on its own line — `profile.* (24 keys)
//! [email, id]` — which keeps both the shape and the way back.

use std::collections::{BTreeMap, BTreeSet};

use crate::config::Thresholds;
use crate::model::endpoint::{normalize_endpoint_key, EndpointTable, UNMAPPED_ENDPOINT};
use crate::model::value::{ObservedValue, ValueLocation};

/// Capture-wide view of how body field paths are shaped.
///
/// One profile per run, shared by every row it is asked to summarize.
#[derive(Debug, Default)]
pub struct FieldNoise {
    /// For every path prefix the capture ever contained, the endpoints it was
    /// seen at.
    ///
    /// Precomputed rather than derived per row because a prefix is shared by
    /// every list that mentions it: the telemetry envelope appears in forty
    /// endpoints' field lists, and re-measuring it forty times would make the
    /// cost of the report grow with the square of the capture.
    prefix_endpoints: BTreeMap<String, BTreeSet<String>>,
}

impl FieldNoise {
    /// Measure every body field path the retained traffic carried.
    ///
    /// Only prefixes are kept. The values themselves are not, because no rule
    /// here asks what a field contained: the question is always how many
    /// siblings a prefix has and how many endpoints agree on it, and both are
    /// answered by the paths alone.
    pub fn profile(observations: &[ObservedValue], table: &EndpointTable) -> Self {
        let mut prefix_endpoints: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for observation in observations {
            let ValueLocation::BodyField(path) = &observation.location else {
                continue;
            };
            let Some(endpoint) = table.key_of_tx(observation.tx_id) else {
                continue;
            };
            let endpoint = normalize_endpoint_key(&endpoint);
            if endpoint == UNMAPPED_ENDPOINT {
                continue;
            }
            for prefix in ancestors(path) {
                prefix_endpoints
                    .entry(prefix.to_string())
                    .or_default()
                    .insert(endpoint.clone());
            }
        }

        Self { prefix_endpoints }
    }

    /// How many distinct endpoints a prefix was seen at.
    ///
    /// Zero for a prefix the capture never contained, which is the answer for
    /// every prefix a synthetic row invents.
    pub fn spread_of(&self, prefix: &str) -> usize {
        self.prefix_endpoints
            .get(prefix)
            .map_or(0, BTreeSet::len)
    }

    /// An endpoint's field list, with structural noise folded into one line each.
    ///
    /// `fields` is the endpoint's counts and `protected` the body paths of every
    /// value the report is going to show. The returned order is the one the
    /// report already used — most-seen first, then alphabetical — so folding a
    /// run of siblings away cannot reorder what survives.
    ///
    /// The fan-out bar needs a long list, but the repeat bar deliberately does
    /// not: a three-key envelope copied into every event of the capture is the
    /// cheapest thing here to spot and the most tedious to read.
    pub fn summarize(
        &self,
        fields: &BTreeMap<String, usize>,
        protected: &BTreeSet<String>,
        thresholds: &Thresholds,
    ) -> Vec<String> {
        let listed = by_frequency(fields);

        let mut summarized: Vec<String> = Vec::with_capacity(listed.len());
        for path in &listed {
            match self.bucket_for(path, &listed, thresholds) {
                Some(bucket) => {
                    let claimed = self.claimed_by(bucket, &listed, thresholds);
                    let tail = protected_tail(bucket, &claimed, &listed, protected);
                    let line = format!("{}.* ({} keys){}", bucket, claimed.len(), tail);
                    if !summarized.contains(&line) {
                        summarized.push(line);
                    }
                }
                None => summarized.push((*path).clone()),
            }
        }
        summarized
    }

    /// The prefix `path` belongs under, if it belongs under one.
    ///
    /// The deepest folding ancestor, not the shallowest: `event.properties` says
    /// where the flags live, where `event` only says that something does.
    ///
    /// The bar is met by the keys this prefix keeps for itself, not by the ones
    /// it was given in total. A container holding two keys of its own beside a
    /// folding sub-object is a two-key line pretending to be a summary, and the
    /// count in front of the reader would be the sub-object's.
    fn bucket_for<'a>(
        &self,
        path: &'a str,
        listed: &[&String],
        thresholds: &Thresholds,
    ) -> Option<&'a str> {
        ancestors(path).into_iter().rev().find(|prefix| {
            self.is_structure(prefix, listed, thresholds)
                && self.bucket_sized(prefix, listed, thresholds)
        })
    }

    /// Whether one prefix is structure rather than data, counting every key under
    /// it.
    ///
    /// The count is deliberately not the bucket's own, because this is the
    /// question a *descendant* asks when it is deciding whether to take a key:
    /// whether a subtree is dense enough to speak for itself, which does not
    /// depend on what its parent does with its other keys.
    ///
    /// Nothing here asks whether a value was seen in the group. The fields that
    /// carry signal are named on the bucket's own line, so the reader loses
    /// neither the shape nor the route back to the value.
    fn is_structure(
        &self,
        prefix: &str,
        listed: &[&String],
        thresholds: &Thresholds,
    ) -> bool {
        let listed_under = listed
            .iter()
            .filter(|path| is_under(path, prefix))
            .count();

        listed_under >= thresholds.field_bucket_min_keys
            || self.spread_of(prefix) >= thresholds.field_repeat_min_endpoints
    }

    /// Whether enough of what is left under a prefix is left to be worth one
    /// line.
    fn bucket_sized(
        &self,
        prefix: &str,
        listed: &[&String],
        thresholds: &Thresholds,
    ) -> bool {
        let claimed = self.claimed_by(prefix, listed, thresholds).len();

        // One key is not a group. Two is the floor, and then the same bar as any
        // other bucket, applied to what this line would actually replace.
        claimed >= 2
            && (claimed >= thresholds.field_bucket_min_keys
                || self.spread_of(prefix) >= thresholds.field_repeat_min_endpoints)
    }

    /// The keys a bucket's own line replaces: everything under it that no
    /// foldable descendant has claimed first.
    ///
    /// This is what keeps a parent and a child from reporting one structure
    /// twice, and it is deliberately *not* the same thing as rejecting the parent.
    /// The two rules disagree exactly where a real capture disagrees with a
    /// tidy one: a container with one busy sub-object in it and a dozen quiet
    /// siblings beside it. Rejecting the parent there is not caution, it is
    /// arithmetic — the busy sub-object reports itself, and the dozen siblings,
    /// which had a prefix of their own and a count well over the bar, get listed
    /// one by one for no reason a reader could name. Claiming only the
    /// unclaimed keys lets both lines stand, and the parent's count stays a
    /// number the reader can check against what the child did not already take.
    fn claimed_by(
        &self,
        prefix: &str,
        listed: &[&String],
        thresholds: &Thresholds,
    ) -> Vec<usize> {
        listed
            .iter()
            .enumerate()
            .filter(|(_, path)| {
                is_under(path, prefix) && !self.claimed_by_descendant(path, prefix, listed, thresholds)
            })
            .map(|(index, _)| index)
            .collect()
    }

    /// Whether a foldable prefix strictly between this path and `prefix` already
    /// accounts for it.
    fn claimed_by_descendant(
        &self,
        path: &str,
        prefix: &str,
        listed: &[&String],
        thresholds: &Thresholds,
    ) -> bool {
        ancestors(path).into_iter().any(|middle| {
            middle.len() > prefix.len()
                && middle.starts_with(prefix)
                && self.is_structure(middle, listed, thresholds)
        })
    }
}

/// The names a folded bucket has to carry so the reader can still get from it
/// back to the values the report shows.
///
/// A bucket's own line already says how many keys it replaced and under what
/// prefix, and it says nothing about *which* keys mattered. That is the whole
/// cost of folding, and it is paid by whoever has to use the field list to find
/// a value they already read about in Core Signal. So the names go in the line,
/// relative to the prefix, and the report is no longer a choice between the wall
/// and a summary that hides the one field in it worth having.
///
/// Only paths the list actually holds are named, and only the ones this line
/// replaces. A value seen in `profile.email` elsewhere in the capture did not
/// put `email` in this endpoint's response, and naming it here would tell the
/// reader to look for something this exchange never carried; a key already
/// counted by a nested bucket is not this line's to announce either, or the two
/// lines would credit the same field twice. Order is the list's own, so the
/// names read in the same order the unfolded cells would have.
fn protected_tail(
    bucket: &str,
    claimed: &[usize],
    listed: &[&String],
    protected: &BTreeSet<String>,
) -> String {
    let names: Vec<&str> = claimed
        .iter()
        .map(|index| listed[*index].as_str())
        .filter(|path| protected.contains(*path))
        .map(|path| &path[bucket.len() + 1..])
        .collect();

    if names.is_empty() {
        return String::new();
    }
    format!(" [{}]", names.join(", "))
}

/// Field paths ordered by how often they were seen, then alphabetically.
///
/// Exported because the order is a report contract, not an implementation
/// detail: query parameter lists follow it too, and a summary that reordered
/// fields relative to them would be the odd one out.
pub fn by_frequency(counts: &BTreeMap<String, usize>) -> Vec<&String> {
    let mut names: Vec<(&String, &usize)> = counts.iter().collect();
    names.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    names.into_iter().map(|(name, _)| name).collect()
}

/// Every proper ancestor of a dotted field path, shallowest first.
///
/// `events[].event_properties.page` has the ancestors `events[]` and
/// `events[].event_properties`. The leaf itself is not one: a field is never
/// part of its own group.
fn ancestors(path: &str) -> Vec<&str> {
    path.match_indices('.').map(|(index, _)| &path[..index]).collect()
}

/// Whether `path` sits inside `prefix`, matching on a component boundary.
///
/// The trailing dot is what stops `a.b` from claiming `a.bc` — the two are
/// different fields that happen to share three characters, and folding them
/// together would rename one of them.
fn is_under(path: &str, prefix: &str) -> bool {
    path.len() > prefix.len()
        && path.starts_with(prefix)
        && path.as_bytes()[prefix.len()] == b'.'
}

/// The outermost path segment: what a body is wrapped in.
///
/// `events[].event_properties.x` and `events[].device_id` share the root
/// `events[]`; two unrelated top-level fields do not share anything. This is
/// what distinguishes a body that *is* one container from a record with a
/// container in it.
pub fn root_of(path: &str) -> &str {
    path.split_once('.').map_or(path, |(root, _)| root)
}

/// Whether an endpoint's shape reads as a sink for a batch rather than a handler
/// for one object.
///
/// Three things together, and the third is what stops the rule from swallowing
/// every large response:
///
/// - enough request fields for the shape to mean anything;
/// - one root holding nearly all of them, so the body *is* a container instead
///   of a record that happens to contain one;
/// - almost nothing back, because a route that reports state returns state.
///
/// Nothing here reads the path. A telemetry sink, a bulk ingest and an error
/// reporter all pass this, and all three are background traffic for a reader
/// trying to understand an API.
pub fn is_collector(
    request_fields: &BTreeMap<String, usize>,
    response_fields: &BTreeMap<String, usize>,
    thresholds: &Thresholds,
) -> bool {
    if request_fields.len() < thresholds.collector_min_fields {
        return false;
    }
    if response_fields.len() > thresholds.collector_max_response_fields {
        return false;
    }

    let mut per_root: BTreeMap<&str, usize> = BTreeMap::new();
    for path in request_fields.keys() {
        *per_root.entry(root_of(path)).or_insert(0) += 1;
    }

    let dominant = per_root.values().copied().max().unwrap_or(0);
    dominant as f64 / request_fields.len() as f64 >= thresholds.collector_min_root_share
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;
    use crate::model::endpoint::Endpoint;
    use crate::model::value::Direction;

    fn thresholds() -> Thresholds {
        Thresholds::for_mode(Mode::Standard)
    }

    /// An endpoint's field counts, as the normalizer would have counted them.
    fn counts(paths: &[&str]) -> BTreeMap<String, usize> {
        paths
            .iter()
            .enumerate()
            .map(|(index, path)| ((*path).to_string(), paths.len() - index))
            .collect()
    }

    fn table_of(entries: &[(usize, &str)]) -> EndpointTable {
        let mut table = EndpointTable::new();
        for (tx_id, key) in entries {
            let slot = table.slot_for(Endpoint::new("POST", *key));
            table.assign(*tx_id, slot);
        }
        table
    }

    fn field(tx_id: usize, path: &str) -> ObservedValue {
        ObservedValue {
            tx_id,
            direction: Direction::Request,
            location: ValueLocation::BodyField(path.to_string()),
            value: "x".to_string(),
        }
    }

    /// A run of sibling constants under one prefix — the shape that fills a cell
    /// with thirty field names and tells the reader nothing.
    const FLAGS: [&str; 10] = [
        "event.properties.experiment_bucket",
        "event.properties.feature_enabled_a",
        "event.properties.feature_enabled_b",
        "event.properties.feature_enabled_c",
        "event.properties.feature_enabled_d",
        "event.properties.feature_enabled_e",
        "event.properties.feature_enabled_f",
        "event.properties.client_hints",
        "event.properties.ab_bucket",
        "event.properties.app_version",
    ];

    #[test]
    fn a_run_of_siblings_becomes_one_line_naming_the_prefix() {
        let noise = FieldNoise::default();
        let fields = counts(&FLAGS);

        let summarized = noise.summarize(&fields, &BTreeSet::new(), &thresholds());

        assert_eq!(
            summarized,
            vec!["event.properties.* (10 keys)".to_string()],
            "ten siblings under one prefix are one fact about the shape"
        );
    }

    /// The control: the same number of fields, spread across separate objects, is
    /// a record with many parts. Folding it would be renaming the data.
    #[test]
    fn a_wide_record_is_not_a_bucket() {
        let noise = FieldNoise::default();
        let fields = counts(&[
            "id", "name", "email", "role", "created_at", "updated_at", "status", "team", "region",
            "tier",
        ]);

        assert_eq!(
            noise.summarize(&fields, &BTreeSet::new(), &thresholds()),
            by_frequency(&fields).into_iter().cloned().collect::<Vec<_>>()
        );
    }

    /// A prefix that repeats across the capture is a template being filled, even
    /// where no single endpoint holds enough of it to trip the fan-out bar.
    #[test]
    fn a_prefix_repeated_across_endpoints_is_structure() {
        let noise = FieldNoise::profile(
            &[field(0, "p.q.a"), field(1, "p.q.b")],
            &table_of(&[(0, "/a"), (1, "/b")]),
        );
        assert_eq!(noise.spread_of("p.q"), 2);

        // Two keys is below the fan-out bar, and two endpoints are below the
        // spread bar, so the repeated shape is not yet recognisable — which is
        // the honest answer rather than a guess from one endpoint's list.
        let fields = counts(&["p.q.a", "p.q.b", "r.s", "r.t"]);
        assert_eq!(
            noise.summarize(&fields, &BTreeSet::new(), &thresholds()),
            by_frequency(&fields).into_iter().cloned().collect::<Vec<_>>()
        );

        // Three endpoints is.
        let observations = (0..6)
            .flat_map(|tx| [field(tx, "p.q.a"), field(tx, "p.q.b")])
            .collect::<Vec<_>>();
        let noise = FieldNoise::profile(
            &observations,
            &table_of(&[
                (0, "/a"),
                (1, "/b"),
                (2, "/c"),
                (3, "/a"),
                (4, "/b"),
                (5, "/c"),
            ]),
        );
        assert_eq!(noise.spread_of("p.q"), 3);
        assert_eq!(
            noise.summarize(&fields, &BTreeSet::new(), &thresholds()),
            vec![
                "p.q.* (2 keys)".to_string(),
                "r.s".to_string(),
                "r.t".to_string()
            ]
        );
    }

    /// A folded bucket has to keep the reader's route back to the value, and the
    /// route is the field's name.
    ///
    /// The old rule here was that a group containing a reported value stayed open
    /// whole. On a real capture that is the wrong side of the trade every time:
    /// the one field that mattered held a twenty-four-key group open, and the
    /// reader got the wall anyway. Naming the field costs eleven characters.
    #[test]
    fn a_protected_field_is_named_inside_its_bucket() {
        let noise = FieldNoise::default();
        let fields = counts(&FLAGS);
        let mut protected = BTreeSet::new();
        protected.insert(FLAGS[4].to_string());

        assert_eq!(
            noise.summarize(&fields, &protected, &thresholds()),
            vec!["event.properties.* (10 keys) [feature_enabled_d]".to_string()],
            "the bucket folds and says which key inside it is signal"
        );
    }

    /// More than one, in the order the unfolded list had them in, so the summary
    /// is readable as a subset of the list it replaced.
    #[test]
    fn every_protected_field_in_a_bucket_is_named() {
        let noise = FieldNoise::default();
        let fields = counts(&FLAGS);
        let protected = [FLAGS[1], FLAGS[4], FLAGS[8]]
            .iter()
            .map(|path| (*path).to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            noise.summarize(&fields, &protected, &thresholds()),
            vec![
                "event.properties.* (10 keys) [feature_enabled_a, feature_enabled_d, ab_bucket]"
                    .to_string()
            ]
        );
    }

    /// A protected field deeper than the bucket is named by the part of the path
    /// the bucket did not already say, so the name plus the prefix reconstructs
    /// the field exactly.
    #[test]
    fn a_protected_field_deeper_than_the_bucket_is_named_relatively() {
        let noise = FieldNoise::default();
        let fields = counts(&[
            "profile.credentials.email",
            "profile.credentials.id",
            "profile.credentials.kind",
            "profile.display_name",
            "profile.company_name",
            "profile.nickname",
            "profile.company_role",
            "profile.auth_type",
            "profile.service",
        ]);
        let mut protected = BTreeSet::new();
        protected.insert("profile.credentials.email".to_string());
        protected.insert("profile.display_name".to_string());

        assert_eq!(
            noise.summarize(&fields, &protected, &thresholds()),
            vec![
                "profile.* (9 keys) [credentials.email, display_name]".to_string()
            ]
        );
    }

    /// A value seen in a field on one endpoint did not put that field in another
    /// endpoint's body, and naming it there would send the reader looking for
    /// something this exchange never carried.
    #[test]
    fn a_protected_field_the_list_does_not_hold_is_not_named() {
        let noise = FieldNoise::default();
        let fields = counts(&FLAGS);
        let mut protected = BTreeSet::new();
        protected.insert(FLAGS[4].to_string());
        protected.insert("event.properties.absent_elsewhere".to_string());

        assert_eq!(
            noise.summarize(&fields, &protected, &thresholds()),
            vec!["event.properties.* (10 keys) [feature_enabled_d]".to_string()],
            "the count and the names must agree on what the list held"
        );
    }

    /// A bucket whose every key is signal is still a bucket, and the line says so
    /// rather than pretending the reader has to look inside it.
    #[test]
    fn a_bucket_of_nothing_but_protected_fields_still_folds() {
        let noise = FieldNoise::default();
        let fields = counts(&FLAGS);
        let protected = FLAGS
            .iter()
            .map(|path| (*path).to_string())
            .collect::<BTreeSet<_>>();

        let summarized = noise.summarize(&fields, &protected, &thresholds());

        assert_eq!(summarized.len(), 1);
        assert!(
            summarized[0].starts_with("event.properties.* (10 keys) ["),
            "expected a fully enumerated bucket, got {:?}",
            summarized[0]
        );
        assert!(summarized[0].contains("experiment_bucket"));
        assert!(summarized[0].contains("app_version"));
    }

    /// The control for the rule above: a group too small to be a bucket keeps its
    /// protected field listed outright, and gains no bracket.
    #[test]
    fn a_protected_field_outside_any_bucket_is_just_listed() {
        let noise = FieldNoise::default();
        let fields = counts(&["id", "name", "role"]);
        let mut protected = BTreeSet::new();
        protected.insert("name".to_string());

        assert_eq!(
            noise.summarize(&fields, &protected, &thresholds()),
            by_frequency(&fields).into_iter().cloned().collect::<Vec<_>>(),
            "three top-level fields are not a group, so there is nothing to name"
        );
    }

    /// The defect this pair of rules exists for: a container with one busy
    /// sub-object in it and a dozen quiet siblings beside it.
    ///
    /// The old rule rejected the parent outright, so the busy sub-object
    /// reported itself and the dozen siblings were listed one by one. They had a
    /// prefix, a count well over the bar, and no reason to be spelled out.
    #[test]
    fn a_busy_subobject_does_not_cost_its_parent_the_rest_of_the_group() {
        let noise = FieldNoise::default();
        let mut fields = counts(&[
            "account.inner.a",
            "account.inner.b",
            "account.inner.c",
            "account.inner.d",
            "account.inner.e",
            "account.inner.f",
            "account.inner.g",
            "account.inner.h",
        ]);
        // Counted below the inner group so the list has the order the
        // report would print it in.
        let siblings = [
            "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven",
            "twelve",
        ];
        for (index, name) in siblings.iter().enumerate() {
            fields.insert(format!("account.{name}"), 100 - index);
        }

        let summarized = noise.summarize(&fields, &BTreeSet::new(), &thresholds());

        assert_eq!(
            summarized,
            vec![
                "account.* (12 keys)".to_string(),
                "account.inner.* (8 keys)".to_string()
            ],
            "the parent takes the twelve the child did not, and says so"
        );
    }

    /// The count in front of the reader has to be the count of what the line
    /// replaced. Crediting a parent with its child's keys makes the two numbers
    /// add up to more than the list holds.
    #[test]
    fn a_parent_counts_only_the_keys_its_child_did_not_take() {
        let noise = FieldNoise::default();
        let fields = counts(&[
            "a.b.one", "a.b.two", "a.b.three", "a.b.four", "a.b.five", "a.b.six", "a.b.seven",
            "a.b.eight", "a.b.nine", "a.b.ten",
        ]);
        let mut protected = BTreeSet::new();
        protected.insert("a.b.five".to_string());
        protected.insert("a.b.six".to_string());

        // `a.b` claims nothing, since it holds no keys outside itself.
        assert_eq!(
            noise.summarize(&fields, &protected, &thresholds()),
            vec!["a.b.* (10 keys) [five, six]".to_string()],
            "the deepest bucket still owns the whole list"
        );
    }

    /// A protected field on each side of a split goes on the line that owns it,
    /// and neither line claims the other's.
    #[test]
    fn protected_fields_are_named_by_the_line_that_replaces_them() {
        let noise = FieldNoise::default();
        let mut fields = counts(&[
            "a.b.inner.one",
            "a.b.inner.two",
            "a.b.inner.three",
            "a.b.inner.four",
            "a.b.inner.five",
            "a.b.inner.six",
            "a.b.inner.seven",
            "a.b.inner.eight",
        ]);
        // Counted below the inner group so the list has the order the
        // report would print it in.
        let siblings = [
            "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven",
            "twelve",
        ];
        for (index, name) in siblings.iter().enumerate() {
            fields.insert(format!("a.b.{name}"), 100 - index);
        }
        let mut protected = BTreeSet::new();
        protected.insert("a.b.two".to_string());
        protected.insert("a.b.inner.four".to_string());

        assert_eq!(
            noise.summarize(&fields, &protected, &thresholds()),
            vec![
                "a.b.* (12 keys) [two]".to_string(),
                "a.b.inner.* (8 keys) [four]".to_string()
            ],
            "each line names only its own protected fields"
        );
    }

    /// The guard against the split being used to smuggle a short line past the
    /// bar: two keys beside a folding child is two keys, and saying `(2 keys)` on
    /// a bucket is a summary of nothing.
    #[test]
    fn a_parent_with_nothing_left_to_say_stays_open() {
        let noise = FieldNoise::default();
        let mut fields = counts(&[
            "a.b.inner.one",
            "a.b.inner.two",
            "a.b.inner.three",
            "a.b.inner.four",
            "a.b.inner.five",
            "a.b.inner.six",
            "a.b.inner.seven",
            "a.b.inner.eight",
        ]);
        fields.insert("a.b.kept_one".to_string(), 100);
        fields.insert("a.b.kept_two".to_string(), 99);

        let summarized = noise.summarize(&fields, &BTreeSet::new(), &thresholds());

        assert_eq!(
            summarized,
            vec![
                "a.b.kept_one".to_string(),
                "a.b.kept_two".to_string(),
                "a.b.inner.* (8 keys)".to_string()
            ],
            "two keys are not a bucket, and the bar is met by what is left"
        );
    }

    /// A summary that hid one sibling but counted it would report a number the
    /// reader cannot check against the list.
    #[test]
    fn a_bucket_counts_only_what_it_replaces() {
        let noise = FieldNoise::default();
        let fields = counts(&[
            "env.alpha",
            "env.beta",
            "env.gamma",
            "env.delta",
            "env.epsilon",
            "env.zeta",
            "env.eta",
            "env.theta",
            "data.id",
        ]);

        let summarized = noise.summarize(&fields, &BTreeSet::new(), &thresholds());

        assert_eq!(
            summarized,
            vec!["env.* (8 keys)".to_string(), "data.id".to_string()]
        );
    }

    /// A prefix matching on characters rather than on structure would swallow its
    /// own neighbours: `a.b` and `a.bc` are unrelated fields.
    #[test]
    fn a_bucket_never_claims_a_field_that_only_shares_its_spelling() {
        let noise = FieldNoise::default();
        let fields = counts(&[
            "env.alpha",
            "env.beta",
            "env.gamma",
            "env.delta",
            "env.epsilon",
            "env.zeta",
            "env.eta",
            "env.theta",
            "env_other.id",
        ]);

        let summarized = noise.summarize(&fields, &BTreeSet::new(), &thresholds());

        assert!(
            summarized.contains(&"env_other.id".to_string()),
            "a sibling of the prefix was absorbed into it: {summarized:?}"
        );
    }

    /// Deep structure is reported at its top, once, rather than once per level.
    #[test]
    fn a_deep_structure_is_reported_once_at_its_top() {
        let noise = FieldNoise::default();
        let fields = counts(&[
            "a.b.c.d.e", "a.b.c.d.f", "a.b.c.d.g", "a.b.c.d.h", "a.b.c.d.i", "a.b.c.d.j",
            "a.b.c.k", "a.b.c.l",
        ]);

        assert_eq!(
            noise.summarize(&fields, &BTreeSet::new(), &thresholds()),
            vec!["a.b.c.* (8 keys)".to_string()]
        );
    }

    /// A short list is a list a reader reads. Below the bar nothing is folded,
    /// which is also what keeps a five-field object from becoming one line.
    #[test]
    fn a_short_list_is_left_whole() {
        let noise = FieldNoise::default();
        let fields = counts(&["a.b", "a.c", "a.d", "x.y", "z"]);

        assert_eq!(
            noise.summarize(&fields, &BTreeSet::new(), &thresholds()),
            by_frequency(&fields).into_iter().cloned().collect::<Vec<_>>()
        );
    }

    /// Order is a report contract: the most-seen field still leads, and folding
    /// a run away never moves what survives.
    #[test]
    fn summarizing_keeps_the_order_the_list_already_had() {
        let noise = FieldNoise::default();
        let mut fields = counts(&FLAGS);
        fields.insert("top_level.lead".to_string(), 1_000);

        let summarized = noise.summarize(&fields, &BTreeSet::new(), &thresholds());

        assert_eq!(
            summarized,
            vec![
                "top_level.lead".to_string(),
                "event.properties.* (10 keys)".to_string()
            ],
            "folding a run away reordered or hid what survived"
        );
    }

    /// The order is defined once, for every list in the report.
    #[test]
    fn fields_are_ordered_by_frequency_then_alphabetically() {
        let mut fields = BTreeMap::new();
        fields.insert("b".to_string(), 5);
        fields.insert("a".to_string(), 5);
        fields.insert("c".to_string(), 9);

        assert_eq!(
            by_frequency(&fields),
            vec![&"c".to_string(), &"a".to_string(), &"b".to_string()]
        );
    }

    #[test]
    fn the_root_of_a_path_is_its_outermost_segment() {
        assert_eq!(root_of("events[].event_properties.page"), "events[]");
        assert_eq!(root_of("[]"), "[]");
        assert_eq!(root_of("id"), "id");
    }

    /// A sink for a batch: one container in, nothing out. The shape of a
    /// telemetry endpoint, judged without reading its path.
    #[test]
    fn a_container_in_and_nothing_out_is_a_collector() {
        let request = counts(&[
            "events[].device_id",
            "events[].event_id",
            "events[].event_properties.a",
            "events[].event_properties.b",
            "events[].event_properties.c",
            "events[].event_properties.d",
            "events[].event_properties.e",
            "events[].user_id",
        ]);

        assert!(is_collector(&request, &BTreeMap::new(), &thresholds()));
    }

    /// The control. A query with eight top-level parameters is a record the
    /// reader wants to see, and calling it a collector would sink it.
    #[test]
    fn a_record_with_many_top_level_fields_is_not_a_collector() {
        let request = counts(&[
            "id", "name", "email", "role", "created_at", "updated_at", "status", "team",
        ]);

        assert!(!is_collector(&request, &BTreeMap::new(), &thresholds()));
    }

    /// A route that answers with state is doing something, whatever it receives.
    #[test]
    fn an_endpoint_that_returns_state_is_not_a_collector() {
        let request = counts(&[
            "events[].device_id",
            "events[].event_id",
            "events[].event_properties.a",
            "events[].event_properties.b",
            "events[].event_properties.c",
            "events[].event_properties.d",
            "events[].event_properties.e",
            "events[].event_properties.f",
        ]);
        let response = counts(&["accepted", "rejected", "errors"]);

        assert!(!is_collector(&request, &response, &thresholds()));
    }

    /// A two-field body is not a shape, it is a fact.
    #[test]
    fn too_few_fields_to_be_a_shape_is_not_a_collector() {
        let request = counts(&["events[].a", "events[].b"]);

        assert!(!is_collector(&request, &BTreeMap::new(), &thresholds()));
    }

    /// The profile is measured over the capture and shared, so the same
    /// structure costs the same whatever endpoint asks about it.
    #[test]
    fn a_prefix_absent_from_the_capture_has_no_spread() {
        let noise = FieldNoise::profile(&[field(0, "a.b")], &table_of(&[(0, "/x")]));

        assert_eq!(noise.spread_of("a"), 1);
        assert_eq!(noise.spread_of("a.b.c"), 0);
        assert_eq!(noise.spread_of("nothing"), 0);
    }
}
