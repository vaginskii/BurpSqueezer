//! Data-flow and multi-hop chain construction.
//!
//! A chain is the ordered trail one Strong Value leaves across transactions.
//! The interesting case is a value the server emits and the client then replays,
//! because that is what ties two endpoints together causally rather than by
//! coincidence.
//!
//! Length is not evidence. A protocol constant pinned to one header appears in
//! every transaction and so produces the longest trail in the capture while
//! saying nothing at all. Three rules keep that out: a trail judged by the same
//! source policy as mining — [`crate::analysis::provenance`] — a score in which
//! hops buy nothing, and a trail that is collapsed to its two ends once the
//! value turns out to be everywhere. See [`shorten`].

use std::collections::HashMap;

use crate::analysis::provenance::{Provenance, Sighting};
use crate::analysis::stats;
use crate::config::Thresholds;
use crate::model::endpoint::EndpointTable;
use crate::model::transaction::TxId;
use crate::model::value::{render_location, Direction, ObservedValue, StrongValue, ValueLocation};

/// Score bonus for a chain containing a response-to-request handover.
const HANDOVER_BONUS: f64 = 0.35;
/// Weight of the endpoints a chain ties together.
const REACH_BONUS: f64 = 0.15;
/// Extra endpoints at which the reach term reaches half its weight.
const REACH_HALF_POINT: f64 = 2.0;

/// One appearance of a value along its trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub tx_id: TxId,
    pub endpoint: String,
    pub direction: Direction,
    pub location: ValueLocation,
}

impl Hop {
    /// Report-ready rendering, e.g. `GET /api/me (req header.authorization)`.
    ///
    /// Delegates to [`render_location`] so a chain hop and the same sighting in
    /// the Strong Values table are always spelled identically. There is no
    /// path-segment special case here on purpose: splicing the concrete segment
    /// back into the slot is what produced `path.{id}`, and a normalized route
    /// already carries `{id}` in the path.
    pub fn label(&self) -> String {
        render_location(&self.endpoint, self.direction, &self.location)
    }
}

impl<'a> From<&'a Hop> for Sighting<'a> {
    fn from(hop: &'a Hop) -> Self {
        Self {
            tx_id: hop.tx_id,
            direction: hop.direction,
            location: &hop.location,
        }
    }
}

/// Hops a trail left out, and where the gap falls in what remains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elision {
    /// How many hops were dropped.
    pub count: usize,
    /// Retained hops preceding the gap.
    ///
    /// Equal to the number retained when the trail was simply cut short, and
    /// smaller when it was collapsed from both ends.
    pub after: usize,
}

/// A Strong Value's trail through the capture.
#[derive(Debug, Clone)]
pub struct Chain {
    /// Index into the Strong Value slice this chain was built from.
    pub value_index: usize,
    /// The hops worth printing, in the order they occurred.
    pub hops: Vec<Hop>,
    /// What was left out, or `None` when the whole trail is present.
    pub elision: Option<Elision>,
    /// Distinct endpoints the whole trail touched, elided hops included.
    pub endpoints: usize,
    /// True when the value was emitted by a response and later sent back from a
    /// different slot.
    pub propagates: bool,
    pub score: f64,
}

impl Chain {
    /// Hops dropped from the trail.
    pub fn elided(&self) -> usize {
        self.elision.map_or(0, |elision| elision.count)
    }

    /// Hops the value actually made, including any not rendered.
    pub fn hop_count(&self) -> usize {
        self.hops.len() + self.elided()
    }

    /// A chain is Multi-Data-Flow once it reaches the configured hop count.
    pub fn is_multi(&self, thresholds: &Thresholds) -> bool {
        self.hop_count() >= thresholds.chain_multi_hops
    }
}

/// Build one chain per Strong Value that actually travels.
///
/// Sorted by descending score, so `--mode` limits always cut the weakest
/// chains first. Deliberately *not* by length: sorting by hop count put the
/// capture's most repetitive value at the top of every report.
pub fn build(
    values: &[StrongValue],
    observations: &[ObservedValue],
    table: &EndpointTable,
    thresholds: &Thresholds,
) -> Vec<Chain> {
    let index = index_by_value(observations);

    let mut chains: Vec<Chain> = values
        .iter()
        .enumerate()
        .filter_map(|(value_index, value)| {
            let sightings = index.get(value.full())?;
            let hops = trail(sightings, table);
            assemble(value_index, value, hops, thresholds)
        })
        .collect();

    chains.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.hop_count().cmp(&a.hop_count()))
            .then_with(|| a.value_index.cmp(&b.value_index))
    });
    chains
}

fn index_by_value(observations: &[ObservedValue]) -> HashMap<&str, Vec<&ObservedValue>> {
    let mut index: HashMap<&str, Vec<&ObservedValue>> = HashMap::new();
    for observation in observations {
        index
            .entry(observation.value.as_str())
            .or_default()
            .push(observation);
    }
    index
}

/// Collapse sightings into an ordered, de-duplicated trail.
///
/// Within one transaction the request is always ordered before the response,
/// which is what lets a handover be recognised as such.
fn trail(sightings: &[&ObservedValue], table: &EndpointTable) -> Vec<Hop> {
    let mut ordered: Vec<&ObservedValue> = sightings.to_vec();
    ordered.sort_by_key(|observation| {
        let direction_rank = match observation.direction {
            Direction::Request => 0,
            Direction::Response => 1,
        };
        (observation.tx_id, direction_rank)
    });

    let mut hops: Vec<Hop> = Vec::new();
    for observation in ordered {
        let Some(endpoint) = table.key_of_tx(observation.tx_id) else {
            continue;
        };
        let hop = Hop {
            tx_id: observation.tx_id,
            endpoint,
            direction: observation.direction,
            location: observation.location.clone(),
        };
        let repeats_previous = hops
            .last()
            .is_some_and(|last| last.tx_id == hop.tx_id && last.direction == hop.direction);
        if !repeats_previous {
            hops.push(hop);
        }
    }
    hops
}

/// Turn a trail into a chain, or reject it as not a flow at all.
fn assemble(
    value_index: usize,
    value: &StrongValue,
    mut hops: Vec<Hop>,
    thresholds: &Thresholds,
) -> Option<Chain> {
    if hops.len() < thresholds.chain_min_hops {
        return None;
    }

    let provenance = Provenance::of(hops.iter().map(Sighting::from));

    // A value seen many times inside one transaction has not travelled.
    if provenance.sighted_transactions() < 2 {
        return None;
    }

    // A trail spent entirely inside the transport envelope is header-to-header
    // propagation, which is chatter unless the value genuinely crossed slots.
    let propagates = provenance.has_handover();
    if provenance.is_transport_only() && !propagates {
        return None;
    }

    let distinct_endpoints = {
        let mut endpoints: Vec<&str> = hops.iter().map(|hop| hop.endpoint.as_str()).collect();
        endpoints.sort_unstable();
        endpoints.dedup();
        endpoints.len()
    };

    // Either the server handed the value over, or the client reused it across
    // separate endpoints. A value repeated against a single endpoint is noise.
    if !propagates && distinct_endpoints < 2 {
        return None;
    }

    // Reach is what a chain adds over the value itself: how much of the API it
    // stitches together. Hop count is not part of the score — repetition is
    // exactly what a constant does best, and it is already penalised inside
    // `value.score` by ubiquity damping.
    let reach = stats::saturate(distinct_endpoints.saturating_sub(1), REACH_HALF_POINT);
    let score = value.score + if propagates { HANDOVER_BONUS } else { 0.0 } + reach * REACH_BONUS;

    let elision = shorten(&mut hops, value, thresholds);

    Some(Chain {
        value_index,
        hops,
        elision,
        endpoints: distinct_endpoints,
        propagates,
        score,
    })
}

/// Cut the trail down to what is worth printing, reporting what was left out.
///
/// Core Signal must show all hops, so this function no longer truncates.
/// Previously, an identifier's trail was cut from the tail and a ubiquitous
/// value's trail was collapsed from both ends. Core Signal completeness
/// takes precedence over display brevity.
fn shorten(_hops: &mut Vec<Hop>, _value: &StrongValue, _thresholds: &Thresholds) -> Option<Elision> {
    // Core Signal must show all hops - no truncation
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;
    use crate::model::endpoint::Endpoint;

    const TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.Xk9sQ2p1bXBlcg";

    fn table(entries: &[(TxId, &str, &str)]) -> EndpointTable {
        let mut table = EndpointTable::new();
        for (tx_id, method, template) in entries {
            let slot = table.slot_for(Endpoint::new(*method, *template));
            table.assign(*tx_id, slot);
        }
        table
    }

    fn observation(
        tx_id: TxId,
        direction: Direction,
        location: ValueLocation,
        value: &str,
    ) -> ObservedValue {
        ObservedValue {
            tx_id,
            direction,
            location,
            value: value.to_string(),
        }
    }

    fn strong(value: &str, score: f64) -> StrongValue {
        let mut sv = StrongValue::new(value.to_string(), 0);
        sv.score = score;
        sv.occurrences = 2;
        sv
    }

    #[test]
    fn builds_a_multi_hop_chain_from_a_handover() {
        let observations = vec![
            observation(
                0,
                Direction::Response,
                ValueLocation::BodyField("token".into()),
                TOKEN,
            ),
            observation(
                1,
                Direction::Request,
                ValueLocation::Header("authorization".into()),
                TOKEN,
            ),
            observation(
                2,
                Direction::Request,
                ValueLocation::Header("authorization".into()),
                TOKEN,
            ),
        ];
        let table = table(&[
            (0, "POST", "/login"),
            (1, "GET", "/me"),
            (2, "GET", "/orders"),
        ]);
        let th = Thresholds::for_mode(Mode::Standard);

        let chains = build(&[strong(TOKEN, 0.8)], &observations, &table, &th);

        assert_eq!(chains.len(), 1);
        let chain = &chains[0];
        assert_eq!(chain.hop_count(), 3);
        assert!(chain.propagates);
        assert!(chain.is_multi(&th));
        assert_eq!(
            chain
                .hops
                .iter()
                .map(|hop| hop.endpoint.as_str())
                .collect::<Vec<_>>(),
            vec!["POST /login", "GET /me", "GET /orders"]
        );
        assert!(chain.score > 0.8);
    }

    #[test]
    fn rejects_a_value_that_never_leaves_one_transaction() {
        let observations = vec![
            observation(
                0,
                Direction::Request,
                ValueLocation::QueryParam("a".into()),
                TOKEN,
            ),
            observation(
                0,
                Direction::Response,
                ValueLocation::BodyField("echo".into()),
                TOKEN,
            ),
        ];
        let table = table(&[(0, "GET", "/echo")]);
        let chains = build(
            &[strong(TOKEN, 0.9)],
            &observations,
            &table,
            &Thresholds::for_mode(Mode::Standard),
        );
        assert!(chains.is_empty());
    }

    #[test]
    fn rejects_repetition_against_a_single_endpoint() {
        let observations = vec![
            observation(
                0,
                Direction::Request,
                ValueLocation::QueryParam("k".into()),
                TOKEN,
            ),
            observation(
                1,
                Direction::Request,
                ValueLocation::QueryParam("k".into()),
                TOKEN,
            ),
        ];
        let table = table(&[(0, "GET", "/search"), (1, "GET", "/search")]);
        let chains = build(
            &[strong(TOKEN, 0.9)],
            &observations,
            &table,
            &Thresholds::for_mode(Mode::Standard),
        );
        assert!(chains.is_empty());
    }

    #[test]
    fn accepts_client_side_reuse_across_endpoints() {
        let observations = vec![
            observation(0, Direction::Request, ValueLocation::PathSegment(1), TOKEN),
            observation(
                1,
                Direction::Request,
                ValueLocation::QueryParam("id".into()),
                TOKEN,
            ),
        ];
        let table = table(&[(0, "GET", "/items/{id}"), (1, "GET", "/audit")]);
        let chains = build(
            &[strong(TOKEN, 0.9)],
            &observations,
            &table,
            &Thresholds::for_mode(Mode::Standard),
        );
        assert_eq!(chains.len(), 1);
        assert!(!chains[0].propagates);
    }

    /// A header the client repeats is not a flow, however many endpoints it
    /// reaches. This is the shape that produced hundred-hop chains over
    /// `pragma`, `host` and `content-type`.
    #[test]
    fn a_trail_that_never_leaves_the_transport_envelope_is_rejected() {
        let header_only = vec![
            observation(
                0,
                Direction::Request,
                ValueLocation::Header("x-trace".into()),
                TOKEN,
            ),
            observation(
                1,
                Direction::Request,
                ValueLocation::Header("x-trace".into()),
                TOKEN,
            ),
        ];
        let table = table(&[(0, "GET", "/a"), (1, "GET", "/b")]);
        let th = Thresholds::for_mode(Mode::Standard);

        // Two distinct endpoints, so only the source policy can reject this.
        assert!(build(&[strong(TOKEN, 0.9)], &header_only, &table, &th).is_empty());

        // The same trail, once a response body has actually handed it over.
        let mut handed_over = header_only;
        handed_over.push(observation(
            0,
            Direction::Response,
            ValueLocation::BodyField("t".into()),
            TOKEN,
        ));
        let chains = build(&[strong(TOKEN, 0.9)], &handed_over, &table, &th);
        assert_eq!(chains.len(), 1);
        assert!(chains[0].propagates);
    }

    /// Endpoints the long ring visits, in order, repeating.
    const RING: [&str; 3] = ["/one", "/two", "/three"];
    /// Transactions in the long ring.
    const RING_LEN: usize = 13;

    /// A response issuing `TOKEN`, then twelve requests replaying it around a
    /// three-endpoint ring: a trail too long for any mode to print whole.
    fn long_ring() -> (Vec<ObservedValue>, EndpointTable) {
        let mut observations = vec![observation(
            0,
            Direction::Response,
            ValueLocation::BodyField("t".into()),
            TOKEN,
        )];
        observations.extend((1..RING_LEN).map(|tx| {
            observation(
                tx,
                Direction::Request,
                ValueLocation::Header("authorization".into()),
                TOKEN,
            )
        }));
        let entries: Vec<(TxId, &str, &str)> = (0..RING_LEN)
            .map(|tx| (tx, "GET", RING[tx % RING.len()]))
            .collect();
        (observations, table(&entries))
    }

    /// A value the capture carried nearly everywhere: a session cookie or
    /// bearer token, whose trail records where the operator browsed.
    fn everywhere(value: &str, score: f64) -> StrongValue {
        let mut sv = strong(value, score);
        sv.coverage = 0.95;
        sv.spread = 0.95;
        sv
    }

    /// Core Signal must show all hops, so a long trail is never truncated.
    #[test]
    fn a_long_trail_shows_all_hops() {
        let (observations, table) = long_ring();
        let th = Thresholds::for_mode(Mode::Standard);

        let chains = build(&[strong(TOKEN, 0.8)], &observations, &table, &th);

        assert_eq!(chains.len(), 1);
        let chain = &chains[0];
        assert_eq!(chain.hops.len(), RING_LEN, "all hops are shown");
        assert_eq!(chain.elided(), 0, "no hops are dropped");
        assert_eq!(chain.hop_count(), RING_LEN);
        assert_eq!(chain.endpoints, RING.len());
        assert!(chain.is_multi(&th));
        assert!(chain.elision.is_none(), "no truncation occurs");
        // The handover is still the first hop.
        assert_eq!(chain.hops[0].direction, Direction::Response);
    }

    /// Length must buy nothing. Here the shorter chain carries the better
    /// value, and that is what decides the order.
    #[test]
    fn score_decides_the_order_not_length() {
        let short_token = "9f3aa1bd7c2e4f5a8b6d0000";
        let observations = vec![
            observation(
                0,
                Direction::Response,
                ValueLocation::BodyField("t".into()),
                TOKEN,
            ),
            observation(
                1,
                Direction::Request,
                ValueLocation::Header("authorization".into()),
                TOKEN,
            ),
            observation(
                2,
                Direction::Request,
                ValueLocation::Header("authorization".into()),
                TOKEN,
            ),
            observation(
                0,
                Direction::Response,
                ValueLocation::BodyField("s".into()),
                short_token,
            ),
            observation(
                1,
                Direction::Request,
                ValueLocation::QueryParam("s".into()),
                short_token,
            ),
        ];
        let table = table(&[
            (0, "POST", "/login"),
            (1, "GET", "/me"),
            (2, "GET", "/orders"),
        ]);

        let chains = build(
            &[strong(TOKEN, 0.6), strong(short_token, 0.9)],
            &observations,
            &table,
            &Thresholds::for_mode(Mode::Standard),
        );
        assert_eq!(chains.len(), 2);
        assert_eq!(chains[0].value_index, 1, "the stronger value leads");
        assert!(chains[0].score > chains[1].score);
        assert!(chains[0].hop_count() < chains[1].hop_count());
    }

    /// Core Signal must show all hops, even for ubiquitous values.
    #[test]
    fn a_ubiquitous_trail_shows_all_hops() {
        let (observations, table) = long_ring();
        let th = Thresholds::for_mode(Mode::Standard);

        let chains = build(&[everywhere(TOKEN, 0.8)], &observations, &table, &th);

        assert_eq!(chains.len(), 1, "a session credential still chains");
        let chain = &chains[0];
        assert_eq!(chain.hops.len(), RING_LEN, "all hops are shown");
        assert_eq!(chain.hop_count(), RING_LEN, "the total stays honest");
        assert_eq!(chain.endpoints, RING.len(), "the reach stays honest");
        assert!(chain.elision.is_none(), "no truncation occurs");

        // The issuing response leads and the final sighting closes.
        assert_eq!(chain.hops[0].direction, Direction::Response);
        assert_eq!(chain.hops.last().expect("hops were kept").tx_id, RING_LEN - 1);
    }

    /// All values keep their full trails now - no collapsing.
    #[test]
    fn all_values_keep_their_full_trails() {
        let (observations, table) = long_ring();
        let th = Thresholds::for_mode(Mode::Standard);

        let local = build(&[strong(TOKEN, 0.8)], &observations, &table, &th);
        let session = build(&[everywhere(TOKEN, 0.8)], &observations, &table, &th);

        assert_eq!(local[0].hops.len(), session[0].hops.len(), "both show all hops");
        assert_eq!(local[0].hop_count(), session[0].hop_count());
    }

    /// A short trail has no middle to drop, so it is left whole.
    #[test]
    fn a_short_ubiquitous_trail_is_left_whole() {
        let observations = vec![
            observation(
                0,
                Direction::Response,
                ValueLocation::BodyField("t".into()),
                TOKEN,
            ),
            observation(
                1,
                Direction::Request,
                ValueLocation::Header("authorization".into()),
                TOKEN,
            ),
        ];
        let table = table(&[(0, "POST", "/login"), (1, "GET", "/me")]);

        let chains = build(
            &[everywhere(TOKEN, 0.8)],
            &observations,
            &table,
            &Thresholds::for_mode(Mode::Standard),
        );

        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].hops.len(), 2);
        assert!(chains[0].elision.is_none());
    }

    /// Core Signal shows all hops regardless of mode.
    #[test]
    fn all_modes_show_all_hops() {
        for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
            let (observations, table) = long_ring();
            let th = Thresholds::for_mode(mode);

            let chains = build(&[strong(TOKEN, 0.8)], &observations, &table, &th);

            assert_eq!(chains.len(), 1);
            let chain = &chains[0];
            assert_eq!(chain.hops.len(), RING_LEN, "{mode}: all hops shown");
            assert!(chain.elision.is_none(), "{mode}: no truncation");
        }
    }
}
