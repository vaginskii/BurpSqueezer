//! Value class detection for routing furniture.
//!
//! Load balancers and session affinity pins issue a credential that is long,
//! random, present on nearly every exchange, and *replaced* rather than reused.
//! Every one of those values passes every quality test mining applies, and a
//! capture served through one of them fills Core Signal with a dozen rows that
//! all say the same thing about infrastructure.
//!
//! The rule here is entirely structural. No cookie is named, and none could be:
//! what decides is where a value sat, what its characters look like, and how its
//! *slot* behaved over the capture. A slot that keeps changing what it holds is
//! the evidence — a slot that never changed held a constant, and constants are
//! already handled by [`crate::analysis::salience`].
//!
//! One classifier, called from one place. Detection that is re-derived at
//! display time is detection that can disagree with itself.

use std::collections::{BTreeMap, BTreeSet};

use super::entropy;
use crate::config::Thresholds;
use crate::model::transaction::TxId;
use crate::model::value::{ObservedValue, ValueLocation};

/// How one cookie slot behaved across the retained traffic.
///
/// A slot is a *name*, not a value: the cookie the client sends and the one the
/// server assigns are the same slot seen from two directions, and both count
/// towards the same figure.
///
/// Both fields are about the slot. That is the whole point of measuring here
/// rather than per value: a slot that rotates cannot also give any one of its
/// values high coverage, so asking both questions of a value asks for a
/// credential that is everywhere and never changes, which is a constant.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SlotChurn {
    /// Distinct values the slot was ever seen carrying.
    pub distinct_values: usize,
    /// Transactions the slot was sighted in.
    pub transactions: usize,
    /// Share of the capture's retained transactions the slot was sighted in.
    pub coverage: f64,
}

impl SlotChurn {
    /// Whether the slot kept changing what it held.
    ///
    /// A slot that only ever carried one value is a constant, and this is not
    /// the rule that judges constants. What marks routing furniture is a stable
    /// name under a stream of replacements.
    ///
    /// The sample bar is what stops a two-transaction capture from calling
    /// anything a rotation: with one observation there is nothing to have
    /// changed, and treating that as churn would collapse real values on short
    /// captures.
    pub fn rotates(&self, min_samples: usize) -> bool {
        self.transactions >= min_samples && self.distinct_values >= 2
    }
}

/// Measure every cookie slot in the capture, by name.
///
/// One pass over the observations, borrowing both the values and the transaction
/// ids rather than copying them: a capture carries these strings many times over
/// and the profile must not cost a second copy of it. `transactions` is the
/// capture's retained transaction count, which is the denominator for the
/// coverage each slot reaches.
pub fn slot_churn(observations: &[ObservedValue], transactions: usize) -> BTreeMap<String, SlotChurn> {
    let mut slots: BTreeMap<String, (BTreeSet<&str>, BTreeSet<TxId>)> = BTreeMap::new();

    for observation in observations {
        let name = match &observation.location {
            ValueLocation::Cookie(name) | ValueLocation::SetCookie(name) => name,
            _ => continue,
        };
        let (values, transactions_seen) = slots.entry(name.clone()).or_default();
        values.insert(observation.value.as_str());
        transactions_seen.insert(observation.tx_id);
    }

    slots
        .into_iter()
        .map(|(name, (values, seen))| {
            let coverage = if transactions == 0 {
                0.0
            } else {
                (seen.len() as f64 / transactions as f64).min(1.0)
            };
            (
                name,
                SlotChurn {
                    distinct_values: values.len(),
                    transactions: seen.len(),
                    coverage,
                },
            )
        })
        .collect()
}

/// What the sticky rule gets to look at for one candidate.
#[derive(Debug, Clone, Copy)]
pub struct StickyEvidence<'a> {
    /// The cookie slot it was seen in, when it was seen in one at all.
    ///
    /// Presence is the location test. A value that never sat in a cookie is not
    /// a cookie of any kind, whatever else is true of it.
    pub slot: Option<&'a str>,
    /// The value's full text.
    pub value: &'a str,
    /// How its slot behaved, or `None` when it was never in one.
    pub churn: Option<SlotChurn>,
}

/// Classify a value's behavioural pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValueClass {
    /// Ordinary application data.
    #[default]
    Normal,
    /// A routing credential: long, random, everywhere, and repeatedly replaced.
    StickyCookie,
}

impl ValueClass {
    /// Classify a value from its slot, its characters, and its slot's churn.
    ///
    /// All of the following must hold, and none of them is a name:
    ///
    /// - the value was carried by a cookie;
    /// - it is at least [`Thresholds::sticky_min_len`] bytes long;
    /// - it reaches [`Thresholds::sticky_min_entropy_bits`] of Shannon entropy;
    /// - the *slot* rides in at least [`Thresholds::sticky_min_coverage`] of
    ///   the capture's transactions;
    /// - that slot keeps changing what it holds, over at least
    ///   [`Thresholds::sticky_min_slot_samples`] transactions.
    ///
    /// Note where the coverage test is applied. A value whose own coverage had
    /// to clear the bar could never pass: the values of a rotating slot are
    /// exactly the ones nothing rides along with. The credential is present on
    /// every exchange; it is its *content* that changes, and that is what the
    /// test has to be asking about.
    ///
    /// Propagation is deliberately not a condition. A capture that only ever
    /// shows one direction of a session still shows a credential that is being
    /// replaced, and the slot's own behaviour is the stronger evidence of it
    /// anyway.
    pub fn classify(evidence: &StickyEvidence<'_>, thresholds: &Thresholds) -> Self {
        if evidence.slot.is_none() {
            return ValueClass::Normal;
        }
        let Some(churn) = evidence.churn else {
            return ValueClass::Normal;
        };

        if evidence.value.len() < thresholds.sticky_min_len {
            return ValueClass::Normal;
        }
        if entropy::shannon_bits_str(evidence.value) < thresholds.sticky_min_entropy_bits {
            return ValueClass::Normal;
        }
        if churn.coverage < thresholds.sticky_min_coverage {
            return ValueClass::Normal;
        }
        if !churn.rotates(thresholds.sticky_min_slot_samples) {
            return ValueClass::Normal;
        }

        ValueClass::StickyCookie
    }

    /// How much of its score this class keeps.
    ///
    /// A credential that names no object is evidence about the infrastructure
    /// between the client and the server, not about anything the reader can
    /// act on, so almost none of it survives.
    pub fn damping_multiplier(&self, thresholds: &Thresholds) -> f64 {
        match self {
            ValueClass::Normal => 1.0,
            ValueClass::StickyCookie => thresholds.sticky_floor,
        }
    }

    /// Whether this class is reported as one row standing for its siblings.
    ///
    /// A class that collapses must never appear several times over, and must
    /// never be rebuilt from its rendered sightings at display time.
    pub fn should_collapse(&self) -> bool {
        matches!(self, ValueClass::StickyCookie)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;

    /// Long, and random enough that it is a credential rather than a label.
    fn credential(seed: &str) -> String {
        format!(
            "{seed}9f3aa1bd7c2e4f5a8b6d000011112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccdd"
        )
    }

    fn evidence<'a>(
        slot: Option<&'a str>,
        value: &'a str,
        churn: Option<SlotChurn>,
    ) -> StickyEvidence<'a> {
        StickyEvidence {
            slot,
            value,
            churn,
        }
    }

    /// A slot that has been replaced often enough, in enough transactions, to be
    /// taken for a rotation — and was carried by nearly every exchange.
    fn rotating() -> SlotChurn {
        SlotChurn {
            distinct_values: 12,
            transactions: 74,
            coverage: 0.97,
        }
    }

    #[test]
    fn a_rotating_long_random_cookie_is_routing_furniture() {
        let value = credential("a");
        let class = ValueClass::classify(
            &evidence(Some("routing"), &value, Some(rotating())),
            &Thresholds::for_mode(Mode::Standard),
        );

        assert_eq!(class, ValueClass::StickyCookie);
        assert!(class.should_collapse());
        assert!(class.damping_multiplier(&Thresholds::for_mode(Mode::Standard)) < 1.0);
    }

    #[test]
    fn a_value_outside_a_cookie_is_never_routing_furniture() {
        // The same characters, the same churn figures, a body field instead of a
        // cookie. Location alone has to settle it, or a rotating array of ids
        // would be collapsed away as if it were plumbing.
        let value = credential("a");
        let class = ValueClass::classify(
            &evidence(None, &value, Some(rotating())),
            &Thresholds::for_mode(Mode::Standard),
        );

        assert_eq!(class, ValueClass::Normal);
        assert!(!class.should_collapse());
        assert_eq!(class.damping_multiplier(&Thresholds::for_mode(Mode::Standard)), 1.0);
    }

    /// The condition that replaces "it propagated". A credential that is handed
    /// out and then never sent back is still one the capture shows being
    /// replaced, which is all this rule asks.
    #[test]
    fn propagation_is_not_required() {
        let value = credential("a");
        let class = ValueClass::classify(
            &evidence(Some("routing"), &value, Some(rotating())),
            &Thresholds::for_mode(Mode::Standard),
        );

        assert_eq!(class, ValueClass::StickyCookie);
    }

    /// A slot that never changed held a constant. That is ubiquity's rule, and
    /// applying this one instead would collapse values that are worth reading.
    #[test]
    fn a_settled_slot_is_not_a_rotation() {
        let value = credential("a");
        let settled = SlotChurn {
            distinct_values: 1,
            transactions: 74,
            coverage: 0.97,
        };

        assert_eq!(
            ValueClass::classify(
                &evidence(Some("routing"), &value, Some(settled)),
                &Thresholds::for_mode(Mode::Standard)
            ),
            ValueClass::Normal
        );
    }

    /// Too few transactions and there is nothing to have rotated yet.
    #[test]
    fn a_slot_needs_enough_samples_to_have_rotated() {
        let value = credential("a");
        let brief = SlotChurn {
            distinct_values: 2,
            transactions: 2,
            coverage: 1.0,
        };

        assert!(!brief.rotates(4));
        assert_eq!(
            ValueClass::classify(
                &evidence(Some("routing"), &value, Some(brief)),
                &Thresholds::for_mode(Mode::Standard)
            ),
            ValueClass::Normal
        );
    }

    #[test]
    fn a_short_or_ordinary_cookie_is_never_routing_furniture() {
        let thresholds = Thresholds::for_mode(Mode::Standard);

        // Long and everywhere, but a constant string is not a credential.
        let flat = "a".repeat(120);
        assert_eq!(
            ValueClass::classify(&evidence(Some("sid"), &flat, Some(rotating())), &thresholds),
            ValueClass::Normal
        );

        // Random and rotating, but a session handle is short.
        let short = credential("a")[..32].to_string();
        assert_eq!(
            ValueClass::classify(&evidence(Some("sid"), &short, Some(rotating())), &thresholds),
            ValueClass::Normal
        );
    }

    #[test]
    fn a_slot_seen_once_in_a_blue_moon_is_never_routing_furniture() {
        // Long, random and rotating, but seen on two exchanges out of two
        // hundred. A pin that is not attached to the session is not what routes
        // the client, whatever it is called.
        let value = credential("a");
        let occasional = SlotChurn {
            distinct_values: 2,
            transactions: 2,
            coverage: 0.01,
        };

        assert_eq!(
            ValueClass::classify(
                &evidence(Some("one_shot"), &value, Some(occasional)),
                &Thresholds::for_mode(Mode::Standard)
            ),
            ValueClass::Normal
        );
    }

    /// The profile is what makes the rule possible, and it has to see both
    /// directions of one slot as one slot: the cookie the client sends and the
    /// cookie the server assigns are the same name being filled.
    #[test]
    fn slot_churn_joins_both_directions_of_one_name() {
        let first = credential("a");
        let second = credential("b");
        let observations = vec![
            ObservedValue {
                tx_id: 0,
                direction: crate::model::value::Direction::Response,
                location: ValueLocation::SetCookie("routing".into()),
                value: first.clone(),
            },
            ObservedValue {
                tx_id: 1,
                direction: crate::model::value::Direction::Request,
                location: ValueLocation::Cookie("routing".into()),
                value: first,
            },
            ObservedValue {
                tx_id: 2,
                direction: crate::model::value::Direction::Request,
                location: ValueLocation::Cookie("routing".into()),
                value: second,
            },
            // A body field is not a slot and must not appear in the profile.
            ObservedValue {
                tx_id: 2,
                direction: crate::model::value::Direction::Response,
                location: ValueLocation::BodyField("data.routing".into()),
                value: credential("c"),
            },
        ];

        let churn = slot_churn(&observations, 4);

        assert_eq!(churn.len(), 1);
        let routing = churn.get("routing").expect("the slot was measured");
        assert_eq!(routing.transactions, 3);
        assert_eq!(routing.distinct_values, 2);
        assert!((routing.coverage - 0.75).abs() < f64::EPSILON, "{}", routing.coverage);
        assert!(routing.rotates(3));
        assert!(!routing.rotates(4));
    }

    /// A capture of nothing must not divide by nothing, and a slot cannot be
    /// everywhere in a capture that contains no transactions.
    #[test]
    fn a_capture_with_no_transactions_measures_no_coverage() {
        let observations = vec![ObservedValue {
            tx_id: 0,
            direction: crate::model::value::Direction::Request,
            location: ValueLocation::Cookie("routing".into()),
            value: credential("a"),
        }];

        let churn = slot_churn(&observations, 0);

        assert_eq!(churn["routing"].coverage, 0.0);
    }

    /// Which is the whole point of the module: a shorter report discounts
    /// harder, so the two never have to agree about what a class is worth.
    #[test]
    fn the_discount_is_the_modes_not_a_constant() {
        for mode in [Mode::Safe, Mode::Standard, Mode::Apocalyptic] {
            let floor = ValueClass::StickyCookie.damping_multiplier(&Thresholds::for_mode(mode));
            assert!(floor > 0.0 && floor < 1.0, "{mode}: {floor} is not a discount");
        }
        assert!(
            ValueClass::StickyCookie.damping_multiplier(&Thresholds::for_mode(Mode::Safe))
                > ValueClass::StickyCookie.damping_multiplier(&Thresholds::for_mode(Mode::Compact))
        );
    }
}
