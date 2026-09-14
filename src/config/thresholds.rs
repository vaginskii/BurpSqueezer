//! The single source of truth for every threshold in the pipeline.
//!
//! Modes change values only; they never change control flow. That keeps the
//! architecture identical across `peaceful`, `standard`, and `apocalyptic`.
//!
//! Bounds on the *input* rather than on the signal live in
//! [`crate::config::Limits`], which no mode may relax.

use super::Mode;

/// All tunables for one run. Constructed once and passed by reference.
#[derive(Debug, Clone)]
pub struct Thresholds {
    pub mode: Mode,

    // --- Gross noise filter ---
    /// Bodies at or above this size may be dropped purely on content type.
    pub gross_body_min_len: usize,

    // --- Statistical noise filter ---
    /// An endpoint seen at least this many times is treated as "frequent" and
    /// is filtered more aggressively.
    pub frequent_endpoint_hits: usize,
    /// Below this Shannon entropy (bits/byte) a sizeable body is near-constant.
    pub low_entropy_bits: f64,
    /// Bodies smaller than this are never judged on entropy.
    pub entropy_min_body_len: usize,
    /// Distinct-parameter-set ratio under which a frequent endpoint counts as
    /// low variation and keeps only a sample of its transactions.
    pub low_variation_ratio: f64,
    /// How many transactions to retain from a low-variation frequent endpoint.
    pub low_variation_keep: usize,

    // --- Path templating ---
    /// Minimum sibling count at one path position before it can collapse.
    pub template_min_siblings: usize,
    /// Distinct/total ratio at a position above which it collapses to `{id}`.
    pub template_distinct_ratio: f64,

    // --- Strong value mining ---
    pub value_min_occurrences: usize,
    pub value_min_len: usize,
    pub value_max_len: usize,
    pub value_min_entropy_bits: f64,
    /// Composite quality score a candidate must reach to be a Strong Value.
    pub value_min_score: f64,
    /// Spread below which a value is not damped at all. Above it, ubiquity is
    /// penalised on the way to `ubiquity_floor`. Also the single line between a
    /// local value and a ubiquitous one, which decides how much a shared value
    /// counts as endpoint evidence, whether it can anchor a sequence, and
    /// whether its chain is printed in full.
    pub ubiquity_onset: f64,
    /// Score multiplier applied to a value present in every transaction.
    pub ubiquity_floor: f64,

    // --- Vocabulary suppression ---
    /// Score multiplier applied to a value whose characters are words rather
    /// than anything a generator produces, and which never named a varying
    /// route position.
    ///
    /// Handover is deliberately not a third condition. A printed enum member
    /// legitimately round-trips — the server returns it in a body, the client
    /// posts it back — so sparing anything that crossed once would spare most
    /// vocabulary along with the identifiers.
    pub label_floor: f64,
    /// Identifier-likeness below which a value's characters count as vocabulary.
    ///
    /// Deliberately tight. It has to admit the word shapes — enum members,
    /// region labels, route nouns — while excluding every shape a generator
    /// produces, including bare digits: an eight-digit object id carries less
    /// entropy than the word `custom_properties` and would be the first thing an
    /// entropy-based rule deleted.
    pub label_max_shape_weight: f64,

    // --- Static catalogue suppression ---
    // An endpoint that ships a fixed table produces values that pass every
    // quality test and mean nothing. These describe what "shipping a table"
    // looks like from outside, and how hard to discount what it emits.
    /// Distinct application-slot values *per transaction* at which an endpoint
    /// is emitting vocabulary in bulk rather than reporting state.
    pub dictionary_min_vocabulary_per_hit: f64,
    /// Share of an endpoint's values that must be seen nowhere else before its
    /// output counts as a self-contained catalogue.
    pub dictionary_min_exclusivity: f64,
    /// Score multiplier applied to a row of such a catalogue.
    pub dictionary_floor: f64,

    // --- Transport (header) admission ---
    // Headers do not take part in mining by default. These are the terms of
    // the single exception, and all of them must hold at once.
    /// Shortest header-borne value that may be considered.
    pub transport_min_len: usize,
    /// Randomness a header-borne value must reach.
    pub transport_min_entropy_bits: f64,
    /// Identifier-likeness a header-borne value's characters must reach.
    pub transport_min_shape_weight: f64,

    // --- Data flow ---
    /// Minimum hops in a chain (2 = one propagation).
    pub chain_min_hops: usize,
    /// Chains of at least this length are Multi-Data-Flow.
    pub chain_multi_hops: usize,
    /// Hops rendered before the rest are summarised as elided.
    ///
    /// A value dragged through a hundred transactions produces a hundred hops
    /// that all say the same thing. The head of the trail carries the
    /// handover; the tail is repetition.
    pub chain_max_hops: usize,
    /// Hops shown from each end of a ubiquitous value's collapsed trail.
    ///
    /// A session credential is genuinely present at every hop, so its trail is
    /// long and every step of it says the same thing. Where it was issued and
    /// where it was last seen is the whole of what a reader can use; the middle
    /// is the reader's own capture, replayed.
    ///
    /// At least 1, and never more than half [`Self::chain_max_hops`]: a
    /// credential must not be printed at greater length than an identifier.
    /// Both bounds are pinned by a test in [`crate::pipeline::relationships`].
    pub chain_collapsed_hops: usize,

    // --- Sequences ---
    pub sequence_min_len: usize,
    pub sequence_max_len: usize,
    pub sequence_min_support: usize,
    /// Repetitions a window needs when a shared local value already ties its
    /// steps together.
    ///
    /// Repetition and a value link are two independent kinds of evidence that a
    /// window is a real flow, and requiring both discards most of what a manual
    /// exploration produces: a tester walks a flow once, so its windows repeat
    /// twice at best. When the same non-ubiquitous value passes through two
    /// steps, that value *is* the evidence, and the window earns its place on a
    /// single sighting.
    pub sequence_linked_min_support: usize,

    // --- Endpoint relevance ---
    /// Number of calls at which an endpoint stops counting as rare.
    ///
    /// Rarity is the whole signal for a deliberate operation: an action a
    /// tester performed once is worth more of the reader's attention than the
    /// same route called constantly by a background poller.
    pub rare_endpoint_hits_ceiling: usize,
    /// Share of the remaining headroom a rare write to an instance route gains.
    ///
    /// Applied to what is left between the endpoint's earned relevance and 1.0,
    /// so it can never lower a score and lifts hardest exactly where the
    /// ordinary terms — traffic volume, field counts, status spread — have the
    /// least to say, which is where these operations always land.
    pub instance_mutation_lift: f64,
    /// Local value evidence an endpoint must hold to reach Core Signal without
    /// being a deliberate write.
    ///
    /// Membership used to be the mere presence of *any* mined value, which one
    /// session cookie was enough to satisfy at two thirds of the capture's
    /// routes. Requiring a quantity of evidence rather than a boolean is what
    /// keeps a static asset out of Core while leaving every endpoint that
    /// handles a real identifier in it.
    pub core_min_local_evidence: f64,
    // --- Field variation ---
    pub variation_min_samples: usize,
    pub variation_max_cardinality: usize,
    pub variation_max_value_len: usize,
    /// Distinct-value ratio above which a field is an identifier rather than a
    /// state: its values never recur, they are simply new each time.
    pub variation_max_distinct_ratio: f64,
    /// Fraction of an endpoint's transactions a field must appear in.
    pub variation_min_coverage: f64,

    // --- Report limits ---
    pub max_strong_values: usize,
    pub max_chains: usize,
    pub max_core_endpoints: usize,
    pub max_other_endpoints: usize,
    pub max_sequences: usize,
    pub max_state_indicators: usize,

    // --- Edge cases ---
    /// At or below this transaction count the dump is "small" and gets relaxed.
    pub small_dump_transactions: usize,
    /// Set when [`Thresholds::relax_for_small_dump`] fired.
    pub relaxed_for_small_dump: bool,
}

impl Thresholds {
    /// Preset for a mode. Only values differ between modes.
    pub fn for_mode(mode: Mode) -> Self {
        let base = Self {
            mode,
            gross_body_min_len: 512,
            frequent_endpoint_hits: 8,
            low_entropy_bits: 2.0,
            entropy_min_body_len: 256,
            low_variation_ratio: 0.2,
            low_variation_keep: 3,
            template_min_siblings: 3,
            template_distinct_ratio: 0.6,
            value_min_occurrences: 2,
            value_min_len: 8,
            value_max_len: 512,
            value_min_entropy_bits: 2.5,
            value_min_score: 0.5,
            ubiquity_onset: 0.60,
            ubiquity_floor: 0.70,
            label_floor: 0.70,
            label_max_shape_weight: 0.35,
            dictionary_min_vocabulary_per_hit: 64.0,
            dictionary_min_exclusivity: 0.9,
            dictionary_floor: 0.35,
            transport_min_len: 24,
            transport_min_entropy_bits: 3.5,
            transport_min_shape_weight: 0.60,
            chain_min_hops: 2,
            chain_multi_hops: 3,
            chain_max_hops: 8,
            chain_collapsed_hops: 2,
            sequence_min_len: 2,
            sequence_max_len: 5,
            sequence_min_support: 2,
            sequence_linked_min_support: 1,
            rare_endpoint_hits_ceiling: 4,
            instance_mutation_lift: 0.5,
            core_min_local_evidence: 0.15,
            variation_min_samples: 4,
            variation_max_cardinality: 5,
            variation_max_value_len: 32,
            variation_max_distinct_ratio: 0.5,
            variation_min_coverage: 0.8,
            max_strong_values: 40,
            max_chains: 25,
            max_core_endpoints: 40,
            max_other_endpoints: 60,
            max_sequences: 15,
            max_state_indicators: 15,
            small_dump_transactions: 25,
            relaxed_for_small_dump: false,
        };

        match mode {
            Mode::Peaceful => Self {
                frequent_endpoint_hits: 16,
                low_entropy_bits: 1.2,
                low_variation_ratio: 0.1,
                low_variation_keep: 6,
                value_min_len: 6,
                value_min_entropy_bits: 2.0,
                value_min_score: 0.35,
                ubiquity_onset: 0.75,
                ubiquity_floor: 0.85,
                label_floor: 0.85,
                dictionary_min_vocabulary_per_hit: 128.0,
                dictionary_min_exclusivity: 0.95,
                dictionary_floor: 0.55,
                transport_min_len: 20,
                transport_min_entropy_bits: 3.2,
                transport_min_shape_weight: 0.60,
                chain_max_hops: 12,
                chain_collapsed_hops: 3,
                rare_endpoint_hits_ceiling: 6,
                instance_mutation_lift: 0.4,
                core_min_local_evidence: 0.10,
                variation_min_samples: 3,
                variation_max_cardinality: 8,
                variation_max_distinct_ratio: 0.7,
                variation_min_coverage: 0.6,
                max_strong_values: 80,
                max_chains: 50,
                max_core_endpoints: 80,
                max_other_endpoints: 150,
                max_sequences: 30,
                max_state_indicators: 30,
                ..base
            },
            Mode::Standard => base,
            Mode::Apocalyptic => Self {
                frequent_endpoint_hits: 4,
                low_entropy_bits: 3.0,
                low_variation_ratio: 0.35,
                low_variation_keep: 2,
                value_min_len: 12,
                value_min_entropy_bits: 3.2,
                value_min_score: 0.7,
                ubiquity_onset: 0.45,
                ubiquity_floor: 0.50,
                label_floor: 0.55,
                dictionary_min_vocabulary_per_hit: 32.0,
                dictionary_min_exclusivity: 0.8,
                dictionary_floor: 0.20,
                transport_min_len: 32,
                transport_min_entropy_bits: 3.8,
                transport_min_shape_weight: 0.65,
                chain_min_hops: 2,
                chain_max_hops: 5,
                chain_collapsed_hops: 1,
                sequence_min_support: 3,
                sequence_linked_min_support: 2,
                rare_endpoint_hits_ceiling: 3,
                instance_mutation_lift: 0.6,
                core_min_local_evidence: 0.25,
                variation_min_samples: 6,
                variation_max_cardinality: 4,
                variation_max_distinct_ratio: 0.35,
                variation_min_coverage: 0.9,
                max_strong_values: 15,
                max_chains: 10,
                max_core_endpoints: 15,
                max_other_endpoints: 10,
                max_sequences: 5,
                max_state_indicators: 5,
                ..base
            },
        }
    }

    /// Soften selection for dumps too small to support statistics.
    ///
    /// Returns `true` when relaxation was applied, so Meta can warn about it.
    pub fn relax_for_small_dump(&mut self, transactions: usize) -> bool {
        if transactions > self.small_dump_transactions {
            return false;
        }
        self.value_min_occurrences = 2;
        self.value_min_len = self.value_min_len.saturating_sub(2).max(4);
        self.value_min_entropy_bits *= 0.7;
        self.value_min_score *= 0.6;
        // Coverage is meaningless over a handful of transactions: two
        // sightings out of five look like ubiquity and are not. The onset is
        // pushed up so damping only fires on values that really are everywhere.
        self.ubiquity_onset = self.ubiquity_onset.max(0.9);
        self.frequent_endpoint_hits = self.frequent_endpoint_hits.max(transactions + 1);
        self.template_min_siblings = 2;
        self.sequence_min_support = 1;
        self.sequence_linked_min_support = 1;
        self.variation_min_samples = 2;
        // Over a handful of transactions there is not enough traffic for an
        // endpoint to accumulate evidence, and demanding a quantity of it would
        // empty Core Signal on exactly the dumps that can least afford it.
        self.core_min_local_evidence = 0.0;
        // Vocabulary is told from identifiers by how the two spread, and a dump
        // this small has no spread to measure. The discount is eased rather than
        // dropped: the shape evidence it rests on is still sound.
        self.label_floor = self.label_floor.max(0.85);
        self.relaxed_for_small_dump = true;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apocalyptic_is_stricter_than_peaceful() {
        let peaceful = Thresholds::for_mode(Mode::Peaceful);
        let apoc = Thresholds::for_mode(Mode::Apocalyptic);
        assert!(apoc.value_min_score > peaceful.value_min_score);
        assert!(apoc.max_strong_values < peaceful.max_strong_values);
        assert!(apoc.value_min_len > peaceful.value_min_len);
    }

    #[test]
    fn the_transport_gate_tightens_with_the_mode() {
        let peaceful = Thresholds::for_mode(Mode::Peaceful);
        let standard = Thresholds::for_mode(Mode::Standard);
        let apoc = Thresholds::for_mode(Mode::Apocalyptic);

        assert!(peaceful.transport_min_len < standard.transport_min_len);
        assert!(standard.transport_min_len < apoc.transport_min_len);
        assert!(peaceful.transport_min_entropy_bits < standard.transport_min_entropy_bits);
        assert!(standard.transport_min_entropy_bits < apoc.transport_min_entropy_bits);
        assert!(peaceful.transport_min_shape_weight <= apoc.transport_min_shape_weight);
        assert!(peaceful.chain_max_hops > standard.chain_max_hops);
        assert!(standard.chain_max_hops > apoc.chain_max_hops);
    }

    /// Chains are capped, but never below the length that defines a
    /// Multi-Data-Flow: the cap must not be able to empty the section.
    #[test]
    fn the_hop_cap_can_never_hide_a_multi_data_flow() {
        for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
            let thresholds = Thresholds::for_mode(mode);
            assert!(thresholds.chain_max_hops >= thresholds.chain_multi_hops);
            assert!(thresholds.chain_max_hops >= thresholds.chain_min_hops);
        }
    }

    /// A usable damping curve needs an onset that leaves room to ramp and a
    /// floor that really is a damping multiplier.
    ///
    /// The two are measured in different units — a share of the capture's
    /// transactions and a score multiplier — so each is bounded in its own
    /// space and the two are never compared with one another.
    fn assert_usable_damping_curve(thresholds: &Thresholds) {
        assert!(
            (0.0..1.0).contains(&thresholds.ubiquity_onset),
            "onset {} leaves no room to ramp",
            thresholds.ubiquity_onset
        );
        assert!(
            thresholds.ubiquity_floor > 0.0 && thresholds.ubiquity_floor < 1.0,
            "floor {} is not a damping multiplier",
            thresholds.ubiquity_floor
        );
    }

    #[test]
    fn every_mode_has_a_usable_damping_curve() {
        for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
            let mut thresholds = Thresholds::for_mode(mode);
            assert_usable_damping_curve(&thresholds);

            thresholds.relax_for_small_dump(4);
            assert_usable_damping_curve(&thresholds);
        }
    }

    /// The catalogue rule is a discount, never an erasure, and a stricter mode
    /// must always discount at least as hard while demanding no more evidence.
    #[test]
    fn the_catalogue_rule_only_ever_tightens_with_the_mode() {
        let peaceful = Thresholds::for_mode(Mode::Peaceful);
        let standard = Thresholds::for_mode(Mode::Standard);
        let apoc = Thresholds::for_mode(Mode::Apocalyptic);

        for thresholds in [&peaceful, &standard, &apoc] {
            let floor = thresholds.dictionary_floor;
            assert!(
                floor > 0.0 && floor < 1.0,
                "dictionary_floor {floor} is not a damping multiplier"
            );
            assert!(
                (0.0..=1.0).contains(&thresholds.dictionary_min_exclusivity),
                "exclusivity is a share of an endpoint's values"
            );
            assert!(thresholds.dictionary_min_vocabulary_per_hit > 0.0);
        }

        // Stricter modes accept less evidence before discounting, and discount
        // what they find more heavily.
        assert!(
            peaceful.dictionary_min_vocabulary_per_hit > standard.dictionary_min_vocabulary_per_hit
        );
        assert!(
            standard.dictionary_min_vocabulary_per_hit > apoc.dictionary_min_vocabulary_per_hit
        );
        assert!(peaceful.dictionary_min_exclusivity > standard.dictionary_min_exclusivity);
        assert!(standard.dictionary_min_exclusivity > apoc.dictionary_min_exclusivity);
        assert!(peaceful.dictionary_floor > standard.dictionary_floor);
        assert!(standard.dictionary_floor > apoc.dictionary_floor);
    }

    /// The lift is a share of remaining headroom, so anything outside `0..1`
    /// would either do nothing or push relevance past its own ceiling.
    #[test]
    fn the_mutation_lift_stays_inside_the_headroom_it_divides() {
        for mode in [Mode::Peaceful, Mode::Standard, Mode::Apocalyptic] {
            let thresholds = Thresholds::for_mode(mode);
            let lift = thresholds.instance_mutation_lift;
            assert!(
                lift > 0.0 && lift < 1.0,
                "{mode} lift {lift} is not a share of the headroom"
            );
            assert!(
                thresholds.rare_endpoint_hits_ceiling >= 1,
                "{mode} would divide by zero rarity"
            );
        }

        // A stricter report is shorter, so what does reach it must be chosen
        // more decisively: fewer endpoints count as rare, and those that do are
        // lifted harder.
        let peaceful = Thresholds::for_mode(Mode::Peaceful);
        let apoc = Thresholds::for_mode(Mode::Apocalyptic);
        assert!(peaceful.rare_endpoint_hits_ceiling > apoc.rare_endpoint_hits_ceiling);
        assert!(peaceful.instance_mutation_lift < apoc.instance_mutation_lift);
    }

    #[test]
    fn relaxation_only_fires_for_small_dumps() {
        let mut big = Thresholds::for_mode(Mode::Standard);
        assert!(!big.relax_for_small_dump(1_000));
        assert!(!big.relaxed_for_small_dump);

        let mut small = Thresholds::for_mode(Mode::Standard);
        assert!(small.relax_for_small_dump(5));
        assert!(small.relaxed_for_small_dump);
        assert!(small.value_min_score < Thresholds::for_mode(Mode::Standard).value_min_score);
        assert!(small.ubiquity_onset > Thresholds::for_mode(Mode::Standard).ubiquity_onset);
    }
}
