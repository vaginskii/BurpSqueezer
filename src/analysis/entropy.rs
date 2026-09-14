//! Shannon entropy and character-shape classification.

/// Shannon entropy in bits per byte, `0.0` for empty input.
///
/// Ranges from 0 (one repeated byte) to 8 (uniform over all byte values).
pub fn shannon_bits(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let total = data.len() as f64;
    -counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Convenience wrapper for text.
pub fn shannon_bits_str(text: &str) -> f64 {
    shannon_bits(text.as_bytes())
}

/// Coarse character composition of a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharShape {
    /// Digits only.
    Numeric,
    /// Hex digits only, at least one letter present.
    Hex,
    /// Canonical 8-4-4-4-12 UUID.
    Uuid,
    /// Three dot-separated base64url segments with a plausible JOSE header.
    Jwt,
    /// Mixed alphanumerics, possibly with `-`, `_`, `+`, `/`, `=`.
    TokenLike,
    /// A local part, an `@`, and a dotted domain: an addressable account.
    EmailLike,
    /// One or more uniformly cased letter runs, joined by `-`, `_` or `/`: words.
    Wordlike,
    /// Contains whitespace or punctuation typical of prose.
    Textual,
}

impl CharShape {
    /// How much the shape alone suggests a machine-generated identifier.
    pub fn identifier_weight(self) -> f64 {
        match self {
            CharShape::Jwt => 1.0,
            CharShape::Uuid => 0.95,
            CharShape::TokenLike => 0.7,
            // Not machine-generated, but it addresses exactly one account and is
            // routinely the input to a login, invite, or ownership change — the
            // same role an opaque user id plays, in a form a human typed.
            CharShape::EmailLike => 0.7,
            CharShape::Hex => 0.65,
            CharShape::Numeric => 0.35,
            CharShape::Wordlike => 0.15,
            CharShape::Textual => 0.0,
        }
    }
}

/// Classify a value's character composition.
pub fn classify(value: &str) -> CharShape {
    if value.is_empty() {
        return CharShape::Textual;
    }
    if is_jwt(value) {
        return CharShape::Jwt;
    }
    if is_uuid(value) {
        return CharShape::Uuid;
    }
    if value.bytes().all(|b| b.is_ascii_digit()) {
        return CharShape::Numeric;
    }
    if value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return CharShape::Hex;
    }
    if is_email_like(value) {
        return CharShape::EmailLike;
    }
    if is_wordlike(value) {
        return CharShape::Wordlike;
    }
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'+' | b'/' | b'='))
    {
        return CharShape::TokenLike;
    }
    CharShape::Textual
}

/// Letter runs in one uniform case, optionally joined by `-`, `_` or `/`.
///
/// Nothing mints identifiers this way: a generated token carries digits or
/// mixed case. What does look like this is vocabulary — route nouns such as
/// `workspaces`, header constants such as `SAMEORIGIN`, and the compound labels
/// that fill enumerations, palettes and profile settings, whose only structure is
/// a separator between ordinary words. Separating the shape lets those be scored
/// as the words they are without naming a single one of them.
///
/// The separator is what makes this worth stating carefully. Requiring a single
/// unbroken run would classify every `snake_case` and `kebab-case` label as
/// `TokenLike`, which is the strongest non-cryptographic shape there is — the
/// exact mistake that let enum members and colour names outrank real ids. `/`
/// belongs in the same set: it separates words in a region label exactly as `_`
/// separates them in an enum member, and admitting it only into the token
/// alphabet is what let a two-word setting outscore an eight-digit object id.
///
/// A dot is deliberately *not* a separator here. Dotted lowercase words are how
/// hostnames are written, and a host is transport furniture that must keep
/// scoring below vocabulary rather than joining it.
///
/// Three casing styles count as uniform: all lower, all upper, and each run
/// capitalised. What matters is that one style holds across every run — a token
/// generator has no reason to be consistent, and mixing styles between runs is
/// therefore evidence against vocabulary rather than for it.
fn is_wordlike(value: &str) -> bool {
    let runs: Vec<&str> = value.split(['-', '_', '/']).collect();
    if runs.iter().any(|run| run.is_empty()) {
        return false;
    }
    if !runs
        .iter()
        .all(|run| run.bytes().all(|b| b.is_ascii_alphabetic()))
    {
        return false;
    }
    let cased = |test: fn(&u8) -> bool| runs.iter().all(|run| run.bytes().all(|b| test(&b)));
    let capitalised = || {
        runs.iter().all(|run| {
            let mut bytes = run.bytes();
            bytes.next().is_some_and(|b| b.is_ascii_uppercase())
                && bytes.all(|b| b.is_ascii_lowercase())
        })
    };
    cased(u8::is_ascii_lowercase) || cased(u8::is_ascii_uppercase) || capitalised()
}

/// A local part, an `@`, and a dotted domain whose last label is alphabetic.
///
/// An address is not machine-generated, so on shape alone it reads as prose and
/// scores nothing. But it addresses exactly one account across every endpoint
/// that accepts it, which is precisely the property the report exists to
/// surface. Recognising the form is what lets it be weighed as identity rather
/// than discarded as text.
fn is_email_like(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    if local.is_empty()
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-'))
    {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    if !labels.iter().all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return false;
    }
    let tld = labels[labels.len() - 1];
    tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

/// Shape-only test for a string that is probably an identifier.
///
/// Used wherever a *positional* decision is made — collapsing a path segment
/// before frequencies are measured, and recognising a route that addresses one
/// object. Both ask the same question, so both ask it here: two copies of this
/// predicate would eventually disagree, and the endpoint keys they produce would
/// silently stop lining up.
///
/// The length floors are what separate an identifier from a word that happens to
/// share its alphabet. A route noun is a word, and collapsing `/api/settings`
/// to `/api/*` would merge endpoints that have nothing to do with each other.
pub fn is_identifier_like(text: &str) -> bool {
    match classify(text) {
        CharShape::Numeric | CharShape::Uuid | CharShape::Jwt => true,
        CharShape::Hex => text.len() >= 8,
        CharShape::TokenLike => text.len() >= 12,
        CharShape::EmailLike | CharShape::Wordlike | CharShape::Textual => false,
    }
}

/// Deliberately strict, shape-only detection of filler / test-like values.
///
/// This is a *display hint* only: it decides whether the `synthetic?` column
/// shows a mark and is never read by scoring, ranking, or filtering. It is
/// tuned for high precision and low recall — a false mark on a real credential
/// is worse than a blank cell — so every rule fires only on a shape that a
/// random token or a real identifier cannot plausibly have. On production
/// captures it is expected to stay silent for almost everything; an empty
/// column is the honest, intended outcome, not a failure.
///
/// Four independent kinds of strong, purely structural evidence:
///   * one character dominates the whole value (near-constant filler);
///   * the value is a short unit tiled three or more times (`abcabcabc`);
///   * an obvious keyboard walk runs through it (`qwerty…`, `12345…`);
///   * it is long yet carries almost no entropy — a long run from a tiny
///     alphabet, which a real token of that length never is.
///
/// Nothing here is application-specific: no field names, hosts, emails, or
/// value literals — only counts, ratios, repetition, and entropy.
pub fn is_synthetic(value: &str) -> bool {
    /// Shortest value worth judging; below this, coincidence is too likely.
    const MIN_LEN: usize = 8;
    /// Share of a single character that reads as near-constant filler.
    const DOMINANT_CHAR_SHARE: f64 = 0.8;
    /// Fewest repeats of a tiled unit that count as an obvious pattern.
    const MIN_TILE_REPEATS: usize = 3;
    /// Length at and above which almost-flat entropy becomes decisive.
    const LOW_ENTROPY_LEN: usize = 16;
    /// Entropy (bits/byte) below which a long value is treated as filler.
    const LOW_ENTROPY_BITS: f64 = 2.0;

    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    if len < MIN_LEN {
        return false;
    }

    // One character dominates: `aaaaaaaa`, `x0000000000`.
    if dominant_char_share(&chars) >= DOMINANT_CHAR_SHARE {
        return true;
    }

    // A short unit tiled three or more times: `abcabcabc`, `10101010`.
    if is_tiled(&chars, MIN_TILE_REPEATS) {
        return true;
    }

    // An obvious keyboard walk. Adjacency on a keyboard is a property of the
    // value's own characters, not of any application, so it stays shape-based.
    const KEYBOARD_WALKS: [&str; 5] =
        ["qwertyuiop", "asdfghjkl", "zxcvbnm", "123456789", "987654321"];
    let lower = value.to_lowercase();
    if KEYBOARD_WALKS.iter().any(|walk| lower.contains(walk)) {
        return true;
    }

    // Long, yet almost no entropy: a real token of this length never is.
    len >= LOW_ENTROPY_LEN && shannon_bits_str(value) < LOW_ENTROPY_BITS
}

/// Largest share any single character holds in the value, `0.0` when empty.
fn dominant_char_share(chars: &[char]) -> f64 {
    if chars.is_empty() {
        return 0.0;
    }
    let mut sorted = chars.to_vec();
    sorted.sort_unstable();
    let (mut best, mut run) = (1usize, 1usize);
    for pair in sorted.windows(2) {
        run = if pair[0] == pair[1] { run + 1 } else { 1 };
        best = best.max(run);
    }
    best as f64 / chars.len() as f64
}

/// Whether the value is one short unit repeated at least `min_repeats` times.
///
/// Only exact tilings count: `abc` × 3 is a hit, an approximate or shifted
/// repeat is not. A generated token is never an exact tiling of a short unit,
/// so a hit here is strong evidence rather than a coincidence.
fn is_tiled(chars: &[char], min_repeats: usize) -> bool {
    let len = chars.len();
    // A unit repeating at least `min_repeats` times cannot be longer than this,
    // so the smallest qualifying tilings are the only ones checked.
    (1..=len / min_repeats.max(1))
        .any(|unit| len % unit == 0 && chars.chunks(unit).all(|chunk| chunk == &chars[..unit]))
}

fn is_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    if groups.len() != 5 {
        return false;
    }
    let expected = [8, 4, 4, 4, 12];
    groups
        .iter()
        .zip(expected)
        .all(|(group, len)| group.len() == len && group.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Shortest first segment a real JWT can have.
///
/// The leading segment is a base64url-encoded JOSE header, and the smallest
/// legal one — `{"alg":"none"}` — is already 19 characters encoded. Without
/// this floor any dotted triple qualifies, so a hostname like `app.example.com`
/// would be scored as the most identifier-like shape there is.
const MIN_JWT_HEADER_LEN: usize = 16;

fn is_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    if parts[0].len() < MIN_JWT_HEADER_LEN {
        return false;
    }
    parts.iter().all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'='))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_input_has_no_entropy() {
        assert_eq!(shannon_bits(b"aaaaaaaa"), 0.0);
        assert_eq!(shannon_bits(b""), 0.0);
    }

    #[test]
    fn balanced_input_has_one_bit() {
        assert!((shannon_bits(b"abab") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn classifies_common_identifier_shapes() {
        assert_eq!(classify("123456"), CharShape::Numeric);
        assert_eq!(classify("deadbeefcafe"), CharShape::Hex);
        assert_eq!(
            classify("3f2504e0-4f89-11d3-9a0c-0305e82c3301"),
            CharShape::Uuid
        );
        assert_eq!(
            classify("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.Xk9sQ2p1bXBlcg"),
            CharShape::Jwt
        );
        assert_eq!(classify("sk_live_Ab12-_"), CharShape::TokenLike);
        assert_eq!(classify("hello world"), CharShape::Textual);
    }

    /// Route nouns and header constants are letters in one case. Ranking them
    /// as `TokenLike` let `workspaces` and `SAMEORIGIN` score like credentials.
    #[test]
    fn a_single_cased_word_is_not_a_token() {
        assert_eq!(classify("workspaces"), CharShape::Wordlike);
        assert_eq!(classify("announcements"), CharShape::Wordlike);
        assert_eq!(classify("SAMEORIGIN"), CharShape::Wordlike);
        assert_eq!(classify("trailers"), CharShape::Wordlike);

        // Mixed case or a digit is how identifiers actually look.
        assert_eq!(classify("userToken"), CharShape::TokenLike);
        assert_eq!(classify("workspace2"), CharShape::TokenLike);

        // Hex is decided first, so a hex-only word keeps its stronger shape.
        assert_eq!(classify("deadbeefcafe"), CharShape::Hex);

        assert!(CharShape::Wordlike.identifier_weight() < CharShape::Numeric.identifier_weight());
        assert!(CharShape::Wordlike.identifier_weight() > CharShape::Textual.identifier_weight());
    }

    /// A separator between two ordinary words does not make an identifier. The
    /// mid-tier noise in Core Signal was almost entirely this shape: palette
    /// entries, enum members, and field names, all scoring `TokenLike` at 0.7
    /// because a hyphen or underscore broke the single-run rule.
    #[test]
    fn delimited_words_are_still_words() {
        for label in [
            "light-slate-gray",
            "group_tags",
            "multi_select",
            "scheduled_drafts",
            "face_with_open_mouth",
            "READ_ONLY",
        ] {
            assert_eq!(classify(label), CharShape::Wordlike, "misclassified {label}");
        }

        // A digit anywhere still means something generated it.
        assert_eq!(classify("group_tags2"), CharShape::TokenLike);
        assert_eq!(classify("sk_live_Ab12"), CharShape::TokenLike);
        // Mixing the cases across runs is not how vocabulary is written.
        assert_eq!(classify("group_TAGS"), CharShape::TokenLike);
        // A dangling or doubled separator is not a run of words.
        assert_eq!(classify("group__tags"), CharShape::TokenLike);
        assert_eq!(classify("-tags"), CharShape::TokenLike);
    }

    /// A slash joins words in a region label exactly as an underscore joins them
    /// in an enum member, and a capitalised word is still a word. Admitting
    /// either only into the token alphabet is what let a two-word profile
    /// setting outscore an eight-digit object id in Core Signal.
    #[test]
    fn slashes_and_capitals_do_not_manufacture_identifiers() {
        for label in ["Europe/Moscow", "America/New", "Basic", "Bearer", "Public"] {
            assert_eq!(classify(label), CharShape::Wordlike, "misclassified {label}");
        }

        // Still not identifier-like, so path templating is unaffected.
        assert!(!is_identifier_like("Europe/Moscow"));

        // A digit or an inner capital is how generated strings actually look.
        assert_eq!(classify("Europe/Moscow2"), CharShape::TokenLike);
        assert_eq!(classify("MoscowTime"), CharShape::TokenLike);
        assert_eq!(classify("aBc/dEf"), CharShape::TokenLike);

        // Each witness above is spelled with at least one letter outside `a-f`,
        // which is deliberate: the hex alphabet is tested before any casing
        // rule, so a mixed-case word drawn only from it is classified by its
        // alphabet and never reaches the vocabulary check. That ordering is
        // what keeps a real key like `deadbeefcafe` out of vocabulary, so the
        // test bends around it rather than asking for it to change.
        assert_eq!(classify("AbcDef"), CharShape::Hex);

        // A dot is not a word separator: dotted lowercase words are hostnames,
        // and transport furniture must stay below vocabulary, not join it.
        assert_eq!(classify("app.pachca.com"), CharShape::Textual);
    }

    /// An address is the one identity a human types. Left as prose it scored
    /// zero on shape, which buried the account it names under colour labels.
    #[test]
    fn an_address_is_weighed_as_identity() {
        assert_eq!(classify("someone@example.com"), CharShape::EmailLike);
        assert_eq!(classify("first.last+tag@mail.example.co.uk"), CharShape::EmailLike);

        assert_eq!(classify("not-an-address"), CharShape::Wordlike);
        assert_eq!(classify("missing@tld"), CharShape::Textual);
        assert_eq!(classify("@example.com"), CharShape::Textual);
        assert_eq!(classify("two@@example.com"), CharShape::Textual);

        assert_eq!(
            CharShape::EmailLike.identifier_weight(),
            CharShape::TokenLike.identifier_weight()
        );
        assert!(CharShape::EmailLike.identifier_weight() > CharShape::Wordlike.identifier_weight());
    }

    /// The predicate two stages share. If it ever drifted, the coarse keys used
    /// to measure frequency would stop matching the templates used to report.
    #[test]
    fn identifier_likeness_needs_shape_and_length() {
        assert!(is_identifier_like("812696"));
        assert!(is_identifier_like("3f2504e0-4f89-11d3-9a0c-0305e82c3301"));
        assert!(is_identifier_like("deadbeefcafe"));
        assert!(is_identifier_like("sk_live_Ab12xy"));

        assert!(!is_identifier_like("dead"), "too short to be a hex key");
        assert!(!is_identifier_like("Ab12"), "too short to be a token");
        assert!(!is_identifier_like("settings"), "a route noun is not a key");
        assert!(!is_identifier_like("group_tags"));
        assert!(!is_identifier_like("someone@example.com"));
    }

    /// A hostname is three dot-separated alphanumeric words, which is also the
    /// crude description of a JWT. Scoring it as the most identifier-like shape
    /// there is put `Host` header values straight into Core Signal.
    #[test]
    fn a_hostname_is_not_a_jwt() {
        assert_eq!(classify("app.pachca.com"), CharShape::Textual);
        assert_eq!(classify("aaa.bbb.ccc"), CharShape::Textual);
    }

    #[test]
    fn jwt_outranks_every_other_shape() {
        assert!(CharShape::Jwt.identifier_weight() > CharShape::TokenLike.identifier_weight());
        assert_eq!(CharShape::Textual.identifier_weight(), 0.0);
    }

    /// The synthetic hint marks only shapes a real identifier cannot plausibly
    /// have. The negative cases are the point of the test: a false mark on a
    /// genuine credential is worse than a blank cell, so they must stay silent.
    #[test]
    fn synthetic_hint_is_high_precision() {
        // Strong, purely structural evidence — marked.
        assert!(is_synthetic("aaaaaaaa"), "a single repeated character");
        assert!(is_synthetic("x000000000000"), "one character dominates");
        assert!(is_synthetic("abcabcabcabc"), "a short unit tiled four times");
        assert!(is_synthetic("10101010"), "a two-char unit tiled");
        assert!(is_synthetic("qwertyuiop123"), "an obvious keyboard walk");
        // 17 chars over three well-spread symbols, aperiodic: no single char
        // dominates and it is not an exact tiling, so only the long-yet-flat
        // entropy rule can catch it — which is the branch under test.
        assert!(is_synthetic("abcabcabcabcabcab"), "long yet almost no entropy");

        // Real identifiers and tokens — must never be flagged.
        assert!(!is_synthetic("3f2504e0-4f89-11d3-9a0c-0305e82c3301"), "a UUID");
        assert!(
            !is_synthetic("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.Xk9sQ2p1bXBlcg"),
            "a JWT"
        );
        assert!(!is_synthetic("9f3aa1bd7c2e4f5a8b6d"), "a random hex id");
        assert!(!is_synthetic("sk_live_Ab12xyQ9"), "a random token");
        assert!(!is_synthetic("81269354"), "an ordinary numeric id");

        // Too short to judge: coincidence is too likely below the floor.
        assert!(!is_synthetic("abcabc"));
    }
}
