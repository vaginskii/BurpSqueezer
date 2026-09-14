//! Stable short fingerprints and redacted rendering of sensitive values.
//!
//! Strong Values are session tokens, API keys, and identifiers. Chains are only
//! readable if each value has a stable handle, but the report is meant to be
//! handed to a third-party model, so the value itself must not travel with it.

/// Characters kept from the head of a masked value.
const HEAD_LEN: usize = 6;
/// Characters kept from the tail of a masked value.
const TAIL_LEN: usize = 4;
/// Values at or below this length are replaced entirely.
const MIN_MASKABLE: usize = HEAD_LEN + TAIL_LEN + 4;

/// FNV-1a 64-bit, truncated to four lowercase hex characters.
///
/// Collisions are possible and acceptable: the fingerprint is a display handle,
/// never a matching key. Chain matching always uses the full value.
pub fn fingerprint(value: &str) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }

    // Fold the 64-bit result down instead of slicing sixteen bits out of it.
    // The prime is 2^40 + 0x1b3, so changing the last byte of the input moves
    // only bits 0..13 and 40..64 of the product: every 16-bit window between
    // them is identical for two values that differ solely in their tail. That
    // is precisely what tokens minted by the same issuer look like. Folding is
    // FNV's own recommendation for a shortened hash and mixes the high bits,
    // where the final byte does land, back down into the bits we keep.
    let folded = hash ^ (hash >> 32);
    let folded = folded ^ (folded >> 16);
    format!("{:04x}", folded as u16)
}

/// Render a value as head, ellipsis, tail, and fingerprint.
///
/// Short values are dropped entirely rather than half-exposed, since a
/// six-character head of an eight-character value is not a redaction.
pub fn mask(value: &str, fingerprint: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= MIN_MASKABLE {
        return format!("<{} chars> [fp:{}]", chars.len(), fingerprint);
    }
    let head: String = chars[..HEAD_LEN].iter().collect();
    let tail: String = chars[chars.len() - TAIL_LEN..].iter().collect();
    format!(
        "{head}\u{2026}{tail} [fp:{fingerprint}] ({} chars)",
        chars.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn fingerprint_is_stable_and_short() {
        let a = fingerprint("session-token-value");
        assert_eq!(a, fingerprint("session-token-value"));
        assert_eq!(a.len(), 4);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_values_get_different_handles() {
        assert_ne!(fingerprint("abc"), fingerprint("abd"));
    }

    /// The realistic collision risk, and the reason the hash is folded rather
    /// than sliced: tokens from one issuer share a prefix and differ at the
    /// tail. A handle blind to the tail would merge two chains in the report
    /// and quietly invent a data flow that never happened.
    #[test]
    fn values_differing_only_at_the_tail_get_different_handles() {
        let handles: BTreeSet<String> = "0123456789abcdef"
            .chars()
            .map(|last| fingerprint(&format!("session-token-2f9c1ae{last}")))
            .collect();
        assert_eq!(handles.len(), 16, "the fingerprint ignored the tail");
    }

    #[test]
    fn long_values_keep_only_head_and_tail() {
        let value = "eyJhbGciOiJIUzI1NiJ9.payloadpayload.signature9k4A";
        let masked = mask(value, "7c2a");
        assert!(masked.starts_with("eyJhbG"));
        assert!(masked.contains("9k4A"));
        assert!(masked.contains("[fp:7c2a]"));
        assert!(!masked.contains("payloadpayload"));
    }

    #[test]
    fn short_values_are_fully_withheld() {
        let masked = mask("abc123", "0f0f");
        assert!(!masked.contains("abc123"));
        assert!(masked.contains("<6 chars>"));
    }

    #[test]
    fn masking_is_safe_for_multibyte_values() {
        let value = "ключ-значение-очень-длинное-значение";
        let masked = mask(value, "abcd");
        assert!(masked.contains("[fp:abcd]"));
    }
}
