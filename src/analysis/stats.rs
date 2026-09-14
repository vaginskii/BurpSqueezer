//! Frequency, spread, and adaptive-threshold helpers.

/// Distinct-to-total ratio, `0.0` when `total` is zero.
///
/// Near 1.0 means every observation differed; near 0.0 means the field barely
/// moves and therefore carries little signal.
pub fn distinct_ratio(distinct: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    distinct as f64 / total as f64
}

/// Map an unbounded count onto `0.0..1.0`, saturating smoothly.
///
/// Used so that a value seen 200 times does not dwarf one seen 20 times.
pub fn saturate(count: usize, half_point: f64) -> f64 {
    if half_point <= 0.0 {
        return 0.0;
    }
    let count = count as f64;
    count / (count + half_point)
}

/// Normalize `value` into `0.0..1.0` against an expected maximum.
pub fn normalize(value: f64, max: f64) -> f64 {
    if max <= 0.0 {
        return 0.0;
    }
    (value / max).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_empty_inputs() {
        assert_eq!(distinct_ratio(0, 0), 0.0);
    }

    #[test]
    fn distinct_ratio_reflects_spread() {
        assert_eq!(distinct_ratio(4, 4), 1.0);
        assert_eq!(distinct_ratio(1, 4), 0.25);
    }

    #[test]
    fn saturation_is_monotonic_and_bounded() {
        let a = saturate(2, 4.0);
        let b = saturate(20, 4.0);
        assert!(a < b);
        assert!(b < 1.0);
        assert_eq!(saturate(0, 4.0), 0.0);
    }

    #[test]
    fn normalization_clamps() {
        assert_eq!(normalize(10.0, 5.0), 1.0);
        assert_eq!(normalize(-1.0, 5.0), 0.0);
        assert_eq!(normalize(1.0, 0.0), 0.0);
    }
}
