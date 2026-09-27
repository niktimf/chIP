use crate::Verdict;
use crate::model::ProcStatSnapshot;

const WARN_STEAL_PCT: f64 = 5.0;

/// Share of elapsed CPU ticks the kernel itself attributes to steal time
/// (`/proc/stat` field 8) over the interval between two snapshots.
#[allow(clippy::cast_precision_loss)]
// `steal_delta` and `total_delta` are cumulative tick counts since boot,
// clamped to u64::MAX; converting to f64 never loses precision within the
// representable tick range (centuries of uptime).
pub fn steal_pct(before: &ProcStatSnapshot, after: &ProcStatSnapshot) -> f64 {
    let total_delta = after.total_ticks().saturating_sub(before.total_ticks());
    if total_delta == 0 {
        return 0.0;
    }
    let steal_delta = after.steal_ticks().saturating_sub(before.steal_ticks());
    steal_delta as f64 / total_delta as f64 * 100.0
}

pub fn judge_steal(pct: f64) -> Verdict {
    if pct >= WARN_STEAL_PCT {
        Verdict::warn(format!(
            "~{pct:.1}% CPU steal over a 5s sample — host may be oversold"
        ))
    } else {
        Verdict::ok(format!("~{pct:.1}% CPU steal over a 5s sample"))
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use pretty_assertions::assert_eq;

    fn snap(steal: u64, total: u64) -> ProcStatSnapshot {
        ProcStatSnapshot::new(steal, total).unwrap()
    }

    #[rstest::rstest]
    #[case::no_steal_ticks_in_the_delta(
        (snap(50, 9000), snap(50, 10000)),
        0.0
    )]
    // 1000 ticks elapsed, 100 of them steal.
    #[case::ten_percent_of_elapsed_ticks(
        (snap(200, 9000), snap(300, 10000)),
        10.0
    )]
    #[case::no_ticks_elapsed_is_not_a_division_by_zero(
        (snap(50, 9000), snap(50, 9000)),
        0.0
    )]
    fn steal_is_the_share_of_elapsed_ticks(
        #[case] sut: (ProcStatSnapshot, ProcStatSnapshot),
        #[case] expected: f64,
    ) {
        let (before, after) = sut;

        let actual = steal_pct(&before, &after);

        assert_eq!(actual, expected);
    }

    #[rstest::rstest]
    #[case::below_threshold(4.9, Severity::Ok)]
    #[case::at_threshold(5.0, Severity::Warn)]
    #[case::well_above_threshold(20.0, Severity::Warn)]
    fn steal_warning_threshold_is_inclusive(
        #[case] value: f64,
        #[case] expected: Severity,
    ) {
        let verdict = judge_steal(value);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[test]
    fn steal_ticks_cannot_exceed_total_ticks() {
        let error = ProcStatSnapshot::new(11, 10).unwrap_err();

        assert_eq!(
            error.to_string(),
            "steal ticks (11) exceeds total CPU ticks (10)"
        );
    }
}
