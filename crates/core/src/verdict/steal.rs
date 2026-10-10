use std::num::NonZeroU64;
use std::time::Duration;

use crate::Verdict;
use crate::model::{Percent, ProcStatSnapshot};

const WARN_STEAL_PCT: f64 = 5.0;

/// Share of elapsed CPU ticks the kernel itself attributes to steal time
/// (`/proc/stat` field 8) over the interval between two snapshots. No
/// elapsed ticks means no steal.
pub fn steal_share(
    before: &ProcStatSnapshot,
    after: &ProcStatSnapshot,
) -> Percent {
    let total_delta = after.total_ticks().saturating_sub(before.total_ticks());
    let steal_delta = after.steal_ticks().saturating_sub(before.steal_ticks());
    NonZeroU64::new(total_delta).map_or(Percent::ZERO, |total| {
        Percent::saturating_ratio(steal_delta, total)
    })
}

/// Judges the steal share measured between two snapshots taken `interval`
/// apart.
pub fn judge_steal(share: Percent, interval: Duration) -> Verdict {
    let pct = share.get();
    let seconds = interval.as_secs_f64();
    if pct >= WARN_STEAL_PCT {
        Verdict::warn(format!(
            "~{pct:.1}% CPU steal over a {seconds}s sample — host may be oversold"
        ))
    } else {
        Verdict::ok(format!("~{pct:.1}% CPU steal over a {seconds}s sample"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use pretty_assertions::assert_eq;

    fn sample_interval() -> Duration {
        Duration::from_secs(5)
    }

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

        let actual = steal_share(&before, &after);

        assert_eq!(actual, Percent::try_from(expected).unwrap());
    }

    #[rstest::rstest]
    #[case::below_threshold(4.9, Severity::Ok)]
    #[case::at_threshold(5.0, Severity::Warn)]
    #[case::well_above_threshold(20.0, Severity::Warn)]
    fn steal_warning_threshold_is_inclusive(
        #[case] value: f64,
        #[case] expected: Severity,
    ) {
        let verdict =
            judge_steal(Percent::try_from(value).unwrap(), sample_interval());

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[test]
    fn the_steal_detail_names_the_sample_interval() {
        let share = Percent::try_from(20.0).unwrap();

        let verdict = judge_steal(share, Duration::from_millis(2500));

        assert_eq!(
            verdict.detail,
            "~20.0% CPU steal over a 2.5s sample — host may be oversold"
        );
    }

    #[test]
    fn a_five_second_sample_is_reported_as_5s() {
        let share = Percent::try_from(3.0).unwrap();

        let verdict = judge_steal(share, sample_interval());

        assert_eq!(verdict.detail, "~3.0% CPU steal over a 5s sample");
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
