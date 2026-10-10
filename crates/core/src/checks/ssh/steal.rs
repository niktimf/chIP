use std::num::NonZeroU64;
use std::time::Duration;

use crate::report::Verdict;
use crate::values::Percent;

/// `/proc/stat`'s first `cpu ` line, reduced to what the steal share needs: the
/// kernel's own steal-time counter (field 8) and the sum of all ten fields.
///
/// Both are monotonically increasing tick counts since boot.
#[derive(Debug, Clone, Copy)]
pub struct ProcStatSnapshot {
    steal_ticks: u64,
    total_ticks: u64,
}

impl ProcStatSnapshot {
    /// # Errors
    ///
    /// Returns `InvalidProcStatSnapshot` when the steal ticks exceed the total.
    pub const fn new(
        steal_ticks: u64,
        total_ticks: u64,
    ) -> Result<Self, InvalidProcStatSnapshot> {
        if steal_ticks > total_ticks {
            Err(InvalidProcStatSnapshot {
                steal: steal_ticks,
                total: total_ticks,
            })
        } else {
            Ok(Self {
                steal_ticks,
                total_ticks,
            })
        }
    }

    pub const fn steal_ticks(self) -> u64 {
        self.steal_ticks
    }

    pub const fn total_ticks(self) -> u64 {
        self.total_ticks
    }

    /// Share of the CPU ticks elapsed since `earlier` that the kernel itself
    /// attributes to steal time. No elapsed ticks means no steal.
    pub fn steal_share_since(self, earlier: Self) -> Percent {
        let total_delta = self.total_ticks.saturating_sub(earlier.total_ticks);
        let steal_delta = self.steal_ticks.saturating_sub(earlier.steal_ticks);
        NonZeroU64::new(total_delta).map_or(Percent::ZERO, |total| {
            Percent::saturating_ratio(steal_delta, total)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("steal ticks ({steal}) exceeds total CPU ticks ({total})")]
pub struct InvalidProcStatSnapshot {
    steal: u64,
    total: u64,
}

const WARN_STEAL_PCT: f64 = 5.0;

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
    use crate::report::Severity;
    use pretty_assertions::assert_eq;

    #[test]
    fn steal_ticks_cannot_exceed_total_ticks() {
        let error = ProcStatSnapshot::new(11, 10).unwrap_err();

        assert_eq!(
            error,
            InvalidProcStatSnapshot {
                steal: 11,
                total: 10
            }
        );
    }

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

        let actual = after.steal_share_since(before);

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
}
