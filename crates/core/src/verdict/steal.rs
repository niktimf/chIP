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
    let total_delta = after.total_ticks.saturating_sub(before.total_ticks);
    if total_delta == 0 {
        return 0.0;
    }
    let steal_delta = after.steal_ticks.saturating_sub(before.steal_ticks);
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
        ProcStatSnapshot {
            steal_ticks: steal,
            total_ticks: total,
        }
    }

    #[test]
    fn no_steal_ticks_in_the_delta_is_zero_percent() {
        assert_eq!(steal_pct(&snap(50, 9000), &snap(50, 10000)), 0.0);
    }

    #[test]
    fn ten_percent_of_the_elapsed_ticks_being_steal_is_ten_percent() {
        // 1000 ticks elapsed, 100 of them steal.
        assert_eq!(steal_pct(&snap(200, 9000), &snap(300, 10000)), 10.0);
    }

    #[test]
    fn a_total_delta_of_zero_is_zero_percent_not_a_division_by_zero() {
        assert_eq!(steal_pct(&snap(50, 9000), &snap(50, 9000)), 0.0);
    }

    #[test]
    fn judge_steal_warns_at_or_above_five_percent() {
        assert_eq!(judge_steal(4.9).severity, Severity::Ok);
        assert_eq!(judge_steal(5.0).severity, Severity::Warn);
        assert_eq!(judge_steal(20.0).severity, Severity::Warn);
    }
}
