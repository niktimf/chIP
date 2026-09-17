use crate::model::{AnchorSeries, PingSweepFacts};
use crate::Verdict;

/// An anchor whose median RTT differs from its city group's median by more
/// than this is treated as being on a bad path of its own and dropped
/// before it can poison the comparison.
const ANCHOR_OUTLIER_DEVIATION_MS: f64 = 15.0;
/// Fewer valid probes than this and the arithmetic is too noisy to trust —
/// report ERROR (retry) rather than a verdict.
const MIN_VALID_PROBES: usize = 6;
/// A median excess below this is not "the candidate is fast" — it is
/// evidence the candidate is not actually in its declared city.
const SUSPICIOUSLY_NEGATIVE_MS: f64 = -5.0;

pub struct LatencyThresholds {
    pub max_excess_ms: f64,
    pub max_loss_delta_pct: f64,
}

/// The raw numbers behind a latency verdict — what `cli::calibrate` (Task 33)
/// prints to help choose `LatencyThresholds`, and what `judge_latency` itself
/// is built on, so the two can never disagree.
pub struct LatencySummary {
    pub median_excess_ms: f64,
    pub p75_excess_ms: f64,
    pub median_loss_delta_pct: f64,
    pub valid_probes: usize,
}

fn median(xs: &[f64]) -> f64 {
    let mut sorted: Vec<f64> = xs.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        f64::midpoint(sorted[mid - 1], sorted[mid])
    } else {
        sorted[mid]
    }
}

/// The "exclusive"/R-6 interpolating quantile — the same method Python's
/// `statistics.quantiles(xs, n=4)` uses, which is what the 2026-09-15
/// calibration run's own analysis script called to arrive at "p75 8.96ms".
/// A simpler nearest-rank formula (`sorted[ceil(n*0.75) - 1]`) does **not**
/// reproduce that number — verified by hand: for this task's own 12-probe
/// golden fixture it gives 8.05ms, off by 9x this test's tolerance, and for
/// any `n` where `n*0.75` is a whole number (this fixture's 12, and the
/// smaller 8-probe fixture below) it can drop the top quartile's spikes
/// from the result entirely — on the 8-probe case it changes the verdict
/// from Warn to Ok. Do not "simplify" this back to nearest-rank.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn percentile75(xs: &[f64]) -> f64 {
    // `n` is a probe count (single/low-double digits in practice) — nowhere
    // near f64's 52-bit mantissa limit, and `rank.floor()` is always in
    // `[0.75, n+1]`, so the usize round-trip below never truncates or wraps.
    let mut sorted: Vec<f64> = xs.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    let rank = 0.75 * (n as f64 + 1.0);
    let lower_idx = (rank.floor() as usize).clamp(1, n) - 1;
    let upper_idx = (lower_idx + 1).min(n - 1);
    let fraction = rank - rank.floor();
    sorted[lower_idx] + fraction * (sorted[upper_idx] - sorted[lower_idx])
}

/// Anchors whose median RTT is within `ANCHOR_OUTLIER_DEVIATION_MS` of the
/// group's median. An anchor with no `Some` values at all cannot have a
/// median and is dropped the same way.
pub fn select_anchors(anchors: &[AnchorSeries]) -> Vec<&AnchorSeries> {
    let medians: Vec<(&AnchorSeries, f64)> = anchors
        .iter()
        .filter_map(|a| {
            let values: Vec<f64> = a.rtt_ms.iter().filter_map(|x| *x).collect();
            (!values.is_empty()).then(|| (a, median(&values)))
        })
        .collect();
    if medians.is_empty() {
        return Vec::new();
    }
    let group_median = median(&medians.iter().map(|(_, m)| *m).collect::<Vec<_>>());
    medians
        .into_iter()
        .filter(|(_, m)| (*m - group_median).abs() <= ANCHOR_OUTLIER_DEVIATION_MS)
        .map(|(a, _)| a)
        .collect()
}

/// The shared computation behind both `judge_latency` and `cli::calibrate`.
/// `Err` names why there is nothing to summarize: no anchor survived outlier
/// rejection, or too few probes were valid on both the candidate and anchor
/// side to trust the arithmetic.
pub fn summarize_latency(facts: &PingSweepFacts) -> Result<LatencySummary, String> {
    let kept = select_anchors(&facts.city_anchors);
    if kept.is_empty() {
        return Err("no anchor for this city survived outlier rejection".to_string());
    }

    let mut excess = Vec::new();
    let mut loss_delta = Vec::new();
    for i in 0..facts.probe_labels.len() {
        let Some(cand_rtt) = facts.candidate_rtt_ms[i] else { continue };
        let winner = kept
            .iter()
            .filter_map(|a| a.rtt_ms[i].map(|r| (r, a.loss_pct[i].unwrap_or(0.0))))
            .min_by(|a, b| a.0.total_cmp(&b.0));
        let Some((best_rtt, best_loss)) = winner else { continue };
        excess.push(cand_rtt - best_rtt);
        loss_delta.push(facts.candidate_loss_pct[i].unwrap_or(0.0) - best_loss);
    }

    if excess.len() < MIN_VALID_PROBES {
        return Err(format!(
            "only {} of {} probes were valid on both sides (need >= {MIN_VALID_PROBES})",
            excess.len(),
            facts.probe_labels.len()
        ));
    }

    Ok(LatencySummary {
        median_excess_ms: median(&excess),
        p75_excess_ms: percentile75(&excess),
        median_loss_delta_pct: median(&loss_delta),
        valid_probes: excess.len(),
    })
}

pub fn judge_latency(facts: &PingSweepFacts, thresholds: &LatencyThresholds) -> Verdict {
    let summary = match summarize_latency(facts) {
        Ok(s) => s,
        Err(reason) => return Verdict::error(reason),
    };
    let LatencySummary { median_excess_ms: med, p75_excess_ms: p75, median_loss_delta_pct: loss_med, valid_probes } = summary;
    let detail = format!("median excess {med:.1}ms, p75 {p75:.1}ms across {valid_probes} probes");

    if med > thresholds.max_excess_ms || loss_med > thresholds.max_loss_delta_pct {
        Verdict::fail(format!("{detail}, threshold {}ms/{}pp exceeded", thresholds.max_excess_ms, thresholds.max_loss_delta_pct))
    } else if p75 > thresholds.max_excess_ms {
        Verdict::warn(format!("{detail} (p75 exceeds the {}ms threshold, median does not)", thresholds.max_excess_ms))
    } else if med < SUSPICIOUSLY_NEGATIVE_MS {
        Verdict::warn(format!("{detail} — candidate is faster than its own city's anchors; check --city"))
    } else {
        Verdict::ok(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AnchorSeries;
    use pretty_assertions::assert_eq;

    fn anchor(id: &str, rtt: &[f64]) -> AnchorSeries {
        AnchorSeries {
            anchor_id: id.into(),
            rtt_ms: rtt.iter().map(|&x| Some(x)).collect(),
            loss_pct: vec![Some(0.0); rtt.len()],
        }
    }

    fn thresholds() -> LatencyThresholds {
        LatencyThresholds { max_excess_ms: 14.0, max_loss_delta_pct: 2.0 }
    }

    #[test]
    fn select_anchors_drops_one_whose_median_is_far_from_the_group() {
        // Two normal anchors around 20ms, one clearly on a bad path at 200ms.
        let anchors = vec![
            anchor("a1", &[18.0, 22.0, 19.0]),
            anchor("a2", &[20.0, 21.0, 20.0]),
            anchor("bad", &[200.0, 210.0, 195.0]),
        ];

        let kept: Vec<&str> = select_anchors(&anchors).iter().map(|a| a.anchor_id.as_str()).collect();

        assert_eq!(kept, vec!["a1", "a2"]);
    }

    #[test]
    fn select_anchors_keeps_everyone_when_all_are_close() {
        let anchors = vec![anchor("a1", &[10.0, 11.0]), anchor("a2", &[12.0, 13.0])];

        assert_eq!(select_anchors(&anchors).len(), 2);
    }

    /// Reconstructs the FI-1-vs-Helsinki-anchors row of the 2026-09-15
    /// calibration run: 12 real RU Globalping probes, real candidate and
    /// real post-selection best-anchor minimum RTT per probe (the run's
    /// per-anchor breakdown behind that minimum was not saved, so this
    /// models it as a single already-winning anchor — sufficient to check
    /// the median/p75 arithmetic against the numbers the run reported:
    /// median excess 4.95ms, p75 8.96ms, well inside a 14ms threshold).
    #[test]
    fn judges_the_2026_09_15_fi1_helsinki_calibration_run_as_ok() {
        let probes = [
            "Moscow/Timeweb", "Novosibirsk/MTS", "Tomsk/ICA", "Nizhniy Novgorod/Rostelecom",
            "Saint Petersburg/SkyNET", "Khanty-Mansiysk/Rostelecom", "Kostroma/Rostelecom",
            "Kursk/Kurier", "Moscow/Mediasoft ekspert", "Moscow/Hosting technology",
            "Moscow/Cloud.ru", "Moscow/Yandex.Cloud",
        ];
        let candidate = [23.378, 70.703, 71.999, 38.032, 6.521, 64.765, 50.927, 50.88, 15.401, 22.39, 15.354, 21.822];
        let best_anchor = [14.12, 65.123, 64.007, 29.98, 7.003, 65.357, 34.615, 24.915, 22.934, 18.065, 18.86, 19.305];
        let facts = PingSweepFacts {
            probe_labels: probes.iter().map(ToString::to_string).collect(),
            candidate_rtt_ms: candidate.iter().map(|&x| Some(x)).collect(),
            candidate_loss_pct: vec![Some(0.0); probes.len()],
            city_anchors: vec![AnchorSeries {
                anchor_id: "helsinki-winner".into(),
                rtt_ms: best_anchor.iter().map(|&x| Some(x)).collect(),
                loss_pct: vec![Some(0.0); probes.len()],
            }],
        };

        let verdict = judge_latency(&facts, &thresholds());

        assert_eq!(verdict.severity, crate::model::Severity::Ok, "{}", verdict.detail);
        assert!(verdict.detail.contains("4.9") || verdict.detail.contains("5.0"), "{}", verdict.detail);
    }

    #[test]
    fn a_large_median_excess_fails() {
        let facts = PingSweepFacts {
            probe_labels: (0..8).map(|i| format!("probe{i}")).collect(),
            candidate_rtt_ms: vec![Some(80.0); 8],
            candidate_loss_pct: vec![Some(0.0); 8],
            city_anchors: vec![anchor("only", &[20.0; 8])],
        };

        let verdict = judge_latency(&facts, &thresholds());

        assert_eq!(verdict.severity, crate::model::Severity::Fail, "{}", verdict.detail);
    }

    #[test]
    fn a_high_p75_with_an_ok_median_warns() {
        // 8 probes: six near-zero excess, two spikes — median stays low,
        // p75 (6th of 8 sorted values) does not.
        let candidate = [20.0, 20.5, 20.2, 20.1, 20.3, 20.0, 60.0, 65.0];
        let facts = PingSweepFacts {
            probe_labels: (0..8).map(|i| format!("probe{i}")).collect(),
            candidate_rtt_ms: candidate.iter().map(|&x| Some(x)).collect(),
            candidate_loss_pct: vec![Some(0.0); 8],
            city_anchors: vec![anchor("only", &[20.0; 8])],
        };

        let verdict = judge_latency(&facts, &thresholds());

        assert_eq!(verdict.severity, crate::model::Severity::Warn, "{}", verdict.detail);
    }

    #[test]
    fn a_loss_delta_over_threshold_fails_even_with_good_rtt() {
        let mut lossy_anchor = anchor("only", &[20.0; 8]);
        lossy_anchor.loss_pct = vec![Some(0.0); 8];
        let facts = PingSweepFacts {
            probe_labels: (0..8).map(|i| format!("probe{i}")).collect(),
            candidate_rtt_ms: vec![Some(21.0); 8],
            candidate_loss_pct: vec![Some(10.0); 8], // 10% vs anchor's 0%
            city_anchors: vec![lossy_anchor],
        };

        let verdict = judge_latency(&facts, &thresholds());

        assert_eq!(verdict.severity, crate::model::Severity::Fail, "{}", verdict.detail);
    }

    #[test]
    fn a_strongly_negative_median_warns_about_the_declared_city() {
        let facts = PingSweepFacts {
            probe_labels: (0..8).map(|i| format!("probe{i}")).collect(),
            candidate_rtt_ms: vec![Some(5.0); 8],
            candidate_loss_pct: vec![Some(0.0); 8],
            city_anchors: vec![anchor("only", &[30.0; 8])],
        };

        let verdict = judge_latency(&facts, &thresholds());

        assert_eq!(verdict.severity, crate::model::Severity::Warn, "{}", verdict.detail);
        assert!(verdict.detail.contains("city"), "{}", verdict.detail);
    }

    #[test]
    fn fewer_than_six_valid_probes_is_an_error_not_a_verdict() {
        let facts = PingSweepFacts {
            probe_labels: (0..8).map(|i| format!("probe{i}")).collect(),
            candidate_rtt_ms: vec![Some(20.0), Some(20.0), None, None, None, None, None, None],
            candidate_loss_pct: vec![Some(0.0); 8],
            city_anchors: vec![anchor("only", &[20.0; 8])],
        };

        let verdict = judge_latency(&facts, &thresholds());

        assert_eq!(verdict.severity, crate::model::Severity::Error, "{}", verdict.detail);
    }

    #[test]
    fn no_surviving_anchors_is_an_error() {
        let facts = PingSweepFacts {
            probe_labels: vec!["p1".into()],
            candidate_rtt_ms: vec![Some(20.0)],
            candidate_loss_pct: vec![Some(0.0)],
            city_anchors: vec![],
        };

        let verdict = judge_latency(&facts, &thresholds());

        assert_eq!(verdict.severity, crate::model::Severity::Error, "{}", verdict.detail);
    }

    /// `cli::calibrate` (Task 33) reads these raw numbers directly, so they
    /// need their own assertion independent of `judge_latency`'s wording.
    #[test]
    fn summarize_latency_exposes_the_same_numbers_judge_latency_is_built_on() {
        let candidate = [23.378, 70.703, 71.999, 38.032, 6.521, 64.765, 50.927, 50.88, 15.401, 22.39, 15.354, 21.822];
        let best_anchor = [14.12, 65.123, 64.007, 29.98, 7.003, 65.357, 34.615, 24.915, 22.934, 18.065, 18.86, 19.305];
        let facts = PingSweepFacts {
            probe_labels: (0..12).map(|i| format!("probe{i}")).collect(),
            candidate_rtt_ms: candidate.iter().map(|&x| Some(x)).collect(),
            candidate_loss_pct: vec![Some(0.0); 12],
            city_anchors: vec![anchor("winner", &best_anchor)],
        };

        let summary = summarize_latency(&facts).unwrap();

        assert_eq!(summary.valid_probes, 12);
        assert!((summary.median_excess_ms - 4.95).abs() < 0.1, "{}", summary.median_excess_ms);
        assert!((summary.p75_excess_ms - 8.96).abs() < 0.1, "{}", summary.p75_excess_ms);
    }
}
