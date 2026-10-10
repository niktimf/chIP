use std::time::Duration;

use crate::Verdict;
use crate::model::{AnchorSeries, Percent, PingSample, PingSweepFacts};
use crate::units::{duration_from_millis, millis};

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

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LatencyThresholds {
    max_excess: Duration,
    max_loss_delta: PercentagePoints,
}

impl LatencyThresholds {
    /// Parses the thresholds in the units the CLI flags use: the RTT excess
    /// in milliseconds, the loss delta in percentage points.
    ///
    /// # Errors
    ///
    /// Returns `InvalidLatencyThresholds` when the RTT excess is not finite and
    /// positive, or the loss delta is not finite and non-negative.
    pub fn from_millis_and_points(
        max_excess_ms: f64,
        max_loss_delta_pp: f64,
    ) -> Result<Self, InvalidLatencyThresholds> {
        let max_excess = duration_from_millis(max_excess_ms)
            .ok()
            .filter(|excess| !excess.is_zero())
            .ok_or(InvalidLatencyThresholds::MaxExcess(max_excess_ms))?;
        let max_loss_delta = PercentagePoints::non_negative(max_loss_delta_pp)
            .ok_or(InvalidLatencyThresholds::MaxLossDelta(max_loss_delta_pp))?;
        Ok(Self {
            max_excess,
            max_loss_delta,
        })
    }

    /// Added on top of the worst p75 RTT excess of a calibration run, so the
    /// suggested threshold leaves room above the known-good nodes it was
    /// measured on.
    pub const SUGGESTED_EXCESS_MARGIN: Duration = Duration::from_millis(5);

    /// Suggests thresholds from the summaries of a calibration run against
    /// known-good nodes: the worst p75 RTT excess plus
    /// [`Self::SUGGESTED_EXCESS_MARGIN`], and the worst median loss delta,
    /// raised to zero when it is negative.
    ///
    /// Returns `None` for an empty run, and when the worst p75 excess is so
    /// negative that adding the margin still leaves no positive threshold.
    pub fn suggested_from(summaries: &[LatencySummary]) -> Option<Self> {
        let worst_p75_excess_ms = summaries
            .iter()
            .map(|summary| summary.p75_excess_ms)
            .reduce(f64::max)?;
        let worst_loss_delta_pp = summaries
            .iter()
            .map(|summary| summary.median_loss_delta_pct)
            .reduce(f64::max)?;
        let max_excess_ms =
            worst_p75_excess_ms + millis(Self::SUGGESTED_EXCESS_MARGIN);
        let max_loss_delta_pp = worst_loss_delta_pp.max(0.0);
        Self::from_millis_and_points(max_excess_ms, max_loss_delta_pp).ok()
    }

    /// The RTT excess threshold in milliseconds, the unit of the CLI flag.
    pub fn max_excess_ms(&self) -> f64 {
        millis(self.max_excess)
    }

    /// The loss delta threshold in percentage points, the unit of the CLI
    /// flag.
    pub const fn max_loss_delta_pp(&self) -> f64 {
        self.max_loss_delta.0
    }
}

/// The largest tolerated loss delta: a finite, non-negative number of
/// percentage points.
///
/// It is not a [`Percent`]: a threshold above 100 points is accepted and
/// never trips, since a delta of two percentages stays within 100.
#[derive(Debug, Clone, Copy, PartialEq)]
struct PercentagePoints(f64);

impl PercentagePoints {
    fn non_negative(points: f64) -> Option<Self> {
        (points.is_finite() && points >= 0.0).then_some(Self(points))
    }
}

/// Which latency threshold is out of range, with the rejected value.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum InvalidLatencyThresholds {
    #[error(
        "invalid latency thresholds: maximum RTT excess must be finite and \
         positive, got {0}"
    )]
    MaxExcess(f64),
    #[error(
        "invalid latency thresholds: maximum loss delta must be finite and \
         non-negative, got {0}"
    )]
    MaxLossDelta(f64),
}

/// The raw numbers behind a latency verdict — what `cli::calibrate`
/// prints to help choose `LatencyThresholds`, and what `judge_latency` itself
/// is built on, so the two can never disagree.
///
/// The fields are differences between the candidate and its best anchor and
/// can be negative, so they stay `f64` in the unit their names carry instead
/// of `Duration` and `Percent`. `crate::units` converts RTTs into these
/// milliseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LatencySummary {
    pub median_excess_ms: f64,
    pub p75_excess_ms: f64,
    /// Candidate loss minus anchor loss, in percentage points.
    pub median_loss_delta_pct: f64,
    pub valid_probes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LatencySummaryError {
    #[error("no anchor for this city survived outlier rejection")]
    NoUsableAnchors,
    #[error(
        "only {valid} of {total} probes were valid on both sides (need >= {required})"
    )]
    TooFewValidProbes {
        valid: usize,
        total: usize,
        required: usize,
    },
}

fn median(xs: &[f64]) -> f64 {
    let mut sorted: Vec<f64> = xs.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
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
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "n is a probe count far below 2^52, and rank.floor() lies in \
              [0.75, n + 1], so the usize round trip neither truncates nor \
              wraps"
)]
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
            let values: Vec<f64> = a
                .samples()
                .iter()
                .filter_map(|sample| sample.map(|sample| millis(sample.rtt())))
                .collect();
            (!values.is_empty()).then(|| (a, median(&values)))
        })
        .collect();
    if medians.is_empty() {
        return Vec::new();
    }
    let group_median =
        median(&medians.iter().map(|(_, m)| *m).collect::<Vec<_>>());
    medians
        .into_iter()
        .filter(|(_, m)| {
            (*m - group_median).abs() <= ANCHOR_OUTLIER_DEVIATION_MS
        })
        .map(|(a, _)| a)
        .collect()
}

/// The shared computation behind both `judge_latency` and `cli::calibrate`.
///
/// `Err` names why there is nothing to summarize: no anchor survived outlier
/// rejection, or too few probes were valid on both the candidate and anchor
/// side to trust the arithmetic.
///
/// # Errors
///
/// Returns `LatencySummaryError` in the two cases listed above.
pub fn summarize_latency(
    facts: &PingSweepFacts,
) -> Result<LatencySummary, LatencySummaryError> {
    let kept = select_anchors(facts.city_anchors());
    if kept.is_empty() {
        return Err(LatencySummaryError::NoUsableAnchors);
    }

    let (excess, loss_delta): (Vec<f64>, Vec<f64>) = facts
        .candidate()
        .iter()
        .enumerate()
        .filter_map(|(probe, candidate)| {
            let delta =
                ProbeDelta::against_best_anchor((*candidate)?, &kept, probe)?;
            Some((delta.excess_ms, delta.loss_delta_pp))
        })
        .unzip();

    if excess.len() < MIN_VALID_PROBES {
        return Err(LatencySummaryError::TooFewValidProbes {
            valid: excess.len(),
            total: facts.candidate().len(),
            required: MIN_VALID_PROBES,
        });
    }

    Ok(LatencySummary {
        median_excess_ms: median(&excess),
        p75_excess_ms: percentile75(&excess),
        median_loss_delta_pct: median(&loss_delta),
        valid_probes: excess.len(),
    })
}

/// How much one probe's candidate sample trails the best kept anchor on the
/// same probe.
struct ProbeDelta {
    excess_ms: f64,
    loss_delta_pp: f64,
}

impl ProbeDelta {
    /// `None` when no kept anchor answered on `probe`: the candidate sample
    /// then has nothing to be compared with.
    fn against_best_anchor(
        candidate: PingSample,
        kept: &[&AnchorSeries],
        probe: usize,
    ) -> Option<Self> {
        let best = kept
            .iter()
            .filter_map(|anchor| anchor.samples()[probe])
            .min_by_key(|sample| sample.rtt())?;
        Some(Self {
            excess_ms: millis(candidate.rtt()) - millis(best.rtt()),
            loss_delta_pp: loss_points(candidate) - loss_points(best),
        })
    }
}

/// A sample without a loss figure counts as lossless.
fn loss_points(sample: PingSample) -> f64 {
    sample.loss().map_or(0.0, Percent::get)
}

pub fn judge_latency(
    facts: &PingSweepFacts,
    thresholds: &LatencyThresholds,
) -> Verdict {
    let summary = match summarize_latency(facts) {
        Ok(s) => s,
        Err(reason) => return Verdict::error(reason.to_string()),
    };
    let LatencySummary {
        median_excess_ms: med,
        p75_excess_ms: p75,
        median_loss_delta_pct: loss_med,
        valid_probes,
    } = summary;
    let detail = format!(
        "median excess {med:.1}ms, p75 {p75:.1}ms across {valid_probes} probes"
    );

    let max_excess_ms = thresholds.max_excess_ms();
    let max_loss_delta_pp = thresholds.max_loss_delta_pp();

    if med > max_excess_ms || loss_med > max_loss_delta_pp {
        Verdict::fail(format!(
            "{detail}, threshold {max_excess_ms}ms/{max_loss_delta_pp}pp exceeded"
        ))
    } else if p75 > max_excess_ms {
        Verdict::warn(format!(
            "{detail} (p75 exceeds the {max_excess_ms}ms threshold, median does not)"
        ))
    } else if med < SUSPICIOUSLY_NEGATIVE_MS {
        Verdict::warn(format!(
            "{detail} — candidate is faster than its own city's anchors; check --city"
        ))
    } else {
        Verdict::ok(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AnchorSeries, Severity};
    use pretty_assertions::assert_eq;

    fn samples(rtt: &[f64], loss_pct: f64) -> Vec<Option<PingSample>> {
        rtt.iter()
            .map(|&rtt| {
                Some(PingSample::from_millis(rtt, Some(loss_pct)).unwrap())
            })
            .collect()
    }

    fn optional_samples(
        rtt: &[Option<f64>],
        loss_pct: f64,
    ) -> Vec<Option<PingSample>> {
        rtt.iter()
            .map(|rtt| {
                rtt.map(|rtt| {
                    PingSample::from_millis(rtt, Some(loss_pct)).unwrap()
                })
            })
            .collect()
    }

    fn anchor(id: &str, rtt: &[f64]) -> AnchorSeries {
        AnchorSeries::new(id, samples(rtt, 0.0))
    }

    fn facts(
        candidate: Vec<Option<PingSample>>,
        city_anchors: Vec<AnchorSeries>,
    ) -> PingSweepFacts {
        PingSweepFacts::new(candidate, city_anchors).unwrap()
    }

    fn thresholds() -> LatencyThresholds {
        LatencyThresholds::from_millis_and_points(14.0, 2.0).unwrap()
    }

    #[test]
    fn an_anchor_whose_median_is_far_from_the_group_is_dropped() {
        // Two normal anchors around 20ms, one clearly on a bad path at 200ms.
        let anchors = vec![
            anchor("a1", &[18.0, 22.0, 19.0]),
            anchor("a2", &[20.0, 21.0, 20.0]),
            anchor("bad", &[200.0, 210.0, 195.0]),
        ];

        let kept: Vec<&str> =
            select_anchors(&anchors).iter().map(|a| a.id()).collect();

        assert_eq!(kept, vec!["a1", "a2"]);
    }

    #[test]
    fn every_anchor_close_to_the_group_is_kept() {
        let anchors =
            vec![anchor("a1", &[10.0, 11.0]), anchor("a2", &[12.0, 13.0])];

        let kept: Vec<&str> =
            select_anchors(&anchors).iter().map(|a| a.id()).collect();

        assert_eq!(kept, vec!["a1", "a2"]);
    }

    #[rstest::rstest]
    #[case::non_finite(f64::NAN)]
    #[case::zero(0.0)]
    #[case::negative(-1.0)]
    fn an_unusable_rtt_excess_threshold_is_rejected(
        #[case] max_excess_ms: f64,
    ) {
        let error =
            LatencyThresholds::from_millis_and_points(max_excess_ms, 2.0)
                .unwrap_err();

        assert!(
            matches!(error, InvalidLatencyThresholds::MaxExcess(_)),
            "{error:?}"
        );
    }

    #[rstest::rstest]
    #[case::non_finite(f64::INFINITY)]
    #[case::negative(-1.0)]
    fn an_unusable_loss_delta_threshold_is_rejected(
        #[case] max_loss_delta_pp: f64,
    ) {
        let error =
            LatencyThresholds::from_millis_and_points(14.0, max_loss_delta_pp)
                .unwrap_err();

        assert!(
            matches!(error, InvalidLatencyThresholds::MaxLossDelta(_)),
            "{error:?}"
        );
    }

    /// Reconstructs the FI-1-vs-Helsinki-anchors row of the 2026-09-15
    /// calibration run: 12 real RU Globalping probes, real candidate and
    /// real post-selection best-anchor minimum RTT per probe (the run's
    /// per-anchor breakdown behind that minimum was not saved, so this
    /// models it as a single already-winning anchor — sufficient to check
    /// the median/p75 arithmetic against the numbers the run reported:
    /// median excess 4.95ms, p75 8.96ms, well inside a 14ms threshold).
    fn fi1_helsinki_calibration_run() -> PingSweepFacts {
        let candidate = [
            23.378, 70.703, 71.999, 38.032, 6.521, 64.765, 50.927, 50.88,
            15.401, 22.39, 15.354, 21.822,
        ];
        let best_anchor = [
            14.12, 65.123, 64.007, 29.98, 7.003, 65.357, 34.615, 24.915,
            22.934, 18.065, 18.86, 19.305,
        ];
        facts(
            samples(&candidate, 0.0),
            vec![anchor("helsinki-winner", &best_anchor)],
        )
    }

    #[test]
    fn judges_the_2026_09_15_fi1_helsinki_calibration_run_as_ok() {
        let sut = fi1_helsinki_calibration_run();

        let verdict = judge_latency(&sut, &thresholds());

        assert_eq!(verdict.severity, Severity::Ok, "{}", verdict.detail);
        assert!(
            verdict.detail.contains("4.9") || verdict.detail.contains("5.0"),
            "{}",
            verdict.detail
        );
    }

    #[rstest::rstest]
    #[case::a_large_median_excess(
        facts(samples(&[80.0; 8], 0.0), vec![anchor("only", &[20.0; 8])]),
        Severity::Fail
    )]
    // 8 probes: six near-zero excess, two spikes; the median stays low, p75
    // (6th of 8 sorted values) does not.
    #[case::a_high_p75_with_an_ok_median(
        facts(
            samples(&[20.0, 20.5, 20.2, 20.1, 20.3, 20.0, 60.0, 65.0], 0.0),
            vec![anchor("only", &[20.0; 8])],
        ),
        Severity::Warn
    )]
    // 10% loss against the anchor's 0%.
    #[case::a_loss_delta_over_threshold_even_with_good_rtt(
        facts(samples(&[21.0; 8], 10.0), vec![anchor("only", &[20.0; 8])]),
        Severity::Fail
    )]
    #[case::fewer_than_six_valid_probes_is_not_a_verdict(
        facts(
            optional_samples(
                &[Some(20.0), Some(20.0), None, None, None, None, None, None],
                0.0,
            ),
            vec![anchor("only", &[20.0; 8])],
        ),
        Severity::Error
    )]
    #[case::no_surviving_anchors(
        facts(samples(&[20.0], 0.0), vec![]),
        Severity::Error
    )]
    fn excess_and_loss_over_the_anchors_set_the_severity(
        #[case] sut: PingSweepFacts,
        #[case] expected: Severity,
    ) {
        let verdict = judge_latency(&sut, &thresholds());

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[test]
    fn a_failed_latency_names_the_thresholds_in_flag_units() {
        let sut =
            facts(samples(&[80.0; 8], 0.0), vec![anchor("only", &[20.0; 8])]);

        let verdict = judge_latency(&sut, &thresholds());

        assert_eq!(
            verdict.detail,
            "median excess 60.0ms, p75 60.0ms across 8 probes, \
             threshold 14ms/2pp exceeded"
        );
    }

    #[test]
    fn a_strongly_negative_median_warns_about_the_declared_city() {
        let sut =
            facts(samples(&[5.0; 8], 0.0), vec![anchor("only", &[30.0; 8])]);

        let verdict = judge_latency(&sut, &thresholds());

        assert_eq!(verdict.severity, Severity::Warn, "{}", verdict.detail);
        assert!(verdict.detail.contains("city"), "{}", verdict.detail);
    }

    #[test]
    fn too_few_probes_exposes_counts_as_typed_error_data() {
        let sut = facts(
            optional_samples(
                &[Some(20.0), Some(20.0), None, None, None, None, None, None],
                0.0,
            ),
            vec![anchor("only", &[20.0; 8])],
        );

        let error = summarize_latency(&sut).unwrap_err();

        assert_eq!(
            error,
            LatencySummaryError::TooFewValidProbes {
                valid: 2,
                total: 8,
                required: 6,
            }
        );
    }

    #[test]
    fn missing_anchors_has_a_matchable_error_variant() {
        let sut = facts(samples(&[20.0], 0.0), vec![]);

        let error = summarize_latency(&sut).unwrap_err();

        assert_eq!(error, LatencySummaryError::NoUsableAnchors);
    }

    fn calibrated(
        p75_excess_ms: f64,
        median_loss_delta_pct: f64,
    ) -> LatencySummary {
        LatencySummary {
            median_excess_ms: 0.0,
            p75_excess_ms,
            median_loss_delta_pct,
            valid_probes: 12,
        }
    }

    #[test]
    fn an_empty_calibration_run_suggests_no_thresholds() {
        let suggested = LatencyThresholds::suggested_from(&[]);

        assert_eq!(suggested, None);
    }

    #[test]
    fn the_suggestion_adds_five_ms_to_the_worst_p75_and_keeps_the_worst_loss() {
        let summaries = [calibrated(8.96, 0.0), calibrated(9.12, 0.5)];

        let suggested = LatencyThresholds::suggested_from(&summaries);

        assert_eq!(
            suggested,
            Some(
                LatencyThresholds::from_millis_and_points(14.12, 0.5).unwrap()
            )
        );
    }

    #[test]
    fn a_negative_worst_loss_delta_is_suggested_as_zero() {
        let summaries = [calibrated(1.0, -0.25), calibrated(2.0, -1.5)];

        let suggested = LatencyThresholds::suggested_from(&summaries);

        assert_eq!(
            suggested,
            Some(LatencyThresholds::from_millis_and_points(7.0, 0.0).unwrap())
        );
    }

    #[test]
    fn a_p75_too_negative_for_the_margin_suggests_no_thresholds() {
        let summaries = [calibrated(-6.0, 0.0)];

        let suggested = LatencyThresholds::suggested_from(&summaries);

        assert_eq!(suggested, None);
    }

    /// `cli::calibrate` reads these raw numbers directly, so they
    /// need their own assertion independent of `judge_latency`'s wording.
    #[test]
    fn the_calibration_run_summarizes_to_the_numbers_the_run_reported() {
        let sut = fi1_helsinki_calibration_run();

        let summary = summarize_latency(&sut).unwrap();

        assert_eq!(summary.valid_probes, 12);
        assert!(
            (summary.median_excess_ms - 4.95).abs() < 0.1,
            "{}",
            summary.median_excess_ms
        );
        assert!(
            (summary.p75_excess_ms - 8.96).abs() < 0.1,
            "{}",
            summary.p75_excess_ms
        );
    }
}
