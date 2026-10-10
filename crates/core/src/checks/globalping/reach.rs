use crate::Verdict;
use crate::checks::globalping::ProbeAlignmentError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpProbeOutcome {
    Ok,
    Failed,
}

/// HTTPS reachability of the candidate's temporary listener, and of a known-
/// good control anchor, measured by the same Globalping probe set.
#[derive(Debug, Clone)]
pub struct ReachProbe {
    pub candidate: HttpProbeOutcome,
    pub control: HttpProbeOutcome,
}

/// Candidate and control outcomes paired probe by probe. The field is
/// private so that only `new`, which checks that both series have the same
/// length, can pair them.
#[derive(Debug, Clone)]
pub struct ReachFacts {
    probes: Vec<ReachProbe>,
}

impl ReachFacts {
    /// Pairs the candidate and control outcomes probe by probe. Both series
    /// come from the same Globalping probe set, so index `i` must mean the
    /// same probe in each; a series of a different length cannot be paired.
    ///
    /// # Errors
    ///
    /// Returns `ProbeAlignmentError` when the two series differ in length.
    pub fn new(
        candidate: Vec<HttpProbeOutcome>,
        control: Vec<HttpProbeOutcome>,
    ) -> Result<Self, ProbeAlignmentError> {
        const CONTROL_ID: &str = "control";
        if control.len() != candidate.len() {
            return Err(ProbeAlignmentError {
                anchor_id: CONTROL_ID.to_owned(),
                expected: candidate.len(),
                actual: control.len(),
            });
        }
        let probes = candidate
            .into_iter()
            .zip(control)
            .map(|(candidate, control)| ReachProbe { candidate, control })
            .collect();
        Ok(Self { probes })
    }

    pub fn probes(&self) -> &[ReachProbe] {
        &self.probes
    }
}

const FAIL_SHARE: f64 = 0.25;
const MIN_VALID_PROBES: usize = 6;

pub fn judge_reach(facts: &ReachFacts) -> Verdict {
    let valid = facts
        .probes()
        .iter()
        .filter(|probe| probe.control == HttpProbeOutcome::Ok)
        .count();
    if valid < MIN_VALID_PROBES {
        return Verdict::error(format!(
            "only {valid} of {} probes had a working control anchor (need >= {MIN_VALID_PROBES})",
            facts.probes().len()
        ));
    }
    let failed = facts
        .probes()
        .iter()
        .filter(|probe| probe.control == HttpProbeOutcome::Ok)
        .filter(|probe| probe.candidate == HttpProbeOutcome::Failed)
        .count();
    #[expect(
        clippy::cast_precision_loss,
        reason = "probe counts are far below 2^52"
    )]
    let share = failed as f64 / valid as f64;
    let detail = format!(
        "{failed}/{valid} valid probes could not reach the candidate over HTTPS"
    );
    if share >= FAIL_SHARE {
        Verdict::fail(detail)
    } else if failed > 0 {
        Verdict::warn(detail)
    } else {
        Verdict::ok(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Severity;
    use HttpProbeOutcome::{Failed, Ok as HttpOk};

    /// A control probe missing from the reply used to read as `Failed`,
    /// which the reach gate takes for "the control was unreachable too".
    #[test]
    fn reach_rejects_a_control_with_fewer_probes_than_the_candidate() {
        let candidate = vec![HttpProbeOutcome::Ok, HttpProbeOutcome::Failed];

        let error =
            ReachFacts::new(candidate, vec![HttpProbeOutcome::Ok]).unwrap_err();

        assert_eq!(
            error,
            ProbeAlignmentError {
                anchor_id: "control".to_owned(),
                expected: 2,
                actual: 1,
            }
        );
    }

    fn facts(
        candidate: &[HttpProbeOutcome],
        control: &[HttpProbeOutcome],
    ) -> ReachFacts {
        ReachFacts::new(candidate.to_vec(), control.to_vec()).unwrap()
    }

    #[test]
    fn a_probe_where_the_control_itself_failed_does_not_count_against_the_candidate()
     {
        // Control fails on probes 0-1 (excluded); of the remaining 10,
        // candidate fails none.
        let control = [
            Failed, Failed, HttpOk, HttpOk, HttpOk, HttpOk, HttpOk, HttpOk,
            HttpOk, HttpOk, HttpOk, HttpOk,
        ];
        let sut = facts(&[HttpOk; 12], &control);

        let verdict = judge_reach(&sut);

        assert_eq!(verdict.severity, Severity::Ok, "{}", verdict.detail);
    }

    #[test]
    fn fewer_than_six_valid_probes_is_an_error() {
        // Control fails everywhere except 4 probes, too few to judge.
        let control = [
            HttpOk, HttpOk, HttpOk, HttpOk, Failed, Failed, Failed, Failed,
            Failed, Failed,
        ];
        let sut = facts(&[HttpOk; 10], &control);

        let verdict = judge_reach(&sut);

        assert_eq!(verdict.severity, Severity::Error, "{}", verdict.detail);
    }

    // Ten valid probes; 25% failing is the FAIL threshold, so three failures
    // (30%) fail and one (10%) only warns.
    #[rstest::rstest]
    #[case::all_reachable(0, Severity::Ok)]
    #[case::ten_percent_failing(1, Severity::Warn)]
    #[case::thirty_percent_failing(3, Severity::Fail)]
    fn the_share_of_valid_probes_the_candidate_fails_sets_the_severity(
        #[case] failed: usize,
        #[case] expected: Severity,
    ) {
        let candidate: Vec<HttpProbeOutcome> = (0..10)
            .map(|probe| if probe < failed { Failed } else { HttpOk })
            .collect();
        let sut = facts(&candidate, &[HttpOk; 10]);

        let verdict = judge_reach(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }
}
