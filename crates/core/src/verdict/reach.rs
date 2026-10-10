use crate::Verdict;
use crate::model::{HttpProbeOutcome, ReachFacts};

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
    use crate::model::HttpProbeOutcome::{Failed, Ok as HttpOk};
    use crate::model::Severity;

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
