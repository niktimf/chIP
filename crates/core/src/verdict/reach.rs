use crate::Verdict;
use crate::model::{HttpProbeOutcome, ReachFacts};

const FAIL_SHARE: f64 = 0.25;
const MIN_VALID_PROBES: usize = 6;

pub fn judge_reach(facts: &ReachFacts) -> Verdict {
    let valid = facts
        .probes
        .iter()
        .filter(|probe| probe.control == HttpProbeOutcome::Ok)
        .count();
    if valid < MIN_VALID_PROBES {
        return Verdict::error(format!(
            "only {valid} of {} probes had a working control anchor (need >= {MIN_VALID_PROBES})",
            facts.probes.len()
        ));
    }
    let failed = facts
        .probes
        .iter()
        .filter(|probe| probe.control == HttpProbeOutcome::Ok)
        .filter(|probe| probe.candidate == HttpProbeOutcome::Failed)
        .count();
    #[allow(clippy::cast_precision_loss)]
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
    use crate::model::{ReachProbe, Severity};

    fn facts(candidate: &[bool], control: &[bool]) -> ReachFacts {
        // true = Ok, false = Failed, for readability in each test.
        ReachFacts {
            probes: candidate
                .iter()
                .zip(control)
                .map(|(&candidate_ok, &control_ok)| ReachProbe {
                    candidate: if candidate_ok { HttpOk } else { Failed },
                    control: if control_ok { HttpOk } else { Failed },
                })
                .collect(),
        }
    }

    #[test]
    fn all_reachable_is_ok() {
        let sut = facts(&[true; 10], &[true; 10]);

        assert_eq!(judge_reach(&sut).severity, Severity::Ok);
    }

    #[test]
    fn a_probe_where_the_control_itself_failed_does_not_count_against_the_candidate()
     {
        // Control fails on probes 0-1 (excluded); of the remaining 10, candidate fails none.
        let candidate = vec![true; 12];
        let mut control = vec![true; 12];
        control[0] = false;
        control[1] = false;
        let sut = facts(&candidate, &control);

        let verdict = judge_reach(&sut);

        assert_eq!(verdict.severity, Severity::Ok, "{}", verdict.detail);
    }

    #[test]
    fn thirty_percent_of_valid_probes_failing_fails() {
        // 10 valid probes, candidate fails 3 of them (30% >= 25% threshold).
        let mut candidate = vec![true; 10];
        candidate[0] = false;
        candidate[1] = false;
        candidate[2] = false;
        let sut = facts(&candidate, &[true; 10]);

        let verdict = judge_reach(&sut);

        assert_eq!(verdict.severity, Severity::Fail, "{}", verdict.detail);
    }

    #[test]
    fn ten_percent_of_valid_probes_failing_warns() {
        let mut candidate = vec![true; 10];
        candidate[0] = false;
        let sut = facts(&candidate, &[true; 10]);

        let verdict = judge_reach(&sut);

        assert_eq!(verdict.severity, Severity::Warn, "{}", verdict.detail);
    }

    #[test]
    fn fewer_than_six_valid_probes_is_an_error() {
        // Control fails everywhere except 4 probes — too few to judge.
        let mut control = vec![false; 10];
        control[0] = true;
        control[1] = true;
        control[2] = true;
        control[3] = true;
        let sut = facts(&[true; 10], &control);

        let verdict = judge_reach(&sut);

        assert_eq!(verdict.severity, Severity::Error, "{}", verdict.detail);
    }
}
