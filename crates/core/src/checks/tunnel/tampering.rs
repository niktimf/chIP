use crate::checks::tunnel::portal::{PortalChecks, PortalOutcome};
use crate::report::Verdict;

pub fn judge_tampering(checks: &PortalChecks) -> Verdict {
    let PortalChecks { https, http } = checks;
    let altered = https
        .iter()
        .chain(http)
        .filter(|outcome| **outcome == PortalOutcome::Altered)
        .count();
    if altered > 0 {
        return Verdict::fail(format!(
            "{altered} connectivity checks were altered"
        ));
    }
    if https.is_empty() {
        return Verdict::error("no HTTPS connectivity check ran");
    }
    let https_ok = https.iter().filter(|o| **o == PortalOutcome::Ok).count();
    // With no plain HTTP probe at all there is no evidence of a block.
    let http_dead = !http.is_empty()
        && http.iter().all(|o| *o == PortalOutcome::Unreachable);
    if http_dead && https_ok > 0 {
        return Verdict::fail(
            "plain HTTP is unreachable while HTTPS is clean: the host blocks outbound HTTP",
        );
    }
    let unreachable_https = https
        .iter()
        .filter(|o| **o == PortalOutcome::Unreachable)
        .count();
    if unreachable_https > 0 {
        return Verdict::warn(format!(
            "{unreachable_https}/{} HTTPS connectivity checks got no answer",
            https.len()
        ));
    }
    Verdict::ok(format!(
        "{https_ok}/{} HTTPS connectivity checks clean",
        https.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Severity;

    #[test]
    fn plain_http_dead_while_https_is_clean_fails_as_a_hoster_block() {
        let sut = PortalChecks {
            https: vec![PortalOutcome::Ok; 3],
            http: vec![PortalOutcome::Unreachable; 3],
        };

        let verdict = judge_tampering(&sut);

        assert_eq!(verdict.severity, Severity::Fail, "{}", verdict.detail);
        assert!(verdict.detail.contains("HTTP"), "{}", verdict.detail);
    }

    #[test]
    fn no_plain_http_probes_are_no_evidence_of_an_http_block() {
        let sut = PortalChecks {
            https: vec![PortalOutcome::Ok; 3],
            http: Vec::new(),
        };

        let verdict = judge_tampering(&sut);

        assert_eq!(verdict.severity, Severity::Ok, "{}", verdict.detail);
    }

    #[rstest::rstest]
    #[case::no_probes_at_all(Vec::new())]
    #[case::only_clean_plain_http_probes(vec![PortalOutcome::Ok; 3])]
    #[case::only_unreachable_plain_http_probes(
        vec![PortalOutcome::Unreachable; 3]
    )]
    fn without_https_probes_there_is_no_verdict(
        #[case] http: Vec<PortalOutcome>,
    ) {
        let sut = PortalChecks {
            https: Vec::new(),
            http,
        };

        let verdict = judge_tampering(&sut);

        assert_eq!(verdict.severity, Severity::Error, "{}", verdict.detail);
        assert_eq!(verdict.detail, "no HTTPS connectivity check ran");
    }

    #[test]
    fn an_altered_plain_http_probe_fails_even_without_https_probes() {
        let sut = PortalChecks {
            https: Vec::new(),
            http: vec![PortalOutcome::Altered],
        };

        let verdict = judge_tampering(&sut);

        assert_eq!(verdict.severity, Severity::Fail, "{}", verdict.detail);
    }

    #[rstest::rstest]
    #[case::everything_clean(
        PortalChecks {
            https: vec![PortalOutcome::Ok; 3],
            http: vec![PortalOutcome::Ok; 3],
        },
        Severity::Ok
    )]
    #[case::any_altered_https_endpoint(
        PortalChecks {
            https: vec![
                PortalOutcome::Ok,
                PortalOutcome::Altered,
                PortalOutcome::Ok,
            ],
            http: vec![PortalOutcome::Ok; 3],
        },
        Severity::Fail
    )]
    #[case::an_altered_plain_http_endpoint(
        PortalChecks {
            https: vec![PortalOutcome::Ok],
            http: vec![PortalOutcome::Altered],
        },
        Severity::Fail
    )]
    #[case::a_couple_of_unreachable_https_endpoints_only_warn(
        PortalChecks {
            https: vec![
                PortalOutcome::Ok,
                PortalOutcome::Unreachable,
                PortalOutcome::Ok,
            ],
            http: vec![PortalOutcome::Ok; 3],
        },
        Severity::Warn
    )]
    fn portal_outcomes_set_the_severity(
        #[case] sut: PortalChecks,
        #[case] expected: Severity,
    ) {
        let verdict = judge_tampering(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }
}
