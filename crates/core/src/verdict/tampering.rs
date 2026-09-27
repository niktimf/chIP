use crate::Verdict;
use crate::model::PortalOutcome;

pub fn judge_tampering(
    https: &[PortalOutcome],
    http: &[PortalOutcome],
) -> Verdict {
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
    let https_ok = https.iter().filter(|o| **o == PortalOutcome::Ok).count();
    let http_dead = http.iter().all(|o| *o == PortalOutcome::Unreachable);
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
    use crate::model::Severity;

    #[test]
    fn plain_http_dead_while_https_is_clean_fails_as_a_hoster_block() {
        let https = vec![PortalOutcome::Ok; 3];
        let http = vec![PortalOutcome::Unreachable; 3];
        let v = judge_tampering(&https, &http);
        assert_eq!(v.severity, Severity::Fail, "{}", v.detail);
        assert!(v.detail.contains("HTTP"), "{}", v.detail);
    }

    #[rstest::rstest]
    #[case::everything_clean(
        (vec![PortalOutcome::Ok; 3], vec![PortalOutcome::Ok; 3]),
        Severity::Ok
    )]
    #[case::any_altered_https_endpoint(
        (
            vec![PortalOutcome::Ok, PortalOutcome::Altered, PortalOutcome::Ok],
            vec![PortalOutcome::Ok; 3],
        ),
        Severity::Fail
    )]
    #[case::an_altered_plain_http_endpoint(
        (vec![PortalOutcome::Ok], vec![PortalOutcome::Altered]),
        Severity::Fail
    )]
    #[case::a_couple_of_unreachable_https_endpoints_only_warn(
        (
            vec![
                PortalOutcome::Ok,
                PortalOutcome::Unreachable,
                PortalOutcome::Ok,
            ],
            vec![PortalOutcome::Ok; 3],
        ),
        Severity::Warn
    )]
    fn portal_outcomes_set_the_severity(
        #[case] sut: (Vec<PortalOutcome>, Vec<PortalOutcome>),
        #[case] expected: Severity,
    ) {
        let (https, http) = sut;

        let verdict = judge_tampering(&https, &http);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }
}
