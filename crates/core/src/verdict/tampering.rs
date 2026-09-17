use crate::model::{PortalOutcome, PortalProbe};
use crate::Verdict;

pub fn classify_portal(probe: &PortalProbe) -> PortalOutcome {
    match probe.actual_status {
        None => PortalOutcome::Unreachable,
        Some(status) if status == probe.expected_status && !probe.redirected => PortalOutcome::Ok,
        Some(_) => PortalOutcome::Altered,
    }
}

pub fn judge_tampering(https: &[PortalOutcome], http: &[PortalOutcome]) -> Verdict {
    let altered = https.iter().filter(|o| **o == PortalOutcome::Altered).count();
    if altered > 0 {
        return Verdict::fail(format!("{altered}/{} HTTPS connectivity checks were altered", https.len()));
    }
    let https_ok = https.iter().filter(|o| **o == PortalOutcome::Ok).count();
    let http_dead = http.iter().all(|o| *o == PortalOutcome::Unreachable);
    if http_dead && https_ok > 0 {
        return Verdict::fail("plain HTTP is unreachable while HTTPS is clean: the host blocks outbound HTTP");
    }
    let unreachable_https = https.iter().filter(|o| **o == PortalOutcome::Unreachable).count();
    if unreachable_https > 0 {
        return Verdict::warn(format!("{unreachable_https}/{} HTTPS connectivity checks got no answer", https.len()));
    }
    Verdict::ok(format!("{https_ok}/{} HTTPS connectivity checks clean", https.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn probe(expected: u16, actual: Option<u16>, redirected: bool) -> PortalProbe {
        PortalProbe { name: "google", expected_status: expected, actual_status: actual, redirected }
    }

    #[test]
    fn exact_status_no_redirect_is_ok() {
        assert_eq!(classify_portal(&probe(204, Some(204), false)), PortalOutcome::Ok);
    }

    #[test]
    fn no_response_is_unreachable() {
        assert_eq!(classify_portal(&probe(204, None, false)), PortalOutcome::Unreachable);
    }

    #[test]
    fn a_redirect_or_wrong_status_is_altered() {
        assert_eq!(classify_portal(&probe(204, Some(204), true)), PortalOutcome::Altered);
        assert_eq!(classify_portal(&probe(204, Some(200), false)), PortalOutcome::Altered);
    }

    #[test]
    fn any_altered_https_endpoint_fails() {
        let https = vec![PortalOutcome::Ok, PortalOutcome::Altered, PortalOutcome::Ok];
        let http = vec![PortalOutcome::Ok; 3];
        assert_eq!(judge_tampering(&https, &http).severity, Severity::Fail);
    }

    #[test]
    fn plain_http_dead_while_https_is_clean_fails_as_a_hoster_block() {
        let https = vec![PortalOutcome::Ok; 3];
        let http = vec![PortalOutcome::Unreachable; 3];
        let v = judge_tampering(&https, &http);
        assert_eq!(v.severity, Severity::Fail, "{}", v.detail);
        assert!(v.detail.contains("HTTP"), "{}", v.detail);
    }

    #[test]
    fn a_couple_of_unreachable_https_endpoints_only_warns() {
        let https = vec![PortalOutcome::Ok, PortalOutcome::Unreachable, PortalOutcome::Ok];
        let http = vec![PortalOutcome::Ok; 3];
        assert_eq!(judge_tampering(&https, &http).severity, Severity::Warn);
    }

    #[test]
    fn everything_clean_is_ok() {
        let clean = vec![PortalOutcome::Ok; 3];
        assert_eq!(judge_tampering(&clean, &clean).severity, Severity::Ok);
    }
}
