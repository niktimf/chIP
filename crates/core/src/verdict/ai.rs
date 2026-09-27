use crate::Verdict;
use crate::model::ServiceState;

/// Reachability probes hit a models-list or similar authenticated endpoint,
/// so a 401/403 with no region marker means "reachable, just unauthenticated"
///
/// — the opposite of `verdict::services`, where 403 needs a region page to
/// count as a refusal at all. AI endpoints answer a plain unsupported-region
/// error even to anonymous requests, so no such page is required here.
pub fn classify_ai_endpoint(
    status: u16,
    body: &str,
    region_markers: &[&str],
    auth_statuses: &[u16],
) -> ServiceState {
    let lower = body.to_lowercase();
    if matches!(status, 403 | 429 | 503)
        && [
            "cf_chl_opt",
            "_cf_chl",
            "just a moment",
            "cf-browser-verification",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return ServiceState::Error(
            "challenged before reaching the API".into(),
        );
    }
    if region_markers
        .iter()
        .any(|m| lower.contains(&m.to_lowercase()))
    {
        return ServiceState::Blocked;
    }
    if auth_statuses.contains(&status) || (200..300).contains(&status) {
        ServiceState::Available
    } else {
        ServiceState::Error(format!("unexpected HTTP {status}"))
    }
}

pub fn judge_ai_endpoints(states: &[(&str, ServiceState)]) -> Verdict {
    let unavailable: Vec<&str> = states
        .iter()
        .filter(|(_, state)| matches!(state, ServiceState::Unavailable(_)))
        .map(|(name, _)| *name)
        .collect();
    if !unavailable.is_empty() {
        return Verdict::error(format!(
            "unavailable: {}",
            unavailable.join(", ")
        ));
    }
    let inconclusive: Vec<&str> = states
        .iter()
        .filter(|(_, state)| matches!(state, ServiceState::Error(_)))
        .map(|(name, _)| *name)
        .collect();
    if !inconclusive.is_empty() {
        return Verdict::warn(format!(
            "could not be judged: {}",
            inconclusive.join(", ")
        ));
    }
    let blocked: Vec<&str> = states
        .iter()
        .filter(|(_, s)| *s == ServiceState::Blocked)
        .map(|(n, _)| *n)
        .collect();
    if blocked.is_empty() {
        Verdict::ok(format!(
            "reachable: {}",
            states
                .iter()
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    } else {
        Verdict::warn(format!("region-refused: {}", blocked.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ServiceState, Severity};

    const MARKERS: &[&str] =
        &["is not available in your", "unsupported_country"];

    #[test]
    fn an_unrecognized_api_response_is_a_warning() {
        let state = classify_ai_endpoint(500, "server error", MARKERS, &[401]);

        assert!(matches!(state, ServiceState::Error(_)));
        assert_eq!(
            judge_ai_endpoints(&[("openai", state)]).severity,
            Severity::Warn
        );
    }

    #[rstest::rstest]
    #[case::region_marker_blocks(
        403,
        "This API is not available in your region",
        ServiceState::Blocked
    )]
    #[case::auth_error_is_a_normal_success(
        401,
        "invalid api key",
        ServiceState::Available
    )]
    fn an_endpoint_is_classified_by_status_and_body(
        #[case] status: u16,
        #[case] sut: &str,
        #[case] expected: ServiceState,
    ) {
        let actual = classify_ai_endpoint(status, sut, MARKERS, &[401]);

        assert_eq!(actual, expected);
    }

    #[rstest::rstest]
    #[case::nothing_blocked(
        vec![("openai", ServiceState::Available)],
        Severity::Ok
    )]
    #[case::a_block_only_warns_never_fails(
        vec![
            ("openai", ServiceState::Blocked),
            ("anthropic", ServiceState::Available),
        ],
        Severity::Warn
    )]
    #[case::unreachable_is_an_error(
        vec![("openai", ServiceState::Unavailable("timeout".into()))],
        Severity::Error
    )]
    fn endpoints_are_judged_by_the_worst_state(
        #[case] sut: Vec<(&'static str, ServiceState)>,
        #[case] expected: Severity,
    ) {
        let verdict = judge_ai_endpoints(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }
}
