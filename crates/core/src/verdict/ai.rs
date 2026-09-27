use crate::Verdict;
use crate::model::ServiceState;
use http::StatusCode;

/// Reachability probes hit a models-list or similar authenticated endpoint,
/// so a 401/403 with no region marker means "reachable, just unauthenticated"
///
/// — the opposite of `verdict::services`, where 403 needs a region page to
/// count as a refusal at all. AI endpoints answer a plain unsupported-region
/// error even to anonymous requests, so no such page is required here.
pub fn classify_ai_endpoint(
    status: StatusCode,
    body: &str,
    region_markers: &[&str],
    auth_statuses: &[StatusCode],
) -> ServiceState {
    let lower = body.to_lowercase();
    if [
        StatusCode::FORBIDDEN,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::SERVICE_UNAVAILABLE,
    ]
    .contains(&status)
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
    if auth_statuses.contains(&status) || status.is_success() {
        ServiceState::Available
    } else {
        ServiceState::Error(format!("unexpected HTTP {status}"))
    }
}

/// Judges one AI API endpoint (`ai:*` gate). A region refusal only warns:
/// the exit is for people, the API check is advisory.
pub fn judge_ai_endpoint(state: &ServiceState) -> Verdict {
    match state {
        ServiceState::Available => Verdict::ok("reachable"),
        ServiceState::Restricted => Verdict::warn("restricted"),
        ServiceState::Blocked => Verdict::warn("region-refused"),
        ServiceState::Error(reason) => {
            Verdict::warn(format!("could not be judged: {reason}"))
        }
        ServiceState::Unavailable(reason) => {
            Verdict::error(format!("unavailable: {reason}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ServiceState, Severity};

    const MARKERS: &[&str] =
        &["is not available in your", "unsupported_country"];
    const AUTH_STATUSES: &[StatusCode] = &[StatusCode::UNAUTHORIZED];

    #[test]
    fn an_unrecognized_api_response_is_a_warning() {
        let state = classify_ai_endpoint(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server error",
            MARKERS,
            AUTH_STATUSES,
        );

        assert!(matches!(state, ServiceState::Error(_)));
        assert_eq!(judge_ai_endpoint(&state).severity, Severity::Warn);
    }

    #[rstest::rstest]
    #[case::region_marker_blocks(
        StatusCode::FORBIDDEN,
        "This API is not available in your region",
        ServiceState::Blocked
    )]
    #[case::auth_error_is_a_normal_success(
        StatusCode::UNAUTHORIZED,
        "invalid api key",
        ServiceState::Available
    )]
    fn an_endpoint_is_classified_by_status_and_body(
        #[case] status: StatusCode,
        #[case] sut: &str,
        #[case] expected: ServiceState,
    ) {
        let actual = classify_ai_endpoint(status, sut, MARKERS, AUTH_STATUSES);

        assert_eq!(actual, expected);
    }

    #[rstest::rstest]
    #[case::reachable(ServiceState::Available, Severity::Ok)]
    #[case::a_block_only_warns_never_fails(
        ServiceState::Blocked,
        Severity::Warn
    )]
    #[case::unreachable_is_an_error(
        ServiceState::Unavailable("timeout".into()),
        Severity::Error
    )]
    fn an_endpoint_is_judged_by_its_state(
        #[case] sut: ServiceState,
        #[case] expected: Severity,
    ) {
        let verdict = judge_ai_endpoint(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }
}
