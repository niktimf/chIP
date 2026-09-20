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
    fn a_region_marker_in_the_body_blocks() {
        assert_eq!(
            classify_ai_endpoint(
                403,
                "This API is not available in your region",
                MARKERS,
                &[401]
            ),
            ServiceState::Blocked
        );
    }

    #[test]
    fn a_normal_success_is_available_even_with_an_auth_error_body() {
        assert_eq!(
            classify_ai_endpoint(401, "invalid api key", MARKERS, &[401]),
            ServiceState::Available
        );
    }

    #[test]
    fn judge_ai_endpoints_never_fails_only_warns_on_a_block() {
        let sut = [
            ("openai", ServiceState::Blocked),
            ("anthropic", ServiceState::Available),
        ];
        let verdict = judge_ai_endpoints(&sut);

        assert_eq!(verdict.severity, Severity::Warn);
    }

    #[test]
    fn judge_ai_endpoints_is_ok_when_nothing_is_blocked() {
        let sut = [("openai", ServiceState::Available)];

        assert_eq!(judge_ai_endpoints(&sut).severity, Severity::Ok);
    }

    #[test]
    fn an_unrecognized_api_response_is_a_warning() {
        let state = classify_ai_endpoint(500, "server error", MARKERS, &[401]);

        assert!(matches!(state, ServiceState::Error(_)));
        assert_eq!(
            judge_ai_endpoints(&[("openai", state)]).severity,
            Severity::Warn
        );
    }

    #[test]
    fn an_unreachable_endpoint_is_an_error() {
        let sut = [("openai", ServiceState::Unavailable("timeout".into()))];

        assert_eq!(judge_ai_endpoints(&sut).severity, Severity::Error);
    }
}
