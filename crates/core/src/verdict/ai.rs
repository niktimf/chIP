use crate::Verdict;
use crate::model::ServiceState;
use crate::verdict::services::{
    CLOUDFLARE_CHALLENGED, is_cloudflare_challenge,
};
use http::StatusCode;

/// An AI API whose reachability the `ai:*` gates probe. The variant carries
/// what the answer means; the shell keeps the URL and headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiProvider {
    OpenAi,
    Anthropic,
    Gemini,
    DeepSeek,
}

impl AiProvider {
    /// Body markers of this API's region refusal.
    const fn region_markers(self) -> &'static [&'static str] {
        match self {
            Self::OpenAi => &[
                "unsupported_country_region_territory",
                "country, region, or territory not supported",
            ],
            Self::Anthropic => &["request not allowed", "unsupported_country"],
            Self::Gemini | Self::DeepSeek => &[],
        }
    }

    /// Statuses that mean "reachable, just unauthenticated" for this API.
    const fn auth_statuses(self) -> &'static [StatusCode] {
        match self {
            Self::OpenAi | Self::Anthropic | Self::DeepSeek => {
                &[StatusCode::UNAUTHORIZED]
            }
            // This API refuses an anonymous caller with 403, not only 401.
            Self::Gemini => &[StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN],
        }
    }
}

/// Classifies the answer of one AI API's models-list endpoint.
///
/// Reachability probes hit a models-list or similar authenticated endpoint,
/// so a 401/403 with no region marker means "reachable, just
/// unauthenticated" — the opposite of `verdict::services`, where 403 needs a
/// region page to count as a refusal at all. AI endpoints answer a plain
/// unsupported-region error even to anonymous requests, so no such page is
/// required here.
pub fn classify_ai_endpoint(
    provider: AiProvider,
    status: StatusCode,
    body: &str,
) -> ServiceState {
    if is_cloudflare_challenge(status, body) {
        return ServiceState::Inconclusive(CLOUDFLARE_CHALLENGED.into());
    }
    let lower = body.to_lowercase();
    if provider
        .region_markers()
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return ServiceState::Blocked;
    }
    if provider.auth_statuses().contains(&status) || status.is_success() {
        ServiceState::Available
    } else {
        ServiceState::Inconclusive(format!("unexpected HTTP {status}"))
    }
}

/// Judges one AI API endpoint (`ai:*` gate). A region refusal only warns:
/// the exit is for people, the API check is advisory.
pub fn judge_ai_endpoint(state: &ServiceState) -> Verdict {
    match state {
        ServiceState::Available => Verdict::ok("reachable"),
        ServiceState::Restricted => Verdict::warn("restricted"),
        ServiceState::Blocked => Verdict::warn("region-refused"),
        ServiceState::Inconclusive(reason) => {
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

    #[test]
    fn an_unrecognized_api_response_cannot_be_classified() {
        let state = classify_ai_endpoint(
            AiProvider::OpenAi,
            StatusCode::INTERNAL_SERVER_ERROR,
            "server error",
        );

        assert_eq!(
            state,
            ServiceState::Inconclusive(
                "unexpected HTTP 500 Internal Server Error".into()
            )
        );
    }

    #[rstest::rstest]
    #[case::openai_region_marker_blocks(
        AiProvider::OpenAi,
        StatusCode::FORBIDDEN,
        "{\"code\": \"unsupported_country_region_territory\"}",
        ServiceState::Blocked
    )]
    #[case::anthropic_region_marker_in_any_case_blocks(
        AiProvider::Anthropic,
        StatusCode::FORBIDDEN,
        "Request not allowed",
        ServiceState::Blocked
    )]
    #[case::auth_error_is_a_normal_success(
        AiProvider::OpenAi,
        StatusCode::UNAUTHORIZED,
        "invalid api key",
        ServiceState::Available
    )]
    #[case::gemini_answers_an_anonymous_caller_with_403(
        AiProvider::Gemini,
        StatusCode::FORBIDDEN,
        "method doesn't allow unregistered callers",
        ServiceState::Available
    )]
    #[case::a_403_from_another_api_is_not_an_auth_error(
        AiProvider::DeepSeek,
        StatusCode::FORBIDDEN,
        "forbidden",
        ServiceState::Inconclusive("unexpected HTTP 403 Forbidden".into())
    )]
    #[case::a_cloudflare_challenge_is_inconclusive(
        AiProvider::Gemini,
        StatusCode::FORBIDDEN,
        "Checking your browser before accessing",
        ServiceState::Inconclusive("Cloudflare challenged the request".into())
    )]
    fn an_endpoint_is_classified_by_provider_status_and_body(
        #[case] provider: AiProvider,
        #[case] status: StatusCode,
        #[case] sut: &str,
        #[case] expected: ServiceState,
    ) {
        let actual = classify_ai_endpoint(provider, status, sut);

        assert_eq!(actual, expected);
    }

    #[rstest::rstest]
    #[case::reachable(ServiceState::Available, Severity::Ok)]
    #[case::a_block_only_warns_never_fails(
        ServiceState::Blocked,
        Severity::Warn
    )]
    #[case::an_unclassified_response_only_warns(
        ServiceState::Inconclusive("unexpected HTTP 500".into()),
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
