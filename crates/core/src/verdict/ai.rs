use crate::model::ServiceState;
use crate::Verdict;

/// Reachability probes hit a models-list or similar authenticated endpoint,
/// so a 401/403 with no region marker means "reachable, just unauthenticated"
/// — the opposite of `verdict::services`, where 403 needs a region page to
/// count as a refusal at all. AI endpoints answer a plain unsupported-region
/// error even to anonymous requests, so no such page is required here.
pub fn classify_ai_endpoint(_status: u16, body: &str, region_markers: &[&str]) -> ServiceState {
    let lower = body.to_lowercase();
    if region_markers.iter().any(|m| lower.contains(&m.to_lowercase())) {
        ServiceState::Blocked
    } else {
        ServiceState::Available
    }
}

pub fn judge_ai_endpoints(states: &[(&str, ServiceState)]) -> Verdict {
    let blocked: Vec<&str> = states.iter().filter(|(_, s)| *s == ServiceState::Blocked).map(|(n, _)| *n).collect();
    if blocked.is_empty() {
        Verdict::ok(format!("reachable: {}", states.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")))
    } else {
        Verdict::warn(format!("region-refused: {}", blocked.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ServiceState, Severity};

    const MARKERS: &[&str] = &["is not available in your", "unsupported_country"];

    #[test]
    fn a_region_marker_in_the_body_blocks() {
        assert_eq!(classify_ai_endpoint(403, "This API is not available in your region", MARKERS), ServiceState::Blocked);
    }

    #[test]
    fn a_normal_success_is_available_even_with_an_auth_error_body() {
        assert_eq!(classify_ai_endpoint(401, "invalid api key", MARKERS), ServiceState::Available);
    }

    #[test]
    fn judge_ai_endpoints_never_fails_only_warns_on_a_block() {
        let states = [("openai", ServiceState::Blocked), ("anthropic", ServiceState::Available)];
        let v = judge_ai_endpoints(&states);
        assert_eq!(v.severity, Severity::Warn);
    }

    #[test]
    fn judge_ai_endpoints_is_ok_when_nothing_is_blocked() {
        let states = [("openai", ServiceState::Available), ("anthropic", ServiceState::Error("timeout".into()))];
        assert_eq!(judge_ai_endpoints(&states).severity, Severity::Ok);
    }
}
