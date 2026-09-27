use chip_core::model::ServiceState;
use chip_core::verdict::ai::classify_ai_endpoint;
use http::header::USER_AGENT;
use http::{HeaderName, HeaderValue, StatusCode};

use super::client::TunnelClient;

const API_UA: HeaderValue = HeaderValue::from_static("curl/8.5.0");

/// Named `static`s rather than inline slices in the endpoint table:
/// `HeaderValue` carries an atomic refcount, so a borrowed temporary cannot
/// be promoted to `'static`.
static API_HEADERS: [(HeaderName, HeaderValue); 1] = [(USER_AGENT, API_UA)];
static ANTHROPIC_HEADERS: [(HeaderName, HeaderValue); 2] = [
    (USER_AGENT, API_UA),
    (
        HeaderName::from_static("anthropic-version"),
        HeaderValue::from_static("2023-06-01"),
    ),
];

/// One AI API as a probe target: where to ask, how to identify, and how to
/// read the answer.
struct AiEndpoint {
    url: &'static str,
    headers: &'static [(HeaderName, HeaderValue)],
    /// Body markers that mean a region refusal.
    region_markers: &'static [&'static str],
    /// Statuses that mean "reachable, just unauthenticated" for this API.
    auth_statuses: &'static [StatusCode],
}

impl AiEndpoint {
    async fn probe(&self, client: &TunnelClient) -> ServiceState {
        match client.get(self.url, self.headers).await {
            Ok(response) => classify_ai_endpoint(
                response.status,
                &response.body,
                self.region_markers,
                self.auth_statuses,
            ),
            Err(error) => ServiceState::Unavailable(error.to_string()),
        }
    }
}

static OPENAI: AiEndpoint = AiEndpoint {
    url: "https://api.openai.com/v1/models",
    headers: &API_HEADERS,
    region_markers: &[
        "unsupported_country_region_territory",
        "country, region, or territory not supported",
    ],
    auth_statuses: &[StatusCode::UNAUTHORIZED],
};

static ANTHROPIC: AiEndpoint = AiEndpoint {
    url: "https://api.anthropic.com/v1/models",
    headers: &ANTHROPIC_HEADERS,
    region_markers: &["request not allowed", "unsupported_country"],
    auth_statuses: &[StatusCode::UNAUTHORIZED],
};

static GEMINI: AiEndpoint = AiEndpoint {
    url: "https://generativelanguage.googleapis.com/v1beta/models",
    headers: &API_HEADERS,
    region_markers: &[],
    // This API refuses an anonymous caller with 403, not only 401.
    auth_statuses: &[StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN],
};

static DEEPSEEK: AiEndpoint = AiEndpoint {
    url: "https://api.deepseek.com/models",
    headers: &API_HEADERS,
    region_markers: &[],
    auth_statuses: &[StatusCode::UNAUTHORIZED],
};

/// One field per probed API, so an endpoint cannot be dropped, duplicated,
/// or attached to another endpoint's gate.
#[derive(Debug)]
pub struct AiEndpointStates {
    pub openai: ServiceState,
    pub anthropic: ServiceState,
    pub gemini: ServiceState,
    pub deepseek: ServiceState,
}

pub async fn probe_ai_endpoints(client: &TunnelClient) -> AiEndpointStates {
    let (openai, anthropic, gemini, deepseek) = tokio::join!(
        OPENAI.probe(client),
        ANTHROPIC.probe(client),
        GEMINI.probe(client),
        DEEPSEEK.probe(client)
    );
    AiEndpointStates {
        openai,
        anthropic,
        gemini,
        deepseek,
    }
}
