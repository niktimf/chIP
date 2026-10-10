use chip_core::checks::tunnel::ServiceState;
use chip_core::checks::tunnel::ai::{AiProvider, classify_ai_endpoint};
use http::header::USER_AGENT;
use http::{HeaderName, HeaderValue};

use super::client::TunnelClient;
use super::fetch_state;

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

/// One AI API as a probe target: where to ask and how to identify. How to
/// read the answer is the provider's rule in core.
struct AiEndpoint {
    provider: AiProvider,
    url: &'static str,
    headers: &'static [(HeaderName, HeaderValue)],
}

impl AiEndpoint {
    async fn probe(&self, client: &TunnelClient) -> ServiceState {
        fetch_state(client, self.url, self.headers, |response| {
            classify_ai_endpoint(self.provider, response.status, &response.body)
        })
        .await
    }
}

static OPENAI: AiEndpoint = AiEndpoint {
    provider: AiProvider::OpenAi,
    url: "https://api.openai.com/v1/models",
    headers: &API_HEADERS,
};

static ANTHROPIC: AiEndpoint = AiEndpoint {
    provider: AiProvider::Anthropic,
    url: "https://api.anthropic.com/v1/models",
    headers: &ANTHROPIC_HEADERS,
};

static GEMINI: AiEndpoint = AiEndpoint {
    provider: AiProvider::Gemini,
    url: "https://generativelanguage.googleapis.com/v1beta/models",
    headers: &API_HEADERS,
};

static DEEPSEEK: AiEndpoint = AiEndpoint {
    provider: AiProvider::DeepSeek,
    url: "https://api.deepseek.com/models",
    headers: &API_HEADERS,
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
