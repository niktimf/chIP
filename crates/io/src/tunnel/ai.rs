use chip_core::model::ServiceState;
use chip_core::verdict::ai::classify_ai_endpoint;

use super::client::TunnelClient;

const API_UA: &str = concat!("chip/", env!("CARGO_PKG_VERSION"));
const OPENAI_REGION_MARKERS: &[&str] = &[
    "unsupported_country_region_territory",
    "country, region, or territory not supported",
];
const ANTHROPIC_REGION_MARKERS: &[&str] =
    &["request not allowed", "unsupported_country"];

async fn probe_one(
    client: &TunnelClient,
    url: &str,
    headers: &[(&str, &str)],
    region_markers: &[&str],
    auth_statuses: &[u16],
) -> ServiceState {
    match client.get(url, headers).await {
        Ok(response) => classify_ai_endpoint(
            response.status,
            &response.body,
            region_markers,
            auth_statuses,
        ),
        Err(error) => ServiceState::Unavailable(error.to_string()),
    }
}

pub async fn probe_ai_endpoints(
    client: &TunnelClient,
) -> Vec<(&'static str, ServiceState)> {
    let (openai, anthropic, gemini, deepseek) = tokio::join!(
        probe_one(
            client,
            "https://api.openai.com/v1/models",
            &[("User-Agent", API_UA)],
            OPENAI_REGION_MARKERS,
            &[401]
        ),
        probe_one(
            client,
            "https://api.anthropic.com/v1/models",
            &[("User-Agent", API_UA), ("anthropic-version", "2023-06-01")],
            ANTHROPIC_REGION_MARKERS,
            &[401]
        ),
        probe_one(
            client,
            "https://generativelanguage.googleapis.com/v1beta/models",
            &[("User-Agent", API_UA)],
            &[],
            &[401, 403]
        ),
        probe_one(
            client,
            "https://api.deepseek.com/models",
            &[("User-Agent", API_UA)],
            &[],
            &[401]
        )
    );
    vec![
        ("openai", openai),
        ("anthropic", anthropic),
        ("gemini", gemini),
        ("deepseek", deepseek),
    ]
}
