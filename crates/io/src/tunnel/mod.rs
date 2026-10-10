mod ai;
mod client;
mod country_geo;
mod portal;
mod services;
mod warn_services;

pub use ai::{AiEndpointStates, probe_ai_endpoints};
pub use client::{TunnelClient, TunnelError, TunnelResponse};
pub use country_geo::{
    ServiceGeoObservations, probe_search_captcha, probe_service_geo,
};
pub use portal::probe_portal_endpoints;
pub use services::{
    probe_chatgpt_app, probe_chatgpt_web, probe_gemini, probe_youtube_premium,
};
pub use warn_services::{
    probe_claude, probe_netflix, probe_notebooklm, probe_tiktok,
};

use chip_core::checks::tunnel::ServiceState;
use http::header::{ACCEPT, ACCEPT_LANGUAGE, USER_AGENT};
use http::{HeaderName, HeaderValue};

use crate::error_chain::describe_error;

const BROWSER_UA: HeaderValue = HeaderValue::from_static(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
);
const ACCEPT_LANGUAGE_EN: HeaderValue =
    HeaderValue::from_static("en-US,en;q=0.9");
const ACCEPT_HTML: HeaderValue = HeaderValue::from_static(
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
);

// The header sets are named `static`s, not inline slices: `HeaderValue`
// carries an atomic refcount, so a borrowed temporary cannot be promoted to
// `'static`.

/// A browser user agent and nothing else.
static BROWSER_HEADERS: [(HeaderName, HeaderValue); 1] =
    [(USER_AGENT, BROWSER_UA)];
/// A browser user agent that asks for an English page.
static BROWSER_EN_HEADERS: [(HeaderName, HeaderValue); 2] = [
    (USER_AGENT, BROWSER_UA),
    (ACCEPT_LANGUAGE, ACCEPT_LANGUAGE_EN),
];
/// A browser user agent that asks for an English HTML page.
static BROWSER_HTML_HEADERS: [(HeaderName, HeaderValue); 3] = [
    (USER_AGENT, BROWSER_UA),
    (ACCEPT, ACCEPT_HTML),
    (ACCEPT_LANGUAGE, ACCEPT_LANGUAGE_EN),
];

/// A service whose page could not be fetched through the tunnel.
fn unavailable(error: &TunnelError) -> ServiceState {
    ServiceState::Unavailable(describe_error(error))
}

/// Fetches `url` through the tunnel and classifies the response; a transport
/// failure becomes `ServiceState::Unavailable` with its cause.
async fn fetch_state(
    client: &TunnelClient,
    url: &str,
    headers: &[(HeaderName, HeaderValue)],
    classify: impl FnOnce(TunnelResponse) -> ServiceState,
) -> ServiceState {
    match client.get(url, headers).await {
        Ok(response) => classify(response),
        Err(error) => unavailable(&error),
    }
}

/// One service page as a probe target: where to ask, which headers to send,
/// and how to read the answer.
struct ServicePage<'a> {
    url: &'a str,
    headers: &'static [(HeaderName, HeaderValue)],
    classify: fn(TunnelResponse) -> ServiceState,
}

impl ServicePage<'_> {
    async fn probe(&self, client: &TunnelClient) -> ServiceState {
        fetch_state(client, self.url, self.headers, self.classify).await
    }
}
