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

use chip_core::model::ServiceState;
use itertools::Itertools as _;

/// Renders an error with every `source()` below it, joined by `": "`.
///
/// `reqwest::Error` prints only its own layer ("error sending request"), so
/// the cause (refused, timed out, SOCKS failure) is reachable only through
/// the source chain.
fn describe_error(error: &dyn std::error::Error) -> String {
    std::iter::successors(Some(error), |current| current.source()).join(": ")
}

/// A service whose page could not be fetched through the tunnel.
fn unavailable(error: &TunnelError) -> ServiceState {
    ServiceState::Unavailable(describe_error(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("GET https://example.test/ failed")]
    struct Outer(#[source] Middle);

    #[derive(Debug, thiserror::Error)]
    #[error("client error (Connect)")]
    struct Middle(#[source] std::io::Error);

    #[test]
    fn an_error_description_names_every_cause_in_the_chain() {
        let error = Outer(Middle(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Connection refused",
        )));

        let description = describe_error(&error);

        assert_eq!(
            description,
            "GET https://example.test/ failed: client error (Connect): \
             Connection refused"
        );
    }
}
