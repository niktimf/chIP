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

use crate::error_chain::describe_error;

/// A service whose page could not be fetched through the tunnel.
fn unavailable(error: &TunnelError) -> ServiceState {
    ServiceState::Unavailable(describe_error(error))
}
