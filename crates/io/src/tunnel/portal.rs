use chip_core::model::PortalOutcome;
use chip_core::verdict::portal::{PortalChecks, PortalEndpoint};
use futures::future::join_all;

use super::client::TunnelClient;
use crate::error_chain::describe_error;

async fn probe(
    client: &TunnelClient,
    endpoint: &PortalEndpoint,
) -> PortalOutcome {
    let url = endpoint.url();
    match client.get(&url, &[]).await {
        Ok(response) => endpoint.classify(
            response.status,
            &response.final_url,
            &response.body,
        ),
        Err(error) => {
            tracing::debug!(
                url,
                error = %describe_error(&error),
                "portal endpoint unreachable"
            );
            PortalOutcome::Unreachable
        }
    }
}

/// Fetches every vendor-documented connectivity endpoint concurrently and
/// classifies each answer.
pub async fn probe_portal_endpoints(client: &TunnelClient) -> PortalChecks {
    let probes = PortalEndpoint::ALL.iter().map(|endpoint| async move {
        (endpoint.scheme(), probe(client, endpoint).await)
    });
    join_all(probes).await.into_iter().collect()
}
