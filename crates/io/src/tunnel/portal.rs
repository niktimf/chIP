use chip_core::model::PortalOutcome;

use super::client::TunnelClient;

#[derive(Debug, Clone, Copy)]
struct PortalEndpoint {
    url: &'static str,
    expected_status: u16,
    expected_body: Option<&'static str>,
}

const PORTAL_ENDPOINTS: &[PortalEndpoint] = &[
    PortalEndpoint {
        url: "http://connectivitycheck.gstatic.com/generate_204",
        expected_status: 204,
        expected_body: Some(""),
    },
    PortalEndpoint {
        url: "http://cp.cloudflare.com/generate_204",
        expected_status: 204,
        expected_body: Some(""),
    },
    PortalEndpoint {
        url: "http://captive.apple.com/hotspot-detect.html",
        expected_status: 200,
        expected_body: Some(
            "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
        ),
    },
    PortalEndpoint {
        url: "http://www.msftconnecttest.com/connecttest.txt",
        expected_status: 200,
        expected_body: Some("Microsoft Connect Test"),
    },
    PortalEndpoint {
        url: "http://detectportal.firefox.com/success.txt",
        expected_status: 200,
        expected_body: Some("success"),
    },
    PortalEndpoint {
        url: "https://connectivitycheck.gstatic.com/generate_204",
        expected_status: 204,
        expected_body: Some(""),
    },
    PortalEndpoint {
        url: "https://cp.cloudflare.com/generate_204",
        expected_status: 204,
        expected_body: Some(""),
    },
];

async fn probe_at(
    client: &TunnelClient,
    url: &str,
    expected_status: u16,
    expected_body: Option<&str>,
) -> PortalOutcome {
    let Ok(response) = client.get(url, &[]).await else {
        return PortalOutcome::Unreachable;
    };
    let body_matches = expected_body
        .is_none_or(|expected| response.body.trim() == expected.trim());
    let final_url_matches = reqwest::Url::parse(url)
        .is_ok_and(|expected| response.final_url == expected);
    if response.status == expected_status && final_url_matches && body_matches {
        PortalOutcome::Ok
    } else {
        PortalOutcome::Altered
    }
}

/// Returns `(https, http)` outcomes for the vendor-documented connectivity
/// endpoints. Requests are concurrent and every task is joined.
pub async fn probe_portal_endpoints(
    client: &TunnelClient,
) -> (Vec<PortalOutcome>, Vec<PortalOutcome>) {
    let mut tasks = tokio::task::JoinSet::new();
    for (index, endpoint) in PORTAL_ENDPOINTS.iter().copied().enumerate() {
        let client = client.clone();
        tasks.spawn(async move {
            let outcome = probe_at(
                &client,
                endpoint.url,
                endpoint.expected_status,
                endpoint.expected_body,
            )
            .await;
            (index, endpoint.url.starts_with("https://"), outcome)
        });
    }

    let mut rows = Vec::with_capacity(PORTAL_ENDPOINTS.len());
    while let Some(result) = tasks.join_next().await {
        if let Ok(row) = result {
            rows.push(row);
        }
    }
    rows.sort_by_key(|(index, _, _)| *index);
    let (https, http): (Vec<_>, Vec<_>) =
        rows.into_iter().partition(|(_, is_https, _)| *is_https);
    (
        https.into_iter().map(|(_, _, outcome)| outcome).collect(),
        http.into_iter().map(|(_, _, outcome)| outcome).collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn exact_response_is_ok_and_wrong_body_is_altered() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("expected"),
            )
            .mount(&server)
            .await;
        let client = TunnelClient::from_client(reqwest::Client::new());

        assert_eq!(
            probe_at(&client, &server.uri(), 200, Some("expected")).await,
            PortalOutcome::Ok
        );
        assert_eq!(
            probe_at(&client, &server.uri(), 200, Some("different")).await,
            PortalOutcome::Altered
        );
    }
}
