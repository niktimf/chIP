use chip_core::model::ServiceState;
use chip_core::verdict::services::{
    classify_claude, classify_netflix, classify_notebooklm, classify_tiktok,
    claude_unavailable_markers,
};

use super::client::TunnelClient;
use super::services::BROWSER_UA;

const NETFLIX_LICENSED_TITLE: &str = "70143836";
const NETFLIX_ORIGINAL_TITLE: &str = "80197526";

fn unavailable(error: impl std::fmt::Display) -> ServiceState {
    ServiceState::Unavailable(error.to_string())
}

async fn probe_netflix_at(
    client: &TunnelClient,
    base_url: &str,
) -> ServiceState {
    let licensed_url = format!("{base_url}/title/{NETFLIX_LICENSED_TITLE}");
    let original_url = format!("{base_url}/title/{NETFLIX_ORIGINAL_TITLE}");
    let (licensed, original) = tokio::join!(
        client.get(&licensed_url, &[("User-Agent", BROWSER_UA)]),
        client.get(&original_url, &[("User-Agent", BROWSER_UA)])
    );
    match (licensed, original) {
        (Ok(licensed), Ok(original)) => classify_netflix(
            licensed.status,
            &licensed.body,
            original.status,
            &original.body,
        ),
        (Err(error), _) | (_, Err(error)) => unavailable(error),
    }
}

pub async fn probe_netflix(client: &TunnelClient) -> ServiceState {
    probe_netflix_at(client, "https://www.netflix.com").await
}

async fn probe_claude_at(client: &TunnelClient, url: &str) -> ServiceState {
    match client
        .get(
            url,
            &[
                ("User-Agent", BROWSER_UA),
                (
                    "Accept",
                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                ),
                ("Accept-Language", "en-US,en;q=0.9"),
                ("Sec-Fetch-Dest", "document"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Sec-Fetch-Site", "none"),
                ("Sec-Fetch-User", "?1"),
                ("Upgrade-Insecure-Requests", "1"),
            ],
        )
        .await
    {
        Ok(response) => classify_claude(
            response.status,
            &response.body,
            claude_unavailable_markers(),
        ),
        Err(error) => unavailable(error),
    }
}

pub async fn probe_claude(client: &TunnelClient) -> ServiceState {
    probe_claude_at(client, "https://claude.ai/").await
}

async fn probe_tiktok_at(client: &TunnelClient, url: &str) -> ServiceState {
    match client
        .get(
            url,
            &[
                ("User-Agent", BROWSER_UA),
                (
                    "Accept",
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                ),
                ("Accept-Language", "en-US,en;q=0.9"),
            ],
        )
        .await
    {
        Ok(response) => classify_tiktok(response.status, &response.body),
        Err(error) => unavailable(error),
    }
}

pub async fn probe_tiktok(client: &TunnelClient) -> ServiceState {
    probe_tiktok_at(client, "https://www.tiktok.com/").await
}

async fn probe_notebooklm_at(client: &TunnelClient, url: &str) -> ServiceState {
    match client
        .get(
            url,
            &[
                ("User-Agent", BROWSER_UA),
                (
                    "Accept",
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                ),
                ("Accept-Language", "en-US,en;q=0.9"),
            ],
        )
        .await
    {
        Ok(response) => classify_notebooklm(
            response.status,
            &response.final_url,
            &response.body,
        ),
        Err(error) => unavailable(error),
    }
}

pub async fn probe_notebooklm(client: &TunnelClient) -> ServiceState {
    probe_notebooklm_at(client, "https://notebooklm.google.com/").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn netflix_probes_both_titles_and_classifies_the_pair() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/title/70143836"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/title/80197526"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = TunnelClient::from_client(reqwest::Client::new());

        let state = probe_netflix_at(&client, &server.uri()).await;

        assert_eq!(state, ServiceState::Restricted);
    }
}
