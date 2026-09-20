use chip_core::model::ServiceState;
use chip_core::verdict::services::{
    classify_chatgpt_app, classify_chatgpt_web, classify_gemini,
    classify_youtube_premium,
};

use super::client::TunnelClient;

pub(super) const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";

fn unavailable(error: impl std::fmt::Display) -> ServiceState {
    ServiceState::Unavailable(error.to_string())
}

async fn probe_chatgpt_web_at(
    client: &TunnelClient,
    url: &str,
) -> ServiceState {
    match client.get(url, &[("User-Agent", BROWSER_UA)]).await {
        Ok(response) => classify_chatgpt_web(&response.body),
        Err(error) => unavailable(error),
    }
}

pub async fn probe_chatgpt_web(client: &TunnelClient) -> ServiceState {
    probe_chatgpt_web_at(
        client,
        "https://api.openai.com/compliance/cookie_requirements",
    )
    .await
}

async fn probe_chatgpt_app_at(
    client: &TunnelClient,
    url: &str,
) -> ServiceState {
    match client.get(url, &[("User-Agent", BROWSER_UA)]).await {
        Ok(response) => classify_chatgpt_app(response.status, &response.body),
        Err(error) => unavailable(error),
    }
}

pub async fn probe_chatgpt_app(client: &TunnelClient) -> ServiceState {
    probe_chatgpt_app_at(client, "https://ios.chat.openai.com").await
}

async fn probe_youtube_premium_at(
    client: &TunnelClient,
    url: &str,
) -> ServiceState {
    match client
        .get(
            url,
            &[
                ("User-Agent", BROWSER_UA),
                ("Accept-Language", "en-US,en;q=0.9"),
            ],
        )
        .await
    {
        Ok(response) => classify_youtube_premium(&response.body),
        Err(error) => unavailable(error),
    }
}

pub async fn probe_youtube_premium(client: &TunnelClient) -> ServiceState {
    probe_youtube_premium_at(client, "https://www.youtube.com/premium").await
}

async fn probe_gemini_at(client: &TunnelClient, url: &str) -> ServiceState {
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
        Ok(response) => classify_gemini(response.status, &response.body),
        Err(error) => unavailable(error),
    }
}

pub async fn probe_gemini(client: &TunnelClient) -> ServiceState {
    probe_gemini_at(client, "https://gemini.google.com/app").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn youtube_premium_classifies_the_fetched_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("Enjoy ad-free videos"),
            )
            .mount(&server)
            .await;
        let client = TunnelClient::from_client(reqwest::Client::new());

        let state = probe_youtube_premium_at(&client, &server.uri()).await;

        assert_eq!(state, ServiceState::Available);
    }

    #[tokio::test]
    async fn transport_failure_stays_distinct_from_an_inconclusive_page() {
        let client = TunnelClient::from_client(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(100))
                .build()
                .unwrap(),
        );

        let state = probe_chatgpt_web_at(&client, "http://127.0.0.1:1").await;

        assert!(matches!(state, ServiceState::Unavailable(_)), "{state:?}");
    }
}
