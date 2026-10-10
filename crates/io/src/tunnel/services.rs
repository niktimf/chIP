use chip_core::model::ServiceState;
use chip_core::verdict::services::{
    classify_chatgpt_app, classify_chatgpt_web, classify_gemini,
    classify_youtube_premium,
};

use super::client::TunnelClient;
use super::{
    BROWSER_EN_HEADERS, BROWSER_HEADERS, BROWSER_HTML_HEADERS, ServicePage,
};

static CHATGPT_WEB: ServicePage = ServicePage {
    url: "https://api.openai.com/compliance/cookie_requirements",
    headers: &BROWSER_HEADERS,
    classify: |response| classify_chatgpt_web(&response.body),
};

static CHATGPT_APP: ServicePage = ServicePage {
    url: "https://ios.chat.openai.com",
    headers: &BROWSER_HEADERS,
    classify: |response| classify_chatgpt_app(response.status, &response.body),
};

static YOUTUBE_PREMIUM: ServicePage = ServicePage {
    url: "https://www.youtube.com/premium",
    headers: &BROWSER_EN_HEADERS,
    classify: |response| classify_youtube_premium(&response.body),
};

static GEMINI: ServicePage = ServicePage {
    url: "https://gemini.google.com/app",
    headers: &BROWSER_HTML_HEADERS,
    classify: |response| classify_gemini(response.status, &response.body),
};

pub async fn probe_chatgpt_web(client: &TunnelClient) -> ServiceState {
    CHATGPT_WEB.probe(client).await
}

pub async fn probe_chatgpt_app(client: &TunnelClient) -> ServiceState {
    CHATGPT_APP.probe(client).await
}

pub async fn probe_youtube_premium(client: &TunnelClient) -> ServiceState {
    YOUTUBE_PREMIUM.probe(client).await
}

pub async fn probe_gemini(client: &TunnelClient) -> ServiceState {
    GEMINI.probe(client).await
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

        let sut = ServicePage {
            url: &server.uri(),
            ..YOUTUBE_PREMIUM
        };

        let state = sut.probe(&client).await;

        assert_eq!(state, ServiceState::Available);
    }

    #[tokio::test]
    async fn a_refused_connection_reports_the_operating_system_cause() {
        let client = TunnelClient::from_client(reqwest::Client::new());
        let sut = ServicePage {
            url: "http://127.0.0.1:1",
            ..CHATGPT_WEB
        };

        let state = sut.probe(&client).await;

        assert!(
            matches!(
                &state,
                ServiceState::Unavailable(detail)
                    if detail.contains("Connection refused")
            ),
            "{state:?}"
        );
    }
}
