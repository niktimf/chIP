use chip_core::checks::tunnel::ServiceState;
use chip_core::checks::tunnel::services::{
    NetflixTitleStatuses, classify_claude, classify_netflix,
    classify_notebooklm, classify_tiktok,
};
use http::header::{
    ACCEPT, ACCEPT_LANGUAGE, UPGRADE_INSECURE_REQUESTS, USER_AGENT,
};
use http::{HeaderName, HeaderValue};

use super::client::TunnelClient;
use super::{
    ACCEPT_LANGUAGE_EN, BROWSER_HEADERS, BROWSER_HTML_HEADERS, BROWSER_UA,
    ServicePage, unavailable,
};

const NETFLIX_LICENSED_TITLE: &str = "70143836";
const NETFLIX_ORIGINAL_TITLE: &str = "80197526";

/// The headers a browser sends when it opens the page from the address bar.
static CLAUDE_HEADERS: [(HeaderName, HeaderValue); 8] = [
    (USER_AGENT, BROWSER_UA),
    (
        ACCEPT,
        HeaderValue::from_static(
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ),
    ),
    (ACCEPT_LANGUAGE, ACCEPT_LANGUAGE_EN),
    (
        HeaderName::from_static("sec-fetch-dest"),
        HeaderValue::from_static("document"),
    ),
    (
        HeaderName::from_static("sec-fetch-mode"),
        HeaderValue::from_static("navigate"),
    ),
    (
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("none"),
    ),
    (HeaderName::from_static("sec-fetch-user"), HeaderValue::from_static("?1")),
    (UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1")),
];

static CLAUDE: ServicePage = ServicePage {
    url: "https://claude.ai/",
    headers: &CLAUDE_HEADERS,
    classify: |response| classify_claude(response.status, &response.body),
};

static TIKTOK: ServicePage = ServicePage {
    url: "https://www.tiktok.com/",
    headers: &BROWSER_HTML_HEADERS,
    classify: |response| classify_tiktok(response.status, &response.body),
};

static NOTEBOOKLM: ServicePage = ServicePage {
    url: "https://notebooklm.google.com/",
    headers: &BROWSER_HTML_HEADERS,
    classify: |response| {
        classify_notebooklm(
            response.status,
            &response.final_url,
            &response.body,
        )
    },
};

async fn probe_netflix_at(
    client: &TunnelClient,
    base_url: &str,
) -> ServiceState {
    let licensed_url = format!("{base_url}/title/{NETFLIX_LICENSED_TITLE}");
    let original_url = format!("{base_url}/title/{NETFLIX_ORIGINAL_TITLE}");
    let (licensed, original) = tokio::join!(
        client.get(&licensed_url, &BROWSER_HEADERS),
        client.get(&original_url, &BROWSER_HEADERS)
    );
    match (licensed, original) {
        (Ok(licensed), Ok(original)) => {
            classify_netflix(NetflixTitleStatuses {
                licensed: licensed.status,
                original: original.status,
            })
        }
        (Err(error), _) | (_, Err(error)) => unavailable(&error),
    }
}

pub async fn probe_netflix(client: &TunnelClient) -> ServiceState {
    probe_netflix_at(client, "https://www.netflix.com").await
}

pub async fn probe_claude(client: &TunnelClient) -> ServiceState {
    CLAUDE.probe(client).await
}

pub async fn probe_tiktok(client: &TunnelClient) -> ServiceState {
    TIKTOK.probe(client).await
}

pub async fn probe_notebooklm(client: &TunnelClient) -> ServiceState {
    NOTEBOOKLM.probe(client).await
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
