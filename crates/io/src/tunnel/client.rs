use std::net::SocketAddr;
use std::time::Duration;

use http::{HeaderName, HeaderValue, StatusCode};
use reqwest::Url;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("could not build the tunnel HTTP client")]
    Build(#[source] reqwest::Error),
    #[error("the request URL cannot be parsed")]
    InvalidUrl(#[source] url::ParseError),
    /// `url` is the request URL without its query, fragment and credentials.
    #[error("GET {url} failed")]
    Request {
        url: Url,
        #[source]
        source: reqwest::Error,
    },
}

impl TunnelError {
    /// `shown` is the URL as `shown_url` gives it.
    fn request(shown: &Url, source: reqwest::Error) -> Self {
        // The message already names the URL; drop reqwest's copy of it, which
        // still carries the query.
        Self::Request {
            url: shown.clone(),
            source: source.without_url(),
        }
    }
}

/// The URL as the request span and `TunnelError` show it: without the query,
/// the fragment and the credentials. The fast.com API URL carries a token in
/// its query, and a request error reaches the verdict text and the JSON
/// report.
fn shown_url(url: &Url) -> Url {
    let mut shown = url.clone();
    shown.set_query(None);
    shown.set_fragment(None);
    // Both setters fail only for a URL that cannot hold credentials, so such
    // a URL has none to drop.
    shown.set_username("").unwrap_or(());
    shown.set_password(None).unwrap_or(());
    shown
}

#[derive(Debug)]
pub struct TunnelResponse {
    pub status: StatusCode,
    pub final_url: reqwest::Url,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct TunnelClient {
    http: reqwest::Client,
}

impl TunnelClient {
    /// Builds a client using remote DNS resolution through the candidate.
    ///
    /// # Errors
    ///
    /// Returns `TunnelError::Build` when the proxy or the client cannot be
    /// built.
    pub fn new(
        socks_addr: SocketAddr,
        request_timeout: Duration,
    ) -> Result<Self, TunnelError> {
        let proxy = reqwest::Proxy::all(format!("socks5h://{socks_addr}"))
            .map_err(TunnelError::Build)?;
        let http = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(request_timeout)
            .build()
            .map_err(TunnelError::Build)?;
        Ok(Self { http })
    }

    #[cfg(test)]
    pub(super) const fn from_client(http: reqwest::Client) -> Self {
        Self { http }
    }

    /// # Errors
    ///
    /// Returns `TunnelError::InvalidUrl` when `url` cannot be parsed, and
    /// `TunnelError::Request` when the request or reading the body fails.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(url = tracing::field::Empty)
    )]
    pub async fn get(
        &self,
        url: &str,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<TunnelResponse, TunnelError> {
        let url = Url::parse(url).map_err(TunnelError::InvalidUrl)?;
        let shown = shown_url(&url);
        tracing::Span::current().record("url", tracing::field::display(&shown));
        let response = headers
            .iter()
            .fold(self.http.get(url), |request, (name, value)| {
                request.header(name, value)
            })
            .send()
            .await
            .map_err(|error| TunnelError::request(&shown, error))?;
        let status = response.status();
        let final_url = response.url().clone();
        let body = response
            .text()
            .await
            .map_err(|error| TunnelError::request(&shown, error))?;
        Ok(TunnelResponse {
            status,
            final_url,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_chain::describe_error;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn the_shown_url_leaves_out_query_fragment_and_credentials() {
        let url: Url = "https://user:pass@api.fast.com/netflix/speedtest/v2\
                        ?https=true&token=abc#top"
            .parse()
            .unwrap();

        let shown = shown_url(&url);

        assert_eq!(shown.as_str(), "https://api.fast.com/netflix/speedtest/v2");
    }

    #[tokio::test]
    async fn a_failed_request_does_not_reveal_the_token_in_its_query() {
        // Port 1 on loopback has no listener, so the request is refused
        // without leaving the machine.
        let sut = TunnelClient::from_client(reqwest::Client::new());

        let error = sut
            .get("http://127.0.0.1:1/v2?https=true&token=secret", &[])
            .await
            .unwrap_err();

        let shown = error.to_string();
        let described = describe_error(&error);
        assert_eq!(shown, "GET http://127.0.0.1:1/v2 failed");
        assert!(!described.contains("secret"), "{described}");
    }

    #[tokio::test]
    async fn get_returns_status_body_and_final_url() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/premium"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("Enjoy ad-free videos"),
            )
            .mount(&server)
            .await;
        let sut = TunnelClient::from_client(reqwest::Client::new());

        let response = sut
            .get(
                &format!("{}/premium", server.uri()),
                &[(
                    http::header::ACCEPT_LANGUAGE,
                    HeaderValue::from_static("en-US"),
                )],
            )
            .await
            .unwrap();

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, "Enjoy ad-free videos");
        assert!(response.final_url.path().ends_with("/premium"));
    }

    #[tokio::test]
    async fn get_sends_supplied_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/echo"))
            .and(header("x-test", "one"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let sut = TunnelClient::from_client(reqwest::Client::new());

        let response = sut
            .get(
                &format!("{}/echo", server.uri()),
                &[(
                    HeaderName::from_static("x-test"),
                    HeaderValue::from_static("one"),
                )],
            )
            .await
            .unwrap();

        assert_eq!(response.status, StatusCode::OK);
    }
}
