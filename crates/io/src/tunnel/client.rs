use std::net::SocketAddr;
use std::time::Duration;

use http::{HeaderName, HeaderValue, StatusCode};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("could not build the tunnel HTTP client")]
    Build(#[source] reqwest::Error),
    #[error("GET {url} failed")]
    Request {
        url: String,
        #[source]
        source: reqwest::Error,
    },
}

impl TunnelError {
    fn request(url: &str, source: reqwest::Error) -> Self {
        // The message already names the URL; drop reqwest's copy of it.
        Self::Request {
            url: url.to_owned(),
            source: source.without_url(),
        }
    }
}

/// The URL up to its query string, for the request span. The fast.com API URL
/// carries a token in its query; the span does not record it.
fn without_query(url: &str) -> &str {
    url.split_once('?').map_or(url, |(base, _)| base)
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
    /// Returns `TunnelError::Request` when the request or reading the body
    /// fails.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(url = without_query(url))
    )]
    pub async fn get(
        &self,
        url: &str,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<TunnelResponse, TunnelError> {
        let response = headers
            .iter()
            .fold(self.http.get(url), |request, (name, value)| {
                request.header(name, value)
            })
            .send()
            .await
            .map_err(|error| TunnelError::request(url, error))?;
        let status = response.status();
        let final_url = response.url().clone();
        let body = response
            .text()
            .await
            .map_err(|error| TunnelError::request(url, error))?;
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
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn the_span_url_leaves_out_a_token_in_the_query() {
        let url =
            "https://api.fast.com/netflix/speedtest/v2?https=true&token=abc";

        let recorded = without_query(url);

        assert_eq!(recorded, "https://api.fast.com/netflix/speedtest/v2");
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
