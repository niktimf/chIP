use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

#[derive(Debug)]
pub struct TunnelResponse {
    pub status: u16,
    pub final_url: reqwest::Url,
    pub body: String,
}

#[derive(Clone)]
pub struct TunnelClient {
    http: reqwest::Client,
}

impl TunnelClient {
    /// Builds a client using remote DNS resolution through the candidate.
    pub fn new(
        socks_addr: SocketAddr,
        request_timeout: Duration,
    ) -> Result<Self, TunnelError> {
        let proxy = reqwest::Proxy::all(format!("socks5h://{socks_addr}"))?;
        let http = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(request_timeout)
            .build()?;
        Ok(Self { http })
    }

    #[cfg(test)]
    pub(super) const fn from_client(http: reqwest::Client) -> Self {
        Self { http }
    }

    pub async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<TunnelResponse, TunnelError> {
        let mut request = self.http.get(url);
        for (key, value) in headers {
            request = request.header(*key, *value);
        }
        let response = request.send().await?;
        let status = response.status().as_u16();
        let final_url = response.url().clone();
        let body = response.text().await?;
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
                &[("Accept-Language", "en-US")],
            )
            .await
            .unwrap();

        assert_eq!(response.status, 200);
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
            .mount(&server)
            .await;
        let sut = TunnelClient::from_client(reqwest::Client::new());

        sut.get(&format!("{}/echo", server.uri()), &[("X-Test", "one")])
            .await
            .unwrap();
    }
}
