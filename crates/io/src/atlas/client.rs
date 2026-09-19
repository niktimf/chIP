use super::select::Anchor;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AtlasError {
    #[error("RIPE Atlas request failed: {0}")]
    Http(#[from] reqwest::Error),
}

pub struct AnchorClient {
    http: reqwest::Client,
    base_url: String,
}

impl AnchorClient {
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            base_url: "https://atlas.ripe.net/api/v2/anchors/".to_string(),
        }
    }

    #[cfg(test)]
    fn with_base_url(http: reqwest::Client, base_url: String) -> Self {
        Self { http, base_url }
    }

    pub async fn anchors(&self) -> Result<Vec<Anchor>, AtlasError> {
        #[derive(serde::Deserialize)]
        struct Page {
            results: Vec<Anchor>,
            next: Option<String>,
        }
        let mut url = format!(
            "{}?page_size=500&fields=fqdn,ip_v4,city,country,as_v4,is_disabled,date_decommissioned",
            self.base_url
        );
        let mut out = Vec::new();
        loop {
            let page: Page = self.http.get(&url).send().await?.json().await?;
            out.extend(page.results.into_iter().filter(|a| {
                !a.is_disabled && a.date_decommissioned.is_none() && !a.ip_v4.is_empty()
            }));
            match page.next {
                Some(next) => url = next,
                None => break,
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn anchors_follows_pagination_and_drops_inactive_or_ipv6_only_rows() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/page1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [
                    {"fqdn": "fi-hel-as1", "ip_v4": "192.0.2.1", "city": "Helsinki", "country": "FI", "as_v4": 1, "is_disabled": false, "date_decommissioned": null},
                    {"fqdn": "fi-hel-as2-dead", "ip_v4": "192.0.2.2", "city": "Helsinki", "country": "FI", "as_v4": 2, "is_disabled": true, "date_decommissioned": null},
                    {"fqdn": "fi-hel-as3-noipv4", "ip_v4": "", "city": "Helsinki", "country": "FI", "as_v4": 3, "is_disabled": false, "date_decommissioned": null}
                ],
                "next": format!("{}/page2", server.uri())
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/page2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [
                    {"fqdn": "de-fra-as4", "ip_v4": "192.0.2.4", "city": "Frankfurt", "country": "DE", "as_v4": 4, "is_disabled": false, "date_decommissioned": null}
                ],
                "next": null
            })))
            .mount(&server)
            .await;

        let client =
            AnchorClient::with_base_url(reqwest::Client::new(), format!("{}/page1", server.uri()));
        let anchors = client.anchors().await.unwrap();

        assert_eq!(
            anchors.iter().map(|a| a.fqdn.as_str()).collect::<Vec<_>>(),
            vec!["fi-hel-as1", "de-fra-as4"]
        );
    }
}
