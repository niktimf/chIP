use chip_core::model::RoutingFacts;
use ipnet::Ipv4Net;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RipestatError {
    #[error("RIPEstat response did not have the expected shape: {0}")]
    Shape(&'static str),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

pub struct RipestatClient {
    http: reqwest::Client,
    base_url: String,
}

impl RipestatClient {
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            base_url: "https://stat.ripe.net/data".to_string(),
        }
    }

    pub async fn routing_status(
        &self,
        prefix: Ipv4Net,
    ) -> Result<RoutingFacts, RipestatError> {
        let url = format!(
            "{}/routing-status/data.json?resource={prefix}",
            self.base_url
        );
        let body: serde_json::Value =
            self.http.get(&url).send().await?.json().await?;
        let data = &body["data"];

        let seeing = data["visibility"]["v4"]["ris_peers_seeing"]
            .as_u64()
            .ok_or(RipestatError::Shape("visibility.v4.ris_peers_seeing"))?;
        let total = data["visibility"]["v4"]["total_ris_peers"]
            .as_u64()
            .ok_or(RipestatError::Shape("visibility.v4.total_ris_peers"))?;

        let origin_count = data["origins"].as_array().map_or(0, Vec::len);

        RoutingFacts::new(
            u32::try_from(seeing)
                .map_err(|_| RipestatError::Shape("value out of range"))?,
            u32::try_from(total)
                .map_err(|_| RipestatError::Shape("value out of range"))?,
            u32::try_from(origin_count).unwrap_or(u32::MAX),
        )
        .map_err(|_| RipestatError::Shape("visibility exceeds total peers"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ROUTING_STATUS: &str = r#"{
        "data": {
            "first_seen": {"prefix": "203.0.113.0/24", "origin": "64500", "time": "2025-01-01T00:00:00"},
            "last_seen": {"prefix": "203.0.113.0/24", "origin": "64500", "time": "2026-01-01T00:00:00"},
            "visibility": {"v4": {"ris_peers_seeing": 300, "total_ris_peers": 320},
                           "v6": {"ris_peers_seeing": 0, "total_ris_peers": 0}},
            "origins": [{"origin": 64500, "route_objects": ["RIPE"]}],
            "less_specifics": 0, "more_specifics": 0
        }
    }"#;

    #[tokio::test]
    async fn routing_status_reads_visibility_and_counts_origins() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/routing-status/data.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(ROUTING_STATUS),
            )
            .mount(&server)
            .await;
        let client = RipestatClient {
            http: reqwest::Client::new(),
            base_url: server.uri(),
        };

        let facts = client
            .routing_status("203.0.113.0/24".parse().unwrap())
            .await
            .unwrap();

        assert_eq!(facts.ris_peers_seeing(), 300);
        assert_eq!(facts.total_ris_peers(), 320);
        assert_eq!(facts.origin_count(), 1);
    }

    #[tokio::test]
    async fn a_response_missing_the_expected_shape_is_a_shape_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/routing-status/data.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": {}})),
            )
            .mount(&server)
            .await;
        let client = RipestatClient {
            http: reqwest::Client::new(),
            base_url: server.uri(),
        };

        let err = client
            .routing_status("203.0.113.0/24".parse().unwrap())
            .await
            .unwrap_err();

        assert!(
            matches!(
                err,
                RipestatError::Shape("visibility.v4.ris_peers_seeing")
            ),
            "{err:?}"
        );
    }
}
