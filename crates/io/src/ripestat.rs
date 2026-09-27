use std::net::Ipv4Addr;
use std::num::NonZeroU32;

use chip_core::model::{Routing, RoutingFacts};
use ipnet::Ipv4Net;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RipestatError {
    #[error("RIPEstat response did not have the expected shape: {0}")]
    Shape(&'static str),
    #[error("RIPEstat returned no RIS peer data for this address")]
    NoPeerData,
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

    /// Asks about the address itself, not its `/24`: `RIPEstat` then resolves
    /// the announced prefix that covers it, which is often a `/18` or a
    /// `/22`. A `/24` that is not announced on its own reads as seen by no
    /// peer at all.
    pub async fn routing_status(
        &self,
        ip: Ipv4Addr,
    ) -> Result<Routing, RipestatError> {
        let url =
            format!("{}/routing-status/data.json?resource={ip}", self.base_url);
        let body: serde_json::Value =
            self.http.get(&url).send().await?.json().await?;
        let data = &body["data"];

        let resource = data["resource"]
            .as_str()
            .ok_or(RipestatError::Shape("resource"))?;
        let total = data["visibility"]["v4"]["total_ris_peers"]
            .as_u64()
            .ok_or(RipestatError::Shape("visibility.v4.total_ris_peers"))?;
        let total = u32::try_from(total)
            .map_err(|_| RipestatError::Shape("value out of range"))?;
        let total = NonZeroU32::new(total).ok_or(RipestatError::NoPeerData)?;
        // RIPEstat echoes the bare address back as `resource` when no
        // announcement covers it, and the announced prefix otherwise.
        if resource.parse::<Ipv4Addr>().is_ok() {
            return Ok(Routing::NotAnnounced {
                total_ris_peers: total,
            });
        }
        let prefix: Ipv4Net = resource
            .parse()
            .map_err(|_| RipestatError::Shape("resource"))?;

        let seeing = data["visibility"]["v4"]["ris_peers_seeing"]
            .as_u64()
            .ok_or(RipestatError::Shape("visibility.v4.ris_peers_seeing"))?;
        let origin_count = data["origins"].as_array().map_or(0, Vec::len);

        let facts = RoutingFacts::new(
            u32::try_from(seeing)
                .map_err(|_| RipestatError::Shape("value out of range"))?,
            total,
            u32::try_from(origin_count).unwrap_or(u32::MAX),
        )
        .map_err(|_| RipestatError::Shape("visibility exceeds total peers"))?;
        Ok(Routing::Announced { prefix, facts })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ROUTING_STATUS: &str = r#"{
        "data": {
            "resource": "203.0.112.0/22",
            "first_seen": {"prefix": "203.0.112.0/22", "origin": "64500", "time": "2025-01-01T00:00:00"},
            "last_seen": {"prefix": "203.0.112.0/22", "origin": "64500", "time": "2026-01-01T00:00:00"},
            "visibility": {"v4": {"ris_peers_seeing": 300, "total_ris_peers": 320},
                           "v6": {"ris_peers_seeing": 0, "total_ris_peers": 0}},
            "origins": [{"origin": 64500, "route_objects": ["RIPE"]}],
            "less_specifics": 0, "more_specifics": 0
        }
    }"#;

    const NOT_ANNOUNCED: &str = r#"{
        "data": {
            "resource": "192.0.2.1",
            "first_seen": {},
            "visibility": {"v4": {"ris_peers_seeing": 0, "total_ris_peers": 325},
                           "v6": {"ris_peers_seeing": 0, "total_ris_peers": 0}},
            "origins": []
        }
    }"#;

    const NO_PEER_DATA: &str = r#"{
        "data": {
            "resource": "203.0.112.0/22",
            "visibility": {"v4": {"ris_peers_seeing": 0, "total_ris_peers": 0}},
            "origins": []
        }
    }"#;

    async fn client_answering(body: &str) -> (MockServer, RipestatClient) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/routing-status/data.json"))
            .and(query_param("resource", "203.0.113.42"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let client = RipestatClient {
            http: reqwest::Client::new(),
            base_url: server.uri(),
        };
        (server, client)
    }

    #[tokio::test]
    async fn routing_status_asks_about_the_address_and_reads_the_covering_prefix()
     {
        let (_server, sut) = client_answering(ROUTING_STATUS).await;

        let routing = sut
            .routing_status(Ipv4Addr::new(203, 0, 113, 42))
            .await
            .unwrap();

        let Routing::Announced { prefix, .. } = routing else {
            panic!("expected an announced prefix, got {routing:?}");
        };
        assert_eq!(prefix, "203.0.112.0/22".parse::<Ipv4Net>().unwrap());
    }

    #[tokio::test]
    async fn an_address_echoed_back_as_the_resource_is_not_announced() {
        let (_server, sut) = client_answering(NOT_ANNOUNCED).await;

        let routing = sut
            .routing_status(Ipv4Addr::new(203, 0, 113, 42))
            .await
            .unwrap();

        let Routing::NotAnnounced { total_ris_peers } = routing else {
            panic!("expected no announcement, got {routing:?}");
        };
        assert_eq!(total_ris_peers.get(), 325);
    }

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
        let sut = RipestatClient {
            http: reqwest::Client::new(),
            base_url: server.uri(),
        };

        let routing = sut
            .routing_status(Ipv4Addr::new(203, 0, 113, 42))
            .await
            .unwrap();

        let Routing::Announced { facts, .. } = routing else {
            panic!("expected an announced prefix, got {routing:?}");
        };
        assert_eq!(facts.ris_peers_seeing(), 300);
        assert_eq!(facts.total_ris_peers().get(), 320);
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
        let sut = RipestatClient {
            http: reqwest::Client::new(),
            base_url: server.uri(),
        };

        let err = sut
            .routing_status(Ipv4Addr::new(203, 0, 113, 42))
            .await
            .unwrap_err();

        assert!(matches!(err, RipestatError::Shape("resource")), "{err:?}");
    }

    #[tokio::test]
    async fn an_answer_without_ris_peers_carries_no_routing_data() {
        let (_server, sut) = client_answering(NO_PEER_DATA).await;

        let error = sut
            .routing_status(Ipv4Addr::new(203, 0, 113, 42))
            .await
            .unwrap_err();

        assert!(matches!(error, RipestatError::NoPeerData), "{error:?}");
    }
}
