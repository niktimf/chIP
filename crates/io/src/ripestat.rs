use std::net::Ipv4Addr;
use std::num::NonZeroU32;

use chip_core::model::{Routing, RoutingFacts};
use ipnet::Ipv4Net;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RipestatError {
    #[error("RIPEstat routing status request failed")]
    Request(#[source] reqwest::Error),
    #[error("RIPEstat response did not have the expected shape")]
    Shape(#[source] reqwest::Error),
    #[error("RIPEstat response field {field} is out of range")]
    OutOfRange {
        field: &'static str,
        source: std::num::TryFromIntError,
    },
    #[error("RIPEstat response field resource is not an IPv4 prefix")]
    Prefix(#[source] ipnet::AddrParseError),
    #[error("RIPEstat response has inconsistent visibility counts")]
    Visibility(#[source] chip_core::model::InvalidRoutingFacts),
    #[error("RIPEstat returned no RIS peer data for this address")]
    NoPeerData,
    #[error(
        "RIPEstat reports the prefix {prefix} as announced with no origin AS"
    )]
    NoOrigins { prefix: Ipv4Net },
}

/// The part of a `routing-status` answer the client reads.
#[derive(Deserialize)]
struct RoutingStatusBody {
    data: RoutingStatusData,
}

#[derive(Deserialize)]
struct RoutingStatusData {
    resource: String,
    visibility: Visibility,
    /// Only counted, and only for an announced prefix. `None` for a missing
    /// or `null` list: the not-announced answer does not need one.
    origins: Option<Vec<serde::de::IgnoredAny>>,
}

#[derive(Deserialize)]
struct Visibility {
    v4: PeerVisibility,
}

#[derive(Deserialize)]
struct PeerVisibility {
    ris_peers_seeing: u64,
    total_ris_peers: u64,
}

impl RoutingStatusData {
    fn into_routing(self) -> Result<Routing, RipestatError> {
        let total = narrow(
            self.visibility.v4.total_ris_peers,
            "visibility.v4.total_ris_peers",
        )?;
        let total = NonZeroU32::new(total).ok_or(RipestatError::NoPeerData)?;
        // RIPEstat echoes the bare address back as `resource` when no
        // announcement covers it, and the announced prefix otherwise.
        if self.resource.parse::<Ipv4Addr>().is_ok() {
            return Ok(Routing::NotAnnounced {
                total_ris_peers: total,
            });
        }
        let prefix: Ipv4Net =
            self.resource.parse().map_err(RipestatError::Prefix)?;
        let seeing = narrow(
            self.visibility.v4.ris_peers_seeing,
            "visibility.v4.ris_peers_seeing",
        )?;
        // Every announcement has an origin AS, and RIPEstat lists it. A
        // missing, `null` or empty list for an announced prefix is not
        // "zero origins" for provenance to accept.
        let origins = self
            .origins
            .filter(|origins| !origins.is_empty())
            .ok_or(RipestatError::NoOrigins { prefix })?;
        let origin_count = narrow(origins.len(), "origins")?;
        let facts = RoutingFacts::new(seeing, total, origin_count)
            .map_err(RipestatError::Visibility)?;
        Ok(Routing::Announced { prefix, facts })
    }
}

/// Narrows a count from the answer to `u32`, naming the field it came from.
fn narrow<T>(value: T, field: &'static str) -> Result<u32, RipestatError>
where
    u32: TryFrom<T, Error = std::num::TryFromIntError>,
{
    u32::try_from(value)
        .map_err(|source| RipestatError::OutOfRange { field, source })
}

#[derive(Debug)]
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
    ///
    /// # Errors
    ///
    /// Returns `RipestatError` when the request fails or answers with a
    /// non-success status, the answer does not have the expected shape, or
    /// no RIS peer reports on the address.
    pub async fn routing_status(
        &self,
        ip: Ipv4Addr,
    ) -> Result<Routing, RipestatError> {
        let url =
            format!("{}/routing-status/data.json?resource={ip}", self.base_url);
        let body: RoutingStatusBody = self
            .http
            .get(&url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(RipestatError::Request)?
            .json()
            .await
            .map_err(RipestatError::Shape)?;
        body.data.into_routing()
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

    const INCONSISTENT_VISIBILITY: &str = r#"{
        "data": {
            "resource": "203.0.112.0/22",
            "visibility": {"v4": {"ris_peers_seeing": 330, "total_ris_peers": 320}},
            "origins": [{"origin": 64500, "route_objects": ["RIPE"]}]
        }
    }"#;

    async fn client_answering(body: &str) -> (MockServer, RipestatClient) {
        client_responding(ResponseTemplate::new(200).set_body_string(body))
            .await
    }

    async fn client_responding(
        response: ResponseTemplate,
    ) -> (MockServer, RipestatClient) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/routing-status/data.json"))
            .and(query_param("resource", "203.0.113.42"))
            .respond_with(response)
            .mount(&server)
            .await;
        let client = RipestatClient {
            http: reqwest::Client::new(),
            base_url: server.uri(),
        };
        (server, client)
    }

    #[tokio::test]
    async fn the_address_is_reported_with_the_prefix_covering_it_and_its_visibility()
     {
        let (_server, sut) = client_answering(ROUTING_STATUS).await;

        let routing = sut
            .routing_status(Ipv4Addr::new(203, 0, 113, 42))
            .await
            .unwrap();

        assert_eq!(
            routing,
            Routing::Announced {
                prefix: "203.0.112.0/22".parse().unwrap(),
                facts: RoutingFacts::new(300, NonZeroU32::new(320).unwrap(), 1)
                    .unwrap(),
            }
        );
    }

    #[tokio::test]
    async fn an_address_echoed_back_as_the_resource_is_not_announced() {
        let (_server, sut) = client_answering(NOT_ANNOUNCED).await;

        let routing = sut
            .routing_status(Ipv4Addr::new(203, 0, 113, 42))
            .await
            .unwrap();

        assert_eq!(
            routing,
            Routing::NotAnnounced {
                total_ris_peers: NonZeroU32::new(325).unwrap(),
            }
        );
    }

    #[tokio::test]
    async fn a_response_missing_the_expected_shape_is_a_shape_error() {
        let (_server, sut) = client_answering(r#"{"data": {}}"#).await;

        let err = sut
            .routing_status(Ipv4Addr::new(203, 0, 113, 42))
            .await
            .unwrap_err();

        assert!(matches!(err, RipestatError::Shape(_)), "{err:?}");
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

    #[rstest::rstest]
    #[case::a_missing_list(r#""visibility": {"v4": {"ris_peers_seeing": 300, "total_ris_peers": 320}}"#)]
    #[case::a_null_list(r#""visibility": {"v4": {"ris_peers_seeing": 300, "total_ris_peers": 320}}, "origins": null"#)]
    #[case::an_empty_list(r#""visibility": {"v4": {"ris_peers_seeing": 300, "total_ris_peers": 320}}, "origins": []"#)]
    #[tokio::test]
    async fn an_announced_prefix_without_origins_is_a_no_origins_error(
        #[case] fields: &str,
    ) {
        let body = format!(
            r#"{{"data": {{"resource": "203.0.112.0/22", {fields}}}}}"#
        );
        let (_server, sut) = client_answering(&body).await;

        let error = sut
            .routing_status(Ipv4Addr::new(203, 0, 113, 42))
            .await
            .unwrap_err();

        assert!(
            matches!(
                error,
                RipestatError::NoOrigins { prefix }
                    if prefix == "203.0.112.0/22".parse::<Ipv4Net>().unwrap()
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_not_announced_address_needs_no_origins_list() {
        let (_server, sut) = client_answering(
            r#"{"data": {"resource": "192.0.2.1",
                "visibility": {"v4": {"ris_peers_seeing": 0, "total_ris_peers": 325}}}}"#,
        )
        .await;

        let routing = sut
            .routing_status(Ipv4Addr::new(203, 0, 113, 42))
            .await
            .unwrap();

        assert_eq!(
            routing,
            Routing::NotAnnounced {
                total_ris_peers: NonZeroU32::new(325).unwrap(),
            }
        );
    }

    #[tokio::test]
    async fn a_server_error_is_a_failed_request_with_its_status() {
        let (_server, sut) =
            client_responding(ResponseTemplate::new(503)).await;

        let error = sut
            .routing_status(Ipv4Addr::new(203, 0, 113, 42))
            .await
            .unwrap_err();

        assert!(
            matches!(
                error,
                RipestatError::Request(ref source)
                    if source.status()
                        == Some(reqwest::StatusCode::SERVICE_UNAVAILABLE)
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn more_peers_seeing_the_prefix_than_exist_is_inconsistent_visibility()
     {
        let (_server, sut) = client_answering(INCONSISTENT_VISIBILITY).await;

        let error = sut
            .routing_status(Ipv4Addr::new(203, 0, 113, 42))
            .await
            .unwrap_err();

        assert!(matches!(error, RipestatError::Visibility(_)), "{error:?}");
    }
}
