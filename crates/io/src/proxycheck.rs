use crate::credentials::ProxycheckApiKey;
use chip_core::model::{
    InvalidRiskScore, ReputationFacts, ReputationFlag, RiskScore,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxycheckError {
    #[error("proxycheck.io daily query allowance exhausted")]
    QuotaExceeded,
    #[error("proxycheck.io error: {0}")]
    Api(String),
    #[error("proxycheck.io response has no entry for {ip}")]
    MissingEntry { ip: Ipv4Addr },
    #[error("proxycheck.io entry for {ip} does not match the v3 shape")]
    MalformedEntry {
        ip: Ipv4Addr,
        source: serde_json::Error,
    },
    #[error("proxycheck.io entry for {ip} has an out-of-range risk score")]
    RiskOutOfRange {
        ip: Ipv4Addr,
        source: InvalidRiskScore,
    },
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

/// One address's entry in a v3 answer. The detection flags are required:
/// an entry without them is a changed or broken response, and reading the
/// gap as `false` would pass the address as clean.
#[derive(Deserialize)]
struct RawEntry {
    detections: RawDetections,
    operator: Option<RawOperator>,
}

#[derive(Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors the independent detection flags of the v3 wire format"
)]
struct RawDetections {
    vpn: bool,
    proxy: bool,
    tor: bool,
    compromised: bool,
    anonymous: bool,
    scraper: bool,
    risk: Option<u64>,
}

impl RawDetections {
    fn flags(&self) -> BTreeSet<ReputationFlag> {
        [
            (self.vpn, ReputationFlag::Vpn),
            (self.proxy, ReputationFlag::Proxy),
            (self.tor, ReputationFlag::Tor),
            (self.compromised, ReputationFlag::Compromised),
            (self.anonymous, ReputationFlag::Anonymous),
            (self.scraper, ReputationFlag::Scraper),
        ]
        .into_iter()
        .filter_map(|(raised, flag)| raised.then_some(flag))
        .collect()
    }
}

/// v3 answers with an object (`{"name": …, "url": …, "anonymity": …}`),
/// not a bare string: reading it as a string silently dropped every
/// operator proxycheck ever named.
#[derive(Deserialize)]
struct RawOperator {
    name: Option<String>,
}

/// A risk above 100 is an error rather than "risk unknown": the rest of the
/// entry is read strictly, and an unknown risk would hide a changed scale.
impl TryFrom<RawEntry> for ReputationFacts {
    type Error = InvalidRiskScore;

    fn try_from(entry: RawEntry) -> Result<Self, Self::Error> {
        let RawEntry {
            detections,
            operator,
        } = entry;
        let risk = detections.risk.map(RiskScore::try_from).transpose()?;
        Ok(Self {
            flags: detections.flags(),
            risk,
            operator: operator.and_then(|operator| operator.name),
        })
    }
}

#[derive(Debug)]
pub struct ProxycheckClient {
    http: reqwest::Client,
    api_key: Option<ProxycheckApiKey>,
    base_url: String,
}

impl ProxycheckClient {
    pub fn new(
        http: reqwest::Client,
        api_key: Option<ProxycheckApiKey>,
    ) -> Self {
        Self {
            http,
            api_key,
            base_url: "https://proxycheck.io".to_string(),
        }
    }

    /// # Errors
    ///
    /// Returns `ProxycheckError` when the request fails, the API reports an
    /// exhausted quota or another error, or the answer has no well-formed
    /// entry for `ip`.
    pub async fn lookup(
        &self,
        ip: Ipv4Addr,
    ) -> Result<ReputationFacts, ProxycheckError> {
        let url = format!("{}/v3/{ip}", self.base_url);
        let mut request = self.http.get(&url);
        if let Some(key) = &self.api_key {
            request = request.query(&[("key", key.expose())]);
        }
        // reqwest errors print the URL, which carries the key: strip it.
        let response =
            request.send().await.map_err(reqwest::Error::without_url)?;
        let mut body: serde_json::Value =
            response.json().await.map_err(reqwest::Error::without_url)?;
        match body["status"].as_str() {
            Some("denied") => return Err(ProxycheckError::QuotaExceeded),
            Some("error") => {
                return Err(ProxycheckError::Api(
                    body["message"]
                        .as_str()
                        .unwrap_or("unknown error")
                        .to_string(),
                ));
            }
            _ => {}
        }
        let entry = body
            .get_mut(ip.to_string())
            .ok_or(ProxycheckError::MissingEntry { ip })?
            .take();
        let entry = serde_json::from_value::<RawEntry>(entry)
            .map_err(|source| ProxycheckError::MalformedEntry { ip, source })?;
        ReputationFacts::try_from(entry)
            .map_err(|source| ProxycheckError::RiskOutOfRange { ip, source })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const CLEAN_HOSTING: &str = r#"{
        "status": "ok",
        "203.0.113.1": {
            "network": {"asn": "AS64500", "range": "203.0.113.0/24", "hostname": "example-hoster.net",
                        "provider": "Example Hosting", "organisation": "Example Hosting", "type": "Hosting"},
            "detections": {"proxy": false, "vpn": false, "compromised": false, "scraper": false, "tor": false,
                          "hosting": true, "anonymous": false, "risk": 33, "confidence": 100,
                          "first_seen": null, "last_seen": null, "times_seen": null},
            "operator": null,
            "location": {"country_code": "DE"}
        }
    }"#;

    const NAMED_OPERATOR: &str = r#"{
        "status": "ok",
        "203.0.113.2": {
            "network": {"asn": "AS64501", "range": "203.0.113.0/24", "hostname": "vpn-host.example.net",
                        "provider": "Example Hosting", "organisation": "Example Hosting", "type": "Hosting"},
            "detections": {"proxy": false, "vpn": true, "compromised": false, "scraper": false, "tor": false,
                          "hosting": true, "anonymous": false, "risk": 50, "confidence": 100,
                          "first_seen": null, "last_seen": null, "times_seen": null},
            "operator": {"name": "Snowd", "url": "https://snowd.example/",
                         "anonymity": "medium", "popularity": "low",
                         "services": ["datacenter_vpns"],
                         "protocols": ["WireGuard", "OpenVPN"]},
            "location": {"country_code": "FI"}
        }
    }"#;

    const OPERATOR_WITHOUT_FLAGS: &str = r#"{
        "status": "ok",
        "203.0.113.3": {
            "network": {"asn": "AS64502", "range": "203.0.113.0/24", "hostname": null,
                        "provider": "Example Hosting", "organisation": "Example VPN OU", "type": "Hosting"},
            "detections": {"proxy": false, "vpn": false, "compromised": false, "scraper": false, "tor": false,
                          "hosting": true, "anonymous": false, "risk": 33, "confidence": 100,
                          "first_seen": null, "last_seen": null, "times_seen": null},
            "operator": {"name": "Snowd", "url": "https://snowd.example/", "anonymity": "medium"},
            "location": {"country_code": "FI"}
        }
    }"#;

    async fn client_against(
        server: &MockServer,
        ip: &str,
        body: &str,
    ) -> ProxycheckClient {
        Mock::given(method("GET"))
            .and(path(format!("/v3/{ip}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(server)
            .await;
        ProxycheckClient {
            http: reqwest::Client::new(),
            api_key: None,
            base_url: server.uri(),
        }
    }

    #[tokio::test]
    async fn a_clean_hosting_address_parses_into_facts_with_no_hard_flags() {
        let server = MockServer::start().await;
        let sut = client_against(&server, "203.0.113.1", CLEAN_HOSTING).await;

        let facts = sut.lookup("203.0.113.1".parse().unwrap()).await.unwrap();

        assert_eq!(facts.flags, BTreeSet::new());
        assert_eq!(facts.risk.map(RiskScore::value), Some(33));
        assert_eq!(facts.operator, None);
    }

    #[tokio::test]
    async fn a_named_vpn_operator_is_read_into_the_operator_field() {
        let server = MockServer::start().await;
        let sut = client_against(&server, "203.0.113.2", NAMED_OPERATOR).await;

        let facts = sut.lookup("203.0.113.2".parse().unwrap()).await.unwrap();

        assert_eq!(facts.flags, BTreeSet::from([ReputationFlag::Vpn]));
        assert_eq!(facts.operator.as_deref(), Some("Snowd"));
    }

    /// proxycheck names the VPN operator of an address whose `detections`
    /// are all false — that is exactly the case the `reputation:operator`
    /// gate exists for, and the one a string-shaped parse used to miss.
    #[tokio::test]
    async fn an_operator_is_read_even_when_no_detection_flag_is_set() {
        let server = MockServer::start().await;
        let sut =
            client_against(&server, "203.0.113.3", OPERATOR_WITHOUT_FLAGS)
                .await;

        let facts = sut.lookup("203.0.113.3".parse().unwrap()).await.unwrap();

        assert_eq!(facts.flags, BTreeSet::new());
        assert_eq!(facts.operator.as_deref(), Some("Snowd"));
    }

    #[tokio::test]
    async fn api_key_is_encoded_as_a_query_parameter() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/203.0.113.1"))
            .and(query_param("key", "a+b&c"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(CLEAN_HOSTING),
            )
            .mount(&server)
            .await;
        let sut = ProxycheckClient {
            http: reqwest::Client::new(),
            api_key: Some(
                ProxycheckApiKey::try_from("a+b&c".to_string()).unwrap(),
            ),
            base_url: server.uri(),
        };

        let facts = sut.lookup("203.0.113.1".parse().unwrap()).await.unwrap();

        assert_eq!(facts.risk.map(RiskScore::value), Some(33));
    }

    #[tokio::test]
    async fn a_denied_status_is_a_quota_exceeded_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/203.0.113.3"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"status": "denied"})),
            )
            .mount(&server)
            .await;
        let sut = ProxycheckClient {
            http: reqwest::Client::new(),
            api_key: None,
            base_url: server.uri(),
        };

        let err = sut
            .lookup("203.0.113.3".parse().unwrap())
            .await
            .unwrap_err();

        assert!(matches!(err, ProxycheckError::QuotaExceeded), "{err:?}");
    }

    #[tokio::test]
    async fn a_response_without_an_entry_for_the_ip_is_a_missing_entry_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/203.0.113.7"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"status": "ok"})),
            )
            .mount(&server)
            .await;
        let sut = ProxycheckClient {
            http: reqwest::Client::new(),
            api_key: None,
            base_url: server.uri(),
        };

        let err = sut
            .lookup("203.0.113.7".parse().unwrap())
            .await
            .unwrap_err();

        assert!(
            matches!(
                err,
                ProxycheckError::MissingEntry { ip }
                    if ip == Ipv4Addr::new(203, 0, 113, 7)
            ),
            "{err:?}"
        );
    }

    /// Without `detections` the flags used to default to `false`, and the
    /// address passed every reputation gate as clean.
    #[tokio::test]
    async fn an_entry_without_detections_is_a_malformed_response() {
        let server = MockServer::start().await;
        let sut = client_against(
            &server,
            "203.0.113.8",
            r#"{"status": "ok", "203.0.113.8": {"operator": null}}"#,
        )
        .await;

        let err = sut
            .lookup("203.0.113.8".parse().unwrap())
            .await
            .unwrap_err();

        assert!(
            matches!(
                err,
                ProxycheckError::MalformedEntry { ip, .. }
                    if ip == Ipv4Addr::new(203, 0, 113, 8)
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_detection_flag_missing_from_the_entry_is_a_malformed_response() {
        let server = MockServer::start().await;
        let sut = client_against(
            &server,
            "203.0.113.8",
            r#"{"status": "ok", "203.0.113.8": {"detections": {
                "proxy": false, "vpn": true, "compromised": false,
                "scraper": false, "anonymous": false, "risk": 10}}}"#,
        )
        .await;

        let err = sut
            .lookup("203.0.113.8".parse().unwrap())
            .await
            .unwrap_err();

        assert!(
            matches!(err, ProxycheckError::MalformedEntry { .. }),
            "{err:?}"
        );
    }

    /// A risk above 100 used to read as "risk unknown".
    #[tokio::test]
    async fn a_risk_above_one_hundred_is_an_out_of_range_error() {
        let server = MockServer::start().await;
        let sut = client_against(
            &server,
            "203.0.113.8",
            r#"{"status": "ok", "203.0.113.8": {"detections": {
                "proxy": false, "vpn": false, "compromised": false,
                "scraper": false, "tor": false, "anonymous": false,
                "risk": 150}}}"#,
        )
        .await;

        let err = sut
            .lookup("203.0.113.8".parse().unwrap())
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "proxycheck.io entry for 203.0.113.8 has an out-of-range risk score"
        );
        assert_eq!(
            std::error::Error::source(&err).map(ToString::to_string),
            Some("risk score must be between 0 and 100, got 150".to_string())
        );
    }

    #[tokio::test]
    async fn an_entry_without_a_risk_score_has_an_unknown_risk() {
        let server = MockServer::start().await;
        let sut = client_against(
            &server,
            "203.0.113.8",
            r#"{"status": "ok", "203.0.113.8": {"detections": {
                "proxy": false, "vpn": false, "compromised": false,
                "scraper": false, "tor": false, "anonymous": false}}}"#,
        )
        .await;

        let facts = sut.lookup("203.0.113.8".parse().unwrap()).await.unwrap();

        assert_eq!(facts.risk, None);
    }

    #[tokio::test]
    async fn a_transport_error_does_not_leak_the_api_key() {
        let sut = ProxycheckClient {
            http: reqwest::Client::new(),
            api_key: Some(
                ProxycheckApiKey::try_from("SECRET123".to_string()).unwrap(),
            ),
            base_url: "http://127.0.0.1:1".into(),
        };

        let err = sut
            .lookup("203.0.113.9".parse().unwrap())
            .await
            .unwrap_err();

        assert!(!err.to_string().contains("SECRET123"), "{err}");
        assert!(!format!("{err:?}").contains("SECRET123"), "{err:?}");
    }
}
