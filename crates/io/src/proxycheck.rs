use crate::credentials::ProxycheckApiKey;
use chip_core::model::{ReputationFacts, RiskScore};
use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxycheckError {
    #[error("proxycheck.io daily query allowance exhausted")]
    QuotaExceeded,
    #[error("proxycheck.io error: {0}")]
    Api(String),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

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

    pub async fn lookup(
        &self,
        ip: Ipv4Addr,
    ) -> Result<ReputationFacts, ProxycheckError> {
        let ip_text = ip.to_string();
        let url = format!("{}/v3/{ip}", self.base_url);
        let mut request = self.http.get(&url);
        if let Some(key) = &self.api_key {
            request = request.query(&[("key", key.expose())]);
        }
        // reqwest errors print the URL, which carries the key: strip it.
        let response =
            request.send().await.map_err(reqwest::Error::without_url)?;
        let body: serde_json::Value =
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
        if !body[&ip_text].is_object() {
            return Err(ProxycheckError::Api(format!(
                "no entry for {ip} in the response"
            )));
        }
        let entry = &body[&ip_text];
        let detections = &entry["detections"];
        let get_bool =
            |field: &str| detections[field].as_bool().unwrap_or(false);
        Ok(ReputationFacts {
            vpn: get_bool("vpn"),
            proxy: get_bool("proxy"),
            tor: get_bool("tor"),
            compromised: get_bool("compromised"),
            anonymous: get_bool("anonymous"),
            scraper: get_bool("scraper"),
            risk: detections["risk"]
                .as_u64()
                .and_then(|risk| RiskScore::try_from(risk).ok()),
            operator: entry["operator"].as_str().map(str::to_string),
        })
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
            "operator": "Snowd",
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
        let client =
            client_against(&server, "203.0.113.1", CLEAN_HOSTING).await;

        let facts =
            client.lookup("203.0.113.1".parse().unwrap()).await.unwrap();

        assert!(!facts.vpn && !facts.proxy && !facts.tor && !facts.compromised);
        assert_eq!(facts.risk.map(RiskScore::value), Some(33));
        assert_eq!(facts.operator, None);
    }

    #[tokio::test]
    async fn a_named_vpn_operator_is_read_into_the_operator_field() {
        let server = MockServer::start().await;
        let client =
            client_against(&server, "203.0.113.2", NAMED_OPERATOR).await;

        let facts =
            client.lookup("203.0.113.2".parse().unwrap()).await.unwrap();

        assert!(facts.vpn);
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
        let client = ProxycheckClient {
            http: reqwest::Client::new(),
            api_key: None,
            base_url: server.uri(),
        };

        let err = client
            .lookup("203.0.113.3".parse().unwrap())
            .await
            .unwrap_err();

        assert!(matches!(err, ProxycheckError::QuotaExceeded), "{err:?}");
    }

    #[tokio::test]
    async fn a_response_without_an_entry_for_the_ip_is_an_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/203.0.113.7"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"status": "ok"})),
            )
            .mount(&server)
            .await;
        let client = ProxycheckClient {
            http: reqwest::Client::new(),
            api_key: None,
            base_url: server.uri(),
        };

        let err = client
            .lookup("203.0.113.7".parse().unwrap())
            .await
            .unwrap_err();

        assert!(
            matches!(
                err,
                ProxycheckError::Api(ref detail)
                    if detail == "no entry for 203.0.113.7 in the response"
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_transport_error_does_not_leak_the_api_key() {
        let client = ProxycheckClient {
            http: reqwest::Client::new(),
            api_key: Some(
                ProxycheckApiKey::try_from("SECRET123".to_string()).unwrap(),
            ),
            base_url: "http://127.0.0.1:1".into(),
        };

        let err = client
            .lookup("203.0.113.9".parse().unwrap())
            .await
            .unwrap_err();

        assert!(!err.to_string().contains("SECRET123"), "{err}");
        assert!(!format!("{err:?}").contains("SECRET123"), "{err:?}");
    }
}
