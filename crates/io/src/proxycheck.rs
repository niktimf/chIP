use chip_core::model::ReputationFacts;
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
    api_key: Option<String>,
    base_url: String,
}

impl ProxycheckClient {
    pub fn new(http: reqwest::Client, api_key: Option<String>) -> Self {
        Self {
            http,
            api_key,
            base_url: "https://proxycheck.io".to_string(),
        }
    }

    pub async fn lookup(&self, ip: &str) -> Result<ReputationFacts, ProxycheckError> {
        let mut url = format!("{}/v3/{ip}", self.base_url);
        if let Some(key) = &self.api_key {
            url = format!("{url}?key={key}");
        }
        // reqwest errors print the URL, which carries the key: strip it.
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let body: serde_json::Value = response.json().await.map_err(reqwest::Error::without_url)?;
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
        let entry = &body[ip];
        let detections = &entry["detections"];
        let get_bool = |field: &str| detections[field].as_bool().unwrap_or(false);
        Ok(ReputationFacts {
            vpn: get_bool("vpn"),
            proxy: get_bool("proxy"),
            tor: get_bool("tor"),
            compromised: get_bool("compromised"),
            anonymous: get_bool("anonymous"),
            scraper: get_bool("scraper"),
            risk: detections["risk"]
                .as_u64()
                .and_then(|r| u32::try_from(r).ok()),
            operator: entry["operator"].as_str().map(str::to_string),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
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

    async fn client_against(server: &MockServer, ip: &str, body: &str) -> ProxycheckClient {
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
        let client = client_against(&server, "203.0.113.1", CLEAN_HOSTING).await;

        let facts = client.lookup("203.0.113.1").await.unwrap();

        assert!(!facts.vpn && !facts.proxy && !facts.tor && !facts.compromised);
        assert_eq!(facts.risk, Some(33));
        assert_eq!(facts.operator, None);
    }

    #[tokio::test]
    async fn a_named_vpn_operator_is_read_into_the_operator_field() {
        let server = MockServer::start().await;
        let client = client_against(&server, "203.0.113.2", NAMED_OPERATOR).await;

        let facts = client.lookup("203.0.113.2").await.unwrap();

        assert!(facts.vpn);
        assert_eq!(facts.operator.as_deref(), Some("Snowd"));
    }

    #[tokio::test]
    async fn a_denied_status_is_a_quota_exceeded_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v3/203.0.113.3"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"status": "denied"})),
            )
            .mount(&server)
            .await;
        let client = ProxycheckClient {
            http: reqwest::Client::new(),
            api_key: None,
            base_url: server.uri(),
        };

        let err = client.lookup("203.0.113.3").await.unwrap_err();

        assert!(matches!(err, ProxycheckError::QuotaExceeded), "{err:?}");
    }

    #[tokio::test]
    async fn a_transport_error_does_not_leak_the_api_key() {
        let client = ProxycheckClient {
            http: reqwest::Client::new(),
            api_key: Some("SECRET123".into()),
            base_url: "http://127.0.0.1:1".into(),
        };

        let err = client.lookup("203.0.113.9").await.unwrap_err();

        assert!(!err.to_string().contains("SECRET123"), "{err}");
        assert!(!format!("{err:?}").contains("SECRET123"), "{err:?}");
    }
}
