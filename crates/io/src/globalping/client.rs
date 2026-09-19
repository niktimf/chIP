use super::types::RawMeasurement;
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GlobalpingError {
    #[error("globalping request failed: {0}")]
    Http(String),
    #[error("globalping rate limit exceeded (try again next hour, or set GLOBALPING_TOKEN)")]
    RateLimited,
    #[error("globalping found no suitable probes for this request")]
    NoSuitableProbes,
    #[error("measurement did not finish within the deadline")]
    Timeout,
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

pub enum MeasurementKind {
    Ping {
        target: String,
        packets: u8,
    },
    Https {
        target: String,
        port: u16,
        path: String,
    },
}

impl MeasurementKind {
    fn type_target_options(&self) -> (&'static str, &str, serde_json::Value) {
        match self {
            MeasurementKind::Ping { target, packets } => (
                "ping",
                target.as_str(),
                serde_json::json!({"packets": packets}),
            ),
            MeasurementKind::Https { target, port, path } => (
                "http",
                target.as_str(),
                serde_json::json!({"protocol": "HTTPS", "port": port, "request": {"path": path, "method": "GET"}}),
            ),
        }
    }
}

pub enum Locations {
    Ru {
        eyeball_limit: u8,
        datacenter_limit: u8,
    },
    Reuse(String),
}

impl Locations {
    fn to_value(&self) -> serde_json::Value {
        match self {
            Locations::Ru {
                eyeball_limit,
                datacenter_limit,
            } => serde_json::json!([
                {"country": "RU", "tags": ["eyeball-network"], "limit": eyeball_limit},
                {"country": "RU", "tags": ["datacenter-network"], "limit": datacenter_limit}
            ]),
            Locations::Reuse(id) => serde_json::Value::String(id.clone()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct Limits {
    pub limit: u32,
    pub remaining: u32,
}

pub struct GlobalpingClient {
    http: reqwest::Client,
    base_url: String,
    token: Option<String>,
}

impl GlobalpingClient {
    pub fn new(http: reqwest::Client, token: Option<String>) -> Self {
        Self {
            http,
            base_url: "https://api.globalping.io".to_string(),
            token,
        }
    }

    fn request(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    pub async fn create(
        &self,
        kind: &MeasurementKind,
        locations: &Locations,
    ) -> Result<String, GlobalpingError> {
        #[derive(Deserialize)]
        struct Created {
            id: String,
        }
        let (typ, target, options) = kind.type_target_options();
        let body = serde_json::json!({"type": typ, "target": target, "locations": locations.to_value(), "measurementOptions": options});
        let resp = self
            .request(
                self.http
                    .post(format!("{}/v1/measurements", self.base_url))
                    .json(&body),
            )
            .send()
            .await?;
        match resp.status() {
            reqwest::StatusCode::TOO_MANY_REQUESTS => return Err(GlobalpingError::RateLimited),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY => {
                return Err(GlobalpingError::NoSuitableProbes);
            }
            s if !s.is_success() => {
                return Err(GlobalpingError::Http(format!(
                    "create measurement: HTTP {s}"
                )));
            }
            _ => {}
        }
        Ok(resp.json::<Created>().await?.id)
    }

    pub async fn poll_until_finished(
        &self,
        id: &str,
        deadline: Duration,
    ) -> Result<RawMeasurement, GlobalpingError> {
        let start = tokio::time::Instant::now();
        loop {
            let measurement: RawMeasurement = self
                .request(
                    self.http
                        .get(format!("{}/v1/measurements/{id}", self.base_url)),
                )
                .send()
                .await?
                .json()
                .await?;
            if measurement.status != "in-progress" {
                return Ok(measurement);
            }
            if start.elapsed() >= deadline {
                return Err(GlobalpingError::Timeout);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn limits(&self) -> Result<Limits, GlobalpingError> {
        #[derive(Deserialize)]
        struct Body {
            #[serde(rename = "rateLimit")]
            rate_limit: RateLimit,
        }
        #[derive(Deserialize)]
        struct RateLimit {
            measurements: Measurements,
        }
        #[derive(Deserialize)]
        struct Measurements {
            create: Limits,
        }
        let resp = self
            .request(self.http.get(format!("{}/v1/limits", self.base_url)))
            .send()
            .await?;
        Ok(resp.json::<Body>().await?.rate_limit.measurements.create)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Kept async so call sites match the brief's `.await` usage.
    #[allow(clippy::unused_async)]
    async fn client_against(server: &MockServer) -> GlobalpingClient {
        GlobalpingClient {
            http: reqwest::Client::new(),
            base_url: server.uri(),
            token: None,
        }
    }

    /// The body of the single request the server received, parsed as JSON.
    /// Asserting on parsed JSON (rather than a matcher in `Mock::given`)
    /// avoids depending on a wiremock body-matching helper beyond the exact
    /// ones this plan has confirmed exist (`method`, `path`).
    async fn received_body(server: &MockServer) -> serde_json::Value {
        let requests = server
            .received_requests()
            .await
            .expect("request recording must be on (default)");
        assert_eq!(
            requests.len(),
            1,
            "expected exactly one request, got {}",
            requests.len()
        );
        serde_json::from_slice(&requests[0].body).unwrap()
    }

    #[tokio::test]
    async fn create_with_ru_locations_sends_the_expected_body_and_returns_the_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/measurements"))
            .respond_with(
                ResponseTemplate::new(202).set_body_json(serde_json::json!({"id": "meas-1"})),
            )
            .mount(&server)
            .await;
        let client = client_against(&server).await;

        let id = client
            .create(
                &MeasurementKind::Ping {
                    target: "192.0.2.1".into(),
                    packets: 10,
                },
                &Locations::Ru {
                    eyeball_limit: 8,
                    datacenter_limit: 4,
                },
            )
            .await
            .unwrap();

        assert_eq!(id, "meas-1");
        let body = received_body(&server).await;
        assert_eq!(body["type"], "ping");
        assert_eq!(body["target"], "192.0.2.1");
        assert_eq!(
            body["locations"],
            serde_json::json!([
                {"country": "RU", "tags": ["eyeball-network"], "limit": 8},
                {"country": "RU", "tags": ["datacenter-network"], "limit": 4}
            ])
        );
        assert_eq!(body["measurementOptions"]["packets"], 10);
    }

    #[tokio::test]
    async fn create_reusing_a_previous_measurement_sends_a_bare_id_string() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/measurements"))
            .respond_with(
                ResponseTemplate::new(202).set_body_json(serde_json::json!({"id": "meas-2"})),
            )
            .mount(&server)
            .await;
        let client = client_against(&server).await;

        let id = client
            .create(
                &MeasurementKind::Ping {
                    target: "192.0.2.2".into(),
                    packets: 10,
                },
                &Locations::Reuse("meas-1".into()),
            )
            .await
            .unwrap();

        assert_eq!(id, "meas-2");
        let body = received_body(&server).await;
        // A bare string, not `{"id": "meas-1"}` — confirmed against the live
        // API during the 2026-09-15 calibration spike.
        assert_eq!(body["locations"], serde_json::json!("meas-1"));
    }

    #[tokio::test]
    async fn create_https_sends_the_expected_measurement_options() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/measurements"))
            .respond_with(
                ResponseTemplate::new(202).set_body_json(serde_json::json!({"id": "meas-3"})),
            )
            .mount(&server)
            .await;
        let client = client_against(&server).await;

        client
            .create(
                &MeasurementKind::Https {
                    target: "192.0.2.1".into(),
                    port: 443,
                    path: "/".into(),
                },
                &Locations::Reuse("meas-1".into()),
            )
            .await
            .unwrap();

        let body = received_body(&server).await;
        assert_eq!(body["type"], "http");
        assert_eq!(
            body["measurementOptions"],
            serde_json::json!({"protocol": "HTTPS", "port": 443, "request": {"path": "/", "method": "GET"}})
        );
    }

    #[tokio::test]
    async fn a_429_response_maps_to_rate_limited() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/measurements"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let client = client_against(&server).await;

        let err = client
            .create(
                &MeasurementKind::Ping {
                    target: "192.0.2.1".into(),
                    packets: 10,
                },
                &Locations::Reuse("x".into()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, GlobalpingError::RateLimited), "{err:?}");
    }

    #[tokio::test]
    async fn a_422_response_maps_to_no_suitable_probes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/measurements"))
            .respond_with(ResponseTemplate::new(422))
            .mount(&server)
            .await;
        let client = client_against(&server).await;

        let err = client
            .create(
                &MeasurementKind::Ping {
                    target: "192.0.2.1".into(),
                    packets: 10,
                },
                &Locations::Reuse("x".into()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, GlobalpingError::NoSuitableProbes), "{err:?}");
    }

    #[tokio::test]
    async fn poll_until_finished_returns_as_soon_as_status_is_not_in_progress() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/measurements/meas-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"id": "meas-1", "status": "finished", "results": []}),
            ))
            .mount(&server)
            .await;
        let client = client_against(&server).await;

        let measurement = client
            .poll_until_finished("meas-1", Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(measurement.status, "finished");
    }

    #[tokio::test]
    async fn poll_until_finished_times_out_on_a_measurement_stuck_in_progress() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/measurements/meas-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"id": "meas-1", "status": "in-progress", "results": []}),
            ))
            .mount(&server)
            .await;
        let client = client_against(&server).await;

        let err = client
            .poll_until_finished("meas-1", Duration::from_millis(50))
            .await
            .unwrap_err();

        assert!(matches!(err, GlobalpingError::Timeout), "{err:?}");
    }

    #[tokio::test]
    async fn limits_reads_the_nested_rate_limit_shape() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/limits"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "rateLimit": {"measurements": {"create": {"type": "ip", "limit": 250, "remaining": 103, "reset": 2817}}}
            })))
            .mount(&server)
            .await;
        let client = client_against(&server).await;

        let limits = client.limits().await.unwrap();

        assert_eq!(
            limits,
            Limits {
                limit: 250,
                remaining: 103
            }
        );
    }
}
