use super::types::RawMeasurement;
use crate::credentials::GlobalpingToken;
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GlobalpingError {
    #[error("globalping request failed: {0}")]
    Http(String),
    #[error(
        "globalping rate limit exceeded (try again next hour, or set GLOBALPING_TOKEN)"
    )]
    RateLimited,
    #[error("globalping found no suitable probes for this request")]
    NoSuitableProbes,
    #[error("measurement did not finish within the deadline")]
    Timeout,
    #[error("globalping returned an empty measurement id")]
    EmptyMeasurementId,
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MeasurementId(String);

impl MeasurementId {
    fn new(value: String) -> Result<Self, GlobalpingError> {
        if value.is_empty() {
            Err(GlobalpingError::EmptyMeasurementId)
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MeasurementId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub struct MeasurementKind(MeasurementKindInner);

enum MeasurementKindInner {
    Ping { target: Ipv4Addr },
    Https { target: Ipv4Addr, port: NonZeroU16 },
}

impl MeasurementKind {
    pub const fn ping(target: Ipv4Addr) -> Self {
        Self(MeasurementKindInner::Ping { target })
    }

    pub const fn https(target: Ipv4Addr, port: NonZeroU16) -> Self {
        Self(MeasurementKindInner::Https { target, port })
    }

    fn type_target_options(&self) -> (&'static str, String, serde_json::Value) {
        match &self.0 {
            MeasurementKindInner::Ping { target } => {
                ("ping", target.to_string(), serde_json::json!({"packets": 10}))
            }
            MeasurementKindInner::Https { target, port } => (
                "http",
                target.to_string(),
                serde_json::json!({"protocol": "HTTPS", "port": port.get(), "request": {"path": "/", "method": "GET"}}),
            ),
        }
    }
}

pub struct Locations(LocationsInner);

enum LocationsInner {
    Ru {
        eyeball_limit: u8,
        datacenter_limit: u8,
    },
    Reuse(MeasurementId),
}

impl Locations {
    pub const fn ru(
        eyeball_limit: u8,
        datacenter_limit: u8,
    ) -> Result<Self, InvalidProbeDistribution> {
        if eyeball_limit == 0 && datacenter_limit == 0 {
            Err(InvalidProbeDistribution)
        } else {
            Ok(Self(LocationsInner::Ru {
                eyeball_limit,
                datacenter_limit,
            }))
        }
    }

    pub const fn reuse(id: MeasurementId) -> Self {
        Self(LocationsInner::Reuse(id))
    }

    fn to_value(&self) -> serde_json::Value {
        match &self.0 {
            LocationsInner::Ru {
                eyeball_limit,
                datacenter_limit,
            } => serde_json::json!([
                {"country": "RU", "tags": ["eyeball-network"], "limit": eyeball_limit},
                {"country": "RU", "tags": ["datacenter-network"], "limit": datacenter_limit}
            ]),
            LocationsInner::Reuse(id) => {
                serde_json::Value::String(id.to_string())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("eyeball and datacenter probe limits cannot both be zero")]
pub struct InvalidProbeDistribution;

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct Limits {
    pub limit: u32,
    pub remaining: u32,
}

#[derive(Clone)]
pub struct GlobalpingClient {
    http: reqwest::Client,
    base_url: String,
    token: Option<GlobalpingToken>,
}

impl GlobalpingClient {
    pub fn new(http: reqwest::Client, token: Option<GlobalpingToken>) -> Self {
        Self {
            http,
            base_url: "https://api.globalping.io".to_string(),
            token,
        }
    }

    fn request(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(token) => req.bearer_auth(token.expose()),
            None => req,
        }
    }

    pub async fn create(
        &self,
        kind: &MeasurementKind,
        locations: &Locations,
    ) -> Result<MeasurementId, GlobalpingError> {
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
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                return Err(GlobalpingError::RateLimited);
            }
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
        MeasurementId::new(resp.json::<Created>().await?.id)
    }

    pub async fn poll_until_finished(
        &self,
        id: &MeasurementId,
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
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ip(value: &str) -> Ipv4Addr {
        value.parse().unwrap()
    }

    fn measurement_id(value: &str) -> MeasurementId {
        MeasurementId::new(value.to_string()).unwrap()
    }

    #[test]
    fn an_empty_measurement_id_is_rejected() {
        let error = MeasurementId::new(String::new()).unwrap_err();

        assert!(matches!(error, GlobalpingError::EmptyMeasurementId));
    }

    #[test]
    fn an_empty_probe_distribution_is_rejected() {
        let error = Locations::ru(0, 0).err().unwrap();

        assert_eq!(error, InvalidProbeDistribution);
    }

    fn client_against(server: &MockServer) -> GlobalpingClient {
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
    async fn create_with_ru_locations_sends_the_expected_body_and_returns_the_id()
     {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/measurements"))
            .respond_with(
                ResponseTemplate::new(202)
                    .set_body_json(serde_json::json!({"id": "meas-1"})),
            )
            .mount(&server)
            .await;
        let client = client_against(&server);

        let id = client
            .create(
                &MeasurementKind::ping(ip("192.0.2.1")),
                &Locations::ru(8, 4).unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(id.as_str(), "meas-1");
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
                ResponseTemplate::new(202)
                    .set_body_json(serde_json::json!({"id": "meas-2"})),
            )
            .mount(&server)
            .await;
        let client = client_against(&server);

        let id = client
            .create(
                &MeasurementKind::ping(ip("192.0.2.2")),
                &Locations::reuse(measurement_id("meas-1")),
            )
            .await
            .unwrap();

        assert_eq!(id.as_str(), "meas-2");
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
                ResponseTemplate::new(202)
                    .set_body_json(serde_json::json!({"id": "meas-3"})),
            )
            .mount(&server)
            .await;
        let client = client_against(&server);

        client
            .create(
                &MeasurementKind::https(
                    ip("192.0.2.1"),
                    NonZeroU16::new(443).unwrap(),
                ),
                &Locations::reuse(measurement_id("meas-1")),
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
        let client = client_against(&server);

        let err = client
            .create(
                &MeasurementKind::ping(ip("192.0.2.1")),
                &Locations::reuse(measurement_id("x")),
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
        let client = client_against(&server);

        let err = client
            .create(
                &MeasurementKind::ping(ip("192.0.2.1")),
                &Locations::reuse(measurement_id("x")),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, GlobalpingError::NoSuitableProbes), "{err:?}");
    }

    #[tokio::test]
    async fn poll_until_finished_returns_as_soon_as_status_is_not_in_progress()
    {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/measurements/meas-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"id": "meas-1", "status": "finished", "results": []}),
            ))
            .mount(&server)
            .await;
        let client = client_against(&server);

        let measurement = client
            .poll_until_finished(
                &measurement_id("meas-1"),
                Duration::from_secs(5),
            )
            .await
            .unwrap();

        assert_eq!(measurement.status, "finished");
    }

    #[tokio::test]
    async fn poll_until_finished_times_out_on_a_measurement_stuck_in_progress()
    {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/measurements/meas-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"id": "meas-1", "status": "in-progress", "results": []}),
            ))
            .mount(&server)
            .await;
        let client = client_against(&server);

        let err = client
            .poll_until_finished(
                &measurement_id("meas-1"),
                Duration::from_millis(50),
            )
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
        let client = client_against(&server);

        let limits = client.limits().await.unwrap();

        assert_eq!(
            limits,
            Limits {
                limit: 250,
                remaining: 103
            }
        );
    }

    #[tokio::test]
    async fn an_authenticated_request_sends_the_token_as_a_bearer_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/limits"))
            .and(header("authorization", "Bearer token-value"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "rateLimit": {"measurements": {"create": {"limit": 250, "remaining": 103}}}
            })))
            .mount(&server)
            .await;
        let sut = GlobalpingClient {
            http: reqwest::Client::new(),
            base_url: server.uri(),
            token: Some(
                GlobalpingToken::try_from("token-value".to_string()).unwrap(),
            ),
        };

        let limits = sut.limits().await.unwrap();

        assert_eq!(limits.remaining, 103);
    }

    #[tokio::test]
    async fn a_transport_error_does_not_leak_the_bearer_token() {
        let sut = GlobalpingClient {
            http: reqwest::Client::new(),
            base_url: "http://127.0.0.1:1".into(),
            token: Some(
                GlobalpingToken::try_from("SECRET123".to_string()).unwrap(),
            ),
        };

        let error = sut.limits().await.unwrap_err();
        let displayed = error.to_string();
        let debugged = format!("{error:?}");

        assert!(!displayed.contains("SECRET123"), "{displayed}");
        assert!(!debugged.contains("SECRET123"), "{debugged}");
    }
}
