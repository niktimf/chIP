use super::types::{MeasurementStatus, RawMeasurement};
use crate::credentials::GlobalpingToken;
use chip_core::model::{HttpProbeOutcome, PingSample};
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
    Timeout(#[source] tokio::time::error::Elapsed),
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

#[derive(Debug)]
pub struct MeasurementKind(MeasurementKindInner);

#[derive(Debug)]
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

#[derive(Debug)]
pub struct Locations(LocationsInner);

#[derive(Debug)]
enum LocationsInner {
    Ru {
        eyeball_limit: u8,
        datacenter_limit: u8,
    },
    Reuse(MeasurementId),
}

impl Locations {
    /// # Errors
    ///
    /// Returns `InvalidProbeDistribution` when both limits are zero.
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

#[derive(Debug, Clone)]
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

    /// # Errors
    ///
    /// Returns `GlobalpingError` when the request fails, the API answers with
    /// a rate limit, no suitable probes or another non-success status, or the
    /// measurement id is empty.
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
        let created: Created =
            Self::checked(resp, "create measurement")?.json().await?;
        MeasurementId::new(created.id)
    }

    /// Turns a non-success status into a typed error before the body is
    /// decoded, so a 429 or 5xx does not surface as a JSON decode error.
    fn checked(
        resp: reqwest::Response,
        operation: &str,
    ) -> Result<reqwest::Response, GlobalpingError> {
        match resp.status() {
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                Err(GlobalpingError::RateLimited)
            }
            reqwest::StatusCode::UNPROCESSABLE_ENTITY => {
                Err(GlobalpingError::NoSuitableProbes)
            }
            status if !status.is_success() => Err(GlobalpingError::Http(
                format!("{operation}: HTTP {status}"),
            )),
            _ => Ok(resp),
        }
    }

    /// Waits for a ping measurement and returns one sample per probe, in
    /// probe order: `None` where the probe got no usable reply. Measurements
    /// that reuse the same probe set line up index by index.
    ///
    /// # Errors
    ///
    /// Returns `GlobalpingError::Timeout` when the measurement does not finish
    /// before `deadline`, and the request errors of `create` otherwise.
    pub async fn poll_ping(
        &self,
        id: &MeasurementId,
        deadline: Duration,
    ) -> Result<Vec<Option<PingSample>>, GlobalpingError> {
        let measurement = self.poll_until_finished(id, deadline).await?;
        Ok(measurement.ping_samples())
    }

    /// Waits for an HTTPS measurement and returns one outcome per probe, in
    /// probe order.
    ///
    /// # Errors
    ///
    /// Returns `GlobalpingError::Timeout` when the measurement does not finish
    /// before `deadline`, and the request errors of `create` otherwise.
    pub async fn poll_https(
        &self,
        id: &MeasurementId,
        deadline: Duration,
    ) -> Result<Vec<HttpProbeOutcome>, GlobalpingError> {
        let measurement = self.poll_until_finished(id, deadline).await?;
        Ok(measurement.https_outcomes())
    }

    async fn poll_until_finished(
        &self,
        id: &MeasurementId,
        deadline: Duration,
    ) -> Result<RawMeasurement, GlobalpingError> {
        tokio::time::timeout(deadline, self.poll(id))
            .await
            .map_err(GlobalpingError::Timeout)?
    }

    async fn poll(
        &self,
        id: &MeasurementId,
    ) -> Result<RawMeasurement, GlobalpingError> {
        loop {
            let resp = self
                .request(
                    self.http
                        .get(format!("{}/v1/measurements/{id}", self.base_url)),
                )
                .send()
                .await?;
            let measurement: RawMeasurement =
                Self::checked(resp, "poll measurement")?.json().await?;
            match measurement.status {
                MeasurementStatus::InProgress => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                MeasurementStatus::Finished
                | MeasurementStatus::Failed
                | MeasurementStatus::Unknown => return Ok(measurement),
            }
        }
    }

    /// # Errors
    ///
    /// Returns `GlobalpingError` when the request fails, the API answers with
    /// a non-success status, or the body cannot be decoded.
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
        let body: Body = Self::checked(resp, "read limits")?.json().await?;
        Ok(body.rate_limit.measurements.create)
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
        let sut = client_against(&server);

        let id = sut
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
        let sut = client_against(&server);

        let id = sut
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
        let sut = client_against(&server);

        sut.create(
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
        let sut = client_against(&server);

        let err = sut
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
        let sut = client_against(&server);

        let err = sut
            .create(
                &MeasurementKind::ping(ip("192.0.2.1")),
                &Locations::reuse(measurement_id("x")),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, GlobalpingError::NoSuitableProbes), "{err:?}");
    }

    #[tokio::test]
    async fn a_finished_ping_measurement_yields_one_sample_per_probe() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/measurements/meas-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"id": "meas-1", "status": "finished", "results": [
                    {"probe": {"city": "Moscow", "network": "Timeweb"},
                     "result": {"status": "finished", "stats": {"min": 20.0, "loss": 0.0}}},
                    {"probe": {"city": "Kursk", "network": "Kurier"},
                     "result": {"status": "failed"}}
                ]}),
            ))
            .mount(&server)
            .await;
        let sut = client_against(&server);

        let samples = sut
            .poll_ping(&measurement_id("meas-1"), Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].unwrap().rtt(), Duration::from_millis(20));
        assert_eq!(samples[1], None);
    }

    #[tokio::test]
    async fn a_finished_https_measurement_yields_one_outcome_per_probe() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/measurements/meas-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"id": "meas-1", "status": "finished", "results": [
                    {"probe": {"city": "Moscow"},
                     "result": {"status": "finished", "statusCode": 200}},
                    {"probe": {"city": "Kursk"},
                     "result": {"status": "failed"}}
                ]}),
            ))
            .mount(&server)
            .await;
        let sut = client_against(&server);

        let outcomes = sut
            .poll_https(&measurement_id("meas-1"), Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(outcomes, [HttpProbeOutcome::Ok, HttpProbeOutcome::Failed]);
    }

    #[tokio::test]
    async fn polling_stops_on_a_measurement_status_the_client_does_not_model() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/measurements/meas-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"id": "meas-1", "status": "cancelled", "results": []}),
            ))
            .mount(&server)
            .await;
        let sut = client_against(&server);

        let samples = sut
            .poll_ping(&measurement_id("meas-1"), Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(samples, []);
    }

    #[tokio::test]
    async fn a_measurement_stuck_in_progress_times_out() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/measurements/meas-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"id": "meas-1", "status": "in-progress", "results": []}),
            ))
            .mount(&server)
            .await;
        let sut = client_against(&server);

        let err = sut
            .poll_ping(&measurement_id("meas-1"), Duration::from_millis(50))
            .await
            .unwrap_err();

        assert!(matches!(err, GlobalpingError::Timeout(_)), "{err:?}");
    }

    #[tokio::test]
    async fn a_429_while_polling_maps_to_rate_limited() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/measurements/meas-1"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let sut = client_against(&server);

        let err = sut
            .poll_ping(&measurement_id("meas-1"), Duration::from_secs(5))
            .await
            .unwrap_err();

        assert!(matches!(err, GlobalpingError::RateLimited), "{err:?}");
    }

    #[tokio::test]
    async fn a_server_error_from_limits_is_an_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/limits"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let sut = client_against(&server);

        let err = sut.limits().await.unwrap_err();

        assert!(matches!(err, GlobalpingError::Http(_)), "{err:?}");
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
        let sut = client_against(&server);

        let limits = sut.limits().await.unwrap();

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
    #[tokio::test]
    async fn a_finished_response_arriving_after_the_deadline_is_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"id": "slow", "status": "finished", "results": []}))
                .set_delay(Duration::from_millis(300)))
            .mount(&server).await;
        let result = client_against(&server)
            .poll_ping(&measurement_id("slow"), Duration::from_millis(50))
            .await;
        assert!(matches!(result, Err(GlobalpingError::Timeout(_))));
    }
}
