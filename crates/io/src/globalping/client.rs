use super::locations::{Locations, LocationsBody};
use super::types::{MeasurementStatus, RawMeasurement};
use crate::credentials::GlobalpingToken;
use chip_core::checks::globalping::latency::PingSample;
use chip_core::checks::globalping::reach::HttpProbeOutcome;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GlobalpingError {
    #[error("globalping request failed: {operation}: HTTP {status}")]
    Status {
        operation: &'static str,
        status: StatusCode,
    },
    #[error("globalping request failed: {operation}")]
    Request {
        operation: &'static str,
        #[source]
        source: reqwest::Error,
    },
    /// The hourly quota is used up. The message names no remedy: raising
    /// the quota is a setting of the application, not of this client.
    #[error("globalping rate limit exceeded")]
    RateLimited,
    #[error("globalping found no suitable probes for this request")]
    NoSuitableProbes,
    #[error("measurement did not finish within the deadline")]
    Timeout(#[source] tokio::time::error::Elapsed),
    #[error("globalping returned an empty measurement id")]
    EmptyMeasurementId,
}

impl GlobalpingError {
    /// Wraps a transport or decoding error of `operation`.
    fn request(operation: &'static str) -> impl FnOnce(reqwest::Error) -> Self {
        move |source| Self::Request { operation, source }
    }
}

/// Marker for a ping measurement: its id is polled with
/// [`GlobalpingClient::poll_ping`]. It has no values and only tags
/// [`MeasurementId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ping {}

/// Marker for an HTTPS measurement: its id is polled with
/// [`GlobalpingClient::poll_https`]. It has no values and only tags
/// [`MeasurementId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Https {}

/// Id of a created measurement, tagged with the kind it was created as.
///
/// Only [`GlobalpingClient::create_ping`] and
/// [`GlobalpingClient::create_https`] produce ids, so the tag always matches
/// the measurement type sent to Globalping, and an id is polled only by the
/// parser of its own kind:
///
/// ```
/// use chip_io::globalping::{GlobalpingClient, Https, MeasurementId};
/// use std::time::Duration;
///
/// async fn outcomes(client: &GlobalpingClient, id: &MeasurementId<Https>) {
///     let _ = client.poll_https(id, Duration::from_secs(90)).await;
/// }
/// ```
///
/// An HTTPS id does not compile as an argument of `poll_ping`:
///
/// ```compile_fail
/// use chip_io::globalping::{GlobalpingClient, Https, MeasurementId};
/// use std::time::Duration;
///
/// async fn samples(client: &GlobalpingClient, id: &MeasurementId<Https>) {
///     let _ = client.poll_ping(id, Duration::from_secs(90)).await;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MeasurementId<K>(String, PhantomData<K>);

impl<K> MeasurementId<K> {
    fn new(value: String) -> Result<Self, GlobalpingError> {
        if value.is_empty() {
            Err(GlobalpingError::EmptyMeasurementId)
        } else {
            Ok(Self(value, PhantomData))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<K> std::fmt::Display for MeasurementId<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Body of `POST /v1/measurements`.
#[derive(Serialize)]
struct CreateMeasurement<'a> {
    locations: LocationsBody<'a>,
    #[serde(flatten)]
    measurement: MeasurementRequest,
    target: Ipv4Addr,
}

/// The measurement type together with its options, so a type is never sent
/// with the options of another.
#[derive(Serialize)]
#[serde(tag = "type", content = "measurementOptions", rename_all = "lowercase")]
enum MeasurementRequest {
    Ping { packets: u8 },
    Http(HttpOptions),
}

#[derive(Serialize)]
struct HttpOptions {
    port: NonZeroU16,
    protocol: &'static str,
    request: HttpRequest,
}

#[derive(Serialize)]
struct HttpRequest {
    method: &'static str,
    path: &'static str,
}

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

    /// Starts a ping measurement of `target`: 10 packets from every probe.
    ///
    /// # Errors
    ///
    /// Returns `GlobalpingError` when the request fails, the API answers with
    /// a rate limit, no suitable probes or another non-success status, or the
    /// measurement id is empty.
    pub async fn create_ping(
        &self,
        target: Ipv4Addr,
        locations: &Locations,
    ) -> Result<MeasurementId<Ping>, GlobalpingError> {
        const PACKETS: u8 = 10;
        self.create(
            MeasurementRequest::Ping { packets: PACKETS },
            target,
            locations,
        )
        .await
    }

    /// Starts an HTTPS measurement: `GET /` on `target:port` from every probe.
    ///
    /// # Errors
    ///
    /// The same as [`GlobalpingClient::create_ping`].
    pub async fn create_https(
        &self,
        target: Ipv4Addr,
        port: NonZeroU16,
        locations: &Locations,
    ) -> Result<MeasurementId<Https>, GlobalpingError> {
        let options = HttpOptions {
            port,
            protocol: "HTTPS",
            request: HttpRequest {
                method: "GET",
                path: "/",
            },
        };
        self.create(MeasurementRequest::Http(options), target, locations)
            .await
    }

    /// Sends the request and tags the id with `K`. The caller picks `K` to
    /// match `measurement`; `create_ping` and `create_https` are the only
    /// callers.
    async fn create<K>(
        &self,
        measurement: MeasurementRequest,
        target: Ipv4Addr,
        locations: &Locations,
    ) -> Result<MeasurementId<K>, GlobalpingError> {
        const OPERATION: &str = "create measurement";
        #[derive(Deserialize)]
        struct Created {
            id: String,
        }
        let body = CreateMeasurement {
            locations: locations.body(),
            measurement,
            target,
        };
        let resp = self
            .request(
                self.http
                    .post(format!("{}/v1/measurements", self.base_url))
                    .json(&body),
            )
            .send()
            .await
            .map_err(GlobalpingError::request(OPERATION))?;
        // Only here does 422 mean "no probe matches the locations"; for the
        // other operations it is an ordinary failed status.
        if resp.status() == StatusCode::UNPROCESSABLE_ENTITY {
            return Err(GlobalpingError::NoSuitableProbes);
        }
        let created: Created = Self::checked(resp, OPERATION)?
            .json()
            .await
            .map_err(GlobalpingError::request(OPERATION))?;
        MeasurementId::new(created.id)
    }

    /// Turns a non-success status into a typed error before the body is
    /// decoded, so a 429 or 5xx does not surface as a JSON decode error.
    fn checked(
        resp: reqwest::Response,
        operation: &'static str,
    ) -> Result<reqwest::Response, GlobalpingError> {
        match resp.status() {
            StatusCode::TOO_MANY_REQUESTS => Err(GlobalpingError::RateLimited),
            status if !status.is_success() => {
                Err(GlobalpingError::Status { operation, status })
            }
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
        id: &MeasurementId<Ping>,
        deadline: Duration,
    ) -> Result<Vec<Option<PingSample>>, GlobalpingError> {
        let measurement =
            self.poll_until_finished(id.as_str(), deadline).await?;
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
        id: &MeasurementId<Https>,
        deadline: Duration,
    ) -> Result<Vec<HttpProbeOutcome>, GlobalpingError> {
        let measurement =
            self.poll_until_finished(id.as_str(), deadline).await?;
        Ok(measurement.https_outcomes())
    }

    async fn poll_until_finished(
        &self,
        id: &str,
        deadline: Duration,
    ) -> Result<RawMeasurement, GlobalpingError> {
        tokio::time::timeout(deadline, self.poll(id))
            .await
            .map_err(GlobalpingError::Timeout)?
    }

    async fn poll(&self, id: &str) -> Result<RawMeasurement, GlobalpingError> {
        const OPERATION: &str = "poll measurement";
        /// Pause between two reads of a measurement still in progress.
        const POLL_INTERVAL: Duration = Duration::from_secs(1);
        loop {
            let resp = self
                .request(
                    self.http
                        .get(format!("{}/v1/measurements/{id}", self.base_url)),
                )
                .send()
                .await
                .map_err(GlobalpingError::request(OPERATION))?;
            let measurement: RawMeasurement = Self::checked(resp, OPERATION)?
                .json()
                .await
                .map_err(GlobalpingError::request(OPERATION))?;
            match measurement.status {
                MeasurementStatus::InProgress => {
                    tokio::time::sleep(POLL_INTERVAL).await;
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
        const OPERATION: &str = "read limits";
        let resp = self
            .request(self.http.get(format!("{}/v1/limits", self.base_url)))
            .send()
            .await
            .map_err(GlobalpingError::request(OPERATION))?;
        let body: Body = Self::checked(resp, OPERATION)?
            .json()
            .await
            .map_err(GlobalpingError::request(OPERATION))?;
        Ok(body.rate_limit.measurements.create)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::globalping::ProbeSelection;
    use std::time::Duration;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ip(value: &str) -> Ipv4Addr {
        value.parse().unwrap()
    }

    fn measurement_id<K>(value: &str) -> MeasurementId<K> {
        MeasurementId::new(value.to_string()).unwrap()
    }

    #[test]
    fn an_empty_measurement_id_is_rejected() {
        let error = MeasurementId::<Ping>::new(String::new()).unwrap_err();

        assert!(matches!(error, GlobalpingError::EmptyMeasurementId));
    }

    fn client_against(server: &MockServer) -> GlobalpingClient {
        GlobalpingClient {
            http: reqwest::Client::new(),
            base_url: server.uri(),
            token: None,
        }
    }

    /// The body of the single request the server received, parsed as JSON.
    /// Comparing parsed JSON checks the body's content and ignores the order
    /// of its keys.
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
    async fn a_ping_from_russian_probes_names_both_probe_groups_and_returns_the_id()
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
            .create_ping(
                ip("192.0.2.1"),
                &Locations::ru(ProbeSelection::new(8, 4).unwrap()),
            )
            .await
            .unwrap();

        assert_eq!(id.as_str(), "meas-1");
        let body = received_body(&server).await;
        assert_eq!(
            body,
            serde_json::json!({
                "type": "ping",
                "target": "192.0.2.1",
                "locations": [
                    {"country": "RU", "tags": ["eyeball-network"], "limit": 8},
                    {"country": "RU", "tags": ["datacenter-network"], "limit": 4}
                ],
                "measurementOptions": {"packets": 10}
            })
        );
    }

    #[tokio::test]
    async fn a_probe_group_without_probes_is_left_out_of_the_request() {
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

        sut.create_ping(
            ip("192.0.2.1"),
            &Locations::ru(ProbeSelection::new(0, 4).unwrap()),
        )
        .await
        .unwrap();

        let body = received_body(&server).await;
        assert_eq!(
            body["locations"],
            serde_json::json!([
                {"country": "RU", "tags": ["datacenter-network"], "limit": 4}
            ])
        );
    }

    #[tokio::test]
    async fn a_measurement_on_earlier_probes_sends_their_id_as_a_bare_string() {
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
            .create_ping(
                ip("192.0.2.2"),
                &Locations::reuse(&measurement_id::<Ping>("meas-1")),
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
    async fn an_https_measurement_asks_for_get_slash_over_https_on_the_port() {
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

        sut.create_https(
            ip("192.0.2.1"),
            NonZeroU16::new(443).unwrap(),
            &Locations::reuse(&measurement_id::<Ping>("meas-1")),
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
            .create_ping(
                ip("192.0.2.1"),
                &Locations::reuse(&measurement_id::<Ping>("x")),
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
            .create_ping(
                ip("192.0.2.1"),
                &Locations::reuse(&measurement_id::<Ping>("x")),
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

    #[rstest::rstest]
    #[case::server_error(StatusCode::INTERNAL_SERVER_ERROR)]
    #[case::unprocessable_entity(StatusCode::UNPROCESSABLE_ENTITY)]
    #[tokio::test]
    async fn a_failed_limits_read_keeps_its_status(#[case] status: StatusCode) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/limits"))
            .respond_with(ResponseTemplate::new(status.as_u16()))
            .mount(&server)
            .await;
        let sut = client_against(&server);

        let err = sut.limits().await.unwrap_err();

        assert!(
            matches!(
                err,
                GlobalpingError::Status {
                    operation: "read limits",
                    status: received,
                } if received == status
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn the_quota_is_read_from_the_nested_rate_limit_shape() {
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
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!(
                        {"id": "slow", "status": "finished", "results": []}
                    ))
                    .set_delay(Duration::from_millis(300)),
            )
            .mount(&server)
            .await;
        let sut = client_against(&server);

        let result = sut
            .poll_ping(&measurement_id("slow"), Duration::from_millis(50))
            .await;

        assert!(matches!(result, Err(GlobalpingError::Timeout(_))));
    }
}
