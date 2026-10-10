use super::types::{MeasurementStatus, RawMeasurement, RawProbeResult};
use crate::error_chain::describe_error;
use chip_core::model::{HttpProbeOutcome, PingSample};

impl RawMeasurement {
    /// One entry per probe, in the order Globalping lists the probes. A probe
    /// that did not finish, or reported a sample `PingSample` rejects, is
    /// `None`; the rejected sample is logged.
    pub(super) fn ping_samples(&self) -> Vec<Option<PingSample>> {
        self.results
            .iter()
            .map(RawProbeResult::ping_sample)
            .collect()
    }

    /// One entry per probe, in the order Globalping lists the probes.
    pub(super) fn https_outcomes(&self) -> Vec<HttpProbeOutcome> {
        self.results
            .iter()
            .map(RawProbeResult::https_outcome)
            .collect()
    }
}

impl RawProbeResult {
    fn ping_sample(&self) -> Option<PingSample> {
        match (&self.result.stats, self.result.status) {
            (Some(stats), MeasurementStatus::Finished) => {
                stats.min.and_then(|rtt| {
                    PingSample::from_millis(rtt, stats.loss)
                        .inspect_err(|error| {
                            tracing::warn!(
                                city = self.probe.city.as_deref(),
                                network = self.probe.network.as_deref(),
                                rtt_ms = rtt,
                                loss = stats.loss,
                                error = %describe_error(error),
                                "invalid ping sample counted as no reply"
                            );
                        })
                        .ok()
                })
            }
            _ => None,
        }
    }

    const fn https_outcome(&self) -> HttpProbeOutcome {
        match (self.result.status, self.result.status_code) {
            (MeasurementStatus::Finished, Some(_)) => HttpProbeOutcome::Ok,
            _ => HttpProbeOutcome::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use chip_core::model::{HttpProbeOutcome, Percent};
    use pretty_assertions::assert_eq;

    use crate::globalping::types::RawMeasurement;

    const PING_FINISHED: &str = r#"{
        "id": "meas-1", "status": "finished",
        "results": [{
            "probe": {"continent": "EU", "region": "Eastern Europe", "country": "RU", "city": "Moscow",
                       "asn": 9123, "network": "Timeweb", "tags": ["datacenter-network"], "resolvers": ["1.1.1.1"]},
            "result": {"status": "finished", "rawOutput": "PING 192.0.2.1", "resolvedAddress": "192.0.2.1",
                       "resolvedHostname": "192.0.2.1", "timings": [],
                       "stats": {"min": 14.0, "avg": 14.5, "max": 15.0, "total": 10, "rcv": 10, "drop": 0, "loss": 1.5}}
        }]
    }"#;

    const PING_FAILED: &str = r#"{
        "id": "meas-2", "status": "finished",
        "results": [{
            "probe": {"continent": "AS", "region": "Asia", "country": "RU", "city": "Vladivostok",
                       "asn": 34470, "network": "PortTelekom", "tags": ["datacenter-network"], "resolvers": []},
            "result": {"status": "failed", "failureSource": "target", "rawOutput": "Request timeout"}
        }]
    }"#;

    const PING_OFFLINE: &str = r#"{
        "id": "meas-3", "status": "finished",
        "results": [{
            "probe": {"country": "RU", "city": "Kursk", "network": "Kurier"},
            "result": {"status": "offline", "rawOutput": ""}
        }]
    }"#;

    const PING_NEGATIVE_RTT: &str = r#"{
        "id": "meas-4", "status": "finished",
        "results": [{
            "probe": {"country": "RU", "city": "Moscow", "network": "Timeweb"},
            "result": {"status": "finished", "stats": {"min": -1.0, "loss": 0.0}}
        }]
    }"#;

    const HTTP_FINISHED: &str = r#"{
        "id": "meas-5", "status": "finished",
        "results": [{
            "probe": {"continent": "EU", "region": "Eastern Europe", "country": "RU", "city": "Moscow",
                       "asn": 9123, "network": "Timeweb", "tags": ["eyeball-network"], "resolvers": []},
            "result": {"status": "finished", "rawHeaders": "HTTP/1.1 200 OK", "rawBody": "", "truncated": false,
                       "headers": {}, "statusCode": 200, "statusCodeName": "OK", "resolvedAddress": "192.0.2.1",
                       "timings": {"total": 350, "dns": 5, "tcp": 65, "tls": 232, "firstByte": 40, "download": 8},
                       "tls": {"authorized": false, "error": "DEPTH_ZERO_SELF_SIGNED_CERT"}}
        }]
    }"#;

    const HTTP_FAILED: &str = r#"{
        "id": "meas-6", "status": "finished",
        "results": [{
            "probe": {"country": "RU", "city": "Moscow", "network": "Timeweb"},
            "result": {"status": "failed", "rawOutput": "connect ETIMEDOUT"}
        }]
    }"#;

    const HTTP_FINISHED_WITHOUT_STATUS_CODE: &str = r#"{
        "id": "meas-7", "status": "finished",
        "results": [{
            "probe": {"country": "RU", "city": "Moscow", "network": "Timeweb"},
            "result": {"status": "finished", "rawOutput": ""}
        }]
    }"#;

    fn measurement(json: &str) -> RawMeasurement {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_finished_ping_reads_as_its_min_rtt_and_loss() {
        let sut = measurement(PING_FINISHED);

        let samples = sut.ping_samples();

        assert_eq!(samples.len(), 1);
        let sample = samples[0].unwrap();
        assert_eq!(sample.rtt(), Duration::from_millis(14));
        assert_eq!(sample.loss(), Some(Percent::try_from(1.5).unwrap()));
    }

    #[test]
    fn a_failed_ping_reads_as_no_reply() {
        let sut = measurement(PING_FAILED);

        let samples = sut.ping_samples();

        assert_eq!(samples, [None]);
    }

    #[test]
    fn a_probe_status_the_client_does_not_model_reads_as_no_reply() {
        let sut = measurement(PING_OFFLINE);

        let samples = sut.ping_samples();

        assert_eq!(samples, [None]);
    }

    #[test]
    fn a_ping_sample_out_of_range_reads_as_no_reply() {
        let sut = measurement(PING_NEGATIVE_RTT);

        let samples = sut.ping_samples();

        assert_eq!(samples, [None]);
    }

    #[test]
    fn an_https_reply_with_a_status_code_reads_as_ok() {
        let sut = measurement(HTTP_FINISHED);

        let outcomes = sut.https_outcomes();

        assert_eq!(outcomes, [HttpProbeOutcome::Ok]);
    }

    #[test]
    fn a_failed_https_request_reads_as_failed() {
        let sut = measurement(HTTP_FAILED);

        let outcomes = sut.https_outcomes();

        assert_eq!(outcomes, [HttpProbeOutcome::Failed]);
    }

    #[test]
    fn a_finished_https_request_without_a_status_code_reads_as_failed() {
        let sut = measurement(HTTP_FINISHED_WITHOUT_STATUS_CODE);

        let outcomes = sut.https_outcomes();

        assert_eq!(outcomes, [HttpProbeOutcome::Failed]);
    }

    #[test]
    fn a_measurement_without_results_is_not_read_as_an_empty_series() {
        let body = r#"{"id": "meas-8", "status": "finished"}"#;

        let decoded = serde_json::from_str::<RawMeasurement>(body);

        assert!(decoded.is_err(), "{decoded:?}");
    }
}
