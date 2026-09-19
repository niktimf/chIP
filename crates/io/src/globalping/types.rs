use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RawMeasurement {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub results: Vec<RawProbeResult>,
}

#[derive(Debug, Deserialize)]
pub struct RawProbeResult {
    pub probe: RawProbe,
    pub result: RawResult,
}

#[derive(Debug, Deserialize, Default)]
pub struct RawProbe {
    pub city: Option<String>,
    pub network: Option<String>,
    pub asn: Option<i64>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RawResult {
    pub status: String,
    #[serde(rename = "failureSource")]
    pub failure_source: Option<String>,
    pub stats: Option<RawPingStats>,
    #[serde(rename = "statusCode")]
    pub status_code: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub struct RawPingStats {
    pub min: Option<f64>,
    pub loss: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PING_FINISHED: &str = r#"{
        "id": "meas-1", "status": "finished",
        "results": [{
            "probe": {"continent": "EU", "region": "Eastern Europe", "country": "RU", "city": "Moscow",
                       "asn": 9123, "network": "Timeweb", "tags": ["datacenter-network"], "resolvers": ["1.1.1.1"]},
            "result": {"status": "finished", "rawOutput": "PING 192.0.2.1", "resolvedAddress": "192.0.2.1",
                       "resolvedHostname": "192.0.2.1", "timings": [],
                       "stats": {"min": 14.12, "avg": 14.5, "max": 15.0, "total": 10, "rcv": 10, "drop": 0, "loss": 0.0}}
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

    const HTTP_FINISHED: &str = r#"{
        "id": "meas-3", "status": "finished",
        "results": [{
            "probe": {"continent": "EU", "region": "Eastern Europe", "country": "RU", "city": "Moscow",
                       "asn": 9123, "network": "Timeweb", "tags": ["eyeball-network"], "resolvers": []},
            "result": {"status": "finished", "rawHeaders": "HTTP/1.1 200 OK", "rawBody": "", "truncated": false,
                       "headers": {}, "statusCode": 200, "statusCodeName": "OK", "resolvedAddress": "192.0.2.1",
                       "timings": {"total": 350, "dns": 5, "tcp": 65, "tls": 232, "firstByte": 40, "download": 8},
                       "tls": {"authorized": false, "error": "DEPTH_ZERO_SELF_SIGNED_CERT"}}
        }]
    }"#;

    #[test]
    fn parses_a_finished_ping_result_with_its_stats() {
        let m: RawMeasurement = serde_json::from_str(PING_FINISHED).unwrap();
        let result = &m.results[0].result;
        assert_eq!(result.status, "finished");
        assert_eq!(m.results[0].probe.city.as_deref(), Some("Moscow"));
        assert_eq!(m.results[0].probe.network.as_deref(), Some("Timeweb"));
        assert_eq!(m.results[0].probe.asn, Some(9123));
        let stats = result.stats.as_ref().unwrap();
        assert_eq!(stats.min, Some(14.12));
        assert_eq!(stats.loss, Some(0.0));
    }

    #[test]
    fn parses_a_failed_ping_result_and_its_failure_source() {
        let m: RawMeasurement = serde_json::from_str(PING_FAILED).unwrap();
        let result = &m.results[0].result;
        assert_eq!(result.status, "failed");
        assert_eq!(result.failure_source.as_deref(), Some("target"));
        assert!(result.stats.is_none());
    }

    #[test]
    fn parses_a_finished_http_result_and_ignores_unmodeled_fields() {
        let m: RawMeasurement = serde_json::from_str(HTTP_FINISHED).unwrap();
        let result = &m.results[0].result;
        assert_eq!(result.status_code, Some(200));
        assert!(result.stats.is_none()); // ping-only field, absent here
    }
}
