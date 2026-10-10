use serde::Deserialize;

/// Status of a measurement and of each probe result in it. Globalping uses
/// one vocabulary for both; a status this client does not model, such as
/// `offline` on a probe result, reads as `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum MeasurementStatus {
    InProgress,
    Finished,
    Failed,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
pub(super) struct RawMeasurement {
    pub(super) status: MeasurementStatus,
    /// Required by the API schema in every status, finished or not, so a
    /// body without it is a decode error rather than "no probes answered".
    pub(super) results: Vec<RawProbeResult>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RawProbeResult {
    pub(super) probe: RawProbe,
    pub(super) result: RawResult,
}

#[derive(Debug, Deserialize)]
pub(super) struct RawProbe {
    pub(super) city: Option<String>,
    pub(super) network: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RawResult {
    pub(super) status: MeasurementStatus,
    pub(super) stats: Option<RawPingStats>,
    #[serde(rename = "statusCode")]
    pub(super) status_code: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RawPingStats {
    pub(super) min: Option<f64>,
    pub(super) loss: Option<f64>,
}
