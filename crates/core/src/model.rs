use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use country_code_enum::CountryCode as RegistryCountryCode;

/// How serious a single check's outcome is. Ordered least to most severe so
/// `Vec<CheckResult>::sort()` (descending) puts the worst results first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Ok,
    Warn,
    /// The check could not reach a verdict at all (quota exhausted, source
    /// unreachable, SSH refused). Distinct from `Fail`: it never alone drives
    /// exit code 1, only exit code 2 when nothing else failed outright.
    Error,
    Fail,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Fail => "FAIL",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of judging one aspect of the candidate: a severity and the
/// human-readable reason. Judge functions in `verdict::*` return this; they
/// never know their own gate id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub severity: Severity,
    pub detail: String,
}

impl Verdict {
    pub fn ok(detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Ok,
            detail: detail.into(),
        }
    }
    pub fn warn(detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warn,
            detail: detail.into(),
        }
    }
    pub fn error(detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            detail: detail.into(),
        }
    }
    pub fn fail(detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Fail,
            detail: detail.into(),
        }
    }
}

/// A gate identifier (`"latency"`, `"service:gemini"`, `"ai:openai"`).
///
/// `Report`, `GateOverrides`, and `--gate`/`--skip-gate` all key on it.
/// Wrapping it, rather than passing a bare `String`,
/// everywhere, is what stops a judge from ever handing `CheckResult::new`
/// its two `impl Into<..>` arguments in the wrong order and having it
/// compile anyway. `From`/`PartialEq<&str>` keep literal construction terse.
/// `Ord` delegates to the inner `String` so `Report` can
/// sort same-severity rows by gate id for a stable table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GateId(String);

impl GateId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for GateId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for GateId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Display for GateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for GateId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for GateId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// A validated, upper-cased country code from the supported country registry.
///
/// It is kept separate from `String` because scan configuration has a `country` and a
/// `city` field of otherwise identical shape sitting next to each other; the
/// type is what makes swapping them at a call site a compile error instead
/// of a silent bug. The private field keeps registry validation on the input
/// boundary without exposing the dependency's type to the rest of the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CountryCode(RegistryCountryCode);

impl CountryCode {
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

/// Error returned when a country code cannot be parsed.
///
/// This implements `std::error::Error`, as required by CLI parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{0}' is not a recognized country code")]
pub struct InvalidCountryCode(String);

impl TryFrom<&str> for CountryCode {
    type Error = InvalidCountryCode;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value
            .parse::<RegistryCountryCode>()
            .map(Self)
            .map_err(|_| InvalidCountryCode(value.to_string()))
    }
}

impl FromStr for CountryCode {
    type Err = InvalidCountryCode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value)
    }
}

impl fmt::Display for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A non-empty city label used for Atlas anchor selection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CityName(String);

impl CityName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("city name must not be empty")]
pub struct InvalidCityName;

impl FromStr for CityName {
    type Err = InvalidCityName;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            Err(InvalidCityName)
        } else {
            Ok(Self(value.to_string()))
        }
    }
}

impl fmt::Display for CityName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A `Verdict` attached to the gate id that produced it — the unit the
/// report, `--gate`, and `--skip-gate` all operate on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub gate: GateId,
    pub severity: Severity,
    pub detail: String,
    /// Set when nothing was judged: the gate was turned off by `--skip-gate`,
    /// `--no-ssh` or `--no-neighbors`. The severity is then `Ok` only because
    /// no verdict was reached, so the report prints `SKIP` instead of `OK`
    /// and the exit code stays unaffected.
    pub skipped: bool,
}

impl CheckResult {
    pub fn new(gate: impl Into<GateId>, verdict: Verdict) -> Self {
        Self {
            gate: gate.into(),
            severity: verdict.severity,
            detail: verdict.detail,
            skipped: false,
        }
    }

    /// A gate the operator turned off. `reason` is what would otherwise have
    /// been judged (or why judging was impossible) and reaches the report
    /// unchanged.
    pub fn skipped(gate: impl Into<GateId>, reason: impl Into<String>) -> Self {
        Self {
            gate: gate.into(),
            severity: Severity::Ok,
            detail: reason.into(),
            skipped: true,
        }
    }

    /// What the report prints in the severity column.
    pub const fn label(&self) -> &'static str {
        if self.skipped {
            "SKIP"
        } else {
            self.severity.as_str()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpProbeOutcome {
    Ok,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortalOutcome {
    Ok,
    Altered,
    Unreachable,
}

/// Result of one captcha observation. Unlike `Option<bool>`, this keeps a
/// transport failure distinct from a clean response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptchaObservation {
    Clear,
    Triggered,
    Unavailable(String),
}

/// HTTPS reachability of the candidate's temporary listener, and of a known-
/// good control anchor, measured by the same Globalping probe set.
#[derive(Debug, Clone)]
pub struct ReachProbe {
    pub candidate: HttpProbeOutcome,
    pub control: HttpProbeOutcome,
}

#[derive(Debug, Clone)]
pub struct ReachFacts {
    pub probes: Vec<ReachProbe>,
}

/// One usable ping result. An absent result is represented by
/// `Option<PingSample>` at the call site; a present sample always has a
/// finite, non-negative RTT and an optional loss percentage in `0..=100`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PingSample {
    rtt_ms: f64,
    loss_pct: Option<f64>,
}

impl PingSample {
    pub fn new(
        rtt_ms: f64,
        loss_pct: Option<f64>,
    ) -> Result<Self, InvalidPingSample> {
        if !rtt_ms.is_finite() || rtt_ms < 0.0 {
            return Err(InvalidPingSample(
                "RTT must be finite and non-negative",
            ));
        }
        if loss_pct.is_some_and(|loss| {
            !loss.is_finite() || !(0.0..=100.0).contains(&loss)
        }) {
            return Err(InvalidPingSample(
                "loss must be finite and between 0 and 100 percent",
            ));
        }
        Ok(Self { rtt_ms, loss_pct })
    }

    pub const fn rtt_ms(self) -> f64 {
        self.rtt_ms
    }

    pub const fn loss_pct(self) -> Option<f64> {
        self.loss_pct
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid ping sample: {0}")]
pub struct InvalidPingSample(&'static str);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "anchor '{anchor_id}' returned {actual} probe samples, expected {expected}"
)]
pub struct ProbeAlignmentError {
    anchor_id: String,
    expected: usize,
    actual: usize,
}

/// One anchor's round-trip series against the same probe set as the
/// candidate. `None` at index `i` means this anchor did not answer probe
///
/// `i` (its own measurement failed or timed out) — not that it was slow.
#[derive(Debug, Clone)]
pub struct AnchorSeries {
    anchor_id: String,
    samples: Vec<Option<PingSample>>,
}

impl AnchorSeries {
    pub fn new(
        anchor_id: impl Into<String>,
        samples: Vec<Option<PingSample>>,
    ) -> Self {
        Self {
            anchor_id: anchor_id.into(),
            samples,
        }
    }

    pub fn id(&self) -> &str {
        &self.anchor_id
    }

    pub fn samples(&self) -> &[Option<PingSample>] {
        &self.samples
    }
}

/// Ping (or, when ICMP is closed, TCP-handshake) round-trip data for the
/// candidate and the anchors of its declared city, all measured by the same
///
/// Globalping probe set so index `i` means the same physical probe
/// everywhere in this struct.
#[derive(Debug, Clone)]
pub struct PingSweepFacts {
    candidate: Vec<Option<PingSample>>,
    city_anchors: Vec<AnchorSeries>,
}

impl PingSweepFacts {
    pub fn new(
        candidate: Vec<Option<PingSample>>,
        city_anchors: Vec<AnchorSeries>,
    ) -> Result<Self, ProbeAlignmentError> {
        let expected = candidate.len();
        if let Some(anchor) = city_anchors
            .iter()
            .find(|anchor| anchor.samples.len() != expected)
        {
            return Err(ProbeAlignmentError {
                anchor_id: anchor.anchor_id.clone(),
                expected,
                actual: anchor.samples.len(),
            });
        }
        Ok(Self {
            candidate,
            city_anchors,
        })
    }

    pub fn candidate(&self) -> &[Option<PingSample>] {
        &self.candidate
    }

    pub fn city_anchors(&self) -> &[AnchorSeries] {
        &self.city_anchors
    }
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct ReputationFacts {
    pub vpn: bool,
    pub proxy: bool,
    pub tor: bool,
    pub compromised: bool,
    pub anonymous: bool,
    pub scraper: bool,
    pub risk: Option<RiskScore>,
    pub operator: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RiskScore(u8);

impl RiskScore {
    pub fn new(value: u8) -> Result<Self, InvalidRiskScore> {
        if value <= 100 {
            Ok(Self(value))
        } else {
            Err(InvalidRiskScore(u64::from(value)))
        }
    }

    pub const fn value(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("risk score must be between 0 and 100, got {0}")]
pub struct InvalidRiskScore(u64);

impl TryFrom<u64> for RiskScore {
    type Error = InvalidRiskScore;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let value_u8 =
            u8::try_from(value).map_err(|_| InvalidRiskScore(value))?;
        Self::new(value_u8).map_err(|_| InvalidRiskScore(value))
    }
}

impl fmt::Display for RiskScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// One vote per keyless `GeoIP` source, or `None` if the source did not
/// answer (including "answered with an unknown country code" — the I/O
/// boundary folds that case into `None` too).
#[derive(Debug, Clone)]
pub struct GeoConsensusFacts {
    pub votes: Vec<Option<CountryCode>>,
}

/// A country vote from a single streaming service (Google, `YouTube`, Apple,
/// Bing, Spotify, Netflix, `TikTok`). Used by `verdict::service_geo` to
///
/// determine whether the IP's location detection is consistent across major
/// services.
#[derive(Debug, Clone)]
pub struct ServiceCountryVote {
    pub service: &'static str,
    pub country: Option<CountryCode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockListStatus {
    Unavailable,
    Clear,
    Listed,
}

#[derive(Debug, Clone)]
pub struct BlockListFacts {
    pub spamhaus: BlockListStatus,
    pub firehol: BlockListStatus,
}

/// The outcome of probing one streaming/AI service, as classified by
/// `verdict::services` from an HTTP status and/or a response body/final URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    Available,
    Restricted,
    Blocked,
    /// The probe reached no conclusion (Cloudflare challenge, unrecognized
    /// body) — never read as evidence of either verdict.
    Error(String),
    /// The endpoint could not be reached or read. This is an ERROR gate, not
    /// a weak service verdict.
    Unavailable(String),
}

#[derive(Debug, Clone)]
pub struct TlsHandshakeFacts {
    pub cert_cn: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_san: Vec<String>,
}

/// A normalized, non-empty PTR record returned by reverse DNS.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PtrName(String);

impl PtrName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("PTR name is empty")]
pub struct InvalidPtrName;

impl TryFrom<&str> for PtrName {
    type Error = InvalidPtrName;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let normalized = value.trim().trim_end_matches('.');
        if normalized.is_empty() {
            Err(InvalidPtrName)
        } else {
            Ok(Self(normalized.to_string()))
        }
    }
}

impl fmt::Display for PtrName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reverse-DNS lookup outcome. `NotFound` is intentionally distinct from an
/// unavailable resolver/process so reports never claim an absent PTR when the
/// lookup itself failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtrLookup {
    Resolved(PtrName),
    NotFound,
    Unavailable(String),
}

#[derive(Debug, Clone)]
pub enum NeighborHttps {
    Closed,
    Open {
        handshake: Option<TlsHandshakeFacts>,
    },
}

#[derive(Debug, Clone)]
pub struct NeighborProbe {
    pub ip: Ipv4Addr,
    pub ptr: PtrLookup,
    pub https: NeighborHttps,
}

#[derive(Debug, Clone)]
pub struct RoutingFacts {
    ris_peers_seeing: u32,
    total_ris_peers: u32,
    origin_count: u32,
}

impl RoutingFacts {
    pub const fn new(
        ris_peers_seeing: u32,
        total_ris_peers: u32,
        origin_count: u32,
    ) -> Result<Self, InvalidRoutingFacts> {
        if ris_peers_seeing > total_ris_peers {
            return Err(InvalidRoutingFacts {
                seeing: ris_peers_seeing,
                total: total_ris_peers,
            });
        }
        Ok(Self {
            ris_peers_seeing,
            total_ris_peers,
            origin_count,
        })
    }

    pub const fn ris_peers_seeing(&self) -> u32 {
        self.ris_peers_seeing
    }

    pub const fn total_ris_peers(&self) -> u32 {
        self.total_ris_peers
    }

    pub const fn origin_count(&self) -> u32 {
        self.origin_count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("RIS peers seeing the prefix ({seeing}) exceeds total peers ({total})")]
pub struct InvalidRoutingFacts {
    seeing: u32,
    total: u32,
}

/// `/proc/stat`'s first `cpu ` line, reduced to what `steal_pct` needs: the
/// kernel's own steal-time counter (field 8) and the sum of all ten fields.
///
/// Both are monotonically increasing tick counts since boot.
#[derive(Debug, Clone, Copy)]
pub struct ProcStatSnapshot {
    steal_ticks: u64,
    total_ticks: u64,
}

impl ProcStatSnapshot {
    pub const fn new(
        steal_ticks: u64,
        total_ticks: u64,
    ) -> Result<Self, InvalidProcStatSnapshot> {
        if steal_ticks > total_ticks {
            Err(InvalidProcStatSnapshot {
                steal: steal_ticks,
                total: total_ticks,
            })
        } else {
            Ok(Self {
                steal_ticks,
                total_ticks,
            })
        }
    }

    pub const fn steal_ticks(self) -> u64 {
        self.steal_ticks
    }

    pub const fn total_ticks(self) -> u64 {
        self.total_ticks
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("steal ticks ({steal}) exceeds total CPU ticks ({total})")]
pub struct InvalidProcStatSnapshot {
    steal: u64,
    total: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_least_to_most_severe() {
        let mut sut = vec![
            Severity::Fail,
            Severity::Ok,
            Severity::Error,
            Severity::Warn,
        ];
        sut.sort();
        assert_eq!(
            sut,
            vec![
                Severity::Ok,
                Severity::Warn,
                Severity::Error,
                Severity::Fail
            ]
        );
    }

    #[test]
    fn a_skipped_check_is_labelled_skip_and_keeps_the_reason_it_carried() {
        let sut = CheckResult::skipped(
            "reach",
            "ports 443 and 8443 are already in use",
        );

        assert_eq!(sut.severity, Severity::Ok);
        assert_eq!(sut.label(), "SKIP");
        assert_eq!(sut.detail, "ports 443 and 8443 are already in use");
    }

    #[test]
    fn a_judged_check_is_labelled_by_its_severity() {
        let sut = CheckResult::new("geo", Verdict::warn("50/50 split"));

        assert_eq!(sut.label(), "WARN");
    }

    #[test]
    fn severity_displays_as_uppercase_word() {
        assert_eq!(Severity::Ok.to_string(), "OK");
        assert_eq!(Severity::Warn.to_string(), "WARN");
        assert_eq!(Severity::Error.to_string(), "ERROR");
        assert_eq!(Severity::Fail.to_string(), "FAIL");
    }

    #[test]
    fn a_two_letter_code_parses_and_upper_cases() {
        let sut: CountryCode = "fi".parse().unwrap();

        assert_eq!(sut.as_str(), "FI");
        assert_eq!(sut, CountryCode::try_from("FI").unwrap());
    }

    #[rstest::rstest]
    #[case::too_long("FIN")]
    #[case::too_short("F")]
    #[case::not_alphabetic("F1")]
    fn malformed_country_codes_are_rejected(#[case] input: &str) {
        let error = CountryCode::try_from(input).unwrap_err();

        assert_eq!(error, InvalidCountryCode(input.to_string()));
    }

    #[test]
    fn an_unassigned_two_letter_code_is_rejected() {
        let error = CountryCode::try_from("ZZ").unwrap_err();

        assert_eq!(error, InvalidCountryCode("ZZ".to_string()));
    }

    #[test]
    fn a_city_name_is_trimmed_at_the_input_boundary() {
        let sut: CityName = "  Helsinki  ".parse().unwrap();

        assert_eq!(sut.as_str(), "Helsinki");
    }

    #[test]
    fn a_blank_city_name_is_rejected() {
        let error = "   ".parse::<CityName>().unwrap_err();

        assert_eq!(error, InvalidCityName);
    }

    #[rstest::rstest]
    #[case::nan_rtt(f64::NAN, Some(0.0), "RTT")]
    #[case::negative_rtt(-1.0, Some(0.0), "RTT")]
    #[case::excessive_loss(10.0, Some(101.0), "loss")]
    #[case::nan_loss(10.0, Some(f64::NAN), "loss")]
    fn invalid_ping_measurements_are_rejected(
        #[case] rtt_ms: f64,
        #[case] loss_pct: Option<f64>,
        #[case] expected_detail: &str,
    ) {
        let error = PingSample::new(rtt_ms, loss_pct).unwrap_err();

        assert!(error.to_string().contains(expected_detail), "{error}");
    }

    #[test]
    fn a_risk_score_above_one_hundred_is_rejected() {
        let error = RiskScore::new(101).unwrap_err();

        assert_eq!(error, InvalidRiskScore(101));
    }

    #[test]
    fn a_ptr_name_is_trimmed_and_normalized_from_dns_form() {
        let sut = PtrName::try_from("  vpn1.example.net.  ").unwrap();

        assert_eq!(sut.as_str(), "vpn1.example.net");
    }

    #[test]
    fn a_root_only_ptr_name_is_rejected() {
        let error = PtrName::try_from(".").unwrap_err();

        assert_eq!(error, InvalidPtrName);
    }
}
