use std::fmt;
use std::str::FromStr;

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

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let word = match self {
            Severity::Ok => "OK",
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
            Severity::Fail => "FAIL",
        };
        f.write_str(word)
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
        Self { severity: Severity::Ok, detail: detail.into() }
    }
    pub fn warn(detail: impl Into<String>) -> Self {
        Self { severity: Severity::Warn, detail: detail.into() }
    }
    pub fn error(detail: impl Into<String>) -> Self {
        Self { severity: Severity::Error, detail: detail.into() }
    }
    pub fn fail(detail: impl Into<String>) -> Self {
        Self { severity: Severity::Fail, detail: detail.into() }
    }
}

/// A gate identifier (`"latency"`, `"service:gemini"`, `"ai:openai"`) — the
/// unit `Report`, `GateOverrides` (Task 4), and `--gate`/`--skip-gate`
/// (Task 30) all key on. Wrapping it, rather than passing a bare `String`
/// everywhere, is what stops a judge from ever handing `CheckResult::new`
/// its two `impl Into<..>` arguments in the wrong order and having it
/// compile anyway. `From`/`PartialEq<&str>` mean every existing
/// `CheckResult::new("some-gate", ..)` call in this plan keeps compiling
/// unchanged. `Ord` delegates to the inner `String` so `Report` (Task 3) can
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

/// A validated, upper-cased two-letter country code — kept separate from
/// `String` specifically because `ScanArgs` (Task 30) has a `country` and a
/// `city` field of otherwise identical shape sitting next to each other; the
/// type is what makes swapping them at a call site a compile error instead
/// of a silent bug. `Copy` and stack-only (`[u8; 2]`): no allocation for
/// something this small and this validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("constructed only from validated ASCII")
    }
}

/// A plain `String` error would not implement `std::error::Error`, and
/// `clap`'s derive requires a `FromStr::Err` that does (so it can wrap parse
/// failures uniformly) — this is the one-line reason every `TryFrom`/
/// `FromStr` in this plan that can fail returns a small `thiserror` type
/// instead of a bare `String`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{0}' is not a two-letter country code")]
pub struct InvalidCountryCode(String);

impl TryFrom<&str> for CountryCode {
    type Error = InvalidCountryCode;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let upper = value.to_ascii_uppercase();
        let bytes = upper.as_bytes();
        match bytes {
            [a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => Ok(Self([*a, *b])),
            _ => Err(InvalidCountryCode(value.to_string())),
        }
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

/// A `Verdict` attached to the gate id that produced it — the unit the
/// report, `--gate`, and `--skip-gate` all operate on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub gate: GateId,
    pub severity: Severity,
    pub detail: String,
}

impl CheckResult {
    pub fn new(gate: impl Into<GateId>, verdict: Verdict) -> Self {
        Self { gate: gate.into(), severity: verdict.severity, detail: verdict.detail }
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

pub struct PortalProbe {
    pub name: &'static str,
    pub expected_status: u16,
    pub actual_status: Option<u16>,
    pub redirected: bool,
}

/// HTTPS reachability of the candidate's temporary listener, and of a known-
/// good control anchor, measured by the same Globalping probe set.
#[derive(Debug, Clone)]
pub struct ReachFacts {
    pub probe_labels: Vec<String>,
    pub candidate: Vec<HttpProbeOutcome>,
    pub control: Vec<HttpProbeOutcome>,
}

/// One anchor's round-trip series against the same probe set as the
/// candidate. `None` at index `i` means this anchor did not answer probe
/// `i` (its own measurement failed or timed out) — not that it was slow.
#[derive(Debug, Clone)]
pub struct AnchorSeries {
    pub anchor_id: String,
    pub rtt_ms: Vec<Option<f64>>,
    pub loss_pct: Vec<Option<f64>>,
}

/// Ping (or, when ICMP is closed, TCP-handshake) round-trip data for the
/// candidate and the anchors of its declared city, all measured by the same
/// Globalping probe set so index `i` means the same physical probe
/// everywhere in this struct.
#[derive(Debug, Clone)]
pub struct PingSweepFacts {
    pub probe_labels: Vec<String>,
    pub candidate_rtt_ms: Vec<Option<f64>>,
    pub candidate_loss_pct: Vec<Option<f64>>,
    pub city_anchors: Vec<AnchorSeries>,
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
    pub risk: Option<u32>,
    pub operator: Option<String>,
}

/// One vote per keyless `GeoIP` source, or `None` if the source did not
/// answer (including "answered with something that wasn't a two-letter
/// code" — `io::geoip`, Task 22, folds that case into `None` too).
#[derive(Debug, Clone)]
pub struct GeoConsensusFacts {
    pub votes: Vec<Option<CountryCode>>,
}

/// A country vote from a single streaming service (Google, `YouTube`, Apple,
/// Bing, Spotify, Netflix, `TikTok`). Used by `verdict::service_geo` to
/// determine whether the IP's location detection is consistent across major
/// services.
#[derive(Debug, Clone)]
pub struct ServiceCountryVote {
    pub service: &'static str,
    pub country: Option<CountryCode>,
}

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct BlockListFacts {
    pub spamhaus_hit: bool,
    pub spamhaus_available: bool,
    pub firehol_hit: bool,
    pub firehol_available: bool,
}

/// The outcome of probing one streaming/AI service, as classified by
/// `verdict::services` from an HTTP status and/or a response body/final URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    Available,
    Restricted,
    Blocked,
    /// The probe reached no conclusion (Cloudflare challenge, unrecognized
    /// body, transport error) — never read as evidence of either verdict.
    Error(String),
}

#[derive(Debug, Clone)]
pub struct TlsHandshakeFacts {
    pub cert_cn: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_san: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NeighborProbe {
    pub ip: String,
    pub ptr: Option<String>,
    pub tcp_open: bool,
    pub handshake: Option<TlsHandshakeFacts>,
}

#[derive(Debug, Clone)]
pub struct RoutingFacts {
    pub ris_peers_seeing: u32,
    pub total_ris_peers: u32,
    pub origin_count: u32,
}

/// `/proc/stat`'s first `cpu ` line, reduced to what `steal_pct` needs: the
/// kernel's own steal-time counter (field 8) and the sum of all ten fields.
/// Both are monotonically increasing tick counts since boot.
#[derive(Debug, Clone, Copy)]
pub struct ProcStatSnapshot {
    pub steal_ticks: u64,
    pub total_ticks: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_least_to_most_severe() {
        let mut xs = vec![Severity::Fail, Severity::Ok, Severity::Error, Severity::Warn];
        xs.sort();
        assert_eq!(xs, vec![Severity::Ok, Severity::Warn, Severity::Error, Severity::Fail]);
    }

    #[test]
    fn severity_displays_as_uppercase_word() {
        assert_eq!(Severity::Ok.to_string(), "OK");
        assert_eq!(Severity::Warn.to_string(), "WARN");
        assert_eq!(Severity::Error.to_string(), "ERROR");
        assert_eq!(Severity::Fail.to_string(), "FAIL");
    }

    #[test]
    fn verdict_constructors_set_the_right_severity() {
        assert_eq!(Verdict::ok("fine").severity, Severity::Ok);
        assert_eq!(Verdict::warn("hmm").severity, Severity::Warn);
        assert_eq!(Verdict::error("no data").severity, Severity::Error);
        assert_eq!(Verdict::fail("bad").severity, Severity::Fail);
        assert_eq!(Verdict::fail("bad").detail, "bad");
    }

    #[test]
    fn a_gate_id_compares_equal_to_the_plain_str_it_was_built_from() {
        let sut: GateId = "reputation".into();

        assert_eq!(sut, "reputation");
        assert_eq!(sut.to_string(), "reputation");
    }

    #[test]
    fn check_result_carries_the_gate_id_and_the_verdict() {
        let sut = CheckResult::new("reputation", Verdict::fail("vpn flag set"));

        assert_eq!(sut.gate, "reputation");
        assert_eq!(sut.severity, Severity::Fail);
        assert_eq!(sut.detail, "vpn flag set");
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
    fn anything_but_two_letters_is_rejected(#[case] input: &str) {
        assert!(CountryCode::try_from(input).is_err(), "{input:?} should have been rejected");
    }
}
