use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;
use std::num::{NonZeroU32, NonZeroU64};
use std::str::FromStr;
use std::time::Duration;

use country_code_enum::CountryCode as RegistryCountryCode;
use ipnet::Ipv4Net;
use strum::{Display, IntoStaticStr};

use crate::gate::GateId;
use crate::units;

/// How serious a single check's outcome is. Ordered least to most severe so
/// `Vec<CheckResult>::sort()` (descending) puts the worst results first.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Display, IntoStaticStr,
)]
#[strum(serialize_all = "UPPERCASE")]
pub enum Severity {
    Ok,
    Warn,
    /// The check could not reach a verdict at all (quota exhausted, source
    /// unreachable, SSH refused). Distinct from `Fail`: it never alone drives
    /// exit code 1, only exit code 2 when nothing else failed outright.
    Error,
    Fail,
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
    pub const RU: Self = Self(RegistryCountryCode::RU);

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

    #[expect(
        clippy::map_err_ignore,
        reason = "the upstream error is a String that only repeats the input \
                  already kept in InvalidCountryCode"
    )]
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
    gate: GateId,
    detail: String,
    outcome: CheckOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckOutcome {
    Judged(Severity),
    Skipped,
}

impl CheckResult {
    pub fn new(gate: GateId, verdict: Verdict) -> Self {
        Self {
            gate,
            detail: verdict.detail,
            outcome: CheckOutcome::Judged(verdict.severity),
        }
    }

    pub fn skipped(gate: GateId, reason: impl Into<String>) -> Self {
        Self {
            gate,
            detail: reason.into(),
            outcome: CheckOutcome::Skipped,
        }
    }

    pub const fn gate(&self) -> GateId {
        self.gate
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub fn into_detail(self) -> String {
        self.detail
    }

    pub const fn severity(&self) -> Severity {
        match self.outcome {
            CheckOutcome::Judged(severity) => severity,
            CheckOutcome::Skipped => Severity::Ok,
        }
    }

    pub const fn is_skipped(&self) -> bool {
        matches!(self.outcome, CheckOutcome::Skipped)
    }

    #[must_use]
    pub const fn escalate_warning(mut self) -> Self {
        if matches!(self.outcome, CheckOutcome::Judged(Severity::Warn)) {
            self.outcome = CheckOutcome::Judged(Severity::Fail);
        }
        self
    }

    pub fn label(&self) -> &'static str {
        match self.outcome {
            CheckOutcome::Skipped => "SKIP",
            CheckOutcome::Judged(severity) => severity.into(),
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

/// What one CDN edge probe showed.
///
/// An edge that answered without a country and an edge that could not be
/// reached are separate states: only the second leaves the gate unable to
/// tell whether that edge sits in Russia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeObservation {
    Country(CountryCode),
    /// The edge answered, but the response named no recognizable location.
    Silent,
    /// The edge could not be fetched; the string is the transport cause.
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

impl ReachFacts {
    /// Pairs the candidate and control outcomes probe by probe. Both series
    /// come from the same Globalping probe set, so index `i` must mean the
    /// same probe in each; a series of a different length cannot be paired.
    ///
    /// # Errors
    ///
    /// Returns `ProbeAlignmentError` when the two series differ in length.
    pub fn new(
        candidate: Vec<HttpProbeOutcome>,
        control: Vec<HttpProbeOutcome>,
    ) -> Result<Self, ProbeAlignmentError> {
        const CONTROL_ID: &str = "control";
        if control.len() != candidate.len() {
            return Err(ProbeAlignmentError {
                anchor_id: CONTROL_ID.to_owned(),
                expected: candidate.len(),
                actual: control.len(),
            });
        }
        let probes = candidate
            .into_iter()
            .zip(control)
            .map(|(candidate, control)| ReachProbe { candidate, control })
            .collect();
        Ok(Self { probes })
    }
}

/// A share of a whole in percent: finite and within `0..=100`.
///
/// Packet loss and the CPU steal share are such shares. A difference between
/// two of them can be negative and is not a `Percent`.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Percent(f64);

impl Percent {
    pub const ZERO: Self = Self(0.0);
    const MAX: f64 = 100.0;

    /// `part` of `whole` in percent. A `part` above `whole` saturates at 100
    /// percent instead of leaving the range.
    #[expect(
        clippy::cast_precision_loss,
        reason = "a share needs no more than f64 precision; part <= whole \
                  keeps the ratio within 0..=1 after rounding"
    )]
    pub fn saturating_ratio(part: u64, whole: NonZeroU64) -> Self {
        let whole = whole.get();
        let part = part.min(whole);
        Self(part as f64 / whole as f64 * Self::MAX)
    }

    pub const fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for Percent {
    type Error = InvalidPercent;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if !value.is_finite() {
            return Err(InvalidPercent::NotFinite(value));
        }
        if !(0.0..=Self::MAX).contains(&value) {
            return Err(InvalidPercent::OutOfRange(value));
        }
        Ok(Self(value))
    }
}

/// Why a number is not a [`Percent`], with the rejected value.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum InvalidPercent {
    #[error("percent must be finite, got {0}")]
    NotFinite(f64),
    #[error("percent must be between 0 and 100, got {0}")]
    OutOfRange(f64),
}

impl InvalidPercent {
    pub const fn value(self) -> f64 {
        match self {
            Self::NotFinite(value) | Self::OutOfRange(value) => value,
        }
    }
}

/// One usable ping result. An absent result is represented by
/// `Option<PingSample>` at the call site; a present sample always has an RTT
/// and an optional loss share.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PingSample {
    rtt: Duration,
    loss: Option<Percent>,
}

impl PingSample {
    /// Parses a ping result in the units measurement sources report: RTT in
    /// milliseconds, loss in percent.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPingSample` when the RTT is negative or not finite, or
    /// the loss is not a finite percentage in `0..=100`.
    #[expect(
        clippy::map_err_ignore,
        reason = "TryFromFloatSecsError only repeats that the RTT is \
                  negative, non-finite or too large; Rtt keeps the value"
    )]
    pub fn from_millis(
        rtt_ms: f64,
        loss_pct: Option<f64>,
    ) -> Result<Self, InvalidPingSample> {
        let rtt = units::duration_from_millis(rtt_ms)
            .map_err(|_| InvalidPingSample::Rtt(rtt_ms))?;
        let loss = loss_pct
            .map(Percent::try_from)
            .transpose()
            .map_err(InvalidPingSample::Loss)?;
        Ok(Self { rtt, loss })
    }

    pub const fn rtt(self) -> Duration {
        self.rtt
    }

    pub const fn loss(self) -> Option<Percent> {
        self.loss
    }
}

/// Which part of a ping measurement is out of range, with the rejected
/// value.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum InvalidPingSample {
    #[error(
        "invalid ping sample: RTT must be finite and non-negative, got {0}"
    )]
    Rtt(f64),
    #[error("invalid ping sample: loss")]
    Loss(#[source] InvalidPercent),
}

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
    /// # Errors
    ///
    /// Returns `ProbeAlignmentError` for the first anchor whose series length
    /// differs from the candidate's.
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

/// A proxycheck detection raised for an address.
///
/// `Ord` follows declaration order, and the reputation verdict lists the
/// flags of an address in that order. `Display` gives the flag's name in
/// the verdict detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
#[strum(serialize_all = "lowercase")]
pub enum ReputationFlag {
    Vpn,
    Proxy,
    Tor,
    Compromised,
    Anonymous,
    Scraper,
}

impl ReputationFlag {
    /// Whether the flag alone fails the reputation gate. The other flags
    /// only warn.
    pub const fn is_hard(self) -> bool {
        match self {
            Self::Vpn | Self::Proxy | Self::Tor | Self::Compromised => true,
            Self::Anonymous | Self::Scraper => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReputationFacts {
    pub flags: BTreeSet<ReputationFlag>,
    pub risk: Option<RiskScore>,
    pub operator: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RiskScore(u8);

impl RiskScore {
    /// # Errors
    ///
    /// Returns `InvalidRiskScore` when `value` exceeds 100.
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
        // `TryFromIntError` carries no data; `InvalidRiskScore` keeps the
        // rejected value, and `new` rejects 101..=255 with the same value.
        u8::try_from(value).map_or(Err(InvalidRiskScore(value)), Self::new)
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

/// One country voter behind the `service-geo` gate. A closed set: the
/// judge's fail-or-warn split keys on the voter, so a voter the judge does
/// not know cannot be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[strum(serialize_all = "lowercase")]
pub enum ServiceGeoSource {
    Google,
    Youtube,
    Apple,
    Spotify,
    Netflix,
    Tiktok,
    Bing,
}

impl ServiceGeoSource {
    /// Google and `YouTube` alone can fail the gate; every other voter's
    /// disagreement is only a warning.
    pub const fn is_critical(self) -> bool {
        matches!(self, Self::Google | Self::Youtube)
    }
}

/// A country vote from a single service. Used by `verdict::service_geo` to
/// determine whether the IP's location detection is consistent across major
/// services.
#[derive(Debug, Clone)]
pub struct ServiceCountryVote {
    pub source: ServiceGeoSource,
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

/// Where the candidate itself stands in the RKN registry export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RknListing {
    NotListed,
    /// The address is in the list of single blocked addresses.
    Address,
    /// The address falls inside a network the registry blocks as a whole.
    Subnet(Ipv4Net),
}

/// The candidate's entry in the RKN registry plus how many other addresses
/// of its `/24` and `/16` are blocked one by one.
///
/// The candidate itself is never counted as its own neighbor, so a `/24` has
/// at most 255 of them and a `/16` at most 65 535: exactly what `u8` and
/// `u16` hold. The `/24` lies inside its `/16`, so it never has more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RknRegistryFacts {
    listing: RknListing,
    neighbors_24: u8,
    neighbors_16: u16,
}

impl RknRegistryFacts {
    /// # Errors
    ///
    /// Returns `InvalidRknRegistryFacts` when the `/24` holds more listed
    /// neighbors than the `/16` around it.
    pub fn new(
        listing: RknListing,
        neighbors_24: u8,
        neighbors_16: u16,
    ) -> Result<Self, InvalidRknRegistryFacts> {
        if u16::from(neighbors_24) > neighbors_16 {
            return Err(InvalidRknRegistryFacts {
                in_24: neighbors_24,
                in_16: neighbors_16,
            });
        }
        Ok(Self {
            listing,
            neighbors_24,
            neighbors_16,
        })
    }

    pub const fn listing(&self) -> RknListing {
        self.listing
    }

    pub const fn neighbors_24(&self) -> u8 {
        self.neighbors_24
    }

    pub const fn neighbors_16(&self) -> u16 {
        self.neighbors_16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the /24 has {in_24} listed neighbors, but its /16 only {in_16}")]
pub struct InvalidRknRegistryFacts {
    in_24: u8,
    in_16: u16,
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

/// How the candidate's address is routed, as the RIS peers see it.
#[derive(Debug, Clone)]
pub enum Routing {
    /// An announcement covers the address. The prefix is usually shorter
    /// than a `/24`: cloud providers announce whole blocks.
    Announced {
        prefix: Ipv4Net,
        facts: RoutingFacts,
    },
    /// No announcement covers the address, so no peer can see it.
    NotAnnounced { total_ris_peers: NonZeroU32 },
}

/// Visibility of an announced prefix.
///
/// The total is never zero: a routing answer without RIS peers carries no
/// data and is rejected where the response is read.
#[derive(Debug, Clone)]
pub struct RoutingFacts {
    ris_peers_seeing: u32,
    total_ris_peers: NonZeroU32,
    origin_count: u32,
}

impl RoutingFacts {
    /// # Errors
    ///
    /// Returns `InvalidRoutingFacts` when more peers see the prefix than
    /// exist in total.
    pub const fn new(
        ris_peers_seeing: u32,
        total_ris_peers: NonZeroU32,
        origin_count: u32,
    ) -> Result<Self, InvalidRoutingFacts> {
        if ris_peers_seeing > total_ris_peers.get() {
            return Err(InvalidRoutingFacts {
                seeing: ris_peers_seeing,
                total: total_ris_peers.get(),
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

    pub const fn total_ris_peers(&self) -> NonZeroU32 {
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
    /// # Errors
    ///
    /// Returns `InvalidProcStatSnapshot` when the steal ticks exceed the total.
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
    use crate::gate::{GEO, REACH};

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
            REACH,
            "ports 443 and 8443 are already in use",
        );

        assert_eq!(sut.severity(), Severity::Ok);
        assert_eq!(sut.label(), "SKIP");
        assert_eq!(sut.detail, "ports 443 and 8443 are already in use");
    }

    #[test]
    fn a_judged_check_is_labelled_by_its_severity() {
        let sut = CheckResult::new(GEO, Verdict::warn("50/50 split"));

        assert_eq!(sut.label(), "WARN");
    }

    #[rstest::rstest]
    #[case::ok(Severity::Ok, "OK")]
    #[case::warn(Severity::Warn, "WARN")]
    #[case::error(Severity::Error, "ERROR")]
    #[case::fail(Severity::Fail, "FAIL")]
    fn severity_displays_as_uppercase_word(
        #[case] sut: Severity,
        #[case] expected: &str,
    ) {
        let actual = sut.to_string();

        assert_eq!(actual, expected);
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
    #[case::nan_rtt(f64::NAN, Some(0.0))]
    #[case::infinite_rtt(f64::INFINITY, Some(0.0))]
    #[case::negative_rtt(-1.0, Some(0.0))]
    fn a_ping_with_an_unusable_rtt_is_rejected(
        #[case] rtt_ms: f64,
        #[case] loss_pct: Option<f64>,
    ) {
        let error = PingSample::from_millis(rtt_ms, loss_pct).unwrap_err();

        assert!(matches!(error, InvalidPingSample::Rtt(_)), "{error:?}");
    }

    #[rstest::rstest]
    #[case::excessive_loss(Some(101.0))]
    #[case::negative_loss(Some(-1.0))]
    #[case::nan_loss(Some(f64::NAN))]
    fn a_ping_with_an_unusable_loss_is_rejected(#[case] loss_pct: Option<f64>) {
        let error = PingSample::from_millis(10.0, loss_pct).unwrap_err();

        assert!(matches!(error, InvalidPingSample::Loss(_)), "{error:?}");
    }

    #[test]
    fn a_ping_rtt_in_milliseconds_becomes_a_duration() {
        let sample = PingSample::from_millis(23.378, None).unwrap();

        assert_eq!(sample.rtt(), Duration::from_micros(23_378));
    }

    #[rstest::rstest]
    #[case::nan(f64::NAN)]
    #[case::infinite(f64::INFINITY)]
    fn a_non_finite_percent_is_rejected(#[case] value: f64) {
        let error = Percent::try_from(value).unwrap_err();

        assert!(matches!(error, InvalidPercent::NotFinite(_)), "{error:?}");
    }

    #[rstest::rstest]
    #[case::below_zero(-1.0)]
    #[case::above_one_hundred(100.1)]
    fn a_percent_outside_zero_to_one_hundred_is_rejected(#[case] value: f64) {
        let error = Percent::try_from(value).unwrap_err();

        assert!(matches!(error, InvalidPercent::OutOfRange(_)), "{error:?}");
    }

    #[rstest::rstest]
    #[case::zero(0.0)]
    #[case::one_hundred(100.0)]
    fn zero_and_one_hundred_are_valid_percents(#[case] value: f64) {
        let result = Percent::try_from(value);

        assert!(result.is_ok(), "{result:?}");
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
