use std::time::Duration;

use strum::Display;

use crate::values::CountryCode;

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

/// A country vote from a single service. Used by the `service_geo` judge to
/// determine whether the IP's location detection is consistent across major
/// services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCountryVote {
    pub source: ServiceGeoSource,
    pub observation: CountryObservation,
}

/// The country one probed source (a CDN edge or a service) placed the
/// candidate in.
///
/// A source that answered without a country and a source that gave no answer
/// are separate states: only the second leaves the gate unable to tell what
/// that source would have said, for example that it sees Russia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CountryObservation {
    Country(CountryCode),
    /// The source answered, but the response named no recognizable location.
    Silent,
    /// The source gave no answer: a failed request, an HTTP error status or a
    /// body of the wrong format. The string is the cause.
    Unavailable(String),
}

/// A CDN whose edge location the CDN-edge gate reads. `Display` gives the
/// name shown in the verdict detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[strum(serialize_all = "snake_case")]
pub enum CdnEdge {
    Cloudflare,
    YoutubeGgc,
    NetflixOca,
}

/// What the probe of one CDN edge showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdnEdgeVote {
    pub edge: CdnEdge,
    pub observation: CountryObservation,
}

/// Result of one captcha observation. Unlike `Option<bool>`, this keeps a
/// transport failure distinct from a clean response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptchaObservation {
    Clear,
    Triggered,
    Unavailable(String),
}

/// The Google Search captcha probe: one request and one more after a pause.
/// A captcha counts only when the retry reproduces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptchaRetry {
    pub first: CaptchaObservation,
    pub retry: CaptchaObservation,
    /// The pause between the two requests; the verdict detail names it.
    pub interval: Duration,
}
