//! Gates of [`Channel::Tunnel`](crate::report::gate::Channel::Tunnel): HTTP
//! through the SOCKS tunnel into the candidate.

pub mod ai;
pub mod portal;
pub mod service_geo;
pub mod services;
pub mod tampering;

/// The outcome of probing one streaming/AI service, as classified by
/// `services` from an HTTP status and/or a response body/final URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    Available,
    Restricted,
    Blocked,
    /// The probe reached no conclusion (Cloudflare challenge, unrecognized
    /// body) — never read as evidence of either verdict.
    Inconclusive(String),
    /// The endpoint could not be reached or read. This is an ERROR gate, not
    /// a weak service verdict.
    Unavailable(String),
}
