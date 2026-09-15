//! Pure domain model and judges. No network, no filesystem, no clock reads
//! beyond what callers pass in — everything here is a function of its inputs.

pub mod model;
pub use model::{CheckResult, CountryCode, GateId, InvalidCountryCode, Severity, Verdict};
