//! Pure domain model and judges. No network, no filesystem, no clock reads
//! beyond what callers pass in — everything here is a function of its inputs.

pub mod model;
pub use model::{
    CheckResult, CityName, CountryCode, GateId, InvalidCountryCode, Severity,
    Verdict,
};

pub mod report;
pub use report::Report;

pub mod gate;
pub use gate::GateOverrides;

pub mod ip_lists;

pub mod profile;
pub use profile::{GateScope, ScanProfile};

pub mod verdict;
