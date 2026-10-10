//! Pure domain model and judges. No network, no filesystem, no clock reads
//! beyond what callers pass in — everything here is a function of its inputs.

pub mod values;
pub use values::{CityName, CountryCode, InvalidCountryCode};

pub mod report;
pub use report::gate::{GateId, GateOverrides};
pub use report::profile::{GateScope, ScanProfile};
pub use report::{CheckResult, Report, ScanOutcome, Severity, Verdict};

pub mod checks;
