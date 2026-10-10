//! The one place where fractional milliseconds and `Duration` convert into
//! each other. Measurement sources and CLI flags give RTTs in milliseconds;
//! the model keeps them as `Duration`, and the latency arithmetic turns them
//! back into `f64` milliseconds because an excess can be negative.

use std::time::{Duration, TryFromFloatSecsError};

const MILLIS_PER_SECOND: f64 = 1_000.0;
const NANOS_PER_MILLI: f64 = 1_000_000.0;

/// Fails for a negative, non-finite or too large value. A value with at most
/// three decimal places, as Globalping reports RTTs, comes back unchanged
/// from [`millis`], so verdict texts print the numbers they were given.
pub fn duration_from_millis(
    millis: f64,
) -> Result<Duration, TryFromFloatSecsError> {
    Duration::try_from_secs_f64(millis / MILLIS_PER_SECOND)
}

/// Goes through whole nanoseconds: `as_secs_f64() * 1000.0` does not round
/// trip, `0.014 s * 1000` prints as `14.000000000000002`. Replace with
/// `Duration::as_millis_f64` once `duration_millis_float` is stable; it is
/// still nightly-only on 1.98.
#[expect(
    clippy::cast_precision_loss,
    reason = "RTTs and latency thresholds stay far below 2^53 ns (~104 days)"
)]
pub fn millis(duration: Duration) -> f64 {
    duration.as_nanos() as f64 / NANOS_PER_MILLI
}
