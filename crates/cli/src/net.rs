//! Network settings shared by `scan` and `calibrate`.

use std::num::NonZeroUsize;
use std::time::Duration;

/// The timeout of one HTTP request of `scan` and `calibrate`, direct or
/// through the SOCKS tunnel.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long polling waits for one Globalping measurement to finish.
pub const GLOBALPING_DEADLINE: Duration = Duration::from_secs(90);
/// How many RIPE Atlas anchors of a city the latency gate and the
/// calibration ping.
pub const CITY_ANCHORS: NonZeroUsize =
    NonZeroUsize::new(3).expect("3 is non-zero");

/// The HTTP client of a command's direct requests: every command sends the
/// same user agent and uses [`REQUEST_TIMEOUT`].
pub fn http_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("chip/", env!("CARGO_PKG_VERSION")))
        .build()
}
