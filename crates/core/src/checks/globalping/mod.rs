//! Gates measured by Globalping probes.
//!
//! The ping sweep of
//! [`Channel::Globalping`](crate::report::gate::Channel::Globalping) and the
//! HTTPS probes of
//! [`Channel::Listener`](crate::report::gate::Channel::Listener). Each
//! gate pairs series measured by one probe set and rejects a series of
//! another length with [`ProbeAlignmentError`].

pub mod latency;
pub mod reach;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "anchor '{anchor_id}' returned {actual} probe samples, expected {expected}"
)]
pub struct ProbeAlignmentError {
    anchor_id: String,
    expected: usize,
    actual: usize,
}
