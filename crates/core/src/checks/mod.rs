//! Facts and judges of every gate, grouped by the
//! [`Channel`](crate::report::gate::Channel) the gate is measured through.

pub mod direct;
pub mod globalping;
pub mod neighbors;
pub mod ssh;
pub mod tunnel;
