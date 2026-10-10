use std::time::Duration;

use crate::checks::globalping::ProbeAlignmentError;
use crate::values::units;
use crate::values::{InvalidPercent, Percent};

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
    /// Returns `InvalidPingSample` when the RTT is negative, not finite or
    /// too large for a `Duration`, or the loss is not a finite percentage in
    /// `0..=100`.
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
        "invalid ping sample: RTT must be finite, non-negative and below \
         2^64 seconds, got {0}"
    )]
    Rtt(f64),
    #[error("invalid ping sample: loss")]
    Loss(#[source] InvalidPercent),
}

/// One anchor's round-trip series against the same probe set as the
/// candidate.
///
/// `None` at index `i` means this anchor did not answer probe `i` (its own
/// measurement failed or timed out), not that it was slow.
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
/// candidate and the anchors of its declared city.
///
/// All series are measured by the same Globalping probe set, so index `i`
/// means the same physical probe everywhere in this struct.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    #[case::nan_rtt(f64::NAN, Some(0.0))]
    #[case::infinite_rtt(f64::INFINITY, Some(0.0))]
    #[case::negative_rtt(-1.0, Some(0.0))]
    #[case::rtt_too_large_for_a_duration(f64::MAX, Some(0.0))]
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

    fn reply(rtt_ms: f64) -> PingSample {
        PingSample::from_millis(rtt_ms, Some(0.0)).unwrap()
    }

    #[test]
    fn a_ping_sweep_keeps_every_anchor_aligned_to_the_candidate_probes() {
        let anchor = AnchorSeries::new("as1", vec![Some(reply(14.0)), None]);

        let sut = PingSweepFacts::new(
            vec![Some(reply(20.0)), Some(reply(50.0))],
            vec![anchor],
        )
        .unwrap();

        assert_eq!(sut.city_anchors().len(), 1);
        assert_eq!(sut.city_anchors()[0].id(), "as1");
        assert_eq!(sut.city_anchors()[0].samples(), [Some(reply(14.0)), None]);
    }

    #[test]
    fn a_ping_sweep_rejects_an_anchor_with_a_different_probe_count() {
        let anchor = AnchorSeries::new("short-anchor", Vec::new());

        let error = PingSweepFacts::new(vec![Some(reply(20.0))], vec![anchor])
            .unwrap_err();

        assert_eq!(
            error,
            ProbeAlignmentError {
                anchor_id: "short-anchor".to_owned(),
                expected: 1,
                actual: 0,
            }
        );
    }
}
