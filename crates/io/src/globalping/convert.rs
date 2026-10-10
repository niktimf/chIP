use super::types::{RawMeasurement, RawProbeResult};
use chip_core::model::{
    AnchorSeries, HttpProbeOutcome, PingSample, PingSweepFacts,
    ProbeAlignmentError, ReachFacts,
};

fn extract_ping(results: &[RawProbeResult]) -> Vec<Option<PingSample>> {
    results
        .iter()
        .map(|r| match (&r.result.stats, r.result.status.as_str()) {
            (Some(stats), "finished") => stats.min.and_then(|rtt| {
                PingSample::new(rtt, stats.loss)
                    .inspect_err(|error| {
                        tracing::warn!(
                            city = r.probe.city.as_deref(),
                            network = r.probe.network.as_deref(),
                            rtt_ms = rtt,
                            loss = stats.loss,
                            %error,
                            "invalid ping sample counted as no reply"
                        );
                    })
                    .ok()
            }),
            _ => None,
        })
        .collect()
}

fn extract_http(result: &RawProbeResult) -> HttpProbeOutcome {
    if result.result.status == "finished" && result.result.status_code.is_some()
    {
        HttpProbeOutcome::Ok
    } else {
        HttpProbeOutcome::Failed
    }
}

/// # Errors
///
/// Returns `ProbeAlignmentError` when an anchor measurement has a different
/// probe count than the candidate's.
pub fn ping_sweep_facts(
    candidate: &RawMeasurement,
    anchors: &[(String, RawMeasurement)],
) -> Result<PingSweepFacts, ProbeAlignmentError> {
    let candidate = extract_ping(&candidate.results);
    let city_anchors = anchors
        .iter()
        .map(|(id, measurement)| {
            AnchorSeries::new(id, extract_ping(&measurement.results))
        })
        .collect();
    PingSweepFacts::new(candidate, city_anchors)
}

/// # Errors
///
/// Returns `ProbeAlignmentError` when the two measurements have different
/// probe counts.
pub fn reach_facts(
    candidate: &RawMeasurement,
    control: &RawMeasurement,
) -> Result<ReachFacts, ProbeAlignmentError> {
    ReachFacts::new(
        candidate.results.iter().map(extract_http).collect(),
        control.results.iter().map(extract_http).collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::{ping_sweep_facts, reach_facts};
    use crate::globalping::types::{
        RawMeasurement, RawPingStats, RawProbe, RawProbeResult, RawResult,
    };

    fn ping_result(
        city: &str,
        network: &str,
        status: &str,
        min: Option<f64>,
        loss: Option<f64>,
    ) -> RawProbeResult {
        RawProbeResult {
            probe: RawProbe {
                city: Some(city.into()),
                network: Some(network.into()),
                asn: None,
                tags: vec![],
            },
            result: RawResult {
                status: status.into(),
                failure_source: (status == "failed")
                    .then(|| "target".to_string()),
                stats: min.map(|min| RawPingStats {
                    min: Some(min),
                    loss,
                }),
                status_code: None,
            },
        }
    }

    fn http_result(
        city: &str,
        status: &str,
        code: Option<u16>,
    ) -> RawProbeResult {
        RawProbeResult {
            probe: RawProbe {
                city: Some(city.into()),
                network: Some("net".into()),
                asn: None,
                tags: vec![],
            },
            result: RawResult {
                status: status.into(),
                failure_source: None,
                stats: None,
                status_code: code,
            },
        }
    }

    fn measurement(results: Vec<RawProbeResult>) -> RawMeasurement {
        RawMeasurement {
            id: "m".into(),
            status: "finished".into(),
            results,
        }
    }

    #[test]
    fn ping_sweep_facts_keeps_one_candidate_sample_per_probe() {
        let candidate = measurement(vec![ping_result(
            "Moscow",
            "Timeweb",
            "finished",
            Some(20.0),
            Some(0.0),
        )]);
        let facts = ping_sweep_facts(&candidate, &[]).unwrap();
        assert_eq!(facts.candidate().len(), 1);
    }

    #[test]
    fn ping_sweep_facts_reads_min_rtt_and_loss_from_finished_results() {
        let candidate = measurement(vec![ping_result(
            "Moscow",
            "Timeweb",
            "finished",
            Some(20.0),
            Some(1.5),
        )]);
        let facts = ping_sweep_facts(&candidate, &[]).unwrap();
        let sample = facts.candidate()[0].unwrap();
        assert!((sample.rtt_ms() - 20.0).abs() < f64::EPSILON);
        assert_eq!(sample.loss_pct(), Some(1.5));
    }

    #[test]
    fn ping_sweep_facts_reads_a_failed_result_as_none() {
        let candidate = measurement(vec![ping_result(
            "Vladivostok",
            "PortTelekom",
            "failed",
            None,
            None,
        )]);
        let facts = ping_sweep_facts(&candidate, &[]).unwrap();
        assert_eq!(facts.candidate(), &[None]);
    }

    #[test]
    fn ping_sweep_facts_carries_every_anchor_aligned_to_the_same_probes() {
        let candidate = measurement(vec![
            ping_result("Moscow", "Timeweb", "finished", Some(20.0), Some(0.0)),
            ping_result("Kursk", "Kurier", "finished", Some(50.0), Some(0.0)),
        ]);
        let anchor_a = measurement(vec![
            ping_result("Moscow", "Timeweb", "finished", Some(14.0), Some(0.0)),
            ping_result("Kursk", "Kurier", "failed", None, None),
        ]);
        let facts =
            ping_sweep_facts(&candidate, &[("as1".to_string(), anchor_a)])
                .unwrap();
        assert_eq!(facts.city_anchors().len(), 1);
        assert_eq!(facts.city_anchors()[0].id(), "as1");
        assert!(
            (facts.city_anchors()[0].samples()[0].unwrap().rtt_ms() - 14.0)
                .abs()
                < f64::EPSILON
        );
        assert_eq!(facts.city_anchors()[0].samples()[1], None);
    }

    #[test]
    fn reach_facts_maps_a_finished_result_with_a_status_code_to_ok() {
        let candidate =
            measurement(vec![http_result("Moscow", "finished", Some(200))]);
        let control =
            measurement(vec![http_result("Moscow", "finished", Some(200))]);
        let facts = reach_facts(&candidate, &control).unwrap();
        assert_eq!(facts.probes.len(), 1);
        assert_eq!(
            facts.probes[0].candidate,
            chip_core::model::HttpProbeOutcome::Ok
        );
        assert_eq!(
            facts.probes[0].control,
            chip_core::model::HttpProbeOutcome::Ok
        );
    }

    #[test]
    fn reach_facts_maps_a_failed_result_to_failed() {
        let candidate =
            measurement(vec![http_result("Moscow", "failed", None)]);
        let control =
            measurement(vec![http_result("Moscow", "finished", Some(200))]);
        let facts = reach_facts(&candidate, &control).unwrap();
        assert_eq!(
            facts.probes[0].candidate,
            chip_core::model::HttpProbeOutcome::Failed
        );
    }

    #[test]
    fn ping_sweep_rejects_an_anchor_with_a_different_probe_count() {
        let candidate = measurement(vec![ping_result(
            "Moscow",
            "Timeweb",
            "finished",
            Some(20.0),
            Some(0.0),
        )]);
        let anchor = measurement(vec![]);

        let error = ping_sweep_facts(
            &candidate,
            &[("short-anchor".to_string(), anchor)],
        )
        .unwrap_err();

        assert!(error.to_string().contains("short-anchor"));
    }

    /// A control probe missing from the reply used to read as `Failed`,
    /// which the reach gate takes for "the control was unreachable too".
    #[test]
    fn reach_rejects_a_control_with_fewer_probes_than_the_candidate() {
        let candidate = measurement(vec![
            http_result("Moscow", "finished", Some(200)),
            http_result("Kursk", "failed", None),
        ]);
        let control =
            measurement(vec![http_result("Moscow", "finished", Some(200))]);

        let error = reach_facts(&candidate, &control).unwrap_err();

        assert_eq!(
            error.to_string(),
            "anchor 'control' returned 1 probe samples, expected 2"
        );
    }
}
