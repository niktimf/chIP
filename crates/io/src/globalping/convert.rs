use super::types::{RawMeasurement, RawProbeResult};
use chip_core::model::{AnchorSeries, HttpProbeOutcome, PingSweepFacts, ReachFacts};

fn probe_label(result: &RawProbeResult) -> String {
    format!(
        "{}/{}",
        result.probe.city.as_deref().unwrap_or("?"),
        result.probe.network.as_deref().unwrap_or("?")
    )
}

fn extract_ping(results: &[RawProbeResult]) -> (Vec<Option<f64>>, Vec<Option<f64>>) {
    results
        .iter()
        .map(|r| match (&r.result.stats, r.result.status.as_str()) {
            (Some(stats), "finished") => (stats.min, stats.loss),
            _ => (None, None),
        })
        .unzip()
}

fn extract_http(results: &[RawProbeResult]) -> Vec<HttpProbeOutcome> {
    results
        .iter()
        .map(|r| {
            if r.result.status == "finished" && r.result.status_code.is_some() {
                HttpProbeOutcome::Ok
            } else {
                HttpProbeOutcome::Failed
            }
        })
        .collect()
}

pub fn ping_sweep_facts(
    candidate: &RawMeasurement,
    anchors: &[(String, RawMeasurement)],
) -> PingSweepFacts {
    let probe_labels = candidate.results.iter().map(probe_label).collect();
    let (candidate_rtt_ms, candidate_loss_pct) = extract_ping(&candidate.results);
    let city_anchors = anchors
        .iter()
        .map(|(id, measurement)| {
            let (rtt_ms, loss_pct) = extract_ping(&measurement.results);
            AnchorSeries {
                anchor_id: id.clone(),
                rtt_ms,
                loss_pct,
            }
        })
        .collect();
    PingSweepFacts {
        probe_labels,
        candidate_rtt_ms,
        candidate_loss_pct,
        city_anchors,
    }
}

pub fn reach_facts(candidate: &RawMeasurement, control: &RawMeasurement) -> ReachFacts {
    ReachFacts {
        probe_labels: candidate.results.iter().map(probe_label).collect(),
        candidate: extract_http(&candidate.results),
        control: extract_http(&control.results),
    }
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
                failure_source: (status == "failed").then(|| "target".to_string()),
                stats: min.map(|min| RawPingStats {
                    min: Some(min),
                    loss,
                }),
                status_code: None,
            },
        }
    }

    fn http_result(city: &str, status: &str, code: Option<u16>) -> RawProbeResult {
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
    fn ping_sweep_facts_labels_probes_as_city_slash_network() {
        let candidate = measurement(vec![ping_result(
            "Moscow",
            "Timeweb",
            "finished",
            Some(20.0),
            Some(0.0),
        )]);
        let facts = ping_sweep_facts(&candidate, &[]);
        assert_eq!(facts.probe_labels, vec!["Moscow/Timeweb"]);
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
        let facts = ping_sweep_facts(&candidate, &[]);
        assert_eq!(facts.candidate_rtt_ms, vec![Some(20.0)]);
        assert_eq!(facts.candidate_loss_pct, vec![Some(1.5)]);
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
        let facts = ping_sweep_facts(&candidate, &[]);
        assert_eq!(facts.candidate_rtt_ms, vec![None]);
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
        let facts = ping_sweep_facts(&candidate, &[("as1".to_string(), anchor_a)]);
        assert_eq!(facts.city_anchors.len(), 1);
        assert_eq!(facts.city_anchors[0].anchor_id, "as1");
        assert_eq!(facts.city_anchors[0].rtt_ms, vec![Some(14.0), None]);
    }

    #[test]
    fn reach_facts_maps_a_finished_result_with_a_status_code_to_ok() {
        let candidate = measurement(vec![http_result("Moscow", "finished", Some(200))]);
        let control = measurement(vec![http_result("Moscow", "finished", Some(200))]);
        let facts = reach_facts(&candidate, &control);
        assert_eq!(
            facts.candidate,
            vec![chip_core::model::HttpProbeOutcome::Ok]
        );
        assert_eq!(facts.control, vec![chip_core::model::HttpProbeOutcome::Ok]);
    }

    #[test]
    fn reach_facts_maps_a_failed_result_to_failed() {
        let candidate = measurement(vec![http_result("Moscow", "failed", None)]);
        let control = measurement(vec![http_result("Moscow", "finished", Some(200))]);
        let facts = reach_facts(&candidate, &control);
        assert_eq!(
            facts.candidate,
            vec![chip_core::model::HttpProbeOutcome::Failed]
        );
    }
}
