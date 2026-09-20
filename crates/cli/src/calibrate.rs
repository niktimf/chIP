use std::time::Duration;

use anyhow::Context as _;
use chip_core::verdict::latency::summarize_latency;
use chip_io::atlas::{AnchorClient, select_for_city};
use chip_io::globalping::{
    GlobalpingClient, Locations, MeasurementId, MeasurementKind,
    ping_sweep_facts,
};

use crate::config::CalibrateCommand;

const MEASUREMENT_DEADLINE: Duration = Duration::from_secs(90);

#[derive(Debug, Clone)]
pub struct CalibrationRow {
    pub label: String,
    pub median_excess_ms: f64,
    pub p75_excess_ms: f64,
    pub median_loss_delta_pct: f64,
}

pub fn suggest_thresholds(rows: &[CalibrationRow]) -> Option<(f64, f64)> {
    let max_p75 = rows.iter().map(|row| row.p75_excess_ms).reduce(f64::max)?;
    let max_loss = rows
        .iter()
        .map(|row| row.median_loss_delta_pct)
        .reduce(f64::max)?;
    Some((max_p75 + 5.0, max_loss.max(0.0)))
}

pub fn render_calibration(rows: &[CalibrationRow]) -> String {
    use std::fmt::Write as _;

    let mut output = String::from(
        "node                         median     p75  loss-delta\n",
    );
    for row in rows {
        let _ = writeln!(
            output,
            "{:<28} {:>7.2} {:>7.2} {:>11.2}",
            row.label,
            row.median_excess_ms,
            row.p75_excess_ms,
            row.median_loss_delta_pct
        );
    }
    if let Some((excess, loss)) = suggest_thresholds(rows) {
        let _ = write!(
            output,
            "\nsuggested: --max-excess-ms {excess:.1} --max-loss-pct {loss:.1}"
        );
    }
    output
}

#[tracing::instrument(
    name = "calibrate",
    level = "info",
    skip_all,
    fields(target_count = command.targets().len())
)]
pub async fn run_calibrate(
    command: &CalibrateCommand,
) -> anyhow::Result<Vec<CalibrationRow>> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("chip/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let anchors = AnchorClient::new(http.clone()).anchors().await?;
    let globalping =
        GlobalpingClient::new(http, command.globalping_token().cloned());
    let mut first_measurement_id: Option<MeasurementId> = None;
    let mut rows = Vec::with_capacity(command.targets().len());

    for target in command.targets() {
        let city_anchors = select_for_city(&anchors, target.city(), 3);
        if city_anchors.is_empty() {
            anyhow::bail!(
                "no RIPE Atlas anchor found for city '{}'",
                target.city()
            );
        }
        let probes = command.probes();
        let locations = first_measurement_id.as_ref().map_or_else(
            || Locations::ru(probes.eyeball(), probes.datacenter()),
            |id| Ok(Locations::reuse(id.clone())),
        )?;
        let candidate_id = globalping
            .create(&MeasurementKind::ping(target.ip()), &locations)
            .await?;
        if first_measurement_id.is_none() {
            first_measurement_id = Some(candidate_id.clone());
        }
        let candidate = globalping
            .poll_until_finished(&candidate_id, MEASUREMENT_DEADLINE)
            .await?;
        let sample = first_measurement_id
            .as_ref()
            .expect("set immediately after the first create call");
        let mut anchor_measurements = Vec::with_capacity(city_anchors.len());
        for anchor in city_anchors {
            let id = globalping
                .create(
                    &MeasurementKind::ping(anchor.ip_v4),
                    &Locations::reuse(sample.clone()),
                )
                .await?;
            let measurement = globalping
                .poll_until_finished(&id, MEASUREMENT_DEADLINE)
                .await?;
            anchor_measurements.push((anchor.fqdn, measurement));
        }
        let facts = ping_sweep_facts(&candidate, &anchor_measurements)
            .context("Globalping returned misaligned probe sets")?;
        let summary = summarize_latency(&facts)
            .map_err(anyhow::Error::new)
            .with_context(|| format!("{} ({})", target.ip(), target.city()))?;
        rows.push(CalibrationRow {
            label: format!("{} ({})", target.ip(), target.city()),
            median_excess_ms: summary.median_excess_ms,
            p75_excess_ms: summary.p75_excess_ms,
            median_loss_delta_pct: summary.median_loss_delta_pct,
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_add_five_ms_to_the_worst_p75() {
        let rows = vec![
            CalibrationRow {
                label: "a".into(),
                median_excess_ms: 4.95,
                p75_excess_ms: 8.96,
                median_loss_delta_pct: 0.0,
            },
            CalibrationRow {
                label: "b".into(),
                median_excess_ms: 5.40,
                p75_excess_ms: 9.12,
                median_loss_delta_pct: 0.5,
            },
        ];

        let (excess, loss) = suggest_thresholds(&rows).unwrap();

        assert!((excess - 14.12).abs() < 0.01);
        assert!((loss - 0.5).abs() < 0.01);
    }

    #[test]
    fn no_threshold_is_suggested_without_calibration_rows() {
        let result = suggest_thresholds(&[]);

        assert_eq!(result, None);
    }
}
