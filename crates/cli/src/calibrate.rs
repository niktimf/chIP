use std::time::Duration;

use anyhow::Context as _;
use chip_core::verdict::latency::summarize_latency;
use chip_io::atlas::{Anchor, AnchorClient, select_for_city};
use chip_io::globalping::{
    GlobalpingClient, Locations, MeasurementId, MeasurementKind,
    RawMeasurement, ping_sweep_facts,
};

use crate::config::{CalibrateCommand, CalibrationTarget, ProbeSelection};

const MEASUREMENT_DEADLINE: Duration = Duration::from_secs(90);

#[derive(Debug, Clone)]
pub struct CalibrationRow {
    pub label: String,
    pub median_excess_ms: f64,
    pub p75_excess_ms: f64,
    pub median_loss_delta_pct: f64,
}

struct CalibrationSession {
    globalping: GlobalpingClient,
    anchors: Vec<Anchor>,
    probes: ProbeSelection,
    first_measurement_id: Option<MeasurementId>,
}

impl CalibrationSession {
    async fn start(command: &CalibrateCommand) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("chip/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let anchors = AnchorClient::new(http.clone()).anchors().await?;
        Ok(Self {
            globalping: GlobalpingClient::new(
                http,
                command.globalping_token().cloned(),
            ),
            anchors,
            probes: command.probes(),
            first_measurement_id: None,
        })
    }

    async fn calibrate(
        &mut self,
        target: &CalibrationTarget,
    ) -> anyhow::Result<CalibrationRow> {
        let city_anchors = select_for_city(&self.anchors, target.city(), 3);
        if city_anchors.is_empty() {
            anyhow::bail!(
                "no RIPE Atlas anchor found for city '{}'",
                target.city()
            );
        }
        let locations = self.first_measurement_id.as_ref().map_or_else(
            || Locations::ru(self.probes.eyeball(), self.probes.datacenter()),
            |id| Ok(Locations::reuse(id.clone())),
        )?;
        let candidate_id = self
            .globalping
            .create(&MeasurementKind::ping(target.ip()), &locations)
            .await?;
        let sample = self
            .first_measurement_id
            .get_or_insert_with(|| candidate_id.clone())
            .clone();
        let candidate = self
            .globalping
            .poll_until_finished(&candidate_id, MEASUREMENT_DEADLINE)
            .await?;
        let anchors = self.measure_anchors(city_anchors, &sample).await?;
        calibration_row(target, &candidate, &anchors)
    }

    async fn measure_anchors(
        &self,
        anchors: Vec<Anchor>,
        sample: &MeasurementId,
    ) -> anyhow::Result<Vec<(String, RawMeasurement)>> {
        let mut measurements = Vec::with_capacity(anchors.len());
        for anchor in anchors {
            let id = self
                .globalping
                .create(
                    &MeasurementKind::ping(anchor.ip_v4),
                    &Locations::reuse(sample.clone()),
                )
                .await?;
            let measurement = self
                .globalping
                .poll_until_finished(&id, MEASUREMENT_DEADLINE)
                .await?;
            measurements.push((anchor.fqdn, measurement));
        }
        Ok(measurements)
    }
}

fn calibration_row(
    target: &CalibrationTarget,
    candidate: &RawMeasurement,
    anchors: &[(String, RawMeasurement)],
) -> anyhow::Result<CalibrationRow> {
    let facts = ping_sweep_facts(candidate, anchors)
        .context("Globalping returned misaligned probe sets")?;
    let summary = summarize_latency(&facts)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("{} ({})", target.ip(), target.city()))?;
    Ok(CalibrationRow {
        label: format!("{} ({})", target.ip(), target.city()),
        median_excess_ms: summary.median_excess_ms,
        p75_excess_ms: summary.p75_excess_ms,
        median_loss_delta_pct: summary.median_loss_delta_pct,
    })
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
    let mut session = CalibrationSession::start(command).await?;
    let mut rows = Vec::with_capacity(command.targets().len());
    for target in command.targets() {
        rows.push(session.calibrate(target).await?);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_add_five_ms_to_the_worst_p75() {
        let sut = vec![
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

        let (excess, loss) = suggest_thresholds(&sut).unwrap();

        assert!((excess - 14.12).abs() < 0.01);
        assert!((loss - 0.5).abs() < 0.01);
    }

    #[test]
    fn no_threshold_is_suggested_without_calibration_rows() {
        let result = suggest_thresholds(&[]);

        assert_eq!(result, None);
    }
}
