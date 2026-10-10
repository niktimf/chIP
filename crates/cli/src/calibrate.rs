use std::time::Duration;

use anyhow::Context as _;
use chip_core::model::{AnchorSeries, PingSample, PingSweepFacts};
use chip_core::verdict::latency::{LatencySummary, summarize_latency};
use chip_io::atlas::{Anchor, AnchorClient, select_for_city};
use chip_io::globalping::{
    GlobalpingClient, Locations, MeasurementId, MeasurementKind,
};

use crate::config::{CalibrateCommand, CalibrationTarget, ProbeSelection};

const MEASUREMENT_DEADLINE: Duration = Duration::from_secs(90);

#[derive(Debug, Clone)]
pub struct CalibrationRow {
    pub label: String,
    pub summary: LatencySummary,
}

/// Threshold values to pass back as `--max-excess-ms` and `--max-loss-pct`,
/// in the units of those flags.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SuggestedThresholds {
    pub max_excess_ms: f64,
    pub max_loss_pct: f64,
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
            .poll_ping(&candidate_id, MEASUREMENT_DEADLINE)
            .await?;
        let anchors = self.measure_anchors(city_anchors, &sample).await?;
        calibration_row(target, candidate, anchors)
    }

    async fn measure_anchors(
        &self,
        anchors: Vec<Anchor>,
        sample: &MeasurementId,
    ) -> anyhow::Result<Vec<AnchorSeries>> {
        let mut measurements = Vec::with_capacity(anchors.len());
        for anchor in anchors {
            let id = self
                .globalping
                .create(
                    &MeasurementKind::ping(anchor.ip_v4),
                    &Locations::reuse(sample.clone()),
                )
                .await?;
            let samples =
                self.globalping.poll_ping(&id, MEASUREMENT_DEADLINE).await?;
            measurements.push(AnchorSeries::new(anchor.fqdn, samples));
        }
        Ok(measurements)
    }
}

fn calibration_row(
    target: &CalibrationTarget,
    candidate: Vec<Option<PingSample>>,
    anchors: Vec<AnchorSeries>,
) -> anyhow::Result<CalibrationRow> {
    let facts = PingSweepFacts::new(candidate, anchors)
        .context("Globalping returned misaligned probe sets")?;
    let summary = summarize_latency(&facts)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("{} ({})", target.ip(), target.city()))?;
    Ok(CalibrationRow {
        label: format!("{} ({})", target.ip(), target.city()),
        summary,
    })
}

pub fn suggest_thresholds(
    rows: &[CalibrationRow],
) -> Option<SuggestedThresholds> {
    const EXCESS_MARGIN_MS: f64 = 5.0;
    let max_p75 = rows
        .iter()
        .map(|row| row.summary.p75_excess_ms)
        .reduce(f64::max)?;
    let max_loss = rows
        .iter()
        .map(|row| row.summary.median_loss_delta_pct)
        .reduce(f64::max)?;
    Some(SuggestedThresholds {
        max_excess_ms: max_p75 + EXCESS_MARGIN_MS,
        max_loss_pct: max_loss.max(0.0),
    })
}

pub fn render_calibration(rows: &[CalibrationRow]) -> String {
    let table = rows
        .iter()
        .map(|row| {
            format!(
                "{:<28} {:>7.2} {:>7.2} {:>11.2}\n",
                row.label,
                row.summary.median_excess_ms,
                row.summary.p75_excess_ms,
                row.summary.median_loss_delta_pct
            )
        })
        .collect::<Vec<_>>()
        .concat();
    let suggestion =
        suggest_thresholds(rows).map_or_else(String::new, |suggested| {
            format!(
                "\nsuggested: --max-excess-ms {:.1} --max-loss-pct {:.1}",
                suggested.max_excess_ms, suggested.max_loss_pct
            )
        });
    format!(
        "node                         median     p75  loss-delta\n\
         {table}{suggestion}"
    )
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

    fn row(
        label: &str,
        median_excess_ms: f64,
        p75_excess_ms: f64,
        median_loss_delta_pct: f64,
    ) -> CalibrationRow {
        CalibrationRow {
            label: label.into(),
            summary: LatencySummary {
                median_excess_ms,
                p75_excess_ms,
                median_loss_delta_pct,
                valid_probes: 12,
            },
        }
    }

    #[test]
    fn thresholds_add_five_ms_to_the_worst_p75() {
        let sut = vec![row("a", 4.95, 8.96, 0.0), row("b", 5.40, 9.12, 0.5)];

        let suggested = suggest_thresholds(&sut).unwrap();

        assert!((suggested.max_excess_ms - 14.12).abs() < 0.01);
        assert!((suggested.max_loss_pct - 0.5).abs() < 0.01);
    }

    #[test]
    fn no_threshold_is_suggested_without_calibration_rows() {
        let result = suggest_thresholds(&[]);

        assert_eq!(result, None);
    }
}
