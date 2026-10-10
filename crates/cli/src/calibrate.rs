use std::fmt;
use std::time::Duration;

use anyhow::Context as _;
use chip_core::model::{AnchorSeries, PingSample, PingSweepFacts};
use chip_core::verdict::latency::{
    LatencySummary, LatencyThresholds, summarize_latency,
};
use chip_io::atlas::{Anchor, AnchorClient, select_for_city};
use chip_io::globalping::{GlobalpingClient, Locations, MeasurementId, Ping};

use crate::config::{CalibrateCommand, CalibrationTarget, ProbeSelection};

const MEASUREMENT_DEADLINE: Duration = Duration::from_secs(90);
/// How many RIPE Atlas anchors of the target's city to measure against.
const ANCHORS_PER_CITY: usize = 3;

#[derive(Debug, Clone)]
pub struct CalibrationRow {
    pub label: String,
    pub summary: LatencySummary,
}

impl fmt::Display for CalibrationRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<28} {:>7.2} {:>7.2} {:>11.2}",
            self.label,
            self.summary.median_excess_ms,
            self.summary.p75_excess_ms,
            self.summary.median_loss_delta_pct
        )
    }
}

/// The calibration rows as a table, followed by the suggested thresholds as
/// the `--max-excess-ms` and `--max-loss-pct` flags to scan with.
pub struct CalibrationReport<'a> {
    rows: &'a [CalibrationRow],
}

impl<'a> CalibrationReport<'a> {
    pub const fn new(rows: &'a [CalibrationRow]) -> Self {
        Self { rows }
    }
}

impl fmt::Display for CalibrationReport<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "node                         median     p75  loss-delta")?;
        for row in self.rows {
            writeln!(f, "{row}")?;
        }
        let summaries: Vec<LatencySummary> =
            self.rows.iter().map(|row| row.summary).collect();
        LatencyThresholds::suggested_from(&summaries).map_or(
            Ok(()),
            |suggested| {
                write!(
                    f,
                    "\nsuggested: --max-excess-ms {:.1} --max-loss-pct {:.1}",
                    suggested.max_excess_ms(),
                    suggested.max_loss_delta_pp()
                )
            },
        )
    }
}

struct CalibrationSession {
    globalping: GlobalpingClient,
    anchors: Vec<Anchor>,
    probes: ProbeSelection,
    first_measurement_id: Option<MeasurementId<Ping>>,
}

impl CalibrationSession {
    async fn start(command: &CalibrateCommand) -> anyhow::Result<Self> {
        const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
        let http = crate::http_client(HTTP_TIMEOUT)
            .context("failed to build the HTTP client")?;
        let anchors = AnchorClient::new(http.clone())
            .anchors()
            .await
            .context("failed to fetch the RIPE Atlas anchor list")?;
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
        let city_anchors =
            select_for_city(&self.anchors, target.city(), ANCHORS_PER_CITY);
        if city_anchors.is_empty() {
            anyhow::bail!(
                "no RIPE Atlas anchor found for city '{}'",
                target.city()
            );
        }
        let locations = self
            .first_measurement_id
            .as_ref()
            .map_or_else(
                || {
                    Locations::ru(
                        self.probes.eyeball(),
                        self.probes.datacenter(),
                    )
                },
                |id| Ok(Locations::reuse(id.clone())),
            )
            .context("failed to build the Globalping probe locations")?;
        let candidate_id = self
            .globalping
            .create_ping(target.ip(), &locations)
            .await
            .with_context(|| {
                format!("failed to start a Globalping ping of {}", target.ip())
            })?;
        let sample = self
            .first_measurement_id
            .get_or_insert_with(|| candidate_id.clone())
            .clone();
        let candidate = self
            .globalping
            .poll_ping(&candidate_id, MEASUREMENT_DEADLINE)
            .await
            .with_context(|| {
                format!(
                    "failed to collect the Globalping ping of {}",
                    target.ip()
                )
            })?;
        let anchors = self.measure_anchors(city_anchors, &sample).await?;
        calibration_row(target, candidate, anchors)
    }

    async fn measure_anchors(
        &self,
        anchors: Vec<Anchor>,
        sample: &MeasurementId<Ping>,
    ) -> anyhow::Result<Vec<AnchorSeries>> {
        let mut measurements = Vec::with_capacity(anchors.len());
        for anchor in anchors {
            let id = self
                .globalping
                .create_ping(anchor.ip_v4, &Locations::reuse(sample.clone()))
                .await
                .with_context(|| {
                    format!(
                        "failed to start a Globalping ping of anchor {}",
                        anchor.fqdn
                    )
                })?;
            let samples = self
                .globalping
                .poll_ping(&id, MEASUREMENT_DEADLINE)
                .await
                .with_context(|| {
                    format!(
                        "failed to collect the Globalping ping of anchor {}",
                        anchor.fqdn
                    )
                })?;
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
    use pretty_assertions::assert_eq;

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
    fn the_report_lists_each_node_and_suggests_the_scan_flags() {
        let rows = [
            row("185.1.2.3 (Helsinki)", 4.95, 8.96, -0.25),
            row("10.0.0.1 (Frankfurt am Main)", 5.404, 9.123, -1.5),
        ];
        let sut = CalibrationReport::new(&rows);

        let rendered = sut.to_string();

        assert_eq!(
            rendered,
            "node                         median     p75  loss-delta\n\
             185.1.2.3 (Helsinki)            4.95    8.96       -0.25\n\
             10.0.0.1 (Frankfurt am Main)    5.40    9.12       -1.50\n\
             \n\
             suggested: --max-excess-ms 14.1 --max-loss-pct 0.0"
        );
    }

    #[test]
    fn a_report_without_nodes_is_only_the_header() {
        let sut = CalibrationReport::new(&[]);

        let rendered = sut.to_string();

        assert_eq!(
            rendered,
            "node                         median     p75  loss-delta\n"
        );
    }
}
