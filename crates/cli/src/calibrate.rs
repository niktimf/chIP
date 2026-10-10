use std::fmt;

use anyhow::Context as _;
use chip_core::checks::globalping::latency::anchor::{Anchor, select_for_city};
use chip_core::checks::globalping::latency::{
    AnchorSeries, LatencySummary, PingSample, PingSweepFacts,
    SuggestedThresholds, summarize_latency,
};
use chip_io::atlas::AnchorClient;
use chip_io::globalping::{
    GlobalpingClient, Locations, MeasurementId, Ping, ProbeSelection,
};
use futures::{StreamExt as _, TryStreamExt as _, stream};

use crate::config::{CalibrateCommand, CalibrationTarget};
use crate::net::{CITY_ANCHORS, GLOBALPING_DEADLINE, http_client};

#[derive(Debug, Clone)]
pub struct CalibrationRow {
    pub label: String,
    pub summary: LatencySummary,
}

impl fmt::Display for CalibrationRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<28} {:>7.2} {:>7.2} ",
            self.label,
            self.summary.median_excess_ms,
            self.summary.p75_excess_ms,
        )?;
        match self.summary.median_loss_delta_pp {
            Some(loss_delta) => write!(f, "{loss_delta:>11.2}"),
            None => write!(f, "{:>11}", "n/a"),
        }
    }
}

/// The calibration rows as a table, followed by the suggested thresholds as
/// the `--max-excess-ms` and `--max-loss-pct` flags to scan with. When no
/// node reported loss, `--max-loss-pct` is left out: the run gives no value
/// for it.
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
        let Some(suggested) = SuggestedThresholds::from_calibration(&summaries)
        else {
            return Ok(());
        };
        write!(
            f,
            "\nsuggested: --max-excess-ms {:.1}",
            suggested.max_excess_ms()
        )?;
        match suggested.max_loss_delta_pp() {
            Some(loss_delta) => write!(f, " --max-loss-pct {loss_delta:.1}"),
            None => write!(f, " (loss not reported, --max-loss-pct unchanged)"),
        }
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
        let http = http_client().context("failed to build the HTTP client")?;
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
            select_for_city(&self.anchors, target.city(), CITY_ANCHORS);
        if city_anchors.is_empty() {
            anyhow::bail!(
                "no RIPE Atlas anchor found for city '{}'",
                target.city()
            );
        }
        let locations = self
            .first_measurement_id
            .as_ref()
            .map_or_else(|| Locations::ru(self.probes), Locations::reuse);
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
            .poll_ping(&candidate_id, GLOBALPING_DEADLINE)
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
        stream::iter(anchors)
            .then(|anchor| self.measure_anchor(anchor, sample))
            .try_collect()
            .await
    }

    async fn measure_anchor(
        &self,
        anchor: Anchor,
        sample: &MeasurementId<Ping>,
    ) -> anyhow::Result<AnchorSeries> {
        let id = self
            .globalping
            .create_ping(anchor.ip_v4(), &Locations::reuse(sample))
            .await
            .with_context(|| {
                format!(
                    "failed to start a Globalping ping of anchor {}",
                    anchor.fqdn()
                )
            })?;
        let samples = self
            .globalping
            .poll_ping(&id, GLOBALPING_DEADLINE)
            .await
            .with_context(|| {
                format!(
                    "failed to collect the Globalping ping of anchor {}",
                    anchor.fqdn()
                )
            })?;
        Ok(AnchorSeries::new(anchor.fqdn(), samples))
    }
}

fn calibration_row(
    target: &CalibrationTarget,
    candidate: Vec<Option<PingSample>>,
    anchors: Vec<AnchorSeries>,
) -> anyhow::Result<CalibrationRow> {
    let facts = PingSweepFacts::new(candidate, anchors)
        .context("Globalping returned misaligned probe sets")?;
    let label = format!("{} ({})", target.ip(), target.city());
    let summary = summarize_latency(&facts)
        .with_context(|| format!("failed to summarize latency of {label}"))?;
    Ok(CalibrationRow { label, summary })
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
    let session = CalibrationSession::start(command).await?;
    // The first target's ping picks the probes that every later ping
    // reuses, so the targets are measured one after another and the session
    // passes from each step to the next.
    stream::try_unfold(
        (session, command.targets().iter()),
        |(mut session, mut targets)| async move {
            let Some(target) = targets.next() else {
                return Ok(None);
            };
            let row = session.calibrate(target).await?;
            Ok(Some((row, (session, targets))))
        },
    )
    .try_collect()
    .await
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn row(
        label: &str,
        median_excess_ms: f64,
        p75_excess_ms: f64,
        median_loss_delta_pp: Option<f64>,
    ) -> CalibrationRow {
        CalibrationRow {
            label: label.into(),
            summary: LatencySummary {
                median_excess_ms,
                p75_excess_ms,
                median_loss_delta_pp,
                valid_probes: 12,
            },
        }
    }

    #[test]
    fn the_report_lists_each_node_and_suggests_the_scan_flags() {
        let rows = [
            row("185.1.2.3 (Helsinki)", 4.95, 8.96, Some(-0.25)),
            row("10.0.0.1 (Frankfurt am Main)", 5.404, 9.123, Some(-1.5)),
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
    fn a_report_without_reported_loss_prints_no_loss_flag() {
        let rows = [row("185.1.2.3 (Helsinki)", 4.95, 8.96, None)];
        let sut = CalibrationReport::new(&rows);

        let rendered = sut.to_string();

        assert_eq!(
            rendered,
            "node                         median     p75  loss-delta\n\
             185.1.2.3 (Helsinki)            4.95    8.96         n/a\n\
             \n\
             suggested: --max-excess-ms 14.0 \
             (loss not reported, --max-loss-pct unchanged)"
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
