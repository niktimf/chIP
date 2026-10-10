mod calibrate;
mod config;
mod scan;

use std::io::Write as _;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use chip_core::{CheckResult, Report, ScanOutcome};
use clap::Parser as _;
use config::{Cli, Command};
use serde::Serialize;
use tokio::io::AsyncWriteExt as _;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .try_init()
    {
        print_error(format_args!(
            "warning: could not install the log subscriber: {error}"
        ));
    }

    let code = match run().await {
        Ok(Completion::Scan(outcome)) => scan_exit_code(outcome),
        Ok(Completion::Calibration) => 0,
        // A reader that stopped early (`chip scan ... | head`) closed the
        // pipe. That is not worth a message, but the output is incomplete,
        // so the run still ends with exit code 2 like any other failure.
        Err(CliError::Output(error))
            if error.kind() == std::io::ErrorKind::BrokenPipe =>
        {
            2
        }
        Err(error) => {
            print_error(format_args!(
                "error: {}",
                chip_io::describe_error(&error)
            ));
            2
        }
    };
    ExitCode::from(code)
}

/// The log filter from `RUST_LOG`, at `info` when the variable is unset. A
/// value that does not parse is reported and replaced by `info` as a whole,
/// so a typo is visible instead of silently changing what is logged.
fn log_filter() -> EnvFilter {
    let builder =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into());
    builder.from_env().unwrap_or_else(|error| {
        print_error(format_args!(
            "warning: ignoring RUST_LOG and logging at info: {error}"
        ));
        builder.parse_lossy("")
    })
}

/// The timeout of one HTTP request of `scan` and `calibrate`, direct or
/// through the SOCKS tunnel.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long polling waits for one Globalping measurement to finish.
const GLOBALPING_DEADLINE: Duration = Duration::from_secs(90);
/// How many RIPE Atlas anchors of a city the latency gate and the
/// calibration ping.
const CITY_ANCHORS: NonZeroUsize = NonZeroUsize::new(3).expect("3 is non-zero");

/// The HTTP client of a command's direct requests: every command sends the
/// same user agent and uses [`REQUEST_TIMEOUT`].
fn http_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("chip/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// How a command finished when nothing stopped it.
enum Completion {
    /// The scan ran to the end; its outcome decides the exit code.
    Scan(ScanOutcome),
    Calibration,
}

/// Why a command stopped. Every variant ends the run with exit code 2.
#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("invalid configuration")]
    Config(#[source] config::ConfigError),
    #[error("could not write output")]
    Output(#[source] std::io::Error),
    #[error("could not encode JSON report")]
    EncodeJson(#[source] serde_json::Error),
    #[error("could not write {}", path.display())]
    WriteJson {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The calibration error already names the failed step, so it is shown
    /// without a prefix of its own.
    #[error(transparent)]
    Calibrate(anyhow::Error),
}

async fn run() -> Result<Completion, CliError> {
    let command = Cli::parse()
        .into_command(|name| std::env::var_os(name))
        .map_err(CliError::Config)?;
    match command {
        Command::Scan(args) => {
            run_scan_command(*args).await.map(Completion::Scan)
        }
        Command::Calibrate(args) => run_calibrate_command(&args)
            .await
            .map(|()| Completion::Calibration),
    }
}

/// Writes the command's output to stdout.
fn print_output(text: &str) -> Result<(), CliError> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{text}")
        .and_then(|()| stdout.flush())
        .map_err(CliError::Output)
}

/// Writes a diagnostic line to stderr.
#[expect(
    clippy::let_underscore_must_use,
    reason = "stderr is the last channel left: a failed write here has \
              nowhere to be reported, and the exit code still carries the \
              failure"
)]
fn print_error(message: std::fmt::Arguments<'_>) {
    let _: std::io::Result<()> =
        writeln!(std::io::stderr().lock(), "{message}");
}

/// Appends the Markdown report to the GitHub Actions step summary. A
/// failure only warns: the report still goes to stdout.
async fn append_step_summary(path: &Path, report: &Report) {
    let write_result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        file.write_all(report.markdown().as_bytes()).await
    }
    .await;
    if let Err(error) = write_result {
        print_error(format_args!(
            "warning: could not write GITHUB_STEP_SUMMARY {}: {error}",
            path.display()
        ));
    }
}

/// The exit code of a finished scan. The JSON report's `exit_code` carries
/// the same number, and pipelines depend on both: `0` passed, `1` failed,
/// `2` undetermined.
const fn scan_exit_code(outcome: ScanOutcome) -> u8 {
    match outcome {
        ScanOutcome::Passed => 0,
        ScanOutcome::Failed => 1,
        ScanOutcome::Undetermined => 2,
    }
}

/// The `--json` report. The fields are in alphabetical order because the
/// first version of the document was a `serde_json::Value`, which writes its
/// keys sorted; pipelines that diff the file see the same order.
#[derive(Debug, Serialize)]
struct JsonReport<'a> {
    exit_code: u8,
    overall: &'static str,
    results: Vec<JsonResult<'a>>,
    schema: u8,
}

impl JsonReport<'_> {
    /// Raised only when a field changes meaning or disappears.
    const SCHEMA: u8 = 1;
}

impl<'a> From<&'a Report> for JsonReport<'a> {
    fn from(report: &'a Report) -> Self {
        let exit_code = scan_exit_code(report.outcome());
        let overall = report.overall().into();
        let results = report.results.iter().map(JsonResult::from).collect();
        Self {
            exit_code,
            overall,
            results,
            schema: Self::SCHEMA,
        }
    }
}

/// One gate's line in the `--json` report.
#[derive(Debug, Serialize)]
struct JsonResult<'a> {
    detail: &'a str,
    gate: &'static str,
    severity: &'static str,
    skipped: bool,
}

impl<'a> From<&'a CheckResult> for JsonResult<'a> {
    fn from(result: &'a CheckResult) -> Self {
        Self {
            detail: result.detail(),
            gate: result.gate().as_str(),
            severity: result.severity().into(),
            skipped: result.is_skipped(),
        }
    }
}

async fn run_scan_command(
    command: config::ScanCommand,
) -> Result<ScanOutcome, CliError> {
    let report = scan::run_scan(&command).await;
    // The files go first: a closed stdout (`chip scan ... | head`) must not
    // cost a pipeline its `--json` report or the job summary. Every output
    // is attempted, and the first error decides how the run ends.
    let json = match command.json_path() {
        Some(path) => write_json_report(path, &report).await,
        None => Ok(()),
    };
    if let Some(path) = command.step_summary_path() {
        append_step_summary(path, &report).await;
    }
    let table = print_output(&report.table());
    json.and(table)?;

    Ok(report.outcome())
}

/// Writes the `--json` report to `path`.
async fn write_json_report(
    path: &Path,
    report: &Report,
) -> Result<(), CliError> {
    let encoded = serde_json::to_vec_pretty(&JsonReport::from(report))
        .map_err(CliError::EncodeJson)?;
    tokio::fs::write(path, encoded).await.map_err(|source| {
        CliError::WriteJson {
            path: path.to_owned(),
            source,
        }
    })
}

async fn run_calibrate_command(
    command: &config::CalibrateCommand,
) -> Result<(), CliError> {
    let rows = calibrate::run_calibrate(command)
        .await
        .map_err(CliError::Calibrate)?;
    print_output(&calibrate::CalibrationReport::new(&rows).to_string())
}

#[cfg(test)]
mod tests {
    use chip_core::Verdict;
    use chip_core::gate::{GEO, LATENCY, REACH, REPUTATION};

    use super::*;

    #[rstest::rstest]
    #[case::a_warning_and_a_skipped_gate_pass(
        vec![
            CheckResult::new(GEO, Verdict::warn("RU 60%")),
            CheckResult::skipped(REACH, "ports are already in use"),
        ],
        0
    )]
    #[case::a_failure_fails(
        vec![
            CheckResult::new(REPUTATION, Verdict::fail("vpn")),
            CheckResult::new(LATENCY, Verdict::error("no probes")),
        ],
        1
    )]
    #[case::an_error_without_a_failure_is_undetermined(
        vec![CheckResult::new(LATENCY, Verdict::error("no probes"))],
        2
    )]
    fn the_json_report_carries_the_exit_code_pipelines_rely_on(
        #[case] results: Vec<CheckResult>,
        #[case] expected: u64,
    ) {
        let report = Report { results };

        let document = serde_json::to_value(JsonReport::from(&report)).unwrap();

        assert_eq!(document["exit_code"].as_u64(), Some(expected));
    }

    #[test]
    fn the_json_report_keeps_its_schema_1_document() {
        let report = Report {
            results: vec![
                CheckResult::new(REPUTATION, Verdict::fail("vpn")),
                CheckResult::new(GEO, Verdict::warn("RU 60%")),
                CheckResult::new(LATENCY, Verdict::error("no probes")),
                CheckResult::skipped(REACH, "ports are already in use"),
            ],
        };

        let document =
            serde_json::to_string_pretty(&JsonReport::from(&report)).unwrap();

        assert_eq!(
            document,
            r#"{
  "exit_code": 1,
  "overall": "FAIL",
  "results": [
    {
      "detail": "vpn",
      "gate": "reputation",
      "severity": "FAIL",
      "skipped": false
    },
    {
      "detail": "RU 60%",
      "gate": "geo",
      "severity": "WARN",
      "skipped": false
    },
    {
      "detail": "no probes",
      "gate": "latency",
      "severity": "ERROR",
      "skipped": false
    },
    {
      "detail": "ports are already in use",
      "gate": "reach",
      "severity": "OK",
      "skipped": true
    }
  ],
  "schema": 1
}"#
        );
    }
}
