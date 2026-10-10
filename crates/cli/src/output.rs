//! What a command leaves behind: the stdout table, the `--json` report, the
//! GitHub Actions step summary and the final error line on stderr.

use std::io::Write as _;
use std::path::Path;

use chip_core::report::{CheckResult, Report};
use serde::Serialize;
use tokio::io::AsyncWriteExt as _;

use crate::config::ScanCommand;
use crate::error::CliError;
use crate::exit_status::ExitStatus;

/// Writes every output of a finished scan.
///
/// The files go first: a closed stdout (`chip scan ... | head`) must not
/// cost a pipeline its `--json` report or the job summary. Every output is
/// attempted, and the first error decides how the run ends. The step
/// summary only warns: the report still goes to stdout.
pub async fn write_scan_report(
    command: &ScanCommand,
    report: &Report,
) -> Result<(), CliError> {
    let json = match command.json_path() {
        Some(path) => write_json_report(path, report).await,
        None => Ok(()),
    };
    if let Some(path) = command.step_summary_path()
        && let Err(error) = write_step_summary(path, report).await
    {
        tracing::warn!(
            path = %path.display(),
            %error,
            "could not write GITHUB_STEP_SUMMARY"
        );
    }
    let table = print_output(&report.table());
    json.and(table)
}

/// Writes the command's output to stdout. A closed stdout is returned as an
/// error instead of the panic `println!` raises.
pub fn print_output(text: &str) -> Result<(), CliError> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{text}")
        .and_then(|()| stdout.flush())
        .map_err(CliError::Output)
}

/// Writes a line straight to stderr. Only for what cannot go through
/// `tracing`: the final error, and the subscriber that failed to install.
#[expect(
    clippy::let_underscore_must_use,
    reason = "stderr is the last channel left: a failed write here has \
              nowhere to be reported, and the exit code still carries the \
              failure"
)]
pub fn print_error(message: std::fmt::Arguments<'_>) {
    let _: std::io::Result<()> =
        writeln!(std::io::stderr().lock(), "{message}");
}

/// Appends the Markdown report to the GitHub Actions step summary, which
/// earlier steps of the job may already have written to.
pub async fn write_step_summary(
    path: &Path,
    report: &Report,
) -> std::io::Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    file.write_all(report.markdown().as_bytes()).await?;
    // A tokio file hands the write to a blocking thread; only `flush` waits
    // for it to land and returns its error.
    file.flush().await
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
        let exit_code = ExitStatus::from(report.outcome()).code();
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

#[cfg(test)]
mod tests {
    use chip_core::report::Verdict;
    use chip_core::report::gate::Gate;

    use super::*;

    #[rstest::rstest]
    #[case::a_warning_and_a_skipped_gate_pass(
        vec![
            CheckResult::new(Gate::Geo, Verdict::warn("RU 60%")),
            CheckResult::skipped(Gate::Reach, "ports are already in use"),
        ],
        0
    )]
    #[case::a_failure_fails(
        vec![
            CheckResult::new(Gate::Reputation, Verdict::fail("vpn")),
            CheckResult::new(Gate::Latency, Verdict::error("no probes")),
        ],
        1
    )]
    #[case::an_error_without_a_failure_is_undetermined(
        vec![CheckResult::new(Gate::Latency, Verdict::error("no probes"))],
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
                CheckResult::new(Gate::Reputation, Verdict::fail("vpn")),
                CheckResult::new(Gate::Geo, Verdict::warn("RU 60%")),
                CheckResult::new(Gate::Latency, Verdict::error("no probes")),
                CheckResult::skipped(Gate::Reach, "ports are already in use"),
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

    #[tokio::test]
    async fn the_step_summary_is_appended_after_what_earlier_steps_wrote() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("summary.md");
        std::fs::write(&path, "## Build\n\nok\n").unwrap();
        let report = Report {
            results: vec![CheckResult::new(Gate::Geo, Verdict::warn("RU 60%"))],
        };

        write_step_summary(&path, &report).await.unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "## Build\n\nok\n\
             ## chIP: WARN\n\n\
             | severity | gate | detail |\n\
             |---|---|---|\n\
             | WARN | geo | RU 60% |\n"
        );
    }
}
