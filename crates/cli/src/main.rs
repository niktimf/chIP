mod calibrate;
mod config;
mod scan;

use std::io::Write as _;
use std::process::ExitCode;

use chip_core::{Report, ScanOutcome};
use clap::Parser as _;
use config::{Cli, Command};
use tokio::io::AsyncWriteExt as _;

#[tokio::main]
async fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if let Err(error) =
        tracing_subscriber::fmt().with_env_filter(filter).try_init()
    {
        print_error(format_args!(
            "warning: could not install the log subscriber: {error}"
        ));
    }

    let command = match Cli::parse().into_command() {
        Ok(command) => command,
        Err(error) => {
            print_error(format_args!(
                "error: invalid configuration: {error:#}"
            ));
            return ExitCode::from(2);
        }
    };
    match command {
        Command::Scan(args) => run_scan_command(*args).await,
        Command::Calibrate(args) => run_calibrate_command(&args).await,
    }
}

/// Writes the command's output to stdout.
///
/// A reader that stopped early (`chip scan ... | head`) closes the pipe; that
/// is not worth a message, but the output is incomplete, so it still ends the
/// run with exit code 2 like any other write failure.
fn print_output(text: &str) -> Result<(), ExitCode> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{text}")
        .and_then(|()| stdout.flush())
        .map_err(|error| {
            if error.kind() != std::io::ErrorKind::BrokenPipe {
                print_error(format_args!(
                    "error: could not write output: {error}"
                ));
            }
            ExitCode::from(2)
        })
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

/// Appends the Markdown report to the GitHub Actions step summary, if the
/// run has one. A failure only warns: the report is already on stdout.
async fn append_step_summary(report: &Report) {
    let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") else {
        return;
    };
    let write_result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        file.write_all(report.markdown().as_bytes()).await
    }
    .await;
    if let Err(error) = write_result {
        print_error(format_args!(
            "warning: could not write GITHUB_STEP_SUMMARY {path}: {error}"
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

/// The `--json` report, schema 1.
fn json_report(report: &Report) -> serde_json::Value {
    serde_json::json!({
        "schema": 1,
        "overall": report.overall().to_string(),
        "exit_code": scan_exit_code(report.outcome()),
        "results": report.results.iter().map(|result| serde_json::json!({
            "gate": result.gate().as_str(),
            "severity": result.severity().to_string(),
            "skipped": result.is_skipped(),
            "detail": result.detail(),
        })).collect::<Vec<_>>(),
    })
}

async fn run_scan_command(command: config::ScanCommand) -> ExitCode {
    let report = scan::run_scan(&command).await;
    if let Err(code) = print_output(&report.table()) {
        return code;
    }

    if let Some(path) = command.json_path() {
        let encoded = match serde_json::to_vec_pretty(&json_report(&report)) {
            Ok(encoded) => encoded,
            Err(error) => {
                print_error(format_args!(
                    "error: could not encode JSON report: {error}"
                ));
                return ExitCode::from(2);
            }
        };
        if let Err(error) = tokio::fs::write(path, encoded).await {
            print_error(format_args!(
                "error: could not write {}: {error}",
                path.display()
            ));
            return ExitCode::from(2);
        }
    }

    append_step_summary(&report).await;

    ExitCode::from(scan_exit_code(report.outcome()))
}

async fn run_calibrate_command(command: &config::CalibrateCommand) -> ExitCode {
    match calibrate::run_calibrate(command).await {
        Ok(rows) => print_output(&calibrate::render_calibration(&rows))
            .map_or_else(|code| code, |()| ExitCode::SUCCESS),
        Err(error) => {
            print_error(format_args!("error: {error:#}"));
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use chip_core::gate::{GEO, LATENCY, REACH, REPUTATION};
    use chip_core::{CheckResult, Verdict};

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

        let document = json_report(&report);

        assert_eq!(document["exit_code"].as_u64(), Some(expected));
    }
}
