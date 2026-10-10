mod calibrate;
mod config;
mod scan;

use std::io::Write as _;
use std::process::ExitCode;

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
async fn append_step_summary(report: &chip_core::Report) {
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

async fn run_scan_command(command: config::ScanCommand) -> ExitCode {
    let report = scan::run_scan(&command).await;
    if let Err(code) = print_output(&report.table()) {
        return code;
    }

    if let Some(path) = command.json_path() {
        let document = serde_json::json!({
            "schema": 1,
            "overall": report.overall().to_string(),
            "exit_code": report.exit_code(),
            "results": report.results.iter().map(|result| serde_json::json!({
                "gate": result.gate().as_str(),
                "severity": result.severity().to_string(),
                "skipped": result.is_skipped(),
                "detail": result.detail(),
            })).collect::<Vec<_>>(),
        });
        let encoded = match serde_json::to_vec_pretty(&document) {
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

    ExitCode::from(u8::try_from(report.exit_code()).unwrap_or(2))
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
