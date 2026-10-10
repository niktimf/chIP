mod calibrate;
mod config;
mod error;
mod exit_status;
mod net;
mod output;
mod scan;

use std::io::IsTerminal as _;
use std::process::ExitCode;

use clap::Parser as _;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::{FromEnvError, LevelFilter};

use crate::config::{Cli, Command};
use crate::error::CliError;
use crate::exit_status::ExitStatus;

#[tokio::main]
async fn main() -> ExitCode {
    let (filter, rejected) = log_filter();
    match tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        // Colors only on a terminal, so a redirected log stays plain text.
        .with_ansi(std::io::stderr().is_terminal())
        .try_init()
    {
        Ok(()) => {
            if let Some(error) = rejected {
                tracing::warn!(%error, "ignoring RUST_LOG and logging at info");
            }
        }
        Err(error) => output::print_error(format_args!(
            "warning: could not install the log subscriber: {error}"
        )),
    }

    let status = run().await.unwrap_or_else(|error| {
        if let Some(message) = error.message() {
            output::print_error(format_args!("error: {message}"));
        }
        ExitStatus::Undetermined
    });
    ExitCode::from(status)
}

/// The log filter from `RUST_LOG`, at `info` when the variable is unset. A
/// value that does not parse is replaced by `info` as a whole and returned
/// next to the filter, so that a typo can be reported once the subscriber
/// is installed instead of silently changing what is logged.
fn log_filter() -> (EnvFilter, Option<FromEnvError>) {
    let builder =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into());
    match builder.from_env() {
        Ok(filter) => (filter, None),
        Err(error) => (builder.parse_lossy(""), Some(error)),
    }
}

async fn run() -> Result<ExitStatus, CliError> {
    let command = Cli::parse()
        .into_command(|name| std::env::var_os(name))
        .map_err(CliError::Config)?;
    match command {
        Command::Scan(command) => {
            let report = scan::run_scan(&command).await;
            output::write_scan_report(&command, &report).await?;
            Ok(report.outcome().into())
        }
        Command::Calibrate(command) => {
            let rows = calibrate::run_calibrate(&command)
                .await
                .map_err(CliError::Calibrate)?;
            output::print_output(
                &calibrate::CalibrationReport::new(&rows).to_string(),
            )?;
            Ok(ExitStatus::Passed)
        }
    }
}
