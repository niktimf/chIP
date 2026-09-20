mod calibrate;
mod config;
mod scan;

use std::process::ExitCode;

use clap::Parser as _;
use config::{Cli, Command};
use tokio::io::AsyncWriteExt as _;

#[tokio::main]
async fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();

    let command = match Cli::parse().into_command() {
        Ok(command) => command,
        Err(error) => {
            eprintln!("error: invalid configuration: {error:#}");
            return ExitCode::from(2);
        }
    };
    match command {
        Command::Scan(args) => run_scan_command(*args).await,
        Command::Calibrate(args) => run_calibrate_command(&args).await,
    }
}

async fn run_scan_command(command: config::ScanCommand) -> ExitCode {
    let report = scan::run_scan(&command).await;
    println!("{}", report.table());

    if let Some(path) = command.json_path() {
        let document = serde_json::json!({
            "schema": 1,
            "overall": report.overall().to_string(),
            "exit_code": report.exit_code(),
            "results": report.results.iter().map(|result| serde_json::json!({
                "gate": result.gate.as_str(),
                "severity": result.severity.to_string(),
                "skipped": result.skipped,
                "detail": result.detail,
            })).collect::<Vec<_>>(),
        });
        let encoded = match serde_json::to_vec_pretty(&document) {
            Ok(encoded) => encoded,
            Err(error) => {
                eprintln!("error: could not encode JSON report: {error}");
                return ExitCode::from(2);
            }
        };
        if let Err(error) = tokio::fs::write(path, encoded).await {
            eprintln!("error: could not write {}: {error}", path.display());
            return ExitCode::from(2);
        }
    }

    if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
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
            eprintln!(
                "warning: could not write GITHUB_STEP_SUMMARY {path}: {error}"
            );
        }
    }

    ExitCode::from(u8::try_from(report.exit_code()).unwrap_or(2))
}

async fn run_calibrate_command(command: &config::CalibrateCommand) -> ExitCode {
    match calibrate::run_calibrate(command).await {
        Ok(rows) => {
            println!("{}", calibrate::render_calibration(&rows));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(2)
        }
    }
}
