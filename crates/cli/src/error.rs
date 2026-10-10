//! Why a command stopped, and what the user is told about it.

use std::path::PathBuf;

use crate::config::ConfigError;
use crate::scan::globalping_rate_limit_hint;

/// Why a command stopped. Every variant ends the run as
/// [`ExitStatus::Undetermined`](crate::exit_status::ExitStatus::Undetermined).
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("invalid configuration")]
    Config(#[source] ConfigError),
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

impl CliError {
    /// The text after `error: ` on stderr, with every cause in the chain.
    ///
    /// `None` when stdout was closed by its reader (`chip scan ... | head`):
    /// that is not worth a message, but the output is incomplete, so the run
    /// still ends as undetermined.
    pub fn message(&self) -> Option<String> {
        let detail = chip_io::describe_error(self);
        match self {
            Self::Output(error)
                if error.kind() == std::io::ErrorKind::BrokenPipe =>
            {
                None
            }
            // The same remedy a scan row names after a rate-limit cause.
            Self::Calibrate(cause) => match globalping_rate_limit_hint(cause) {
                Some(hint) => Some(format!("{detail} ({hint})")),
                None => Some(detail),
            },
            _ => Some(detail),
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context as _;
    use chip_io::globalping::GlobalpingError;

    use super::*;

    #[test]
    fn a_closed_stdout_ends_the_run_without_a_message() {
        let sut = CliError::Output(std::io::ErrorKind::BrokenPipe.into());

        let message = sut.message();

        assert_eq!(message, None);
    }

    #[test]
    fn a_calibration_stopped_by_the_rate_limit_names_the_remedy() {
        let cause = Err::<(), _>(GlobalpingError::RateLimited)
            .context("failed to ping the anchors of Helsinki")
            .unwrap_err();
        let sut = CliError::Calibrate(cause);

        let message = sut.message();

        assert_eq!(
            message.as_deref(),
            Some(
                "failed to ping the anchors of Helsinki: globalping rate \
                 limit exceeded (try again next hour, or set \
                 GLOBALPING_TOKEN)"
            )
        );
    }

    #[test]
    fn an_error_is_shown_with_every_cause_in_its_chain() {
        let sut = CliError::WriteJson {
            path: PathBuf::from("/reports/scan.json"),
            source: std::io::Error::other("no space left on device"),
        };

        let message = sut.message();

        assert_eq!(
            message.as_deref(),
            Some("could not write /reports/scan.json: no space left on device")
        );
    }
}
