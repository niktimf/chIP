//! The exit code of a run, the one place that numbers it.

use std::process::ExitCode;

use chip_core::report::ScanOutcome;

/// How a run ended. Pipelines read it twice, as the process exit code and as
/// the `exit_code` of the `--json` report, so both come from [`Self::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// The scan passed, or `calibrate` printed its table.
    Passed,
    /// At least one gate of the scan failed.
    Failed,
    /// The scan could not reach a verdict, or the command stopped with an
    /// error before it finished.
    Undetermined,
}

impl ExitStatus {
    pub const fn code(self) -> u8 {
        match self {
            Self::Passed => 0,
            Self::Failed => 1,
            Self::Undetermined => 2,
        }
    }
}

impl From<ScanOutcome> for ExitStatus {
    fn from(outcome: ScanOutcome) -> Self {
        match outcome {
            ScanOutcome::Passed => Self::Passed,
            ScanOutcome::Failed => Self::Failed,
            ScanOutcome::Undetermined => Self::Undetermined,
        }
    }
}

impl From<ExitStatus> for ExitCode {
    fn from(status: ExitStatus) -> Self {
        Self::from(status.code())
    }
}
