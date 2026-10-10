use crate::report::gate::GateId;
use crate::report::{Severity, Verdict};

/// A `Verdict` attached to the gate id that produced it — the unit the
/// report, `--gate`, and `--skip-gate` all operate on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    gate: GateId,
    detail: String,
    outcome: CheckOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckOutcome {
    Judged(Severity),
    Skipped,
}

impl CheckResult {
    pub fn new(gate: GateId, verdict: Verdict) -> Self {
        Self {
            gate,
            detail: verdict.detail,
            outcome: CheckOutcome::Judged(verdict.severity),
        }
    }

    pub fn skipped(gate: GateId, reason: impl Into<String>) -> Self {
        Self {
            gate,
            detail: reason.into(),
            outcome: CheckOutcome::Skipped,
        }
    }

    pub const fn gate(&self) -> GateId {
        self.gate
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub fn into_detail(self) -> String {
        self.detail
    }

    pub const fn severity(&self) -> Severity {
        match self.outcome {
            CheckOutcome::Judged(severity) => severity,
            CheckOutcome::Skipped => Severity::Ok,
        }
    }

    pub const fn is_skipped(&self) -> bool {
        matches!(self.outcome, CheckOutcome::Skipped)
    }

    #[must_use]
    pub const fn escalate_warning(mut self) -> Self {
        if matches!(self.outcome, CheckOutcome::Judged(Severity::Warn)) {
            self.outcome = CheckOutcome::Judged(Severity::Fail);
        }
        self
    }

    pub fn label(&self) -> &'static str {
        match self.outcome {
            CheckOutcome::Skipped => "SKIP",
            CheckOutcome::Judged(severity) => severity.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::gate::{GEO, REACH};

    #[test]
    fn a_skipped_check_is_labelled_skip_and_keeps_the_reason_it_carried() {
        let sut = CheckResult::skipped(
            REACH,
            "ports 443 and 8443 are already in use",
        );

        assert_eq!(sut.severity(), Severity::Ok);
        assert_eq!(sut.label(), "SKIP");
        assert_eq!(sut.detail(), "ports 443 and 8443 are already in use");
    }

    #[test]
    fn a_judged_check_is_labelled_by_its_severity() {
        let sut = CheckResult::new(GEO, Verdict::warn("50/50 split"));

        assert_eq!(sut.label(), "WARN");
    }
}
