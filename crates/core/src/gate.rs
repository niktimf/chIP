use crate::model::{CheckResult, GateId, Severity};
use std::collections::HashSet;

/// `--gate`/`--skip-gate` as parsed: which gate ids to force to FAIL when
/// they land on WARN, and which to neutralize entirely. Skip wins when a
///
/// gate id appears in both — an operator who disabled a check did not also
/// mean to make it stricter.
#[derive(Debug, Default, Clone)]
pub struct GateOverrides {
    pub escalate: HashSet<GateId>,
    pub skip: HashSet<GateId>,
}

impl GateOverrides {
    pub fn apply(&self, result: CheckResult) -> CheckResult {
        if self.skip.contains(&result.gate) {
            return CheckResult {
                severity: Severity::Ok,
                detail: format!("skipped by --skip-gate: {}", result.detail),
                ..result
            };
        }
        if self.escalate.contains(&result.gate)
            && result.severity == Severity::Warn
        {
            return CheckResult {
                severity: Severity::Fail,
                ..result
            };
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CheckResult, GateId, Severity, Verdict};

    fn overrides(escalate: &[&str], skip: &[&str]) -> GateOverrides {
        GateOverrides {
            escalate: escalate.iter().map(|&s| GateId::from(s)).collect(),
            skip: skip.iter().map(|&s| GateId::from(s)).collect(),
        }
    }

    #[test]
    fn a_gate_not_named_anywhere_passes_through_unchanged() {
        let result = CheckResult::new("geo", Verdict::warn("50/50 split"));
        let sut = overrides(&[], &[]);

        let out = sut.apply(result.clone());

        assert_eq!(out, result);
    }

    #[test]
    fn escalate_turns_warn_into_fail_but_leaves_ok_and_fail_alone() {
        let sut = overrides(&["service:claude"], &[]);

        assert_eq!(
            sut.apply(CheckResult::new(
                "service:claude",
                Verdict::warn("blocked")
            ))
            .severity,
            Severity::Fail
        );
        assert_eq!(
            sut.apply(CheckResult::new(
                "service:claude",
                Verdict::ok("available")
            ))
            .severity,
            Severity::Ok
        );
        assert_eq!(
            sut.apply(CheckResult::new("service:claude", Verdict::fail("x")))
                .severity,
            Severity::Fail
        );
    }

    #[test]
    fn skip_neutralizes_the_result_but_says_so_in_the_detail() {
        let sut = overrides(&[], &["reputation:operator"]);

        let out = sut.apply(CheckResult::new(
            "reputation:operator",
            Verdict::fail("named Snowd"),
        ));

        assert_eq!(out.severity, Severity::Ok);
        assert!(out.detail.contains("skipped"), "{}", out.detail);
        assert!(out.detail.contains("named Snowd"), "{}", out.detail);
    }

    #[test]
    fn skip_wins_over_escalate_for_the_same_gate() {
        let sut = overrides(&["latency"], &["latency"]);

        let out = sut.apply(CheckResult::new(
            "latency",
            Verdict::warn("p75 over threshold"),
        ));

        assert_eq!(out.severity, Severity::Ok);
    }
}
