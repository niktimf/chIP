use crate::model::{CheckResult, Severity};
use std::fmt::Write;

/// Every gate's result for one scan, ready to render.
pub struct Report {
    pub results: Vec<CheckResult>,
}

impl Report {
    /// `0` no FAIL; `1` at least one FAIL; `2` no FAIL but at least one ERROR.
    /// This order is fixed by the Global Constraints — a FAIL always wins.
    pub fn exit_code(&self) -> i32 {
        if self.results.iter().any(|r| r.severity == Severity::Fail) {
            1
        } else if self.results.iter().any(|r| r.severity == Severity::Error) {
            2
        } else {
            0
        }
    }

    pub fn overall(&self) -> Severity {
        self.results.iter().map(|r| r.severity).max().unwrap_or(Severity::Ok)
    }

    fn sorted(&self) -> Vec<&CheckResult> {
        let mut rows: Vec<&CheckResult> = self.results.iter().collect();
        rows.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.gate.cmp(&b.gate)));
        rows
    }

    pub fn table(&self) -> String {
        let mut out = String::new();
        for row in self.sorted() {
            let _ = writeln!(out, "{:<5}  {:<28}  {}", row.severity.to_string(), row.gate, row.detail);
        }
        let _ = write!(out, "OVERALL: {}", self.overall());
        out
    }

    pub fn markdown(&self) -> String {
        let mut out = format!("## chIP: {}\n\n| severity | gate | detail |\n|---|---|---|\n", self.overall());
        for row in self.sorted() {
            let detail = row.detail.replace('|', r"\|").replace('\n', "<br>");
            let _ = writeln!(out, "| {} | {} | {} |", row.severity, row.gate, detail);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CheckResult, Severity, Verdict};

    fn cr(gate: &str, v: Verdict) -> CheckResult {
        CheckResult::new(gate, v)
    }

    #[test]
    fn exit_code_is_zero_when_nothing_failed_or_errored() {
        let report = Report { results: vec![cr("geo", Verdict::ok("RU 90%")), cr("neighbors", Verdict::warn("noisy"))] };
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn exit_code_is_one_when_anything_failed_even_alongside_an_error() {
        let report = Report {
            results: vec![cr("reputation", Verdict::fail("vpn")), cr("geo", Verdict::error("no sources answered"))],
        };
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn exit_code_is_two_when_nothing_failed_but_something_could_not_be_judged() {
        let report = Report { results: vec![cr("latency", Verdict::error("fewer than 6 valid probes"))] };
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn overall_is_the_most_severe_result_present() {
        let report = Report { results: vec![cr("a", Verdict::ok("x")), cr("b", Verdict::warn("y"))] };
        assert_eq!(report.overall(), Severity::Warn);
    }

    #[test]
    fn overall_of_an_empty_report_is_ok() {
        assert_eq!(Report { results: vec![] }.overall(), Severity::Ok);
    }

    #[test]
    fn table_lists_the_worst_result_first() {
        let report = Report {
            results: vec![cr("geo", Verdict::ok("RU 90%")), cr("reputation", Verdict::fail("vpn flag"))],
        };
        let table = report.table();
        let fail_pos = table.find("FAIL").unwrap();
        let ok_pos = table.find("OK").unwrap();
        assert!(fail_pos < ok_pos, "table:\n{table}");
        assert!(table.contains("reputation"), "table:\n{table}");
        assert!(table.contains("vpn flag"), "table:\n{table}");
        assert!(table.trim_end().ends_with("OVERALL: FAIL"), "table:\n{table}");
    }

    #[test]
    fn markdown_escapes_pipes_and_newlines_in_the_detail_cell() {
        let report = Report { results: vec![cr("tampering", Verdict::warn("altered: a|b\nsecond line"))] };
        let md = report.markdown();
        assert!(md.contains(r"altered: a\|b<br>second line"), "markdown:\n{md}");
    }
}
