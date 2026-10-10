use crate::model::{CheckResult, Severity};

fn is_unsafe_formatting(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn terminal_cell(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\n' => r"\n".to_owned(),
            '\r' => r"\r".to_owned(),
            '\t' => r"\t".to_owned(),
            control if is_unsafe_formatting(control) => {
                control.escape_unicode().to_string()
            }
            safe => safe.to_string(),
        })
        .collect()
}

fn markdown_cell(value: &str) -> String {
    value
        .replace("\r\n", "\n")
        .chars()
        .map(|character| match character {
            '\r' | '\n' => "<br>".to_owned(),
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '\\' | '|' | '`' | '*' | '_' | '[' | ']' | '(' | ')' | '#'
            | '!' | '~' => format!("\\{character}"),
            control if is_unsafe_formatting(control) => {
                control.escape_unicode().to_string()
            }
            safe => safe.to_string(),
        })
        .collect()
}

/// How a whole scan ended, the verdict a pipeline acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOutcome {
    /// Nothing failed and every gate reached a verdict; warnings and skipped
    /// gates do not change that.
    Passed,
    /// At least one gate failed.
    Failed,
    /// Nothing failed, but at least one gate could not reach a verdict.
    Undetermined,
}

/// Every gate's result for one scan, ready to render.
#[derive(Debug)]
pub struct Report {
    pub results: Vec<CheckResult>,
}

impl Report {
    /// A FAIL wins over an ERROR: a scan with both is `Failed`, not
    /// `Undetermined`.
    pub fn outcome(&self) -> ScanOutcome {
        match self.overall() {
            Severity::Ok | Severity::Warn => ScanOutcome::Passed,
            Severity::Error => ScanOutcome::Undetermined,
            Severity::Fail => ScanOutcome::Failed,
        }
    }

    pub fn overall(&self) -> Severity {
        self.results
            .iter()
            .map(CheckResult::severity)
            .max()
            .unwrap_or(Severity::Ok)
    }

    fn sorted(&self) -> Vec<&CheckResult> {
        let mut rows: Vec<&CheckResult> = self.results.iter().collect();
        rows.sort_by(|a, b| {
            b.severity()
                .cmp(&a.severity())
                .then_with(|| a.gate().cmp(&b.gate()))
        });
        rows
    }

    pub fn table(&self) -> String {
        let rows = self
            .sorted()
            .into_iter()
            .map(|row| {
                format!(
                    "{:<5}  {:<28}  {}\n",
                    row.label(),
                    terminal_cell(row.gate().as_str()),
                    terminal_cell(row.detail())
                )
            })
            .collect::<Vec<_>>()
            .concat();
        format!("{rows}OVERALL: {}", self.overall())
    }

    pub fn markdown(&self) -> String {
        let rows = self
            .sorted()
            .into_iter()
            .map(|row| {
                format!(
                    "| {} | {} | {} |\n",
                    row.label(),
                    markdown_cell(row.gate().as_str()),
                    markdown_cell(row.detail())
                )
            })
            .collect::<Vec<_>>()
            .concat();
        format!(
            "## chIP: {}\n\n| severity | gate | detail |\n|---|---|---|\n{rows}",
            self.overall()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::{
        BLOCKLISTS, GEO, GateId, LATENCY, NEIGHBORS, REACH, REPUTATION,
        TAMPERING,
    };
    use crate::model::{CheckResult, Severity, Verdict};

    fn cr(gate: GateId, v: Verdict) -> CheckResult {
        CheckResult::new(gate, v)
    }

    fn skipped_reach() -> CheckResult {
        CheckResult::skipped(REACH, "ports 443 and 8443 are already in use")
    }

    #[test]
    fn a_skipped_gate_is_shown_as_skip_in_the_table() {
        let sut = Report {
            results: vec![skipped_reach()],
        };

        let table = sut.table();

        assert!(table.starts_with("SKIP "), "{table}");
        assert!(
            table.contains("ports 443 and 8443 are already in use"),
            "{table}"
        );
    }

    #[test]
    fn a_skipped_gate_is_shown_as_skip_in_markdown() {
        let sut = Report {
            results: vec![skipped_reach()],
        };

        let markdown = sut.markdown();

        assert!(markdown.contains("| SKIP | reach |"), "{markdown}");
    }

    fn skipped_reach_and_ok_geo() -> Report {
        Report {
            results: vec![skipped_reach(), cr(GEO, Verdict::ok("7/7 say FI"))],
        }
    }

    #[test]
    fn a_skipped_gate_does_not_change_the_outcome() {
        let sut = skipped_reach_and_ok_geo();

        let outcome = sut.outcome();

        assert_eq!(outcome, ScanOutcome::Passed);
    }

    #[test]
    fn a_skipped_gate_does_not_change_the_overall_severity() {
        let sut = skipped_reach_and_ok_geo();

        let overall = sut.overall();

        assert_eq!(overall, Severity::Ok);
    }

    #[rstest::rstest]
    #[case::nothing_failed_or_errored(
        vec![
            cr(GEO, Verdict::ok("RU 90%")),
            cr(NEIGHBORS, Verdict::warn("noisy")),
        ],
        ScanOutcome::Passed
    )]
    #[case::an_empty_report(vec![], ScanOutcome::Passed)]
    #[case::a_failure_wins_over_an_error(
        vec![
            cr(REPUTATION, Verdict::fail("vpn")),
            cr(GEO, Verdict::error("no sources answered")),
        ],
        ScanOutcome::Failed
    )]
    #[case::nothing_failed_but_something_could_not_be_judged(
        vec![
            cr(GEO, Verdict::ok("RU 90%")),
            cr(LATENCY, Verdict::error("fewer than 6 valid probes")),
        ],
        ScanOutcome::Undetermined
    )]
    fn the_outcome_follows_the_worst_result(
        #[case] results: Vec<CheckResult>,
        #[case] expected: ScanOutcome,
    ) {
        let sut = Report { results };

        let actual = sut.outcome();

        assert_eq!(actual, expected);
    }

    #[test]
    fn the_overall_severity_is_the_most_severe_result_present() {
        let sut = Report {
            results: vec![
                cr(BLOCKLISTS, Verdict::ok("x")),
                cr(GEO, Verdict::warn("y")),
            ],
        };

        let overall = sut.overall();

        assert_eq!(overall, Severity::Warn);
    }

    #[test]
    fn an_empty_report_is_ok_overall() {
        let sut = Report { results: vec![] };

        let overall = sut.overall();

        assert_eq!(overall, Severity::Ok);
    }

    #[test]
    fn table_lists_the_worst_result_first() {
        let sut = Report {
            results: vec![
                cr(GEO, Verdict::ok("RU 90%")),
                cr(REPUTATION, Verdict::fail("vpn flag")),
            ],
        };
        let table = sut.table();
        let fail_pos = table.find("FAIL").unwrap();
        let ok_pos = table.find("OK").unwrap();
        assert!(fail_pos < ok_pos, "table:\n{table}");
        assert!(table.contains("reputation"), "table:\n{table}");
        assert!(table.contains("vpn flag"), "table:\n{table}");
        assert!(table.trim_end().ends_with("OVERALL: FAIL"), "table:\n{table}");
    }

    /// Gate ids are static identifiers from the registry, so hostile input
    /// can only arrive through the free-text detail; the cell escaping is
    /// exercised there.
    #[test]
    fn markdown_neutralizes_markup_and_control_characters_in_the_detail() {
        let sut = Report {
            results: vec![cr(
                TAMPERING,
                Verdict::warn(
                    "altered: [a|b](https://attacker)\r\n<script>&\\\x1b\u{202e}",
                ),
            )],
        };

        let md = sut.markdown();

        assert!(
            md.contains(
                r"tampering | altered: \[a\|b\]\(https://attacker\)<br>&lt;script&gt;&amp;\\\u{1b}\u{202e}"
            ),
            "markdown:\n{md}"
        );
        assert!(!md.contains("<script>"), "markdown:\n{md}");
        assert!(!md.contains('\x1b'), "markdown:\n{md}");
        assert!(!md.contains('\u{202e}'), "markdown:\n{md}");
    }

    #[test]
    fn terminal_table_keeps_each_result_on_one_escape_free_line() {
        let sut = Report {
            results: vec![cr(
                REPUTATION,
                Verdict::warn("operator\r\nFAIL fake\x1b[31m\u{202e}"),
            )],
        };

        let table = sut.table();

        assert_eq!(table.lines().count(), 2, "table:\n{table}");
        assert!(
            table.contains(r"operator\r\nFAIL fake\u{1b}[31m\u{202e}"),
            "table:\n{table}"
        );
        assert!(!table.contains('\x1b'), "table:\n{table}");
        assert!(!table.contains('\u{202e}'), "table:\n{table}");
    }
}
