use crate::model::{CheckResult, Severity};
use std::fmt::Write;

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
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => escaped.push_str(r"\n"),
            '\r' => escaped.push_str(r"\r"),
            '\t' => escaped.push_str(r"\t"),
            control if is_unsafe_formatting(control) => {
                let _ = write!(escaped, r"\u{{{:x}}}", u32::from(control));
            }
            safe => escaped.push(safe),
        }
    }
    escaped
}

fn markdown_cell(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
                escaped.push_str("<br>");
            }
            '\n' => escaped.push_str("<br>"),
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\\' | '|' | '`' | '*' | '_' | '[' | ']' | '(' | ')' | '#'
            | '!' | '~' => {
                escaped.push('\\');
                escaped.push(character);
            }
            control if is_unsafe_formatting(control) => {
                let _ = write!(escaped, r"\u{{{:x}}}", u32::from(control));
            }
            safe => escaped.push(safe),
        }
    }
    escaped
}

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
        self.results
            .iter()
            .map(|r| r.severity)
            .max()
            .unwrap_or(Severity::Ok)
    }

    fn sorted(&self) -> Vec<&CheckResult> {
        let mut rows: Vec<&CheckResult> = self.results.iter().collect();
        rows.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.gate.cmp(&b.gate))
        });
        rows
    }

    pub fn table(&self) -> String {
        let mut out = String::new();
        for row in self.sorted() {
            let _ = writeln!(
                out,
                "{:<5}  {:<28}  {}",
                row.severity.to_string(),
                terminal_cell(row.gate.as_str()),
                terminal_cell(&row.detail)
            );
        }
        let _ = write!(out, "OVERALL: {}", self.overall());
        out
    }

    pub fn markdown(&self) -> String {
        let mut out = format!(
            "## chIP: {}\n\n| severity | gate | detail |\n|---|---|---|\n",
            self.overall()
        );
        for row in self.sorted() {
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                row.severity,
                markdown_cell(row.gate.as_str()),
                markdown_cell(&row.detail)
            );
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
        let report = Report {
            results: vec![
                cr("geo", Verdict::ok("RU 90%")),
                cr("neighbors", Verdict::warn("noisy")),
            ],
        };
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn exit_code_is_one_when_anything_failed_even_alongside_an_error() {
        let report = Report {
            results: vec![
                cr("reputation", Verdict::fail("vpn")),
                cr("geo", Verdict::error("no sources answered")),
            ],
        };
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn exit_code_is_two_when_nothing_failed_but_something_could_not_be_judged()
    {
        let report = Report {
            results: vec![cr(
                "latency",
                Verdict::error("fewer than 6 valid probes"),
            )],
        };
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn overall_is_the_most_severe_result_present() {
        let report = Report {
            results: vec![
                cr("a", Verdict::ok("x")),
                cr("b", Verdict::warn("y")),
            ],
        };
        assert_eq!(report.overall(), Severity::Warn);
    }

    #[test]
    fn overall_of_an_empty_report_is_ok() {
        assert_eq!(Report { results: vec![] }.overall(), Severity::Ok);
    }

    #[test]
    fn table_lists_the_worst_result_first() {
        let report = Report {
            results: vec![
                cr("geo", Verdict::ok("RU 90%")),
                cr("reputation", Verdict::fail("vpn flag")),
            ],
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
    fn markdown_neutralizes_markup_and_control_characters_in_cells() {
        let report = Report {
            results: vec![cr(
                "tampering|<gate>",
                Verdict::warn(
                    "altered: [a|b](https://attacker)\r\n<script>&\\\x1b\u{202e}",
                ),
            )],
        };

        let md = report.markdown();

        assert!(
            md.contains(
                r"tampering\|&lt;gate&gt; | altered: \[a\|b\]\(https://attacker\)<br>&lt;script&gt;&amp;\\\u{1b}\u{202e}"
            ),
            "markdown:\n{md}"
        );
        assert!(!md.contains("<script>"), "markdown:\n{md}");
        assert!(!md.contains('\x1b'), "markdown:\n{md}");
        assert!(!md.contains('\u{202e}'), "markdown:\n{md}");
    }

    #[test]
    fn terminal_table_keeps_each_result_on_one_escape_free_line() {
        let report = Report {
            results: vec![cr(
                "reputation\nforged-gate",
                Verdict::warn("operator\r\nFAIL fake\x1b[31m\u{202e}"),
            )],
        };

        let table = report.table();

        assert_eq!(table.lines().count(), 2, "table:\n{table}");
        assert!(table.contains(r"reputation\nforged-gate"), "table:\n{table}");
        assert!(
            table.contains(r"operator\r\nFAIL fake\u{1b}[31m\u{202e}"),
            "table:\n{table}"
        );
        assert!(!table.contains('\x1b'), "table:\n{table}");
        assert!(!table.contains('\u{202e}'), "table:\n{table}");
    }
}
