use strum::{Display, IntoStaticStr};

/// How serious a single check's outcome is. Ordered least to most severe:
/// [`Report`](crate::report::Report) lists rows worst first, and its
/// maximum is the scan's overall severity.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Display, IntoStaticStr,
)]
#[strum(serialize_all = "UPPERCASE")]
pub enum Severity {
    Ok,
    Warn,
    /// The check could not reach a verdict at all (quota exhausted, source
    /// unreachable, SSH refused). Distinct from `Fail`: when no row failed,
    /// an ERROR makes the scan `Undetermined`, never `Failed` (see
    /// [`ScanOutcome`](crate::report::ScanOutcome)).
    Error,
    Fail,
}

/// The result of judging one aspect of the candidate: a severity and the
/// human-readable reason. Judge functions in `checks::*` return this; they
/// never know their own gate id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub severity: Severity,
    pub detail: String,
}

impl Verdict {
    pub fn ok(detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Ok,
            detail: detail.into(),
        }
    }
    pub fn warn(detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warn,
            detail: detail.into(),
        }
    }
    pub fn error(detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            detail: detail.into(),
        }
    }
    pub fn fail(detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Fail,
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_least_to_most_severe() {
        let mut sut = vec![
            Severity::Fail,
            Severity::Ok,
            Severity::Error,
            Severity::Warn,
        ];
        sut.sort();
        assert_eq!(
            sut,
            vec![
                Severity::Ok,
                Severity::Warn,
                Severity::Error,
                Severity::Fail
            ]
        );
    }

    #[rstest::rstest]
    #[case::ok(Severity::Ok, "OK")]
    #[case::warn(Severity::Warn, "WARN")]
    #[case::error(Severity::Error, "ERROR")]
    #[case::fail(Severity::Fail, "FAIL")]
    fn severity_displays_as_uppercase_word(
        #[case] sut: Severity,
        #[case] expected: &str,
    ) {
        let actual = sut.to_string();

        assert_eq!(actual, expected);
    }
}
