use crate::model::{CheckResult, CountryCode, GateId};

/// Which gates a scan judges, chosen by the country the candidate was
/// ordered in.
///
/// A Russian address is a bridge, not an exit. Its country is known in
/// advance, foreign services see it as Russian or refuse it, and the RIPE
/// Atlas anchors the latency gate compares against are abroad, so those gates
/// are reported as `SKIP` instead of being judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanProfile {
    Exit,
    RuBridge,
}

/// Whether a profile judges a gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateScope {
    Judged,
    /// Reported as `SKIP` with this reason instead of being judged.
    Skipped(&'static str),
}

const RU_BRIDGE_REASON: &str =
    "--country RU: judged only for a foreign exit, not for a Russian bridge";

impl ScanProfile {
    pub fn for_country(country: &CountryCode) -> Self {
        if country.as_str() == "RU" {
            Self::RuBridge
        } else {
            Self::Exit
        }
    }

    pub fn scope(self, gate: &str) -> GateScope {
        match self {
            Self::Exit => GateScope::Judged,
            Self::RuBridge => {
                let foreign_only = matches!(gate, "geo" | "latency")
                    || gate == "service-geo"
                    || gate.starts_with("service-geo:")
                    || gate.starts_with("service:")
                    || gate.starts_with("ai:");
                if foreign_only {
                    GateScope::Skipped(RU_BRIDGE_REASON)
                } else {
                    GateScope::Judged
                }
            }
        }
    }

    pub fn judges(self, gate: &str) -> bool {
        self.scope(gate) == GateScope::Judged
    }

    /// Turns a result of a gate this profile does not judge into a `SKIP` row
    /// carrying the reason; other results pass through unchanged.
    pub fn apply(self, result: CheckResult) -> CheckResult {
        match self.scope(result.gate.as_str()) {
            GateScope::Skipped(reason) => {
                CheckResult::skipped(result.gate, reason)
            }
            GateScope::Judged => result,
        }
    }

    /// A `SKIP` row for each of `gates` this profile does not judge, for gates
    /// whose probes were never started.
    pub fn skipped<'a>(
        self,
        gates: impl IntoIterator<Item = &'a str>,
    ) -> Vec<CheckResult> {
        gates
            .into_iter()
            .filter_map(|gate| match self.scope(gate) {
                GateScope::Skipped(reason) => {
                    Some(CheckResult::skipped(GateId::from(gate), reason))
                }
                GateScope::Judged => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Severity, Verdict};

    #[rstest::rstest]
    #[case::russia_in_any_case("ru", ScanProfile::RuBridge)]
    #[case::finland("FI", ScanProfile::Exit)]
    fn the_ordered_country_picks_the_profile(
        #[case] country: &str,
        #[case] expected: ScanProfile,
    ) {
        let sut: CountryCode = country.parse().unwrap();

        let actual = ScanProfile::for_country(&sut);

        assert_eq!(actual, expected);
    }

    #[rstest::rstest]
    #[case::geo("geo")]
    #[case::latency("latency")]
    #[case::service("service:chatgpt_web")]
    #[case::service_geo("service-geo")]
    #[case::service_geo_family("service-geo:cdn")]
    #[case::ai("ai:openai")]
    fn a_bridge_skips_gates_meant_for_a_foreign_exit(#[case] gate: &str) {
        let sut = ScanProfile::RuBridge;

        assert!(!sut.judges(gate));
    }

    #[rstest::rstest]
    #[case::reputation("reputation")]
    #[case::blocklists("blocklists")]
    #[case::rkn_registry("rkn-registry")]
    #[case::reach("reach")]
    #[case::provenance("provenance")]
    #[case::tampering("tampering")]
    #[case::steal("steal")]
    #[case::neighbors("neighbors")]
    fn a_bridge_judges_the_remaining_gates(#[case] gate: &str) {
        let sut = ScanProfile::RuBridge;

        assert!(sut.judges(gate));
    }

    #[test]
    fn an_exit_judges_every_gate() {
        assert!(ScanProfile::Exit.judges("latency"));
    }

    #[test]
    fn apply_turns_an_excluded_failure_into_a_skip_with_the_reason() {
        let result = CheckResult::new("latency", Verdict::error("no anchors"));

        let out = ScanProfile::RuBridge.apply(result);

        assert!(out.is_skipped());
        assert_eq!(out.severity(), Severity::Ok);
        assert!(out.detail.contains("--country RU"), "{}", out.detail);
    }

    #[test]
    fn skipped_reports_only_the_excluded_gates() {
        let out =
            ScanProfile::RuBridge.skipped(["tampering", "service:netflix"]);

        let gates: Vec<_> =
            out.iter().map(|result| result.gate.as_str()).collect();
        assert_eq!(gates, ["service:netflix"]);
    }
}
