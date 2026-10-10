use crate::report::CheckResult;
use crate::report::gate::{BridgePolicy, Gate};
use crate::values::CountryCode;

/// Which gates a scan judges, chosen by the country the candidate was
/// ordered in.
///
/// A Russian address is a bridge, not an exit. Its country is known in
/// advance, foreign services see it as Russian or refuse it, and the RIPE
/// Atlas anchors the latency gate compares against are abroad, so those gates
/// are reported as `SKIP` instead of being judged. Which gates that covers
/// is a per-gate fact ([`Gate::bridge`]), not a naming rule.
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

impl ScanProfile {
    const RU_BRIDGE_REASON: &str = "--country RU: judged only for a foreign exit, not for a Russian bridge";

    pub fn for_country(country: &CountryCode) -> Self {
        if *country == CountryCode::RU {
            Self::RuBridge
        } else {
            Self::Exit
        }
    }

    pub const fn scope(self, gate: Gate) -> GateScope {
        match self {
            Self::Exit => GateScope::Judged,
            Self::RuBridge => match gate.bridge() {
                BridgePolicy::ForeignExitOnly => {
                    GateScope::Skipped(Self::RU_BRIDGE_REASON)
                }
                BridgePolicy::Judged => GateScope::Judged,
            },
        }
    }

    pub fn judges(self, gate: Gate) -> bool {
        self.scope(gate) == GateScope::Judged
    }

    /// Turns a result of a gate this profile does not judge into a `SKIP` row
    /// carrying the reason; other results pass through unchanged.
    pub fn apply(self, result: CheckResult) -> CheckResult {
        match self.scope(result.gate()) {
            GateScope::Skipped(reason) => {
                CheckResult::skipped(result.gate(), reason)
            }
            GateScope::Judged => result,
        }
    }

    /// A `SKIP` row for each of `gates` this profile does not judge, for gates
    /// whose probes were never started.
    pub fn skipped(
        self,
        gates: impl IntoIterator<Item = Gate>,
    ) -> Vec<CheckResult> {
        gates
            .into_iter()
            .filter_map(|gate| match self.scope(gate) {
                GateScope::Skipped(reason) => {
                    Some(CheckResult::skipped(gate, reason))
                }
                GateScope::Judged => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Severity, Verdict};
    use std::collections::HashSet;
    use strum::IntoEnumIterator;

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

    /// The gates a Russian bridge does not judge, listed by hand. The list
    /// follows the name rule that `ScanProfile::scope` used before the gate
    /// registry: `geo`, `latency`, and every `service:`, `service-geo` and
    /// `ai:` gate.
    const FOREIGN_EXIT_ONLY: [Gate; 17] = [
        Gate::Geo,
        Gate::Latency,
        Gate::ServiceChatgptWeb,
        Gate::ServiceChatgptApp,
        Gate::ServiceGemini,
        Gate::ServiceYoutubePremium,
        Gate::ServiceNetflix,
        Gate::ServiceClaude,
        Gate::ServiceTiktok,
        Gate::ServiceNotebooklm,
        Gate::ServiceGeo,
        Gate::ServiceGeoCaptcha,
        Gate::ServiceGeoCdn,
        Gate::AiOpenai,
        Gate::AiAnthropic,
        Gate::AiGemini,
        Gate::AiDeepseek,
    ];

    #[test]
    fn a_bridge_skips_exactly_the_gates_meant_for_a_foreign_exit() {
        let sut = ScanProfile::RuBridge;

        let skipped: HashSet<Gate> =
            Gate::iter().filter(|&gate| !sut.judges(gate)).collect();

        assert_eq!(skipped, HashSet::from(FOREIGN_EXIT_ONLY));
    }

    #[test]
    fn an_exit_judges_every_gate() {
        let sut = ScanProfile::Exit;

        let skipped: Vec<Gate> =
            Gate::iter().filter(|&gate| !sut.judges(gate)).collect();

        assert_eq!(skipped, Vec::<Gate>::new());
    }

    #[test]
    fn an_excluded_failure_becomes_a_skip_with_the_reason() {
        let result =
            CheckResult::new(Gate::Latency, Verdict::error("no anchors"));

        let out = ScanProfile::RuBridge.apply(result);

        assert!(out.is_skipped());
        assert_eq!(out.severity(), Severity::Ok);
        assert!(out.detail().contains("--country RU"), "{}", out.detail());
    }

    #[test]
    fn skipped_reports_only_the_excluded_gates() {
        let out = ScanProfile::RuBridge
            .skipped([Gate::Tampering, Gate::ServiceNetflix]);

        let gates: Vec<Gate> = out.iter().map(CheckResult::gate).collect();
        assert_eq!(gates, [Gate::ServiceNetflix]);
    }
}
