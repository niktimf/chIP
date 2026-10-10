use std::collections::BTreeSet;
use std::fmt;

use strum::Display;

use crate::Verdict;
use itertools::Itertools as _;

/// A proxycheck detection raised for an address.
///
/// `Ord` follows declaration order, and the reputation verdict lists the
/// flags of an address in that order. `Display` gives the flag's name in
/// the verdict detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
#[strum(serialize_all = "lowercase")]
pub enum ReputationFlag {
    Vpn,
    Proxy,
    Tor,
    Compromised,
    Anonymous,
    Scraper,
}

impl ReputationFlag {
    /// Whether the flag alone fails the reputation gate. The other flags
    /// only warn.
    pub const fn is_hard(self) -> bool {
        match self {
            Self::Vpn | Self::Proxy | Self::Tor | Self::Compromised => true,
            Self::Anonymous | Self::Scraper => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReputationFacts {
    pub flags: BTreeSet<ReputationFlag>,
    pub risk: Option<RiskScore>,
    pub operator: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RiskScore(u8);

impl RiskScore {
    /// # Errors
    ///
    /// Returns `InvalidRiskScore` when `value` exceeds 100.
    pub fn new(value: u8) -> Result<Self, InvalidRiskScore> {
        if value <= 100 {
            Ok(Self(value))
        } else {
            Err(InvalidRiskScore(u64::from(value)))
        }
    }

    pub const fn value(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("risk score must be between 0 and 100, got {0}")]
pub struct InvalidRiskScore(u64);

impl TryFrom<u64> for RiskScore {
    type Error = InvalidRiskScore;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        // `TryFromIntError` carries no data; `InvalidRiskScore` keeps the
        // rejected value, and `new` rejects 101..=255 with the same value.
        u8::try_from(value).map_or(Err(InvalidRiskScore(value)), Self::new)
    }
}

impl fmt::Display for RiskScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// proxycheck risk score from which the gate warns. The free tier scores
/// plain datacenter hosting around 33, so 50 keeps a clean hosting address
/// below the line while flagging genuinely risky ranges.
const WARN_RISK: u8 = 50;

pub fn judge_reputation(facts: &ReputationFacts) -> Verdict {
    let detail = format!(
        "risk {}, {}",
        facts
            .risk
            .map_or_else(|| "?".to_string(), |r| r.to_string()),
        if facts.flags.is_empty() {
            "no flags".to_string()
        } else {
            format!("flags: {}", facts.flags.iter().join(", "))
        },
    );

    if facts.flags.iter().any(|flag| flag.is_hard()) {
        return Verdict::fail(detail);
    }
    let risk_over = facts.risk.is_some_and(|r| r.value() >= WARN_RISK);
    let soft_flag = facts.flags.iter().any(|flag| !flag.is_hard());
    if soft_flag || risk_over {
        return Verdict::warn(detail);
    }
    Verdict::ok(detail)
}

/// Whether proxycheck names a VPN operator behind the address.
///
/// Its own gate (`reputation:operator`), because a rotation may knowingly
/// buy from a hosting company that also sells VPN service, and waving that
/// through must not also disable the vpn/proxy/tor flags.
pub fn judge_reputation_operator(facts: &ReputationFacts) -> Verdict {
    facts.operator.as_deref().map_or_else(
        || Verdict::ok("no VPN operator claims this address"),
        |operator| Verdict::fail(format!("named VPN operator: {operator}")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Severity;
    use std::collections::BTreeSet;

    #[test]
    fn a_risk_score_above_one_hundred_is_rejected() {
        let error = RiskScore::new(101).unwrap_err();

        assert_eq!(error, InvalidRiskScore(101));
    }

    fn risk(value: u8) -> RiskScore {
        RiskScore::new(value).unwrap()
    }

    fn clean() -> ReputationFacts {
        ReputationFacts {
            flags: BTreeSet::new(),
            risk: Some(risk(33)),
            operator: None,
        }
    }

    fn clean_with(flags: &[ReputationFlag]) -> ReputationFacts {
        ReputationFacts {
            flags: flags.iter().copied().collect(),
            ..clean()
        }
    }

    #[test]
    fn a_clean_hosting_address_at_datacenter_floor_risk_is_ok() {
        let sut = clean();

        let verdict = judge_reputation(&sut);

        assert_eq!(verdict.severity, Severity::Ok, "{}", verdict.detail);
    }

    #[rstest::rstest]
    #[case::vpn(clean_with(&[ReputationFlag::Vpn]))]
    #[case::proxy(clean_with(&[ReputationFlag::Proxy]))]
    #[case::tor(clean_with(&[ReputationFlag::Tor]))]
    #[case::compromised(clean_with(&[ReputationFlag::Compromised]))]
    fn each_hard_flag_fails_on_its_own(#[case] sut: ReputationFacts) {
        let verdict = judge_reputation(&sut);

        assert_eq!(verdict.severity, Severity::Fail, "{}", verdict.detail);
    }

    fn named_operator() -> ReputationFacts {
        ReputationFacts {
            operator: Some("Snowd".into()),
            ..clean()
        }
    }

    /// The operator is judged apart from the detection flags so an operator
    /// this rotation accepts can be waved through with
    /// `--skip-gate reputation:operator` without also disabling the vpn,
    /// proxy and tor checks.
    #[test]
    fn a_named_operator_does_not_fail_the_flag_gate() {
        let sut = named_operator();

        let verdict = judge_reputation(&sut);

        assert_eq!(verdict.severity, Severity::Ok);
    }

    #[test]
    fn a_named_operator_fails_the_operator_gate() {
        let sut = named_operator();

        let verdict = judge_reputation_operator(&sut);

        assert_eq!(verdict.severity, Severity::Fail);
        assert_eq!(verdict.detail, "named VPN operator: Snowd");
    }

    #[test]
    fn an_address_no_operator_claims_passes_the_operator_gate() {
        let sut = clean();

        let verdict = judge_reputation_operator(&sut);

        assert_eq!(verdict.severity, Severity::Ok);
        assert_eq!(verdict.detail, "no VPN operator claims this address");
    }

    #[rstest::rstest]
    #[case::anonymous(clean_with(&[ReputationFlag::Anonymous]))]
    #[case::scraper(clean_with(&[ReputationFlag::Scraper]))]
    fn each_soft_flag_only_warns(#[case] sut: ReputationFacts) {
        let verdict = judge_reputation(&sut);

        assert_eq!(verdict.severity, Severity::Warn, "{}", verdict.detail);
    }

    #[rstest::rstest]
    #[case::at_threshold(50, Severity::Warn)]
    #[case::below_threshold(49, Severity::Ok)]
    fn risk_threshold_is_inclusive(
        #[case] value: u8,
        #[case] expected: Severity,
    ) {
        let sut = ReputationFacts {
            risk: Some(risk(value)),
            ..clean()
        };

        let verdict = judge_reputation(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[test]
    fn the_detail_names_raised_flags_in_declaration_order() {
        let sut = clean_with(&[ReputationFlag::Scraper, ReputationFlag::Vpn]);

        let verdict = judge_reputation(&sut);

        assert_eq!(verdict.detail, "risk 33, flags: vpn, scraper");
    }

    #[test]
    fn a_clean_address_says_so_instead_of_an_empty_flag_list() {
        let sut = clean();

        let verdict = judge_reputation(&sut);

        assert_eq!(verdict.detail, "risk 33, no flags");
    }

    #[test]
    fn a_flagged_address_lists_its_flags() {
        let sut = clean_with(&[ReputationFlag::Anonymous, ReputationFlag::Vpn]);

        let verdict = judge_reputation(&sut);

        assert_eq!(verdict.detail, "risk 33, flags: vpn, anonymous");
    }
}
