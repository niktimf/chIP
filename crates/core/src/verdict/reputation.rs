use crate::Verdict;
use crate::model::{ReputationFacts, RiskScore};

pub fn judge_reputation(
    facts: &ReputationFacts,
    warn_risk: RiskScore,
) -> Verdict {
    let detail = format!(
        "risk {}, flags: {}{}",
        facts
            .risk
            .map_or_else(|| "?".to_string(), |r| r.to_string()),
        [
            facts.vpn.then_some("vpn"),
            facts.proxy.then_some("proxy"),
            facts.tor.then_some("tor"),
            facts.compromised.then_some("compromised"),
            facts.anonymous.then_some("anonymous"),
            facts.scraper.then_some("scraper"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", "),
        facts
            .operator
            .as_deref()
            .map(|o| format!(", operator: {o}"))
            .unwrap_or_default(),
    );

    if facts.vpn
        || facts.proxy
        || facts.tor
        || facts.compromised
        || facts.operator.is_some()
    {
        return Verdict::fail(detail);
    }
    let risk_over = facts.risk.is_some_and(|r| r >= warn_risk);
    if facts.anonymous || facts.scraper || risk_over {
        return Verdict::warn(detail);
    }
    Verdict::ok(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn risk(value: u8) -> RiskScore {
        RiskScore::new(value).unwrap()
    }

    fn clean() -> ReputationFacts {
        ReputationFacts {
            vpn: false,
            proxy: false,
            tor: false,
            compromised: false,
            anonymous: false,
            scraper: false,
            risk: Some(risk(33)),
            operator: None,
        }
    }

    #[test]
    fn a_clean_hosting_address_at_datacenter_floor_risk_is_ok() {
        let v = judge_reputation(&clean(), risk(50));
        assert_eq!(v.severity, Severity::Ok, "{}", v.detail);
    }

    #[rstest::rstest]
    #[case::vpn(ReputationFacts { vpn: true, ..clean() })]
    #[case::proxy(ReputationFacts { proxy: true, ..clean() })]
    #[case::tor(ReputationFacts { tor: true, ..clean() })]
    #[case::compromised(ReputationFacts { compromised: true, ..clean() })]
    #[case::operator(ReputationFacts { operator: Some("Snowd".into()), ..clean() })]
    fn each_hard_flag_fails_on_its_own(#[case] facts: ReputationFacts) {
        assert_eq!(judge_reputation(&facts, risk(50)).severity, Severity::Fail);
    }

    #[rstest::rstest]
    #[case::anonymous(ReputationFacts { anonymous: true, ..clean() })]
    #[case::scraper(ReputationFacts { scraper: true, ..clean() })]
    fn each_soft_flag_only_warns(#[case] facts: ReputationFacts) {
        assert_eq!(judge_reputation(&facts, risk(50)).severity, Severity::Warn);
    }

    #[rstest::rstest]
    #[case::at_threshold(50, Severity::Warn)]
    #[case::below_threshold(49, Severity::Ok)]
    fn risk_threshold_is_inclusive(
        #[case] value: u8,
        #[case] expected: Severity,
    ) {
        let facts = ReputationFacts {
            risk: Some(risk(value)),
            ..clean()
        };

        let verdict = judge_reputation(&facts, risk(50));

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[test]
    fn the_operator_name_is_named_in_the_detail() {
        let facts = ReputationFacts {
            operator: Some("Snowd".into()),
            ..clean()
        };
        assert!(judge_reputation(&facts, risk(50)).detail.contains("Snowd"));
    }
}
