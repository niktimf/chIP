use crate::model::ReputationFacts;
use crate::Verdict;

pub fn judge_reputation(facts: &ReputationFacts, warn_risk: u32) -> Verdict {
    let detail = format!(
        "risk {}, flags: {}{}",
        facts.risk.map_or("?".to_string(), |r| r.to_string()),
        [
            facts.vpn.then_some("vpn"), facts.proxy.then_some("proxy"),
            facts.tor.then_some("tor"), facts.compromised.then_some("compromised"),
            facts.anonymous.then_some("anonymous"), facts.scraper.then_some("scraper"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", "),
        facts.operator.as_deref().map(|o| format!(", operator: {o}")).unwrap_or_default(),
    );

    if facts.vpn || facts.proxy || facts.tor || facts.compromised || facts.operator.is_some() {
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

    fn clean() -> ReputationFacts {
        ReputationFacts {
            vpn: false, proxy: false, tor: false, compromised: false,
            anonymous: false, scraper: false, risk: Some(33), operator: None,
        }
    }

    #[test]
    fn a_clean_hosting_address_at_datacenter_floor_risk_is_ok() {
        let v = judge_reputation(&clean(), 50);
        assert_eq!(v.severity, Severity::Ok, "{}", v.detail);
    }

    #[rstest::rstest]
    #[case::vpn(ReputationFacts { vpn: true, ..clean() })]
    #[case::proxy(ReputationFacts { proxy: true, ..clean() })]
    #[case::tor(ReputationFacts { tor: true, ..clean() })]
    #[case::compromised(ReputationFacts { compromised: true, ..clean() })]
    #[case::operator(ReputationFacts { operator: Some("Snowd".into()), ..clean() })]
    fn each_hard_flag_fails_on_its_own(#[case] facts: ReputationFacts) {
        assert_eq!(judge_reputation(&facts, 50).severity, Severity::Fail);
    }

    #[rstest::rstest]
    #[case::anonymous(ReputationFacts { anonymous: true, ..clean() })]
    #[case::scraper(ReputationFacts { scraper: true, ..clean() })]
    fn each_soft_flag_only_warns(#[case] facts: ReputationFacts) {
        assert_eq!(judge_reputation(&facts, 50).severity, Severity::Warn);
    }

    #[test]
    fn risk_at_or_above_the_threshold_warns() {
        let facts = ReputationFacts { risk: Some(50), ..clean() };
        assert_eq!(judge_reputation(&facts, 50).severity, Severity::Warn);
        let facts = ReputationFacts { risk: Some(49), ..clean() };
        assert_eq!(judge_reputation(&facts, 50).severity, Severity::Ok);
    }

    #[test]
    fn the_operator_name_is_named_in_the_detail() {
        let facts = ReputationFacts { operator: Some("Snowd".into()), ..clean() };
        assert!(judge_reputation(&facts, 50).detail.contains("Snowd"));
    }
}
