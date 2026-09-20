use crate::Verdict;
use crate::model::{ReputationFacts, RiskScore};

pub fn judge_reputation(
    facts: &ReputationFacts,
    warn_risk: RiskScore,
) -> Verdict {
    let flags = [
        facts.vpn.then_some("vpn"),
        facts.proxy.then_some("proxy"),
        facts.tor.then_some("tor"),
        facts.compromised.then_some("compromised"),
        facts.anonymous.then_some("anonymous"),
        facts.scraper.then_some("scraper"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let detail = format!(
        "risk {}, {}",
        facts
            .risk
            .map_or_else(|| "?".to_string(), |r| r.to_string()),
        if flags.is_empty() {
            "no flags".to_string()
        } else {
            format!("flags: {}", flags.join(", "))
        },
    );

    if facts.vpn || facts.proxy || facts.tor || facts.compromised {
        return Verdict::fail(detail);
    }
    let risk_over = facts.risk.is_some_and(|r| r >= warn_risk);
    if facts.anonymous || facts.scraper || risk_over {
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
    fn each_hard_flag_fails_on_its_own(#[case] sut: ReputationFacts) {
        assert_eq!(judge_reputation(&sut, risk(50)).severity, Severity::Fail);
    }

    /// The operator is judged apart from the detection flags so an operator
    /// this rotation accepts can be waved through with
    /// `--skip-gate reputation:operator` without also disabling the vpn,
    /// proxy and tor checks.
    #[test]
    fn a_named_operator_fails_its_own_gate_and_not_the_flag_gate() {
        let sut = ReputationFacts {
            operator: Some("Snowd".into()),
            ..clean()
        };

        assert_eq!(judge_reputation(&sut, risk(50)).severity, Severity::Ok);
        let operator = judge_reputation_operator(&sut);
        assert_eq!(operator.severity, Severity::Fail);
        assert_eq!(operator.detail, "named VPN operator: Snowd");
    }

    #[test]
    fn an_address_no_operator_claims_passes_the_operator_gate() {
        let sut = clean();

        let verdict = judge_reputation_operator(&sut);

        assert_eq!(verdict.severity, Severity::Ok);
        assert_eq!(verdict.detail, "no VPN operator claims this address");
    }

    #[rstest::rstest]
    #[case::anonymous(ReputationFacts { anonymous: true, ..clean() })]
    #[case::scraper(ReputationFacts { scraper: true, ..clean() })]
    fn each_soft_flag_only_warns(#[case] sut: ReputationFacts) {
        assert_eq!(judge_reputation(&sut, risk(50)).severity, Severity::Warn);
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

        let verdict = judge_reputation(&sut, risk(50));

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[test]
    fn a_clean_address_says_so_instead_of_an_empty_flag_list() {
        let sut = clean();

        let verdict = judge_reputation(&sut, risk(50));

        assert_eq!(verdict.detail, "risk 33, no flags");
    }

    #[test]
    fn a_flagged_address_lists_its_flags() {
        let sut = ReputationFacts {
            vpn: true,
            anonymous: true,
            ..clean()
        };

        let verdict = judge_reputation(&sut, risk(50));

        assert_eq!(verdict.detail, "risk 33, flags: vpn, anonymous");
    }
}
