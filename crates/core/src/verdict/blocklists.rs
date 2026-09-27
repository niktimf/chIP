use crate::Verdict;
use crate::model::{BlockListFacts, BlockListStatus};

pub fn judge_blocklists(facts: &BlockListFacts) -> Verdict {
    use BlockListStatus::{Clear, Listed, Unavailable};

    if facts.spamhaus == Unavailable && facts.firehol == Unavailable {
        return Verdict::error(
            "neither Spamhaus DROP nor FireHOL level1 could be fetched",
        );
    }
    match (facts.spamhaus, facts.firehol) {
        (Listed, Listed) => {
            Verdict::fail("listed on Spamhaus DROP and FireHOL level1")
        }
        (Listed, _) => Verdict::fail("listed on Spamhaus DROP"),
        (_, Listed) => Verdict::fail("listed on FireHOL level1"),
        (Clear | Unavailable, Clear | Unavailable) => {
            Verdict::ok("not listed on Spamhaus DROP or FireHOL level1")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BlockListFacts, Severity};
    use BlockListStatus::{Clear, Listed, Unavailable};

    const fn facts(
        spamhaus: BlockListStatus,
        firehol: BlockListStatus,
    ) -> BlockListFacts {
        BlockListFacts { spamhaus, firehol }
    }

    #[rstest::rstest]
    #[case::absent_from_both_lists(facts(Clear, Clear), Severity::Ok)]
    #[case::present_on_spamhaus(facts(Listed, Clear), Severity::Fail)]
    #[case::present_on_firehol(facts(Clear, Listed), Severity::Fail)]
    #[case::one_list_unavailable_is_judged_on_the_other(
        facts(Unavailable, Clear),
        Severity::Ok
    )]
    #[case::both_lists_unavailable(
        facts(Unavailable, Unavailable),
        Severity::Error
    )]
    fn the_lists_set_the_severity(
        #[case] sut: BlockListFacts,
        #[case] expected: Severity,
    ) {
        let verdict = judge_blocklists(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }
}
