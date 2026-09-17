use crate::model::BlockListFacts;
use crate::Verdict;

pub fn judge_blocklists(facts: &BlockListFacts) -> Verdict {
    if !facts.spamhaus_available && !facts.firehol_available {
        return Verdict::error("neither Spamhaus DROP nor FireHOL level1 could be fetched");
    }
    match (facts.spamhaus_hit, facts.firehol_hit) {
        (true, true) => Verdict::fail("listed on Spamhaus DROP and FireHOL level1"),
        (true, false) => Verdict::fail("listed on Spamhaus DROP"),
        (false, true) => Verdict::fail("listed on FireHOL level1"),
        (false, false) => Verdict::ok("not listed on Spamhaus DROP or FireHOL level1"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Severity, BlockListFacts};

    fn clean() -> BlockListFacts {
        BlockListFacts { spamhaus_hit: false, spamhaus_available: true, firehol_hit: false, firehol_available: true }
    }

    #[test]
    fn absent_from_both_lists_is_ok() {
        assert_eq!(judge_blocklists(&clean()).severity, Severity::Ok);
    }

    #[test]
    fn present_on_spamhaus_fails() {
        let f = BlockListFacts { spamhaus_hit: true, ..clean() };
        assert_eq!(judge_blocklists(&f).severity, Severity::Fail);
    }

    #[test]
    fn present_on_firehol_fails() {
        let f = BlockListFacts { firehol_hit: true, ..clean() };
        assert_eq!(judge_blocklists(&f).severity, Severity::Fail);
    }

    #[test]
    fn one_list_unavailable_is_judged_on_the_other() {
        let f = BlockListFacts { spamhaus_available: false, ..clean() };
        assert_eq!(judge_blocklists(&f).severity, Severity::Ok);
    }

    #[test]
    fn both_lists_unavailable_is_an_error() {
        let f = BlockListFacts { spamhaus_available: false, firehol_available: false, ..clean() };
        assert_eq!(judge_blocklists(&f).severity, Severity::Error);
    }
}
