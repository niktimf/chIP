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

    fn clean() -> BlockListFacts {
        BlockListFacts {
            spamhaus: BlockListStatus::Clear,
            firehol: BlockListStatus::Clear,
        }
    }

    #[test]
    fn absent_from_both_lists_is_ok() {
        assert_eq!(judge_blocklists(&clean()).severity, Severity::Ok);
    }

    #[test]
    fn present_on_spamhaus_fails() {
        let f = BlockListFacts {
            spamhaus: BlockListStatus::Listed,
            ..clean()
        };
        assert_eq!(judge_blocklists(&f).severity, Severity::Fail);
    }

    #[test]
    fn present_on_firehol_fails() {
        let f = BlockListFacts {
            firehol: BlockListStatus::Listed,
            ..clean()
        };
        assert_eq!(judge_blocklists(&f).severity, Severity::Fail);
    }

    #[test]
    fn one_list_unavailable_is_judged_on_the_other() {
        let f = BlockListFacts {
            spamhaus: BlockListStatus::Unavailable,
            ..clean()
        };
        assert_eq!(judge_blocklists(&f).severity, Severity::Ok);
    }

    #[test]
    fn both_lists_unavailable_is_an_error() {
        let f = BlockListFacts {
            spamhaus: BlockListStatus::Unavailable,
            firehol: BlockListStatus::Unavailable,
        };
        assert_eq!(judge_blocklists(&f).severity, Severity::Error);
    }
}
