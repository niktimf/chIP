use crate::Verdict;
use crate::model::{RknListing, RknRegistryFacts};

/// Blocked neighbors in the `/24` from which the subnet is worth a warning.
/// Taken from the 2026-09-26 slice of the registry, where the 90th percentile
/// of `/24`s with at least one blocked address was 4.
const WARN_NEIGHBORS: u8 = 5;
/// Blocked neighbors from which the `/24` is close to being blocked whole.
const NEAR_FULL_BLOCK_NEIGHBORS: u8 = 50;

/// A listed address fails: the registry names the address itself.
///
/// Blocked neighbors only warn, because they describe the subnet and prove
/// nothing about the candidate; `--gate rkn-registry` turns that warning into
/// a failure.
pub fn judge_rkn_registry(facts: &RknRegistryFacts) -> Verdict {
    let counts = format!(
        "{} other addresses of its /24 and {} of its /16 are listed",
        facts.neighbors_24(),
        facts.neighbors_16()
    );
    match facts.listing() {
        RknListing::Address => {
            Verdict::fail(format!("listed in the RKN registry; {counts}"))
        }
        RknListing::Subnet(network) => Verdict::fail(format!(
            "inside {network}, which the RKN registry blocks whole; {counts}"
        )),
        RknListing::NotListed
            if facts.neighbors_24() >= NEAR_FULL_BLOCK_NEIGHBORS =>
        {
            Verdict::warn(format!(
                "not listed, but the /24 is close to a full block: {counts}"
            ))
        }
        RknListing::NotListed if facts.neighbors_24() >= WARN_NEIGHBORS => {
            Verdict::warn(format!("not listed; {counts}"))
        }
        RknListing::NotListed => {
            Verdict::ok(format!("not listed in the RKN registry; {counts}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn facts(listing: RknListing, neighbors_24: u8) -> RknRegistryFacts {
        RknRegistryFacts::new(listing, neighbors_24, u16::from(neighbors_24))
            .unwrap()
    }

    #[test]
    fn a_listed_address_fails() {
        let sut = facts(RknListing::Address, 0);

        let verdict = judge_rkn_registry(&sut);

        assert_eq!(verdict.severity, Severity::Fail);
        assert!(verdict.detail.contains("listed in the RKN registry"));
    }

    #[test]
    fn an_address_inside_a_blocked_subnet_fails_and_names_the_subnet() {
        let sut =
            facts(RknListing::Subnet("198.51.100.0/24".parse().unwrap()), 0);

        let verdict = judge_rkn_registry(&sut);

        assert_eq!(verdict.severity, Severity::Fail);
        assert!(
            verdict.detail.contains("198.51.100.0/24"),
            "{}",
            verdict.detail
        );
    }

    #[test]
    fn four_blocked_neighbors_are_ok() {
        let sut = facts(RknListing::NotListed, 4);

        assert_eq!(judge_rkn_registry(&sut).severity, Severity::Ok);
    }

    #[test]
    fn five_blocked_neighbors_warn() {
        let sut = facts(RknListing::NotListed, 5);

        let verdict = judge_rkn_registry(&sut);

        assert_eq!(verdict.severity, Severity::Warn);
        assert!(!verdict.detail.contains("full block"), "{}", verdict.detail);
    }

    #[test]
    fn fifty_blocked_neighbors_warn_that_the_subnet_is_close_to_a_full_block() {
        let sut = facts(RknListing::NotListed, 50);

        let verdict = judge_rkn_registry(&sut);

        assert_eq!(verdict.severity, Severity::Warn);
        assert!(verdict.detail.contains("full block"), "{}", verdict.detail);
    }

    #[test]
    fn neighbors_never_raise_a_failure_on_their_own() {
        let sut = facts(RknListing::NotListed, 255);

        assert_eq!(judge_rkn_registry(&sut).severity, Severity::Warn);
    }

    #[test]
    fn the_16_count_reaches_the_detail_for_the_json_report() {
        let sut = RknRegistryFacts::new(RknListing::NotListed, 1, 37).unwrap();

        let verdict = judge_rkn_registry(&sut);

        assert!(verdict.detail.contains("37 of its /16"), "{}", verdict.detail);
    }

    #[test]
    fn a_24_cannot_have_more_listed_neighbors_than_its_16() {
        let error =
            RknRegistryFacts::new(RknListing::NotListed, 9, 2).unwrap_err();

        assert_eq!(
            error.to_string(),
            "the /24 has 9 listed neighbors, but its /16 only 2"
        );
    }

    #[test]
    fn a_fully_listed_24_and_16_are_valid_facts() {
        let sut = RknRegistryFacts::new(RknListing::NotListed, 255, 65_535);

        assert!(sut.is_ok());
    }
}
