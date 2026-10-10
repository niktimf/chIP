use crate::report::Verdict;
use ipnet::Ipv4Net;

/// Where the candidate itself stands in the RKN registry export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RknListing {
    NotListed,
    /// The address is in the list of single blocked addresses.
    Address,
    /// The address falls inside a network the registry blocks as a whole.
    Subnet(Ipv4Net),
}

/// The candidate's entry in the RKN registry plus how many other addresses
/// of its `/24` and `/16` are blocked one by one.
///
/// The candidate itself is never counted as its own neighbor, so a `/24` has
/// at most 255 of them and a `/16` at most 65 535: exactly what `u8` and
/// `u16` hold. The `/24` lies inside its `/16`, so it never has more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RknRegistryFacts {
    listing: RknListing,
    neighbors_24: u8,
    neighbors_16: u16,
}

impl RknRegistryFacts {
    /// # Errors
    ///
    /// Returns `InvalidRknRegistryFacts` when the `/24` holds more listed
    /// neighbors than the `/16` around it.
    pub fn new(
        listing: RknListing,
        neighbors_24: u8,
        neighbors_16: u16,
    ) -> Result<Self, InvalidRknRegistryFacts> {
        if u16::from(neighbors_24) > neighbors_16 {
            return Err(InvalidRknRegistryFacts {
                in_24: neighbors_24,
                in_16: neighbors_16,
            });
        }
        Ok(Self {
            listing,
            neighbors_24,
            neighbors_16,
        })
    }

    pub const fn listing(&self) -> RknListing {
        self.listing
    }

    pub const fn neighbors_24(&self) -> u8 {
        self.neighbors_24
    }

    pub const fn neighbors_16(&self) -> u16 {
        self.neighbors_16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the /24 has {in_24} listed neighbors, but its /16 only {in_16}")]
pub struct InvalidRknRegistryFacts {
    in_24: u8,
    in_16: u16,
}

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
    use crate::report::Severity;

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

        let verdict = judge_rkn_registry(&sut);

        assert_eq!(verdict.severity, Severity::Ok, "{}", verdict.detail);
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

        let verdict = judge_rkn_registry(&sut);

        assert_eq!(verdict.severity, Severity::Warn, "{}", verdict.detail);
    }

    #[test]
    fn the_detail_names_the_listed_neighbors_of_the_16() {
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
        let actual = RknRegistryFacts::new(RknListing::NotListed, 255, 65_535)
            .map(|facts| (facts.neighbors_24(), facts.neighbors_16()));

        assert_eq!(actual, Ok((255, 65_535)));
    }
}
