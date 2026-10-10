//! Address lists downloaded from block-list sources and the lookups the
//! judges need from them. The adapters only fetch and parse the text; which
//! entry covers the candidate is decided here.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::model::{
    BlockListFacts, BlockListStatus, RknListing, RknRegistryFacts,
};

/// A real list always has entries, so an empty one is a corrupted download,
/// not a clean list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the list has no IPv4 entries")]
pub struct EmptyList;

/// The networks of one list. Never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkList(Vec<Ipv4Net>);

impl NetworkList {
    /// # Errors
    ///
    /// Returns `EmptyList` when `networks` is empty.
    pub fn new(networks: Vec<Ipv4Net>) -> Result<Self, EmptyList> {
        if networks.is_empty() {
            Err(EmptyList)
        } else {
            Ok(Self(networks))
        }
    }

    /// The first listed network that holds `ip`.
    pub fn containing(&self, ip: Ipv4Addr) -> Option<Ipv4Net> {
        self.0.iter().find(|network| network.contains(&ip)).copied()
    }
}

/// Single listed addresses. Never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressList(BTreeSet<Ipv4Addr>);

impl AddressList {
    /// # Errors
    ///
    /// Returns `EmptyList` when `addresses` is empty.
    pub fn new(addresses: BTreeSet<Ipv4Addr>) -> Result<Self, EmptyList> {
        if addresses.is_empty() {
            Err(EmptyList)
        } else {
            Ok(Self(addresses))
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.0.contains(&ip)
    }

    /// Listed addresses in `network`, not counting `ip` itself.
    fn neighbors(&self, network: Ipv4Net, ip: Ipv4Addr) -> usize {
        self.0
            .range(network.network()..=network.broadcast())
            .filter(|&&address| address != ip)
            .count()
    }
}

/// One block-list source as the scan received it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchedList {
    /// The download failed or parsed to nothing; the list says nothing
    /// about the candidate either way.
    Unavailable,
    Fetched(NetworkList),
}

impl FetchedList {
    fn status(&self, ip: Ipv4Addr) -> BlockListStatus {
        match self {
            Self::Unavailable => BlockListStatus::Unavailable,
            Self::Fetched(networks) => match networks.containing(ip) {
                Some(_) => BlockListStatus::Listed,
                None => BlockListStatus::Clear,
            },
        }
    }
}

/// Spamhaus DROP and `FireHOL` level1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockLists {
    pub spamhaus: FetchedList,
    pub firehol: FetchedList,
}

impl BlockLists {
    pub fn check(&self, ip: Ipv4Addr) -> BlockListFacts {
        BlockListFacts {
            spamhaus: self.spamhaus.status(ip),
            firehol: self.firehol.status(ip),
        }
    }
}

/// The RKN registry export: addresses blocked one by one and networks
/// blocked as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RknRegistry {
    addresses: AddressList,
    subnets: NetworkList,
}

impl RknRegistry {
    pub const fn new(addresses: AddressList, subnets: NetworkList) -> Self {
        Self { addresses, subnets }
    }

    /// Looks `ip` up in the registry and counts its listed neighbors.
    ///
    /// # Panics
    ///
    /// Only on a broken invariant: a `/24` holds 255 addresses besides `ip`,
    /// a `/16` 65 535, and the `/24` lies inside the `/16`.
    #[expect(
        clippy::expect_used,
        reason = "a /24 holds 255 addresses besides the candidate and a /16 \
                  65 535, so the counts fit u8 and u16; the /24 lies inside \
                  the /16, so it never counts more"
    )]
    pub fn check(&self, ip: Ipv4Addr) -> RknRegistryFacts {
        let listing = if self.addresses.contains(ip) {
            RknListing::Address
        } else {
            self.subnets
                .containing(ip)
                .map_or(RknListing::NotListed, RknListing::Subnet)
        };
        let around = |prefix_len| Ipv4Net::new_assert(ip, prefix_len).trunc();
        let neighbors_24 =
            u8::try_from(self.addresses.neighbors(around(24), ip))
                .expect("a /24 has at most 255 neighbors");
        let neighbors_16 =
            u16::try_from(self.addresses.neighbors(around(16), ip))
                .expect("a /16 has at most 65 535 neighbors");
        RknRegistryFacts::new(listing, neighbors_24, neighbors_16)
            .expect("the /24 lies inside its /16")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn networks(cidrs: &[&str]) -> NetworkList {
        NetworkList::new(
            cidrs.iter().map(|cidr| cidr.parse().unwrap()).collect(),
        )
        .unwrap()
    }

    fn addresses(ips: &[&str]) -> AddressList {
        AddressList::new(ips.iter().map(|ip| ip.parse().unwrap()).collect())
            .unwrap()
    }

    fn registry() -> RknRegistry {
        RknRegistry::new(
            addresses(&[
                "203.0.113.7",
                "203.0.113.8",
                "203.0.113.9",
                "203.0.113.10",
                "203.0.113.11",
                "203.0.114.1",
            ]),
            networks(&["198.51.100.0/24"]),
        )
    }

    #[test]
    fn an_empty_network_list_is_rejected() {
        let error = NetworkList::new(Vec::new()).unwrap_err();

        assert_eq!(error, EmptyList);
    }

    #[test]
    fn an_empty_address_list_is_rejected() {
        let error = AddressList::new(BTreeSet::new()).unwrap_err();

        assert_eq!(error, EmptyList);
    }

    #[rstest::rstest]
    #[case::inside_spamhaus_only(
        "203.0.113.5",
        BlockListStatus::Listed,
        BlockListStatus::Clear
    )]
    #[case::inside_both(
        "192.0.2.1",
        BlockListStatus::Listed,
        BlockListStatus::Listed
    )]
    #[case::outside_both(
        "8.8.8.8",
        BlockListStatus::Clear,
        BlockListStatus::Clear
    )]
    fn block_lists_report_each_source_on_its_own(
        #[case] ip: &str,
        #[case] spamhaus: BlockListStatus,
        #[case] firehol: BlockListStatus,
    ) {
        let sut = BlockLists {
            spamhaus: FetchedList::Fetched(networks(&[
                "203.0.113.0/24",
                "192.0.2.0/24",
            ])),
            firehol: FetchedList::Fetched(networks(&["192.0.2.0/24"])),
        };

        let facts = sut.check(ip.parse().unwrap());

        assert_eq!((facts.spamhaus, facts.firehol), (spamhaus, firehol));
    }

    #[test]
    fn an_unavailable_source_does_not_hide_the_other() {
        let sut = BlockLists {
            spamhaus: FetchedList::Unavailable,
            firehol: FetchedList::Fetched(networks(&["192.0.2.0/24"])),
        };

        let facts = sut.check(Ipv4Addr::new(192, 0, 2, 1));

        assert_eq!(facts.spamhaus, BlockListStatus::Unavailable);
        assert_eq!(facts.firehol, BlockListStatus::Listed);
    }

    #[test]
    fn a_listed_address_is_not_its_own_neighbor() {
        let sut = registry();

        let facts = sut.check(Ipv4Addr::new(203, 0, 113, 7));

        assert_eq!(facts.listing(), RknListing::Address);
        assert_eq!(facts.neighbors_24(), 4);
    }

    #[test]
    fn an_address_inside_a_blocked_subnet_names_that_subnet() {
        let sut = registry();

        let facts = sut.check(Ipv4Addr::new(198, 51, 100, 42));

        assert_eq!(
            facts.listing(),
            RknListing::Subnet("198.51.100.0/24".parse().unwrap())
        );
    }

    #[test]
    fn neighbors_are_counted_within_the_24_and_the_16() {
        let sut = registry();

        let facts = sut.check(Ipv4Addr::new(203, 0, 113, 200));

        assert_eq!(facts.listing(), RknListing::NotListed);
        assert_eq!(facts.neighbors_24(), 5);
        assert_eq!(facts.neighbors_16(), 6);
    }
}
