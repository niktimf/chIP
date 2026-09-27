//! Address lists downloaded from block-list sources and the lookups the
//! judges need from them. The adapters only fetch and parse the text; which
//! entry covers the candidate is decided here.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::model::{
    BlockListFacts, BlockListStatus, InvalidRknRegistryFacts, RknListing,
    RknRegistryFacts,
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

    /// Listed addresses in the network `netmask` cuts around `ip`, not
    /// counting `ip` itself.
    fn neighbors(&self, ip: Ipv4Addr, netmask: u32) -> usize {
        let first = u32::from(ip) & netmask;
        let last = first | !netmask;
        self.0
            .range(Ipv4Addr::from(first)..=Ipv4Addr::from(last))
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

const NETMASK_24: u32 = 0xffff_ff00;
const NETMASK_16: u32 = 0xffff_0000;

/// The RKN registry export: addresses blocked one by one and networks
/// blocked as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RknRegistry {
    addresses: AddressList,
    subnets: NetworkList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RknCheckError {
    /// A `/24` holds 255 addresses besides the candidate and a `/16` 65 535,
    /// so a larger count means the lookup itself is broken.
    #[error("counted {count} listed neighbors in a /{prefix_len}")]
    NeighborCount { prefix_len: u8, count: usize },
    #[error(transparent)]
    Facts(#[from] InvalidRknRegistryFacts),
}

impl RknRegistry {
    pub const fn new(addresses: AddressList, subnets: NetworkList) -> Self {
        Self { addresses, subnets }
    }

    pub fn check(
        &self,
        ip: Ipv4Addr,
    ) -> Result<RknRegistryFacts, RknCheckError> {
        let listing = if self.addresses.contains(ip) {
            RknListing::Address
        } else {
            self.subnets
                .containing(ip)
                .map_or(RknListing::NotListed, RknListing::Subnet)
        };
        let in_24 = self.addresses.neighbors(ip, NETMASK_24);
        let in_16 = self.addresses.neighbors(ip, NETMASK_16);
        let neighbors_24 =
            u8::try_from(in_24).map_err(|_| RknCheckError::NeighborCount {
                prefix_len: 24,
                count: in_24,
            })?;
        let neighbors_16 =
            u16::try_from(in_16).map_err(|_| RknCheckError::NeighborCount {
                prefix_len: 16,
                count: in_16,
            })?;
        Ok(RknRegistryFacts::new(listing, neighbors_24, neighbors_16)?)
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

        let facts = sut.check(Ipv4Addr::new(203, 0, 113, 7)).unwrap();

        assert_eq!(facts.listing(), RknListing::Address);
        assert_eq!(facts.neighbors_24(), 4);
    }

    #[test]
    fn an_address_inside_a_blocked_subnet_names_that_subnet() {
        let sut = registry();

        let facts = sut.check(Ipv4Addr::new(198, 51, 100, 42)).unwrap();

        assert_eq!(
            facts.listing(),
            RknListing::Subnet("198.51.100.0/24".parse().unwrap())
        );
    }

    #[test]
    fn neighbors_are_counted_within_the_24_and_the_16() {
        let sut = registry();

        let facts = sut.check(Ipv4Addr::new(203, 0, 113, 200)).unwrap();

        assert_eq!(facts.listing(), RknListing::NotListed);
        assert_eq!(facts.neighbors_24(), 5);
        assert_eq!(facts.neighbors_16(), 6);
    }
}
