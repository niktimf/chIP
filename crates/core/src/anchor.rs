//! RIPE Atlas anchors and the rule that picks the ones a scan pings.

use std::net::Ipv4Addr;
use std::num::NonZeroUsize;

use itertools::Itertools as _;

use crate::model::{CityName, CountryCode};

/// An active RIPE Atlas anchor that has an IPv4 address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    fqdn: String,
    ip_v4: Ipv4Addr,
    city: String,
    country: CountryCode,
    as_v4: u32,
}

/// The fields of an [`Anchor`], named at the call site. The anchor name and
/// its city are both strings; a struct literal keeps them from being swapped
/// the way two positional arguments could be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorFields {
    pub fqdn: String,
    pub ip_v4: Ipv4Addr,
    pub city: String,
    pub country: CountryCode,
    pub as_v4: u32,
}

impl Anchor {
    pub fn new(fields: AnchorFields) -> Self {
        let AnchorFields {
            fqdn,
            ip_v4,
            city,
            country,
            as_v4,
        } = fields;
        Self {
            fqdn,
            ip_v4,
            city,
            country,
            as_v4,
        }
    }

    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    pub const fn ip_v4(&self) -> Ipv4Addr {
        self.ip_v4
    }

    /// Whether the name marks the client probe hosted next to an anchor
    /// rather than the anchor itself.
    fn is_client_probe(&self) -> bool {
        const CLIENT_MARKER: &str = "-client";
        self.fqdn.contains(CLIENT_MARKER)
    }
}

/// Anchors whose city contains `city`, ignoring case. See [`pick`] for which
/// of them are kept.
pub fn select_for_city(
    anchors: &[Anchor],
    city: &CityName,
    count: NonZeroUsize,
) -> Vec<Anchor> {
    let needle = city.as_str().to_lowercase();
    pick(
        anchors
            .iter()
            .filter(|anchor| anchor.city.to_lowercase().contains(&needle)),
        count,
    )
}

/// Anchors in `country`. See [`pick`] for which of them are kept.
pub fn select_for_country(
    anchors: &[Anchor],
    country: &CountryCode,
    count: NonZeroUsize,
) -> Vec<Anchor> {
    pick(anchors.iter().filter(|anchor| anchor.country == *country), count)
}

/// Sorted by `fqdn` first so "first wins" is deterministic, then client
/// probes dropped and one anchor kept per AS (`unique_by` keeps the first
/// match for each key it sees), at most `count` of them.
fn pick<'a>(
    matched: impl Iterator<Item = &'a Anchor>,
    count: NonZeroUsize,
) -> Vec<Anchor> {
    matched
        .sorted_by(|left, right| left.fqdn.cmp(&right.fqdn))
        .filter(|anchor| !anchor.is_client_probe())
        .unique_by(|anchor| anchor.as_v4)
        .take(count.get())
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO: NonZeroUsize = NonZeroUsize::new(2).expect("2 is non-zero");
    const THREE: NonZeroUsize = NonZeroUsize::new(3).expect("3 is non-zero");

    fn anchor(fqdn: &str, city: &str, country: &str, as_v4: u32) -> Anchor {
        Anchor::new(AnchorFields {
            fqdn: fqdn.into(),
            ip_v4: Ipv4Addr::new(192, 0, 2, 1),
            city: city.into(),
            country: country.parse().unwrap(),
            as_v4,
        })
    }

    fn fqdns(anchors: &[Anchor]) -> Vec<&str> {
        anchors.iter().map(Anchor::fqdn).collect()
    }

    #[test]
    fn a_city_matches_a_substring_of_the_anchor_city_in_any_case() {
        let anchors = [
            anchor("fi-hel-as1", "Helsinki", "FI", 1),
            anchor("nl-ams-as2", "Amsterdam, Netherlands", "NL", 2),
        ];

        let picked =
            select_for_city(&anchors, &"helsinki".parse().unwrap(), THREE);

        assert_eq!(fqdns(&picked), ["fi-hel-as1"]);
    }

    #[test]
    fn at_most_one_anchor_per_as_is_picked_up_to_the_count() {
        let anchors = [
            anchor("fi-hel-as3", "Helsinki", "FI", 3),
            anchor("fi-hel-as1-second", "Helsinki", "FI", 1),
            anchor("fi-hel-as2", "Helsinki", "FI", 2),
            anchor("fi-hel-as1", "Helsinki", "FI", 1),
        ];

        let picked =
            select_for_city(&anchors, &"helsinki".parse().unwrap(), TWO);

        assert_eq!(fqdns(&picked), ["fi-hel-as1", "fi-hel-as2"]);
    }

    #[test]
    fn a_client_probe_is_never_picked_as_an_anchor() {
        let anchors = [anchor("fi-hel-as1-client", "Helsinki", "FI", 1)];

        let picked =
            select_for_city(&anchors, &"helsinki".parse().unwrap(), THREE);

        assert_eq!(picked, []);
    }

    #[test]
    fn only_anchors_of_the_given_country_are_picked() {
        let anchors = [
            anchor("fi-hel-as1", "Helsinki", "FI", 1),
            anchor("de-fra-as2", "Frankfurt", "DE", 2),
        ];

        let picked =
            select_for_country(&anchors, &"FI".parse().unwrap(), THREE);

        assert_eq!(fqdns(&picked), ["fi-hel-as1"]);
    }
}
