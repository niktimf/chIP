use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;

/// One line of a plain-text IPv4 list such as `FireHOL` netsets or the RKN
/// subnet export: a network, or a bare address read as its `/32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetsetEntry(Ipv4Net);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidNetsetEntry;

impl FromStr for NetsetEntry {
    type Err = InvalidNetsetEntry;

    #[expect(
        clippy::map_err_ignore,
        reason = "a line that is neither a network nor an address has no \
                  single parse error to keep, and the only caller skips it"
    )]
    fn from_str(line: &str) -> Result<Self, Self::Err> {
        line.parse::<Ipv4Net>()
            .or_else(|_| line.parse::<Ipv4Addr>().map(Ipv4Net::from))
            .map(Self)
            .map_err(|_| InvalidNetsetEntry)
    }
}

impl From<NetsetEntry> for Ipv4Net {
    fn from(entry: NetsetEntry) -> Self {
        entry.0
    }
}

/// Every IPv4 entry of a list body. Comments, blank lines and IPv6 entries
/// are not entries and are skipped.
pub fn parse(body: &str) -> Vec<Ipv4Net> {
    body.lines()
        .filter_map(|line| line.trim().parse::<NetsetEntry>().ok())
        .map(Ipv4Net::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    #[case::network("192.0.2.0/24", "192.0.2.0/24")]
    #[case::bare_address_is_a_32("198.51.100.7", "198.51.100.7/32")]
    fn an_entry_is_a_network_or_a_bare_address(
        #[case] line: &str,
        #[case] expected: &str,
    ) {
        let actual = line.parse::<NetsetEntry>().map(Ipv4Net::from);

        assert_eq!(actual, Ok(expected.parse().unwrap()));
    }

    #[rstest::rstest]
    #[case::comment("# Maintainer : FireHOL")]
    #[case::blank("")]
    #[case::ipv6("2001:db8::/32")]
    fn a_line_that_is_not_ipv4_is_not_an_entry(#[case] line: &str) {
        let actual = line.parse::<NetsetEntry>();

        assert_eq!(actual, Err(InvalidNetsetEntry));
    }

    #[test]
    fn only_the_ipv4_entries_of_a_body_are_kept() {
        let body = "# comment\n192.0.2.0/24\n\n 198.51.100.7 \n2001:db8::1\n";

        let actual = parse(body);

        assert_eq!(
            actual,
            vec![
                "192.0.2.0/24".parse::<Ipv4Net>().unwrap(),
                "198.51.100.7/32".parse().unwrap(),
            ]
        );
    }
}
