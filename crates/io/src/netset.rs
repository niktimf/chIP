use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use itertools::Itertools as _;

/// One line of a downloaded list: an entry, or a line the format allows
/// and that holds no entry (a comment, a blank line, an IPv6 entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Line<T> {
    Entry(T),
    Skip,
}

impl<T> Line<T> {
    fn into_entry(self) -> Option<T> {
        match self {
            Self::Entry(entry) => Some(entry),
            Self::Skip => None,
        }
    }
}

/// A line that is neither an entry nor a line the format allows: a changed
/// format or a broken download.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Garbage;

/// The entries of a list body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedList<C> {
    entries: C,
    garbage: usize,
}

impl<C> ParsedList<C> {
    /// Reads every line of `body` with `line`, keeps the entries and counts
    /// the garbage lines.
    pub fn parse<T>(
        body: &str,
        line: impl Fn(&str) -> Result<Line<T>, Garbage>,
    ) -> Self
    where
        C: FromIterator<T>,
    {
        let (lines, garbage): (Vec<Line<T>>, Vec<Garbage>) = body
            .lines()
            .map(|text| line(text.trim()))
            .partition_result();
        Self {
            entries: lines.into_iter().filter_map(Line::into_entry).collect(),
            garbage: garbage.len(),
        }
    }

    /// The entries of `list`; garbage lines, if any, are counted in the log.
    pub fn into_logged_entries(self, list: &str) -> C {
        if self.garbage > 0 {
            tracing::debug!(
                list,
                skipped = self.garbage,
                "list lines that hold no entry skipped"
            );
        }
        self.entries
    }
}

/// Reads one line of a plain-text IPv4 list such as `FireHOL` netsets or
/// the RKN subnet export: a network, or a bare address read as its `/32`.
fn netset_line(line: &str) -> Result<Line<Ipv4Net>, Garbage> {
    const COMMENT: char = '#';
    if line.is_empty() || line.starts_with(COMMENT) {
        return Ok(Line::Skip);
    }
    if let Ok(network) = line.parse::<Ipv4Net>() {
        return Ok(Line::Entry(network));
    }
    if let Ok(address) = line.parse::<Ipv4Addr>() {
        return Ok(Line::Entry(Ipv4Net::from(address)));
    }
    if line.parse::<Ipv6Net>().is_ok() || line.parse::<Ipv6Addr>().is_ok() {
        return Ok(Line::Skip);
    }
    Err(Garbage)
}

/// Every IPv4 entry of a netset body.
pub fn parse(body: &str) -> ParsedList<Vec<Ipv4Net>> {
    ParsedList::parse(body, netset_line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(cidr: &str) -> Ipv4Net {
        cidr.parse().unwrap()
    }

    #[rstest::rstest]
    #[case::network("192.0.2.0/24", "192.0.2.0/24")]
    #[case::bare_address_is_a_32("198.51.100.7", "198.51.100.7/32")]
    fn an_entry_is_a_network_or_a_bare_address(
        #[case] line: &str,
        #[case] expected: &str,
    ) {
        let actual = netset_line(line);

        assert_eq!(actual, Ok(Line::Entry(network(expected))));
    }

    #[rstest::rstest]
    #[case::comment("# Maintainer : FireHOL")]
    #[case::blank("")]
    #[case::ipv6_network("2001:db8::/32")]
    #[case::ipv6_address("2001:db8::1")]
    fn a_line_the_format_allows_without_ipv4_is_skipped(#[case] line: &str) {
        let actual = netset_line(line);

        assert_eq!(actual, Ok(Line::Skip));
    }

    #[test]
    fn a_line_that_is_no_address_is_garbage() {
        let actual = netset_line("<html>");

        assert_eq!(actual, Err(Garbage));
    }

    #[test]
    fn only_the_ipv4_entries_of_a_body_are_kept_and_garbage_is_counted() {
        let body =
            "# comment\n192.0.2.0/24\n\n 198.51.100.7 \n2001:db8::1\n<html>\n";

        let actual = parse(body);

        assert_eq!(
            actual,
            ParsedList {
                entries: vec![
                    network("192.0.2.0/24"),
                    network("198.51.100.7/32")
                ],
                garbage: 1,
            }
        );
    }
}
