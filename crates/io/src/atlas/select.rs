use itertools::Itertools as _;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Anchor {
    pub fqdn: String,
    pub ip_v4: String,
    pub city: String,
    pub country: String,
    pub as_v4: u32,
    pub is_disabled: bool,
    pub date_decommissioned: Option<String>,
}

/// Sorted by `fqdn` first so "first wins" is deterministic, then one anchor
/// per AS (`unique_by` keeps the first match for each key it sees).
fn pick(mut matched: Vec<&Anchor>, count: usize) -> Vec<Anchor> {
    matched.sort_by(|a, b| a.fqdn.cmp(&b.fqdn));
    matched
        .into_iter()
        .filter(|a| !a.fqdn.contains("-client"))
        .unique_by(|a| a.as_v4)
        .take(count)
        .cloned()
        .collect()
}

pub fn select_for_city(anchors: &[Anchor], city: &str, count: usize) -> Vec<Anchor> {
    let needle = city.to_lowercase();
    let matched: Vec<&Anchor> = anchors
        .iter()
        .filter(|a| a.city.to_lowercase().contains(&needle))
        .collect();
    pick(matched, count)
}

pub fn select_for_country(anchors: &[Anchor], country: &str, count: usize) -> Vec<Anchor> {
    let matched: Vec<&Anchor> = anchors
        .iter()
        .filter(|a| a.country.eq_ignore_ascii_case(country))
        .collect();
    pick(matched, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(fqdn: &str, city: &str, country: &str, as_v4: u32) -> Anchor {
        Anchor {
            fqdn: fqdn.into(),
            ip_v4: "192.0.2.1".into(),
            city: city.into(),
            country: country.into(),
            as_v4,
            is_disabled: false,
            date_decommissioned: None,
        }
    }

    #[test]
    fn select_for_city_matches_a_substring_case_insensitively() {
        let anchors = vec![
            anchor("fi-hel-as1", "Helsinki", "FI", 1),
            anchor("nl-ams-as2", "Amsterdam, Netherlands", "NL", 2),
        ];
        let picked = select_for_city(&anchors, "helsinki", 3);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].fqdn, "fi-hel-as1");
    }

    #[test]
    fn select_for_city_keeps_at_most_one_anchor_per_as_and_stops_at_count() {
        let anchors = vec![
            anchor("fi-hel-as1", "Helsinki", "FI", 1),
            anchor("fi-hel-as1-second", "Helsinki", "FI", 1), // same AS, dropped
            anchor("fi-hel-as2", "Helsinki", "FI", 2),
            anchor("fi-hel-as3", "Helsinki", "FI", 3),
        ];
        let picked = select_for_city(&anchors, "helsinki", 2);
        assert_eq!(
            picked.iter().map(|a| a.as_v4).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn select_for_city_excludes_client_probes() {
        let anchors = vec![anchor("fi-hel-as1-client", "Helsinki", "FI", 1)];
        assert!(select_for_city(&anchors, "helsinki", 3).is_empty());
    }

    #[test]
    fn select_for_country_matches_the_two_letter_code_exactly() {
        let anchors = vec![
            anchor("fi-hel-as1", "Helsinki", "FI", 1),
            anchor("de-fra-as2", "Frankfurt", "DE", 2),
        ];
        let picked = select_for_country(&anchors, "fi", 3);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].country, "FI");
    }
}
