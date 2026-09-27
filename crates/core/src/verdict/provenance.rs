use crate::Verdict;
use crate::model::{Routing, RoutingFacts};
use ipnet::Ipv4Net;

const MIN_VISIBILITY_RATIO: f64 = 0.9;

pub fn judge_routing(routing: &Routing) -> Verdict {
    match routing {
        Routing::NotAnnounced { total_ris_peers } => Verdict::warn(format!(
            "no BGP announcement covers the address; \
             seen by 0/{total_ris_peers} RIS peers"
        )),
        Routing::Announced { prefix, facts } => {
            judge_visibility(*prefix, facts)
        }
    }
}

fn judge_visibility(prefix: Ipv4Net, facts: &RoutingFacts) -> Verdict {
    let ris_peers_seeing = f64::from(facts.ris_peers_seeing());
    let total_ris_peers = f64::from(facts.total_ris_peers().get());
    let ratio = ris_peers_seeing / total_ris_peers;
    let detail = format!(
        "{prefix} seen by {}/{} RIS peers, {} origin AS{}",
        facts.ris_peers_seeing(),
        facts.total_ris_peers(),
        facts.origin_count(),
        if facts.origin_count() == 1 { "" } else { "es" }
    );
    if ratio < MIN_VISIBILITY_RATIO || facts.origin_count() > 1 {
        Verdict::warn(detail)
    } else {
        Verdict::ok(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use std::num::NonZeroU32;

    fn peers(total: u32) -> NonZeroU32 {
        NonZeroU32::new(total).unwrap()
    }

    /// Yandex Cloud announces this `/16` as one block from AS200350; its
    /// `/24`s are not announced on their own (`RIPEstat`, 2026-09-27).
    fn announced(seeing: u32, total: u32, origins: u32) -> Routing {
        Routing::Announced {
            prefix: "158.160.0.0/16".parse().unwrap(),
            facts: RoutingFacts::new(seeing, peers(total), origins).unwrap(),
        }
    }

    #[test]
    fn the_detail_names_the_announced_prefix() {
        let sut = announced(325, 325, 1);

        let verdict = judge_routing(&sut);

        assert!(
            verdict.detail.starts_with("158.160.0.0/16 "),
            "{}",
            verdict.detail
        );
    }

    #[test]
    fn an_address_no_announcement_covers_warns() {
        let sut = Routing::NotAnnounced {
            total_ris_peers: peers(325),
        };

        let verdict = judge_routing(&sut);

        assert_eq!(verdict.severity, Severity::Warn);
        assert!(
            verdict.detail.contains("no BGP announcement"),
            "{}",
            verdict.detail
        );
    }

    #[rstest::rstest]
    // Real FI-1 peer counts, 2026-09-14: 325/325, one origin (AS57043).
    #[case::fully_visible_single_origin(announced(325, 325, 1), Severity::Ok)]
    #[case::below_ninety_percent_visibility(
        announced(250, 325, 1),
        Severity::Warn
    )]
    #[case::more_than_one_origin_as(announced(325, 325, 2), Severity::Warn)]
    fn visibility_and_origins_set_the_severity(
        #[case] sut: Routing,
        #[case] expected: Severity,
    ) {
        let verdict = judge_routing(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[test]
    fn visibility_cannot_exceed_the_total_peer_count() {
        let error = RoutingFacts::new(326, peers(325), 1).unwrap_err();

        assert_eq!(
            error.to_string(),
            "RIS peers seeing the prefix (326) exceeds total peers (325)"
        );
    }
}
