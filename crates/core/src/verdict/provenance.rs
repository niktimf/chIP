use crate::Verdict;
use crate::model::RoutingFacts;

const MIN_VISIBILITY_RATIO: f64 = 0.9;

pub fn judge_routing(facts: &RoutingFacts) -> Verdict {
    if facts.total_ris_peers == 0 {
        return Verdict::error("RIPEstat returned no RIS peer data for this prefix");
    }
    let ratio = f64::from(facts.ris_peers_seeing) / f64::from(facts.total_ris_peers);
    let detail = format!(
        "seen by {}/{} RIS peers, {} origin AS{}",
        facts.ris_peers_seeing,
        facts.total_ris_peers,
        facts.origin_count,
        if facts.origin_count == 1 { "" } else { "es" }
    );
    if ratio < MIN_VISIBILITY_RATIO || facts.origin_count > 1 {
        Verdict::warn(detail)
    } else {
        Verdict::ok(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    #[test]
    fn fully_visible_single_origin_is_ok() {
        // Real FI-1 numbers, 2026-09-14: 325/325 peers, one origin (AS57043).
        let f = RoutingFacts {
            ris_peers_seeing: 325,
            total_ris_peers: 325,
            origin_count: 1,
        };
        assert_eq!(judge_routing(&f).severity, Severity::Ok);
    }

    #[test]
    fn below_ninety_percent_visibility_warns() {
        let f = RoutingFacts {
            ris_peers_seeing: 250,
            total_ris_peers: 325,
            origin_count: 1,
        };
        assert_eq!(judge_routing(&f).severity, Severity::Warn);
    }

    #[test]
    fn more_than_one_origin_as_warns() {
        let f = RoutingFacts {
            ris_peers_seeing: 325,
            total_ris_peers: 325,
            origin_count: 2,
        };
        assert_eq!(judge_routing(&f).severity, Severity::Warn);
    }

    #[test]
    fn zero_total_peers_is_an_error_not_a_verdict() {
        let f = RoutingFacts {
            ris_peers_seeing: 0,
            total_ris_peers: 0,
            origin_count: 0,
        };
        assert_eq!(judge_routing(&f).severity, Severity::Error);
    }
}
