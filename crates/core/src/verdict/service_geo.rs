use crate::model::{CountryCode, ServiceCountryVote};
use crate::Verdict;

pub fn judge_service_country(votes: &[ServiceCountryVote], expected: &CountryCode, fail_on: &[&str]) -> Verdict {
    let russia = CountryCode::try_from("RU").expect("RU is a valid country code");
    let disagreements: Vec<String> = votes
        .iter()
        .filter_map(|v| v.country.map(|c| (v.service, c)))
        .filter(|(_, c)| c != expected)
        .map(|(s, c)| format!("{s}={c}"))
        .collect();
    if disagreements.is_empty() {
        return Verdict::ok(format!("all responding services agree on {expected}"));
    }
    let gate_hit = votes.iter().any(|v| {
        fail_on.contains(&v.service) && v.country.is_some_and(|c| c != *expected || c == russia)
    });
    let detail = format!("disagreement: {}", disagreements.join(", "));
    if gate_hit { Verdict::fail(detail) } else { Verdict::warn(detail) }
}

pub fn judge_search_captcha(first_triggered: bool, second_triggered_after_delay: bool) -> Verdict {
    if first_triggered && second_triggered_after_delay {
        Verdict::fail("Google Search served a captcha twice, ~30s apart")
    } else if first_triggered {
        Verdict::ok("Google Search served a captcha once but not on retry — treated as a flap")
    } else {
        Verdict::ok("Google Search served no captcha")
    }
}

pub fn judge_cdn_edge(edges: &[(&str, Option<CountryCode>)]) -> Verdict {
    let russia = CountryCode::try_from("RU").expect("RU is a valid country code");
    let ru: Vec<&str> = edges.iter().filter(|(_, c)| *c == Some(russia)).map(|(name, _)| *name).collect();
    if ru.is_empty() {
        Verdict::ok(format!(
            "edges: {}",
            edges
                .iter()
                .map(|&(n, c)| format!("{n}={}", c.map_or_else(|| "?".to_string(), |code| code.to_string())))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    } else {
        Verdict::fail(format!("CDN edge in Russia: {}", ru.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    const FAIL_SERVICES: &[&str] = &["google", "youtube"];

    fn cc(code: &str) -> CountryCode {
        code.parse().unwrap()
    }

    fn vote(service: &'static str, country: Option<&str>) -> ServiceCountryVote {
        ServiceCountryVote { service, country: country.map(cc) }
    }

    #[test]
    fn everyone_agreeing_is_ok() {
        let sut = vec![vote("google", Some("FI")), vote("apple", Some("FI"))];

        assert_eq!(judge_service_country(&sut, &cc("FI"), FAIL_SERVICES).severity, Severity::Ok);
    }

    #[test]
    fn google_or_youtube_disagreeing_fails() {
        let sut = vec![vote("google", Some("DE")), vote("apple", Some("FI"))];

        assert_eq!(judge_service_country(&sut, &cc("FI"), FAIL_SERVICES).severity, Severity::Fail);
    }

    #[test]
    fn google_or_youtube_seeing_russia_fails_even_when_everyone_else_agrees() {
        let sut = vec![vote("youtube", Some("RU")), vote("apple", Some("FI"))];

        assert_eq!(judge_service_country(&sut, &cc("FI"), FAIL_SERVICES).severity, Severity::Fail);
    }

    #[test]
    fn a_non_gate_service_disagreeing_only_warns() {
        let sut = vec![vote("google", Some("FI")), vote("spotify", Some("DE"))];

        assert_eq!(judge_service_country(&sut, &cc("FI"), FAIL_SERVICES).severity, Severity::Warn);
    }

    #[test]
    fn a_vote_that_did_not_answer_is_silently_skipped() {
        let sut = vec![vote("google", Some("FI")), vote("apple", None)];

        assert_eq!(judge_service_country(&sut, &cc("FI"), FAIL_SERVICES).severity, Severity::Ok);
    }

    #[test]
    fn captcha_only_fails_after_it_reproduces_on_retry() {
        assert_eq!(judge_search_captcha(true, false).severity, Severity::Ok);
        assert_eq!(judge_search_captcha(true, true).severity, Severity::Fail);
        assert_eq!(judge_search_captcha(false, false).severity, Severity::Ok);
    }

    #[test]
    fn a_cdn_edge_landing_in_russia_fails() {
        let sut = vec![("cloudflare", Some(cc("RU"))), ("youtube_ggc", Some(cc("FI")))];

        assert_eq!(judge_cdn_edge(&sut).severity, Severity::Fail);
    }

    #[test]
    fn cdn_edges_outside_russia_are_ok_regardless_of_which_country() {
        let sut = vec![("cloudflare", Some(cc("SE"))), ("youtube_ggc", None)];

        assert_eq!(judge_cdn_edge(&sut).severity, Severity::Ok);
    }
}
