use crate::Verdict;
use crate::model::{CaptchaObservation, CountryCode, ServiceCountryVote};

pub fn judge_service_country(
    votes: &[ServiceCountryVote],
    expected: &CountryCode,
    fail_on: &[&str],
) -> Verdict {
    let critical_answered = votes
        .iter()
        .any(|vote| fail_on.contains(&vote.service) && vote.country.is_some());
    if !critical_answered {
        return Verdict::error("neither Google nor YouTube reported a country");
    }
    let russia =
        CountryCode::try_from("RU").expect("RU is a valid country code");
    let disagreements: Vec<String> = votes
        .iter()
        .filter_map(|v| v.country.map(|c| (v.service, c)))
        .filter(|(_, c)| c != expected)
        .map(|(s, c)| format!("{s}={c}"))
        .collect();
    if disagreements.is_empty() {
        return Verdict::ok(format!(
            "all responding services agree on {expected}"
        ));
    }
    let gate_hit = votes.iter().any(|v| {
        fail_on.contains(&v.service)
            && v.country.is_some_and(|c| c != *expected || c == russia)
    });
    let detail = format!("disagreement: {}", disagreements.join(", "));
    if gate_hit {
        Verdict::fail(detail)
    } else {
        Verdict::warn(detail)
    }
}

pub fn judge_search_captcha(
    first: &CaptchaObservation,
    second: &CaptchaObservation,
) -> Verdict {
    use CaptchaObservation::{Clear, Triggered, Unavailable};
    match (first, second) {
        (Triggered, Triggered) => {
            Verdict::fail("Google Search served a captcha twice, ~30s apart")
        }
        (Unavailable(reason), _) | (_, Unavailable(reason)) => Verdict::error(
            format!("Google Search captcha check unavailable: {reason}"),
        ),
        (Triggered, Clear) => Verdict::ok(
            "Google Search served a captcha once but not on retry — treated as a flap",
        ),
        (Clear, _) => Verdict::ok("Google Search served no captcha"),
    }
}

pub fn judge_cdn_edge(edges: &[(&str, Option<CountryCode>)]) -> Verdict {
    let russia =
        CountryCode::try_from("RU").expect("RU is a valid country code");
    let ru: Vec<&str> = edges
        .iter()
        .filter(|(_, c)| *c == Some(russia))
        .map(|(name, _)| *name)
        .collect();
    let named: Vec<String> = edges
        .iter()
        .filter_map(|&(name, country)| {
            country.map(|code| format!("{name}={code}"))
        })
        .collect();
    let silent: Vec<&str> = edges
        .iter()
        .filter(|(_, country)| country.is_none())
        .map(|&(name, _)| name)
        .collect();
    if named.is_empty() {
        Verdict::error("no CDN edge reported a country")
    } else if ru.is_empty() {
        Verdict::ok(format!(
            "edges: {}{}",
            named.join(", "),
            if silent.is_empty() {
                String::new()
            } else {
                format!("; no country from: {}", silent.join(", "))
            }
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

    fn vote(
        service: &'static str,
        country: Option<&str>,
    ) -> ServiceCountryVote {
        ServiceCountryVote {
            service,
            country: country.map(cc),
        }
    }

    #[test]
    fn edges_without_a_country_are_named_apart_from_the_ones_with_one() {
        let sut = vec![
            ("cloudflare", Some(cc("FI"))),
            ("youtube_ggc", None),
            ("netflix_oca", Some(cc("LV"))),
        ];

        let verdict = judge_cdn_edge(&sut);

        assert_eq!(
            verdict.detail,
            "edges: cloudflare=FI, netflix_oca=LV; \
             no country from: youtube_ggc"
        );
    }

    #[test]
    fn the_detail_stays_short_when_every_edge_named_a_country() {
        let sut = vec![
            ("cloudflare", Some(cc("FI"))),
            ("netflix_oca", Some(cc("LV"))),
        ];

        let verdict = judge_cdn_edge(&sut);

        assert_eq!(verdict.detail, "edges: cloudflare=FI, netflix_oca=LV");
    }

    #[rstest::rstest]
    #[case::everyone_agreeing(
        vec![vote("google", Some("FI")), vote("apple", Some("FI"))],
        Severity::Ok
    )]
    #[case::google_or_youtube_disagreeing(
        vec![vote("google", Some("DE")), vote("apple", Some("FI"))],
        Severity::Fail
    )]
    #[case::google_or_youtube_seeing_russia_while_everyone_else_agrees(
        vec![vote("youtube", Some("RU")), vote("apple", Some("FI"))],
        Severity::Fail
    )]
    #[case::a_non_gate_service_disagreeing_only_warns(
        vec![vote("google", Some("FI")), vote("spotify", Some("DE"))],
        Severity::Warn
    )]
    #[case::a_vote_that_did_not_answer_is_silently_skipped(
        vec![vote("google", Some("FI")), vote("apple", None)],
        Severity::Ok
    )]
    #[case::no_critical_service_answer_is_an_error(
        vec![
            vote("google", None),
            vote("youtube", None),
            vote("apple", Some("FI")),
        ],
        Severity::Error
    )]
    fn service_votes_against_the_ordered_country_set_the_severity(
        #[case] sut: Vec<ServiceCountryVote>,
        #[case] expected: Severity,
    ) {
        let verdict = judge_service_country(&sut, &cc("FI"), FAIL_SERVICES);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[rstest::rstest]
    #[case::clear_twice(
        (CaptchaObservation::Clear, CaptchaObservation::Clear),
        Severity::Ok
    )]
    #[case::gone_on_retry(
        (CaptchaObservation::Triggered, CaptchaObservation::Clear),
        Severity::Ok
    )]
    #[case::reproduced_on_retry(
        (CaptchaObservation::Triggered, CaptchaObservation::Triggered),
        Severity::Fail
    )]
    fn captcha_only_fails_after_it_reproduces_on_retry(
        #[case] sut: (CaptchaObservation, CaptchaObservation),
        #[case] expected: Severity,
    ) {
        let (first, retry) = sut;

        let verdict = judge_search_captcha(&first, &retry);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[rstest::rstest]
    #[case::an_edge_landing_in_russia(
        vec![("cloudflare", Some(cc("RU"))), ("youtube_ggc", Some(cc("FI")))],
        Severity::Fail
    )]
    #[case::edges_outside_russia_whatever_the_country(
        vec![("cloudflare", Some(cc("SE"))), ("youtube_ggc", None)],
        Severity::Ok
    )]
    #[case::no_edge_answered(
        vec![("cloudflare", None), ("youtube_ggc", None)],
        Severity::Error
    )]
    fn cdn_edges_set_the_severity(
        #[case] sut: Vec<(&'static str, Option<CountryCode>)>,
        #[case] expected: Severity,
    ) {
        let verdict = judge_cdn_edge(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }
}
