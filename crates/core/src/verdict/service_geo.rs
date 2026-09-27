use crate::Verdict;
use crate::model::{CaptchaObservation, CountryCode, ServiceCountryVote};

pub fn judge_service_country(
    votes: &[ServiceCountryVote],
    expected: &CountryCode,
) -> Verdict {
    let critical_answered = votes
        .iter()
        .any(|vote| vote.source.is_critical() && vote.country.is_some());
    if !critical_answered {
        return Verdict::error("neither Google nor YouTube reported a country");
    }
    let russia =
        CountryCode::try_from("RU").expect("RU is a valid country code");
    let disagreements: Vec<String> = votes
        .iter()
        .filter_map(|v| v.country.map(|c| (v.source, c)))
        .filter(|(_, c)| c != expected)
        .map(|(s, c)| format!("{s}={c}"))
        .collect();
    if disagreements.is_empty() {
        return Verdict::ok(format!(
            "all responding services agree on {expected}"
        ));
    }
    // `c == russia` matters only when `expected` is RU itself, and the CLI
    // never gets here in that case: a RuBridge profile skips this gate. The
    // clause stays so that a direct caller asking about an RU "exit" still
    // sees a critical RU sighting fail rather than count as agreement.
    let gate_hit = votes.iter().any(|v| {
        v.source.is_critical()
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
    use crate::model::{ServiceGeoSource, Severity};

    fn cc(code: &str) -> CountryCode {
        code.parse().unwrap()
    }

    fn vote(
        source: ServiceGeoSource,
        country: Option<&str>,
    ) -> ServiceCountryVote {
        ServiceCountryVote {
            source,
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
        vec![
            vote(ServiceGeoSource::Google, Some("FI")),
            vote(ServiceGeoSource::Apple, Some("FI")),
        ],
        Severity::Ok
    )]
    #[case::google_or_youtube_disagreeing(
        vec![
            vote(ServiceGeoSource::Google, Some("DE")),
            vote(ServiceGeoSource::Apple, Some("FI")),
        ],
        Severity::Fail
    )]
    #[case::google_or_youtube_seeing_russia_while_everyone_else_agrees(
        vec![
            vote(ServiceGeoSource::Youtube, Some("RU")),
            vote(ServiceGeoSource::Apple, Some("FI")),
        ],
        Severity::Fail
    )]
    #[case::a_non_critical_service_disagreeing_only_warns(
        vec![
            vote(ServiceGeoSource::Google, Some("FI")),
            vote(ServiceGeoSource::Spotify, Some("DE")),
        ],
        Severity::Warn
    )]
    #[case::a_vote_that_did_not_answer_is_silently_skipped(
        vec![
            vote(ServiceGeoSource::Google, Some("FI")),
            vote(ServiceGeoSource::Apple, None),
        ],
        Severity::Ok
    )]
    #[case::no_critical_service_answer_is_an_error(
        vec![
            vote(ServiceGeoSource::Google, None),
            vote(ServiceGeoSource::Youtube, None),
            vote(ServiceGeoSource::Apple, Some("FI")),
        ],
        Severity::Error
    )]
    fn service_votes_against_the_ordered_country_set_the_severity(
        #[case] sut: Vec<ServiceCountryVote>,
        #[case] expected: Severity,
    ) {
        let verdict = judge_service_country(&sut, &cc("FI"));

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
