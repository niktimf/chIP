use crate::Verdict;
use crate::model::{
    CaptchaObservation, CountryCode, EdgeObservation, ServiceCountryVote,
};

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
    let russia = CountryCode::RU;
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

/// Names the edges that `describe` picks out, in input order.
fn edges_where(
    edges: &[(&str, EdgeObservation)],
    describe: impl Fn(&str, &EdgeObservation) -> Option<String>,
) -> Vec<String> {
    edges
        .iter()
        .filter_map(|(name, observation)| describe(name, observation))
        .collect()
}

pub fn judge_cdn_edge(edges: &[(&str, EdgeObservation)]) -> Verdict {
    let russia = EdgeObservation::Country(CountryCode::RU);
    let ru = edges_where(edges, |name, observation| {
        (*observation == russia).then(|| name.to_string())
    });
    if !ru.is_empty() {
        return Verdict::fail(format!("CDN edge in Russia: {}", ru.join(", ")));
    }
    let named = edges_where(edges, |name, observation| match observation {
        EdgeObservation::Country(code) => Some(format!("{name}={code}")),
        EdgeObservation::Silent | EdgeObservation::Unavailable(_) => None,
    });
    let unavailable =
        edges_where(edges, |name, observation| match observation {
            EdgeObservation::Unavailable(cause) => {
                Some(format!("{name} ({cause})"))
            }
            EdgeObservation::Country(_) | EdgeObservation::Silent => None,
        });
    // An unreachable edge may be the one sitting in Russia, so the gate has
    // no verdict, as with an unreachable service in `services`.
    if !unavailable.is_empty() {
        let seen = if named.is_empty() {
            String::new()
        } else {
            format!("; edges: {}", named.join(", "))
        };
        return Verdict::error(format!(
            "CDN edge unavailable: {}{seen}",
            unavailable.join(", ")
        ));
    }
    if named.is_empty() {
        return Verdict::error("no CDN edge reported a country");
    }
    let silent = edges_where(edges, |name, observation| {
        (*observation == EdgeObservation::Silent).then(|| name.to_string())
    });
    let silent = if silent.is_empty() {
        String::new()
    } else {
        format!("; no country from: {}", silent.join(", "))
    };
    Verdict::ok(format!("edges: {}{silent}", named.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ServiceGeoSource, Severity};

    fn cc(code: &str) -> CountryCode {
        code.parse().unwrap()
    }

    fn edge(code: &str) -> EdgeObservation {
        EdgeObservation::Country(cc(code))
    }

    fn unreachable(cause: &str) -> EdgeObservation {
        EdgeObservation::Unavailable(cause.to_string())
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
            ("cloudflare", edge("FI")),
            ("youtube_ggc", EdgeObservation::Silent),
            ("netflix_oca", edge("LV")),
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
        let sut = vec![("cloudflare", edge("FI")), ("netflix_oca", edge("LV"))];

        let verdict = judge_cdn_edge(&sut);

        assert_eq!(verdict.detail, "edges: cloudflare=FI, netflix_oca=LV");
    }

    #[test]
    fn an_unreachable_edge_is_named_with_its_cause_next_to_the_answers() {
        let sut = vec![
            ("cloudflare", edge("FI")),
            ("youtube_ggc", unreachable("connection refused")),
        ];

        let verdict = judge_cdn_edge(&sut);

        assert_eq!(
            verdict.detail,
            "CDN edge unavailable: youtube_ggc (connection refused); \
             edges: cloudflare=FI"
        );
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
        vec![("cloudflare", edge("RU")), ("youtube_ggc", edge("FI"))],
        Severity::Fail
    )]
    #[case::edges_outside_russia_whatever_the_country(
        vec![
            ("cloudflare", edge("SE")),
            ("youtube_ggc", EdgeObservation::Silent),
        ],
        Severity::Ok
    )]
    #[case::no_edge_answered(
        vec![
            ("cloudflare", EdgeObservation::Silent),
            ("youtube_ggc", EdgeObservation::Silent),
        ],
        Severity::Error
    )]
    // The unreachable edge may be the Russian one, so the gate cannot pass.
    #[case::an_unreachable_edge_beside_foreign_ones(
        vec![
            ("cloudflare", edge("SE")),
            ("youtube_ggc", unreachable("timed out")),
        ],
        Severity::Error
    )]
    #[case::a_russian_edge_beside_an_unreachable_one(
        vec![
            ("cloudflare", edge("RU")),
            ("youtube_ggc", unreachable("timed out")),
        ],
        Severity::Fail
    )]
    fn cdn_edges_set_the_severity(
        #[case] sut: Vec<(&'static str, EdgeObservation)>,
        #[case] expected: Severity,
    ) {
        let verdict = judge_cdn_edge(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }
}
