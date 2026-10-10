use http::StatusCode;
use regex::regex;

use crate::Verdict;
use crate::values::CountryCode;

mod facts;
pub use facts::{
    CaptchaObservation, CaptchaRetry, CdnEdge, CdnEdgeVote, CountryObservation,
    ServiceCountryVote, ServiceGeoSource,
};

/// Names the votes that `describe` picks out, in input order.
fn votes_where(
    votes: &[ServiceCountryVote],
    describe: impl Fn(ServiceGeoSource, &CountryObservation) -> Option<String>,
) -> Vec<String> {
    votes
        .iter()
        .filter_map(|vote| describe(vote.source, &vote.observation))
        .collect()
}

/// Judges the services' country votes against the `expected` exit country.
///
/// A Google or `YouTube` country other than `expected` fails the gate, and
/// so does one of them seeing Russia. A service that gave no answer may be
/// the one that would have failed it: an unavailable critical service leaves
/// the gate with no verdict, and an unavailable other service keeps it from
/// passing, since that service could at most have warned. A service that
/// answered without a country is skipped.
pub fn judge_service_country(
    votes: &[ServiceCountryVote],
    expected: &CountryCode,
) -> Verdict {
    let russia = CountryCode::RU;
    // `code == russia` matters only when `expected` is RU itself, and the
    // CLI never gets here in that case: a RuBridge profile skips this gate.
    // The clause stays so that a direct caller asking about an RU "exit"
    // still sees a critical RU sighting fail rather than count as agreement.
    let gate_hit = votes.iter().any(|vote| {
        vote.source.is_critical()
            && matches!(
                vote.observation,
                CountryObservation::Country(code)
                    if code != *expected || code == russia
            )
    });
    let critical_unavailable = votes.iter().any(|vote| {
        vote.source.is_critical()
            && matches!(vote.observation, CountryObservation::Unavailable(_))
    });
    let critical_answered = votes.iter().any(|vote| {
        vote.source.is_critical()
            && matches!(vote.observation, CountryObservation::Country(_))
    });
    let disagreements =
        votes_where(votes, |source, observation| match observation {
            CountryObservation::Country(code) => {
                (code != expected).then(|| format!("{source}={code}"))
            }
            CountryObservation::Silent | CountryObservation::Unavailable(_) => {
                None
            }
        });
    let unavailable =
        votes_where(votes, |source, observation| match observation {
            CountryObservation::Unavailable(cause) => {
                Some(format!("{source} ({cause})"))
            }
            CountryObservation::Country(_) | CountryObservation::Silent => None,
        });
    let unavailable_note = if unavailable.is_empty() {
        String::new()
    } else {
        format!("; service unavailable: {}", unavailable.join(", "))
    };
    let disagreement =
        format!("disagreement: {}{unavailable_note}", disagreements.join(", "));
    if gate_hit {
        return Verdict::fail(disagreement);
    }
    if critical_unavailable {
        let named =
            votes_where(votes, |source, observation| match observation {
                CountryObservation::Country(code) => {
                    Some(format!("{source}={code}"))
                }
                CountryObservation::Silent
                | CountryObservation::Unavailable(_) => None,
            });
        let seen = if named.is_empty() {
            String::new()
        } else {
            format!("; services: {}", named.join(", "))
        };
        return Verdict::error(format!(
            "service unavailable: {}{seen}",
            unavailable.join(", ")
        ));
    }
    if !critical_answered {
        return Verdict::error("neither Google nor YouTube reported a country");
    }
    if !disagreements.is_empty() {
        return Verdict::warn(disagreement);
    }
    if !unavailable.is_empty() {
        return Verdict::warn(format!(
            "service unavailable: {}; the others agree on {expected}",
            unavailable.join(", ")
        ));
    }
    Verdict::ok(format!("all responding services agree on {expected}"))
}

/// Reads one fetched Google Search page: a 429 or a block page is a captcha.
pub fn classify_search_captcha(
    status: StatusCode,
    body: &str,
) -> CaptchaObservation {
    let blocked =
        regex!(r"(?i)unusual traffic from|is blocked|unaddressed abuse");
    if status == StatusCode::TOO_MANY_REQUESTS || blocked.is_match(body) {
        CaptchaObservation::Triggered
    } else {
        CaptchaObservation::Clear
    }
}

pub fn judge_search_captcha(probe: &CaptchaRetry) -> Verdict {
    use CaptchaObservation::{Clear, Triggered, Unavailable};
    match (&probe.first, &probe.retry) {
        (Triggered, Triggered) => {
            let seconds = probe.interval.as_secs_f64();
            Verdict::fail(format!(
                "Google Search served a captcha twice, ~{seconds}s apart"
            ))
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

/// Foreign location codes a CDN edge can carry, with the ISO 3166-1
/// alpha-2 code of their country.
const FOREIGN_AIRPORTS: &[(&str, &str)] = &[
    ("HEL", "FI"),
    ("FRA", "DE"),
    ("BER", "DE"),
    ("MUC", "DE"),
    ("DUS", "DE"),
    ("HAM", "DE"),
    ("AMS", "NL"),
    ("ARN", "SE"),
    ("STO", "SE"),
    ("GOT", "SE"),
    ("LHR", "GB"),
    ("LON", "GB"),
    ("MAN", "GB"),
    ("CDG", "FR"),
    ("PAR", "FR"),
    ("MRS", "FR"),
    ("WAW", "PL"),
    ("KTW", "PL"),
    ("GDN", "PL"),
    ("RIX", "LV"),
    ("TLL", "EE"),
    ("VNO", "LT"),
    ("OSL", "NO"),
    ("CPH", "DK"),
    ("VIE", "AT"),
    ("ZRH", "CH"),
    ("GVA", "CH"),
    ("MXP", "IT"),
    ("MIL", "IT"),
    ("FCO", "IT"),
    ("ROM", "IT"),
    ("MAD", "ES"),
    ("BCN", "ES"),
    ("LIS", "PT"),
    ("PRG", "CZ"),
    ("BUD", "HU"),
    ("OTP", "RO"),
    ("BUH", "RO"),
    ("SOF", "BG"),
    ("BEG", "RS"),
    ("ZAG", "HR"),
    ("ATH", "GR"),
    ("DUB", "IE"),
    ("BRU", "BE"),
    ("IST", "TR"),
    ("ISL", "TR"),
    // Neighbours whose edges show up on Russian-facing routes; the gate
    // does not fail on them, but naming the country beats "no country".
    ("KBP", "UA"),
    ("IEV", "UA"),
    ("HRK", "UA"),
    ("ODS", "UA"),
    ("LWO", "UA"),
    ("DNK", "UA"),
    ("MSQ", "BY"),
    ("ALA", "KZ"),
    ("NQZ", "KZ"),
    ("TSE", "KZ"),
    ("TBS", "GE"),
    ("EVN", "AM"),
    ("GYD", "AZ"),
    ("BAK", "AZ"),
    ("TAS", "UZ"),
    ("KIV", "MD"),
];

/// The country of a CDN edge from the airport code in its name, as
/// Cloudflare's `colo` and Google's cache cluster names carry it. An unknown
/// code is no country rather than a guess.
///
/// # Panics
///
/// Only on a broken invariant: a country in `FOREIGN_AIRPORTS` that is not an
/// ISO 3166-1 alpha-2 code.
#[expect(
    clippy::expect_used,
    reason = "the table holds only ISO 3166-1 alpha-2 codes"
)]
pub fn airport_country(code: &str) -> Option<CountryCode> {
    /// Russian location codes a CDN edge can carry, from the `OurAirports`
    /// dataset rather than a hand-picked list of large cities.
    const RUSSIAN: &[&str] = &[
        "AAQ", "ABA", "ACS", "ADH", "AEM", "AER", "AMV", "ARH", "ASF", "BAX",
        "BCX", "BGN", "BGS", "BKA", "BQG", "BQJ", "BQS", "BTK", "BVJ", "BVV",
        "BWO", "BZK", "CEE", "CEK", "CKH", "CKL", "CSH", "CSY", "CYX", "CZR",
        "DEE", "DHG", "DKS", "DLR", "DME", "DPT", "DYR", "EDN", "EGO", "EIE",
        "EIK", "EKS", "ERG", "ESL", "ETL", "EYA", "EYK", "EZV", "GDX", "GDZ",
        "GOJ", "GOY", "GRV", "GSV", "GVN", "GYG", "HMA", "HTA", "HTG", "IAA",
        "IAR", "IGT", "IJK", "IKS", "IKT", "INA", "IRM", "ITU", "IWA", "JOK",
        "KCK", "KCY", "KDY", "KEJ", "KGD", "KGP", "KHV", "KJA", "KKQ", "KLD",
        "KLF", "KMW", "KNY", "KPW", "KRO", "KRR", "KSZ", "KUF", "KVK", "KVM",
        "KVR", "KVX", "KXD", "KXK", "KYZ", "KZN", "LDG", "LED", "LNX", "LPK",
        "MCX", "MJY", "MJZ", "MMK", "MOW", "MQF", "MQJ", "MRV", "NAL", "NBC",
        "NEI", "NER", "NFG", "NGK", "NJC", "NLI", "NNM", "NOI", "NOJ", "NOZ",
        "NSK", "NUX", "NYA", "NYM", "NYR", "NZG", "ODO", "OGZ", "OHH", "OHO",
        "OKT", "OLZ", "OMS", "ONK", "OSW", "OVB", "OVS", "PEE", "PES", "PEX",
        "PEZ", "PKC", "PKV", "PVS", "PWE", "PYJ", "REN", "RGK", "RMZ", "ROV",
        "RYB", "RZH", "SBT", "SCW", "SEK", "SES", "SGC", "SKX", "SLY", "STW",
        "SUK", "SUY", "SVO", "SVX", "SWT", "SWV", "SYS", "TBW", "TGK", "TGP",
        "THX", "TJM", "TKM", "TLK", "TLY", "TOF", "TOX", "TQL", "TYA", "TYD",
        "UCT", "UEN", "UFA", "UHS", "UIK", "UKG", "UKX", "ULK", "ULV", "ULY",
        "UMS", "URJ", "URS", "USK", "USR", "UTS", "UUA", "UUD", "UUS", "VAQ",
        "VEO", "VGD", "VHV", "VKO", "VKT", "VKV", "VLU", "VOG", "VOZ", "VRI",
        "VUS", "VVO", "VYI", "YAE", "YKS", "YMK", "ZIA", "ZIX", "ZKP", "ZZO",
    ];
    if RUSSIAN.contains(&code) {
        return Some(CountryCode::RU);
    }
    FOREIGN_AIRPORTS
        .iter()
        .find(|&&(airport, _)| airport == code)
        .map(|&(_, country)| {
            CountryCode::try_from(country)
                .expect("the table holds only ISO 3166-1 alpha-2 codes")
        })
}

/// Names the edges that `describe` picks out, in input order.
fn edges_where(
    edges: &[CdnEdgeVote],
    describe: impl Fn(CdnEdge, &CountryObservation) -> Option<String>,
) -> Vec<String> {
    edges
        .iter()
        .filter_map(|vote| describe(vote.edge, &vote.observation))
        .collect()
}

pub fn judge_cdn_edge(edges: &[CdnEdgeVote]) -> Verdict {
    let russia = CountryObservation::Country(CountryCode::RU);
    let ru = edges_where(edges, |edge, observation| {
        (*observation == russia).then(|| edge.to_string())
    });
    if !ru.is_empty() {
        return Verdict::fail(format!("CDN edge in Russia: {}", ru.join(", ")));
    }
    let named = edges_where(edges, |edge, observation| match observation {
        CountryObservation::Country(code) => Some(format!("{edge}={code}")),
        CountryObservation::Silent | CountryObservation::Unavailable(_) => None,
    });
    let unavailable =
        edges_where(edges, |edge, observation| match observation {
            CountryObservation::Unavailable(cause) => {
                Some(format!("{edge} ({cause})"))
            }
            CountryObservation::Country(_) | CountryObservation::Silent => None,
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
    let silent = edges_where(edges, |edge, observation| {
        (*observation == CountryObservation::Silent).then(|| edge.to_string())
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
    use crate::report::Severity;

    fn cc(code: &str) -> CountryCode {
        code.parse().unwrap()
    }

    fn seen(code: &str) -> CountryObservation {
        CountryObservation::Country(cc(code))
    }

    fn unreachable(cause: &str) -> CountryObservation {
        CountryObservation::Unavailable(cause.to_string())
    }

    const fn at(edge: CdnEdge, observation: CountryObservation) -> CdnEdgeVote {
        CdnEdgeVote { edge, observation }
    }

    const fn vote(
        source: ServiceGeoSource,
        observation: CountryObservation,
    ) -> ServiceCountryVote {
        ServiceCountryVote {
            source,
            observation,
        }
    }

    #[test]
    fn edges_without_a_country_are_named_apart_from_the_ones_with_one() {
        let sut = vec![
            at(CdnEdge::Cloudflare, seen("FI")),
            at(CdnEdge::YoutubeGgc, CountryObservation::Silent),
            at(CdnEdge::NetflixOca, seen("LV")),
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
            at(CdnEdge::Cloudflare, seen("FI")),
            at(CdnEdge::NetflixOca, seen("LV")),
        ];

        let verdict = judge_cdn_edge(&sut);

        assert_eq!(verdict.detail, "edges: cloudflare=FI, netflix_oca=LV");
    }

    #[test]
    fn an_unreachable_edge_is_named_with_its_cause_next_to_the_answers() {
        let sut = vec![
            at(CdnEdge::Cloudflare, seen("FI")),
            at(CdnEdge::YoutubeGgc, unreachable("connection refused")),
        ];

        let verdict = judge_cdn_edge(&sut);

        assert_eq!(
            verdict.detail,
            "CDN edge unavailable: youtube_ggc (connection refused); \
             edges: cloudflare=FI"
        );
    }

    #[test]
    fn a_disagreement_names_each_service_and_the_country_it_saw() {
        let sut = vec![
            vote(ServiceGeoSource::Google, seen("FI")),
            vote(ServiceGeoSource::Spotify, seen("DE")),
            vote(ServiceGeoSource::Tiktok, seen("NL")),
        ];

        let verdict = judge_service_country(&sut, &cc("FI"));

        assert_eq!(verdict.detail, "disagreement: spotify=DE, tiktok=NL");
    }

    #[test]
    fn an_unavailable_critical_service_is_named_with_its_cause_next_to_the_answers()
     {
        let sut = vec![
            vote(ServiceGeoSource::Google, unreachable("timed out")),
            vote(ServiceGeoSource::Youtube, seen("FI")),
            vote(ServiceGeoSource::Apple, seen("FI")),
        ];

        let verdict = judge_service_country(&sut, &cc("FI"));

        assert_eq!(
            verdict.detail,
            "service unavailable: google (timed out); \
             services: youtube=FI, apple=FI"
        );
    }

    #[test]
    fn a_failing_disagreement_also_names_the_unavailable_services() {
        let sut = vec![
            vote(ServiceGeoSource::Google, unreachable("timed out")),
            vote(ServiceGeoSource::Youtube, seen("RU")),
        ];

        let verdict = judge_service_country(&sut, &cc("FI"));

        assert_eq!(
            verdict.detail,
            "disagreement: youtube=RU; service unavailable: google (timed out)"
        );
    }

    #[test]
    fn an_unavailable_other_service_is_named_beside_the_agreed_country() {
        let sut = vec![
            vote(ServiceGeoSource::Google, seen("FI")),
            vote(ServiceGeoSource::Bing, unreachable("HTTP 503")),
        ];

        let verdict = judge_service_country(&sut, &cc("FI"));

        assert_eq!(
            verdict.detail,
            "service unavailable: bing (HTTP 503); the others agree on FI"
        );
    }

    #[rstest::rstest]
    #[case::everyone_agreeing(
        vec![
            vote(ServiceGeoSource::Google, seen("FI")),
            vote(ServiceGeoSource::Apple, seen("FI")),
        ],
        Severity::Ok
    )]
    #[case::google_or_youtube_disagreeing(
        vec![
            vote(ServiceGeoSource::Google, seen("DE")),
            vote(ServiceGeoSource::Apple, seen("FI")),
        ],
        Severity::Fail
    )]
    #[case::google_or_youtube_seeing_russia_while_everyone_else_agrees(
        vec![
            vote(ServiceGeoSource::Youtube, seen("RU")),
            vote(ServiceGeoSource::Apple, seen("FI")),
        ],
        Severity::Fail
    )]
    #[case::a_non_critical_service_disagreeing_only_warns(
        vec![
            vote(ServiceGeoSource::Google, seen("FI")),
            vote(ServiceGeoSource::Spotify, seen("DE")),
        ],
        Severity::Warn
    )]
    #[case::a_service_that_answered_without_a_country_is_skipped(
        vec![
            vote(ServiceGeoSource::Google, seen("FI")),
            vote(ServiceGeoSource::Apple, CountryObservation::Silent),
        ],
        Severity::Ok
    )]
    #[case::a_critical_service_that_answered_without_a_country_is_skipped(
        vec![
            vote(ServiceGeoSource::Google, seen("FI")),
            vote(ServiceGeoSource::Youtube, CountryObservation::Silent),
        ],
        Severity::Ok
    )]
    #[case::no_critical_service_naming_a_country_is_an_error(
        vec![
            vote(ServiceGeoSource::Google, CountryObservation::Silent),
            vote(ServiceGeoSource::Youtube, CountryObservation::Silent),
            vote(ServiceGeoSource::Apple, seen("FI")),
        ],
        Severity::Error
    )]
    // Google may be the one that sees Russia, so YouTube agreeing is not
    // enough to pass.
    #[case::an_unavailable_google_beside_an_agreeing_youtube(
        vec![
            vote(ServiceGeoSource::Google, unreachable("HTTP 403")),
            vote(ServiceGeoSource::Youtube, seen("FI")),
        ],
        Severity::Error
    )]
    #[case::youtube_seeing_russia_beside_an_unavailable_google(
        vec![
            vote(ServiceGeoSource::Google, unreachable("timed out")),
            vote(ServiceGeoSource::Youtube, seen("RU")),
        ],
        Severity::Fail
    )]
    #[case::google_disagreeing_beside_an_unavailable_youtube(
        vec![
            vote(ServiceGeoSource::Google, seen("DE")),
            vote(ServiceGeoSource::Youtube, unreachable("timed out")),
        ],
        Severity::Fail
    )]
    // The unavailable service could at most have warned.
    #[case::an_unavailable_non_critical_service_beside_agreeing_ones(
        vec![
            vote(ServiceGeoSource::Google, seen("FI")),
            vote(ServiceGeoSource::Apple, unreachable("timed out")),
        ],
        Severity::Warn
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
        CaptchaObservation::Clear,
        CaptchaObservation::Clear,
        Severity::Ok
    )]
    #[case::gone_on_retry(
        CaptchaObservation::Triggered,
        CaptchaObservation::Clear,
        Severity::Ok
    )]
    #[case::reproduced_on_retry(
        CaptchaObservation::Triggered,
        CaptchaObservation::Triggered,
        Severity::Fail
    )]
    fn captcha_only_fails_after_it_reproduces_on_retry(
        #[case] first: CaptchaObservation,
        #[case] retry: CaptchaObservation,
        #[case] expected: Severity,
    ) {
        let sut = CaptchaRetry {
            first,
            retry,
            interval: std::time::Duration::from_secs(30),
        };

        let verdict = judge_search_captcha(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[rstest::rstest]
    #[case::first_request_failed(
        CaptchaObservation::Unavailable("timed out".to_owned()),
        CaptchaObservation::Clear
    )]
    #[case::retry_failed_after_a_captcha(
        CaptchaObservation::Triggered,
        CaptchaObservation::Unavailable("timed out".to_owned())
    )]
    fn a_captcha_request_that_got_no_page_is_an_error(
        #[case] first: CaptchaObservation,
        #[case] retry: CaptchaObservation,
    ) {
        let sut = CaptchaRetry {
            first,
            retry,
            interval: std::time::Duration::from_secs(30),
        };

        let verdict = judge_search_captcha(&sut);

        assert_eq!(
            verdict,
            Verdict::error(
                "Google Search captcha check unavailable: timed out"
            )
        );
    }

    #[test]
    fn a_reproduced_captcha_names_the_pause_between_the_requests() {
        let sut = CaptchaRetry {
            first: CaptchaObservation::Triggered,
            retry: CaptchaObservation::Triggered,
            interval: std::time::Duration::from_secs(30),
        };

        let verdict = judge_search_captcha(&sut);

        assert_eq!(
            verdict.detail,
            "Google Search served a captcha twice, ~30s apart"
        );
    }

    #[rstest::rstest]
    #[case::too_many_requests(
        StatusCode::TOO_MANY_REQUESTS,
        "",
        CaptchaObservation::Triggered
    )]
    #[case::unusual_traffic_page(
        StatusCode::OK,
        "Our systems have detected unusual traffic from your computer network",
        CaptchaObservation::Triggered
    )]
    #[case::block_notice_in_any_case(
        StatusCode::FORBIDDEN,
        "Your IP address Is Blocked",
        CaptchaObservation::Triggered
    )]
    #[case::abuse_notice(
        StatusCode::OK,
        "We have received unaddressed abuse reports",
        CaptchaObservation::Triggered
    )]
    #[case::ordinary_results_page(
        StatusCode::OK,
        "<title>cats - Google Search</title>",
        CaptchaObservation::Clear
    )]
    fn a_search_page_is_a_captcha_when_rate_limited_or_showing_a_block_notice(
        #[case] status: StatusCode,
        #[case] body: &str,
        #[case] expected: CaptchaObservation,
    ) {
        let actual = classify_search_captcha(status, body);

        assert_eq!(actual, expected);
    }

    #[rstest::rstest]
    #[case::an_edge_landing_in_russia(
        vec![at(CdnEdge::Cloudflare, seen("RU")), at(CdnEdge::YoutubeGgc, seen("FI"))],
        Severity::Fail
    )]
    #[case::edges_outside_russia_whatever_the_country(
        vec![
            at(CdnEdge::Cloudflare, seen("SE")),
            at(CdnEdge::YoutubeGgc, CountryObservation::Silent),
        ],
        Severity::Ok
    )]
    #[case::no_edge_answered(
        vec![
            at(CdnEdge::Cloudflare, CountryObservation::Silent),
            at(CdnEdge::YoutubeGgc, CountryObservation::Silent),
        ],
        Severity::Error
    )]
    // The unreachable edge may be the Russian one, so the gate cannot pass.
    #[case::an_unreachable_edge_beside_foreign_ones(
        vec![
            at(CdnEdge::Cloudflare, seen("SE")),
            at(CdnEdge::YoutubeGgc, unreachable("timed out")),
        ],
        Severity::Error
    )]
    #[case::a_russian_edge_beside_an_unreachable_one(
        vec![
            at(CdnEdge::Cloudflare, seen("RU")),
            at(CdnEdge::YoutubeGgc, unreachable("timed out")),
        ],
        Severity::Fail
    )]
    fn cdn_edges_set_the_severity(
        #[case] sut: Vec<CdnEdgeVote>,
        #[case] expected: Severity,
    ) {
        let verdict = judge_cdn_edge(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[rstest::rstest]
    #[case::moscow("SVO", "RU")]
    // A Russian edge outside the handful of capital-city codes still has to
    // be recognized: the CDN-edge gate fails on RU and nothing else.
    #[case::ufa("UFA", "RU")]
    #[case::novosibirsk("OVB", "RU")]
    // Missed by the original hand-picked list; caught since the list is
    // derived from the OurAirports dataset.
    #[case::voronezh("VOZ", "RU")]
    #[case::surgut("SGC", "RU")]
    // The airport is shut for civil traffic, but an edge in the city still
    // carries its code.
    #[case::rostov("ROV", "RU")]
    // Seen for real on 2026-09-20: a Finnish address was served by the
    // Kharkiv GGC edge, and the short table read it as "no country".
    #[case::kharkiv("HRK", "UA")]
    #[case::minsk("MSQ", "BY")]
    #[case::helsinki("HEL", "FI")]
    fn an_edge_airport_code_names_its_country(
        #[case] code: &str,
        #[case] expected: &str,
    ) {
        let actual = airport_country(code);

        assert_eq!(actual, Some(cc(expected)));
    }

    #[test]
    fn every_foreign_airport_in_the_table_names_a_country() {
        let unnamed: Vec<&str> = FOREIGN_AIRPORTS
            .iter()
            .map(|&(airport, _)| airport)
            .filter(|airport| airport_country(airport).is_none())
            .collect();

        assert_eq!(unnamed, Vec::<&str>::new());
    }

    #[test]
    fn an_unknown_airport_code_is_no_country_rather_than_a_guess() {
        let actual = airport_country("ZZZ");

        assert_eq!(actual, None);
    }
}
