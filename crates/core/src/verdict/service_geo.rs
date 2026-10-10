use http::StatusCode;
use regex::regex;

use crate::Verdict;
use crate::model::{
    CaptchaObservation, CaptchaRetry, CdnEdge, CdnEdgeVote, CountryCode,
    EdgeObservation, ServiceCountryVote,
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

/// The country of a CDN edge from the airport code in its name, as
/// Cloudflare's `colo` and Google's cache cluster names carry it. An unknown
/// code is no country rather than a guess.
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
    let mapped = match code {
        "HEL" => "FI",
        "FRA" | "BER" | "MUC" | "DUS" | "HAM" => "DE",
        "AMS" => "NL",
        "ARN" | "STO" | "GOT" => "SE",
        "LHR" | "LON" | "MAN" => "GB",
        "CDG" | "PAR" | "MRS" => "FR",
        "WAW" | "KTW" | "GDN" => "PL",
        "RIX" => "LV",
        "TLL" => "EE",
        "VNO" => "LT",
        "OSL" => "NO",
        "CPH" => "DK",
        "VIE" => "AT",
        "ZRH" | "GVA" => "CH",
        "MXP" | "MIL" | "FCO" | "ROM" => "IT",
        "MAD" | "BCN" => "ES",
        "LIS" => "PT",
        "PRG" => "CZ",
        "BUD" => "HU",
        "OTP" | "BUH" => "RO",
        "SOF" => "BG",
        "BEG" => "RS",
        "ZAG" => "HR",
        "ATH" => "GR",
        "DUB" => "IE",
        "BRU" => "BE",
        "IST" | "ISL" => "TR",
        // Neighbours whose edges show up on Russian-facing routes; the gate
        // does not fail on them, but naming the country beats "no country".
        "KBP" | "IEV" | "HRK" | "ODS" | "LWO" | "DNK" => "UA",
        "MSQ" => "BY",
        "ALA" | "NQZ" | "TSE" => "KZ",
        "TBS" => "GE",
        "EVN" => "AM",
        "GYD" | "BAK" => "AZ",
        "TAS" => "UZ",
        "KIV" => "MD",
        _ => return None,
    };
    CountryCode::try_from(mapped).ok()
}

/// Names the edges that `describe` picks out, in input order.
fn edges_where(
    edges: &[CdnEdgeVote],
    describe: impl Fn(CdnEdge, &EdgeObservation) -> Option<String>,
) -> Vec<String> {
    edges
        .iter()
        .filter_map(|vote| describe(vote.edge, &vote.observation))
        .collect()
}

pub fn judge_cdn_edge(edges: &[CdnEdgeVote]) -> Verdict {
    let russia = EdgeObservation::Country(CountryCode::RU);
    let ru = edges_where(edges, |edge, observation| {
        (*observation == russia).then(|| edge.to_string())
    });
    if !ru.is_empty() {
        return Verdict::fail(format!("CDN edge in Russia: {}", ru.join(", ")));
    }
    let named = edges_where(edges, |edge, observation| match observation {
        EdgeObservation::Country(code) => Some(format!("{edge}={code}")),
        EdgeObservation::Silent | EdgeObservation::Unavailable(_) => None,
    });
    let unavailable =
        edges_where(edges, |edge, observation| match observation {
            EdgeObservation::Unavailable(cause) => {
                Some(format!("{edge} ({cause})"))
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
    let silent = edges_where(edges, |edge, observation| {
        (*observation == EdgeObservation::Silent).then(|| edge.to_string())
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

    const fn at(edge: CdnEdge, observation: EdgeObservation) -> CdnEdgeVote {
        CdnEdgeVote { edge, observation }
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
            at(CdnEdge::Cloudflare, edge("FI")),
            at(CdnEdge::YoutubeGgc, EdgeObservation::Silent),
            at(CdnEdge::NetflixOca, edge("LV")),
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
            at(CdnEdge::Cloudflare, edge("FI")),
            at(CdnEdge::NetflixOca, edge("LV")),
        ];

        let verdict = judge_cdn_edge(&sut);

        assert_eq!(verdict.detail, "edges: cloudflare=FI, netflix_oca=LV");
    }

    #[test]
    fn an_unreachable_edge_is_named_with_its_cause_next_to_the_answers() {
        let sut = vec![
            at(CdnEdge::Cloudflare, edge("FI")),
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
            vote(ServiceGeoSource::Google, Some("FI")),
            vote(ServiceGeoSource::Spotify, Some("DE")),
            vote(ServiceGeoSource::Tiktok, Some("NL")),
        ];

        let verdict = judge_service_country(&sut, &cc("FI"));

        assert_eq!(verdict.detail, "disagreement: spotify=DE, tiktok=NL");
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
        let sut = CaptchaRetry { first, retry };

        let verdict = judge_search_captcha(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
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
        let sut = classify_search_captcha(status, body);

        assert_eq!(sut, expected);
    }

    #[rstest::rstest]
    #[case::an_edge_landing_in_russia(
        vec![at(CdnEdge::Cloudflare, edge("RU")), at(CdnEdge::YoutubeGgc, edge("FI"))],
        Severity::Fail
    )]
    #[case::edges_outside_russia_whatever_the_country(
        vec![
            at(CdnEdge::Cloudflare, edge("SE")),
            at(CdnEdge::YoutubeGgc, EdgeObservation::Silent),
        ],
        Severity::Ok
    )]
    #[case::no_edge_answered(
        vec![
            at(CdnEdge::Cloudflare, EdgeObservation::Silent),
            at(CdnEdge::YoutubeGgc, EdgeObservation::Silent),
        ],
        Severity::Error
    )]
    // The unreachable edge may be the Russian one, so the gate cannot pass.
    #[case::an_unreachable_edge_beside_foreign_ones(
        vec![
            at(CdnEdge::Cloudflare, edge("SE")),
            at(CdnEdge::YoutubeGgc, unreachable("timed out")),
        ],
        Severity::Error
    )]
    #[case::a_russian_edge_beside_an_unreachable_one(
        vec![
            at(CdnEdge::Cloudflare, edge("RU")),
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
        let sut = airport_country(code);

        assert_eq!(sut, Some(cc(expected)));
    }

    #[test]
    fn an_unknown_airport_code_is_no_country_rather_than_a_guess() {
        let sut = airport_country("ZZZ");

        assert_eq!(sut, None);
    }
}
