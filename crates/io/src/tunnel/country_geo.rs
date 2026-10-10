use std::time::Duration;

use chip_core::model::{
    CaptchaObservation, CountryCode, EdgeObservation, ServiceCountryVote,
    ServiceGeoSource,
};
use http::StatusCode;
use http::header::{ACCEPT_LANGUAGE, USER_AGENT};
use regex::regex;

use super::client::{TunnelClient, TunnelError, TunnelResponse};
use super::services::{ACCEPT_LANGUAGE_EN, BROWSER_HEADERS, BROWSER_UA};
use crate::error_chain::describe_error;

const FAST_API_URL: &str = "https://api.fast.com/netflix/speedtest/v2?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=1";

/// Russian location codes a CDN edge can carry.
const RU_IATA_CODES: &[&str] = &[
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

fn country(raw: &str) -> Option<CountryCode> {
    CountryCode::try_from(raw.trim()).ok()
}

fn json_string(body: &str, pointer: &str) -> Option<String> {
    let owned = serde_json::from_str::<serde_json::Value>(body).ok()?;
    owned.pointer(pointer)?.as_str().map(ToString::to_string)
}

fn google_country(body: &str) -> Option<CountryCode> {
    regex!(r#""[a-z]{2}_([A-Z]{2})""#)
        .captures(body)
        .and_then(|captures| captures.get(1))
        .and_then(|matched| country(matched.as_str()))
        .or_else(|| {
            regex!(r#""[a-z]{2}-([A-Z]{2})""#)
                .captures_iter(body)
                .last()
                .and_then(|captures| captures.get(1))
                .and_then(|matched| country(matched.as_str()))
        })
}

fn youtube_country(body: &str) -> Option<CountryCode> {
    regex!(r#""countryCode":"(\w+)""#)
        .captures(body)?
        .get(1)
        .and_then(|matched| country(matched.as_str()))
}

fn spotify_country(body: &str) -> Option<CountryCode> {
    regex!(r#""geoLocationCountryCode":"([^"]*)""#)
        .captures(body)?
        .get(1)
        .and_then(|matched| country(matched.as_str()))
}

fn bing_country(body: &str) -> Option<CountryCode> {
    if body.contains("cn.bing.com") {
        return country("CN");
    }
    let value = regex!(r#"Region\s*:\s*"([^"]+)""#)
        .captures(body)?
        .get(1)?
        .as_str();
    (value != "WW").then(|| country(value)).flatten()
}

/// A service that cannot be reached casts no country vote; the cause goes to
/// the log, since the vote has no place for it.
async fn response(client: &TunnelClient, url: &str) -> Option<TunnelResponse> {
    client
        .get(url, &BROWSER_HEADERS)
        .await
        .inspect_err(|error| {
            tracing::debug!(
                url,
                error = %describe_error(error),
                "country vote source unreachable"
            );
        })
        .ok()
}

struct CountryResponses {
    google: Option<TunnelResponse>,
    youtube: Option<TunnelResponse>,
    apple: Option<TunnelResponse>,
    spotify: Option<TunnelResponse>,
    /// Kept with its error: the CDN-edge gate reads the same response and
    /// must tell an unreachable edge from a silent one.
    netflix: Result<TunnelResponse, TunnelError>,
    tiktok: Option<TunnelResponse>,
    bing: Option<TunnelResponse>,
}

impl CountryResponses {
    async fn fetch(client: &TunnelClient) -> Self {
        let (google, youtube, apple, spotify, netflix, tiktok, bing) = tokio::join!(
            response(client, "https://www.google.com"),
            response(client, "https://www.youtube.com"),
            response(client, "https://gspe1-ssl.ls.apple.com/pep/gcc"),
            response(client, "https://accounts.spotify.com/status"),
            client.get(FAST_API_URL, &BROWSER_HEADERS),
            response(
                client,
                "https://www.tiktok.com/api/v1/web-cookie-privacy/config?appId=1988"
            ),
            response(client, "https://www.bing.com/search?q=cats")
        );
        Self {
            google,
            youtube,
            apple,
            spotify,
            netflix,
            tiktok,
            bing,
        }
    }

    fn votes(&self) -> Vec<ServiceCountryVote> {
        let google = self
            .google
            .as_ref()
            .and_then(|item| google_country(&item.body));
        let youtube = self
            .youtube
            .as_ref()
            .and_then(|item| youtube_country(&item.body))
            .or(google);
        vec![
            vote(ServiceGeoSource::Google, google),
            vote(ServiceGeoSource::Youtube, youtube),
            vote(
                ServiceGeoSource::Apple,
                self.apple.as_ref().and_then(|item| country(&item.body)),
            ),
            vote(
                ServiceGeoSource::Spotify,
                self.spotify
                    .as_ref()
                    .and_then(|item| spotify_country(&item.body)),
            ),
            vote(
                ServiceGeoSource::Netflix,
                json_country(
                    self.netflix.as_ref().ok(),
                    "/client/location/country",
                ),
            ),
            vote(
                ServiceGeoSource::Tiktok,
                json_country(self.tiktok.as_ref(), "/body/appProps/region"),
            ),
            vote(
                ServiceGeoSource::Bing,
                self.bing.as_ref().and_then(|item| bing_country(&item.body)),
            ),
        ]
    }
}

const fn vote(
    source: ServiceGeoSource,
    country: Option<CountryCode>,
) -> ServiceCountryVote {
    ServiceCountryVote { source, country }
}

fn json_country(
    response: Option<&TunnelResponse>,
    pointer: &str,
) -> Option<CountryCode> {
    response
        .and_then(|item| json_string(&item.body, pointer))
        .and_then(|value| country(&value))
}

/// Service country votes and CDN edges, read from one set of requests.
#[derive(Debug)]
pub struct ServiceGeoObservations {
    pub votes: Vec<ServiceCountryVote>,
    pub edges: Vec<(&'static str, EdgeObservation)>,
}

/// Probes the services' country votes and the CDN edges together. The
/// fast.com API answers both questions, so it is fetched once.
pub async fn probe_service_geo(
    client: &TunnelClient,
) -> ServiceGeoObservations {
    let (countries, cloudflare, youtube) = tokio::join!(
        CountryResponses::fetch(client),
        client
            .get("https://www.cloudflare.com/cdn-cgi/trace", &BROWSER_HEADERS),
        client.get(
            "https://redirector.googlevideo.com/report_mapping?di=no",
            &BROWSER_HEADERS
        ),
    );
    let edges = vec![
        ("cloudflare", edge_observation(&cloudflare, cloudflare_country)),
        ("youtube_ggc", edge_observation(&youtube, ggc_country)),
        (
            "netflix_oca",
            edge_observation(&countries.netflix, netflix_oca_country),
        ),
    ];
    ServiceGeoObservations {
        votes: countries.votes(),
        edges,
    }
}

async fn captcha_observation(
    client: &TunnelClient,
    url: &str,
) -> CaptchaObservation {
    match client
        .get(
            url,
            &[
                (USER_AGENT, BROWSER_UA),
                (ACCEPT_LANGUAGE, ACCEPT_LANGUAGE_EN),
            ],
        )
        .await
    {
        Err(error) => CaptchaObservation::Unavailable(describe_error(&error)),
        Ok(response)
            if response.status == StatusCode::TOO_MANY_REQUESTS
                || regex!(
                    r"(?i)unusual traffic from|is blocked|unaddressed abuse"
                )
                .is_match(&response.body) =>
        {
            CaptchaObservation::Triggered
        }
        Ok(_) => CaptchaObservation::Clear,
    }
}

pub async fn probe_search_captcha(
    client: &TunnelClient,
) -> (CaptchaObservation, CaptchaObservation) {
    let url = "https://www.google.com/search?q=cats";
    let first = captcha_observation(client, url).await;
    tokio::time::sleep(Duration::from_secs(30)).await;
    let second = captcha_observation(client, url).await;
    (first, second)
}

fn value_from_lines(body: &str, key: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate == key).then(|| value.trim().to_string())
    })
}

fn ggc_iata(body: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let cluster = line.split_whitespace().nth(2)?;
        let cluster = cluster
            .rsplit_once('-')
            .map_or(cluster, |(_, suffix)| suffix);
        let code = cluster.get(..3)?.to_ascii_uppercase();
        (code.bytes().all(|byte| byte.is_ascii_uppercase())).then_some(code)
    })
}

fn iata_country(code: &str) -> Option<CountryCode> {
    if RU_IATA_CODES.contains(&code) {
        return country("RU");
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
    country(mapped)
}

fn edge_observation(
    response: &Result<TunnelResponse, TunnelError>,
    locate: fn(&str) -> Option<CountryCode>,
) -> EdgeObservation {
    match response {
        Ok(response) => locate(&response.body)
            .map_or(EdgeObservation::Silent, EdgeObservation::Country),
        Err(error) => EdgeObservation::Unavailable(describe_error(error)),
    }
}

fn cloudflare_country(body: &str) -> Option<CountryCode> {
    value_from_lines(body, "colo").and_then(|code| iata_country(&code))
}

fn ggc_country(body: &str) -> Option<CountryCode> {
    ggc_iata(body).and_then(|code| iata_country(&code))
}

fn netflix_oca_country(body: &str) -> Option<CountryCode> {
    json_string(body, "/targets/0/location/country")
        .and_then(|value| country(&value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsers_read_the_upstream_wire_shapes() {
        assert_eq!(google_country(r#"x "en_FI" y"#).unwrap().as_str(), "FI");
        assert_eq!(
            youtube_country(r#"{"countryCode":"DE"}"#).unwrap().as_str(),
            "DE"
        );
        assert_eq!(
            spotify_country(r#"{"geoLocationCountryCode":"NL"}"#)
                .unwrap()
                .as_str(),
            "NL"
        );
        assert_eq!(
            ggc_iata("192.0.2.0/24 => fra16s52").as_deref(),
            Some("FRA")
        );
    }

    #[rstest::rstest]
    #[case::moscow("SVO", "RU")]
    // A Russian edge outside the handful of capital-city codes still has to
    // be recognized — the CDN-edge gate fails on RU and nothing else.
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
        #[case] sut: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(iata_country(sut).unwrap().as_str(), expected);
    }

    #[test]
    fn an_unknown_airport_code_is_no_country_rather_than_a_guess() {
        assert!(iata_country("ZZZ").is_none());
    }

    #[tokio::test]
    async fn an_edge_that_cannot_be_reached_is_unavailable_with_its_cause() {
        // Port 1 on loopback has no listener, so the request is refused
        // without leaving the machine.
        let client = TunnelClient::from_client(reqwest::Client::new());
        let response = client.get("http://127.0.0.1:1/", &[]).await;

        let sut = edge_observation(&response, cloudflare_country);

        let EdgeObservation::Unavailable(cause) = sut else {
            panic!("expected an unavailable edge, got {sut:?}");
        };
        assert!(
            cause.starts_with("GET http://127.0.0.1:1/ failed: "),
            "{cause}"
        );
    }

    #[test]
    fn an_edge_that_answered_without_a_location_is_silent() {
        let response = Ok(TunnelResponse {
            status: StatusCode::OK,
            final_url: "https://www.cloudflare.com/cdn-cgi/trace"
                .parse()
                .unwrap(),
            body: "fl=1\nh=www.cloudflare.com\n".to_string(),
        });

        let sut = edge_observation(&response, cloudflare_country);

        assert_eq!(sut, EdgeObservation::Silent);
    }
}
