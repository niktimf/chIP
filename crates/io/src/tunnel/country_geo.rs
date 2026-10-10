use std::time::Duration;

use chip_core::model::{
    CaptchaObservation, CaptchaRetry, CdnEdge, CdnEdgeVote, CountryCode,
    EdgeObservation, ServiceCountryVote, ServiceGeoSource,
};
use chip_core::verdict::service_geo::{
    airport_country, classify_search_captcha,
};
use regex::regex;
use serde::Deserialize;

use super::client::{TunnelClient, TunnelError, TunnelResponse};
use super::{BROWSER_EN_HEADERS, BROWSER_HEADERS};
use crate::error_chain::describe_error;

const FAST_API_URL: &str = "https://api.fast.com/netflix/speedtest/v2?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=1";

fn country(raw: &str) -> Option<CountryCode> {
    CountryCode::try_from(raw.trim()).ok()
}

/// The part of the fast.com API answer the probes read: the country fast.com
/// places the client in, and the Netflix OCA edges it hands out.
#[derive(Deserialize)]
struct FastResponse {
    client: Option<FastPeer>,
    targets: Option<Vec<FastPeer>>,
}

#[derive(Deserialize)]
struct FastPeer {
    location: FastLocation,
}

#[derive(Deserialize)]
struct FastLocation {
    country: String,
}

impl FastResponse {
    fn parse(body: &str) -> Option<Self> {
        serde_json::from_str(body).ok()
    }

    fn client_country(&self) -> Option<CountryCode> {
        country(&self.client.as_ref()?.location.country)
    }

    fn first_target_country(&self) -> Option<CountryCode> {
        country(&self.targets.as_ref()?.first()?.location.country)
    }
}

/// The `TikTok` web cookie-privacy config; its region is the country `TikTok`
/// places the client in.
#[derive(Deserialize)]
struct TiktokConfig {
    body: TiktokConfigBody,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TiktokConfigBody {
    app_props: TiktokAppProps,
}

#[derive(Deserialize)]
struct TiktokAppProps {
    region: String,
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

fn netflix_country(body: &str) -> Option<CountryCode> {
    FastResponse::parse(body)?.client_country()
}

fn tiktok_country(body: &str) -> Option<CountryCode> {
    let config: TiktokConfig = serde_json::from_str(body).ok()?;
    country(&config.body.app_props.region)
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
                self.netflix
                    .as_ref()
                    .ok()
                    .and_then(|item| netflix_country(&item.body)),
            ),
            vote(
                ServiceGeoSource::Tiktok,
                self.tiktok
                    .as_ref()
                    .and_then(|item| tiktok_country(&item.body)),
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

/// Service country votes and CDN edges, read from one set of requests.
#[derive(Debug)]
pub struct ServiceGeoObservations {
    pub votes: Vec<ServiceCountryVote>,
    pub edges: Vec<CdnEdgeVote>,
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
        CdnEdgeVote {
            edge: CdnEdge::Cloudflare,
            observation: edge_observation(&cloudflare, cloudflare_country),
        },
        CdnEdgeVote {
            edge: CdnEdge::YoutubeGgc,
            observation: edge_observation(&youtube, ggc_country),
        },
        CdnEdgeVote {
            edge: CdnEdge::NetflixOca,
            observation: edge_observation(
                &countries.netflix,
                netflix_oca_country,
            ),
        },
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
    client.get(url, &BROWSER_EN_HEADERS).await.map_or_else(
        |error| CaptchaObservation::Unavailable(describe_error(&error)),
        |response| classify_search_captcha(response.status, &response.body),
    )
}

/// Fetches Google Search twice, `retry_after` apart. The judge counts a
/// captcha only when the retry reproduces it.
pub async fn probe_search_captcha(
    client: &TunnelClient,
    retry_after: Duration,
) -> CaptchaRetry {
    search_captcha_at(
        client,
        "https://www.google.com/search?q=cats",
        retry_after,
    )
    .await
}

async fn search_captcha_at(
    client: &TunnelClient,
    url: &str,
    retry_after: Duration,
) -> CaptchaRetry {
    let first = captcha_observation(client, url).await;
    tokio::time::sleep(retry_after).await;
    let retry = captcha_observation(client, url).await;
    CaptchaRetry { first, retry }
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
    value_from_lines(body, "colo").and_then(|code| airport_country(&code))
}

fn ggc_country(body: &str) -> Option<CountryCode> {
    ggc_iata(body).and_then(|code| airport_country(&code))
}

fn netflix_oca_country(body: &str) -> Option<CountryCode> {
    FastResponse::parse(body)?.first_target_country()
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn cc(code: &str) -> CountryCode {
        code.parse().unwrap()
    }

    #[rstest::rstest]
    #[case::locale_with_an_underscore(r#"x "en_FI" y"#, "FI")]
    #[case::the_last_language_tag(r#"["en-US","de-DE"]"#, "DE")]
    fn google_names_the_country_of_its_page_locale(
        #[case] body: &str,
        #[case] expected: &str,
    ) {
        let sut = google_country(body);

        assert_eq!(sut, Some(cc(expected)));
    }

    #[test]
    fn youtube_names_the_country_of_its_country_code_field() {
        let sut = youtube_country(r#"{"countryCode":"DE"}"#);

        assert_eq!(sut, Some(cc("DE")));
    }

    #[test]
    fn spotify_names_the_country_of_its_geolocation_field() {
        let sut = spotify_country(r#"{"geoLocationCountryCode":"NL"}"#);

        assert_eq!(sut, Some(cc("NL")));
    }

    #[test]
    fn netflix_votes_for_the_country_fast_com_places_the_client_in() {
        let body = r#"{
            "client": {"location": {"city": "Helsinki", "country": "FI"}},
            "targets": [{"location": {"city": "Riga", "country": "LV"}}]
        }"#;

        let sut = netflix_country(body);

        assert_eq!(sut, Some(cc("FI")));
    }

    #[test]
    fn the_netflix_oca_edge_is_in_the_country_of_the_first_target() {
        let body = r#"{
            "client": {"location": {"country": "FI"}},
            "targets": [
                {"location": {"country": "LV"}},
                {"location": {"country": "SE"}}
            ]
        }"#;

        let sut = netflix_oca_country(body);

        assert_eq!(sut, Some(cc("LV")));
    }

    #[test]
    fn fast_com_without_targets_names_no_oca_edge() {
        let body = r#"{"client": {"location": {"country": "FI"}}}"#;

        let sut = netflix_oca_country(body);

        assert_eq!(sut, None);
    }

    #[test]
    fn tiktok_votes_for_the_region_of_its_app_props() {
        let body = r#"{"body": {"appProps": {"region": "NL", "lang": "en"}}}"#;

        let sut = tiktok_country(body);

        assert_eq!(sut, Some(cc("NL")));
    }

    #[test]
    fn a_google_cache_cluster_name_carries_its_airport_code() {
        let sut = ggc_iata("192.0.2.0/24 => fra16s52");

        assert_eq!(sut.as_deref(), Some("FRA"));
    }

    #[tokio::test]
    async fn a_captcha_gone_on_retry_is_recorded_as_a_triggered_then_clear_pair()
     {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("cats - Search"),
            )
            .mount(&server)
            .await;
        let client = TunnelClient::from_client(reqwest::Client::new());

        let sut =
            search_captcha_at(&client, &server.uri(), Duration::ZERO).await;

        assert_eq!(
            sut,
            CaptchaRetry {
                first: CaptchaObservation::Triggered,
                retry: CaptchaObservation::Clear,
            }
        );
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
