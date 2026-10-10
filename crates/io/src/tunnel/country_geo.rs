use std::time::Duration;

use chip_core::checks::tunnel::service_geo::{
    CaptchaObservation, CaptchaRetry, CdnEdge, CdnEdgeVote, CountryObservation,
    ServiceCountryVote, ServiceGeoSource, airport_country,
    classify_search_captcha,
};
use chip_core::values::CountryCode;
use regex::regex;
use serde::Deserialize;
use serde::de::DeserializeOwned;

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
    fn client_country(&self) -> Option<CountryCode> {
        country(&self.client.as_ref()?.location.country)
    }

    fn first_target_country(&self) -> Option<CountryCode> {
        country(&self.targets.as_ref()?.first()?.location.country)
    }
}

/// The `TikTok` web cookie-privacy config; its region is the country `TikTok`
/// places the client in. Every level is optional: a JSON answer without the
/// region is an answer without a country, not a broken one.
#[derive(Deserialize)]
struct TiktokConfig {
    body: Option<TiktokConfigBody>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TiktokConfigBody {
    app_props: Option<TiktokAppProps>,
}

#[derive(Deserialize)]
struct TiktokAppProps {
    region: Option<String>,
}

impl TiktokConfig {
    fn country(&self) -> Option<CountryCode> {
        country(self.body.as_ref()?.app_props.as_ref()?.region.as_ref()?)
    }
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

type Fetched = Result<TunnelResponse, TunnelError>;

/// The body of a response that arrived with a success status, or the cause
/// of the missing answer: the transport error or the HTTP error status. A
/// 403 or 5xx page is not the service's answer, whatever text it holds.
fn answered_body(response: &Fetched) -> Result<&str, String> {
    match response {
        Ok(response) if response.status.is_success() => Ok(&response.body),
        Ok(response) => Err(format!("HTTP {}", response.status)),
        Err(error) => Err(describe_error(error)),
    }
}

/// The country a page or plain-text answer names.
fn observation(
    response: &Fetched,
    locate: fn(&str) -> Option<CountryCode>,
) -> CountryObservation {
    match answered_body(response) {
        Ok(body) => locate(body)
            .map_or(CountryObservation::Silent, CountryObservation::Country),
        Err(cause) => CountryObservation::Unavailable(cause),
    }
}

/// The country a JSON answer names. A body that is not JSON of the expected
/// shape, such as an HTML error page served with 200, is no answer: the
/// source is unavailable with the parse error as the cause.
fn json_observation<T: DeserializeOwned>(
    response: &Fetched,
    locate: fn(&T) -> Option<CountryCode>,
) -> CountryObservation {
    let parsed = answered_body(response).and_then(|body| {
        serde_json::from_str::<T>(body)
            .map_err(|error| format!("unreadable JSON: {error}"))
    });
    match parsed {
        Ok(answer) => locate(&answer)
            .map_or(CountryObservation::Silent, CountryObservation::Country),
        Err(cause) => CountryObservation::Unavailable(cause),
    }
}

struct CountryResponses {
    google: Fetched,
    youtube: Fetched,
    apple: Fetched,
    spotify: Fetched,
    /// The CDN-edge gate reads the same response for the Netflix OCA edge.
    netflix: Fetched,
    tiktok: Fetched,
    bing: Fetched,
}

impl CountryResponses {
    async fn fetch(client: &TunnelClient) -> Self {
        let (google, youtube, apple, spotify, netflix, tiktok, bing) = tokio::join!(
            client.get("https://www.google.com", &BROWSER_HEADERS),
            client.get("https://www.youtube.com", &BROWSER_HEADERS),
            client
                .get("https://gspe1-ssl.ls.apple.com/pep/gcc", &BROWSER_HEADERS),
            client.get("https://accounts.spotify.com/status", &BROWSER_HEADERS),
            client.get(FAST_API_URL, &BROWSER_HEADERS),
            client.get(
                "https://www.tiktok.com/api/v1/web-cookie-privacy/config?appId=1988",
                &BROWSER_HEADERS
            ),
            client.get("https://www.bing.com/search?q=cats", &BROWSER_HEADERS)
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

    /// One vote per service. `YouTube` votes only with its own page: a page
    /// without a country is a silent vote, not Google's country again.
    fn votes(&self) -> Vec<ServiceCountryVote> {
        vec![
            vote(
                ServiceGeoSource::Google,
                observation(&self.google, google_country),
            ),
            vote(
                ServiceGeoSource::Youtube,
                observation(&self.youtube, youtube_country),
            ),
            vote(ServiceGeoSource::Apple, observation(&self.apple, country)),
            vote(
                ServiceGeoSource::Spotify,
                observation(&self.spotify, spotify_country),
            ),
            vote(
                ServiceGeoSource::Netflix,
                json_observation(&self.netflix, FastResponse::client_country),
            ),
            vote(
                ServiceGeoSource::Tiktok,
                json_observation(&self.tiktok, TiktokConfig::country),
            ),
            vote(ServiceGeoSource::Bing, observation(&self.bing, bing_country)),
        ]
    }
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
            observation: observation(&cloudflare, cloudflare_country),
        },
        CdnEdgeVote {
            edge: CdnEdge::YoutubeGgc,
            observation: observation(&youtube, ggc_country),
        },
        CdnEdgeVote {
            edge: CdnEdge::NetflixOca,
            observation: json_observation(
                &countries.netflix,
                FastResponse::first_target_country,
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
    CaptchaRetry {
        first,
        retry,
        interval: retry_after,
    }
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

fn cloudflare_country(body: &str) -> Option<CountryCode> {
    value_from_lines(body, "colo").and_then(|code| airport_country(&code))
}

fn ggc_country(body: &str) -> Option<CountryCode> {
    ggc_iata(body).and_then(|code| airport_country(&code))
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

    fn answered(status: StatusCode, body: &str) -> TunnelResponse {
        TunnelResponse {
            status,
            final_url: "https://example.test/".parse().unwrap(),
            body: body.to_string(),
        }
    }

    fn page(body: &str) -> TunnelResponse {
        answered(StatusCode::OK, body)
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

        let sut =
            json_observation(&Ok(page(body)), FastResponse::client_country);

        assert_eq!(sut, CountryObservation::Country(cc("FI")));
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

        let sut = json_observation(
            &Ok(page(body)),
            FastResponse::first_target_country,
        );

        assert_eq!(sut, CountryObservation::Country(cc("LV")));
    }

    #[test]
    fn fast_com_without_targets_names_no_oca_edge() {
        let body = r#"{"client": {"location": {"country": "FI"}}}"#;

        let sut = json_observation(
            &Ok(page(body)),
            FastResponse::first_target_country,
        );

        assert_eq!(sut, CountryObservation::Silent);
    }

    #[test]
    fn tiktok_votes_for_the_region_of_its_app_props() {
        let body = r#"{"body": {"appProps": {"region": "NL", "lang": "en"}}}"#;

        let sut = json_observation(&Ok(page(body)), TiktokConfig::country);

        assert_eq!(sut, CountryObservation::Country(cc("NL")));
    }

    #[test]
    fn tiktok_json_without_a_region_is_an_answer_without_a_country() {
        let body = r#"{"body": {"appProps": {"lang": "en"}}}"#;

        let sut = json_observation(&Ok(page(body)), TiktokConfig::country);

        assert_eq!(sut, CountryObservation::Silent);
    }

    // The 403 page still carries a locale; it is not the service's answer.
    #[rstest::rstest]
    #[case::forbidden(StatusCode::FORBIDDEN, "HTTP 403 Forbidden")]
    #[case::server_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "HTTP 503 Service Unavailable"
    )]
    fn a_service_answering_with_an_error_status_is_unavailable(
        #[case] status: StatusCode,
        #[case] expected: &str,
    ) {
        let response = Ok(answered(status, r#"<html lang="en_FI">"#));

        let sut = observation(&response, google_country);

        assert_eq!(sut, CountryObservation::Unavailable(expected.to_string()));
    }

    #[test]
    fn a_json_source_answering_with_an_error_status_is_unavailable() {
        let response = Ok(answered(StatusCode::FORBIDDEN, "{}"));

        let sut = json_observation(&response, FastResponse::client_country);

        assert_eq!(
            sut,
            CountryObservation::Unavailable("HTTP 403 Forbidden".to_string())
        );
    }

    #[test]
    fn an_html_page_instead_of_fast_com_json_is_unavailable_with_the_cause() {
        let response = Ok(page("<html><body>Access denied</body></html>"));

        let sut =
            json_observation(&response, FastResponse::first_target_country);

        assert_eq!(
            sut,
            CountryObservation::Unavailable(
                "unreadable JSON: expected value at line 1 column 1"
                    .to_string()
            )
        );
    }

    #[test]
    fn youtube_without_a_country_votes_silent_instead_of_repeating_google() {
        let sut = CountryResponses {
            google: Ok(page(r#"x "en_FI" y"#)),
            youtube: Ok(page("<html>consent page</html>")),
            apple: Ok(page("FI")),
            spotify: Ok(page(r#"{"geoLocationCountryCode":"FI"}"#)),
            netflix: Ok(page(r#"{"client": {"location": {"country": "FI"}}}"#)),
            tiktok: Ok(page(r#"{"body": {"appProps": {"region": "FI"}}}"#)),
            bing: Ok(page(r#"Region: "FI""#)),
        };

        let votes = sut.votes();

        assert_eq!(
            votes[..2],
            [
                vote(
                    ServiceGeoSource::Google,
                    CountryObservation::Country(cc("FI"))
                ),
                vote(ServiceGeoSource::Youtube, CountryObservation::Silent),
            ]
        );
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
                interval: Duration::ZERO,
            }
        );
    }

    #[tokio::test]
    async fn an_edge_that_cannot_be_reached_is_unavailable_with_its_cause() {
        // Port 1 on loopback has no listener, so the request is refused
        // without leaving the machine.
        let client = TunnelClient::from_client(reqwest::Client::new());
        let response = client.get("http://127.0.0.1:1/", &[]).await;

        let sut = observation(&response, cloudflare_country);

        let CountryObservation::Unavailable(cause) = sut else {
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

        let sut = observation(&response, cloudflare_country);

        assert_eq!(sut, CountryObservation::Silent);
    }
}
