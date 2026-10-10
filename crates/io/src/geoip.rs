use chip_core::checks::direct::geo::{GeoConsensusFacts, GeoVote};
use chip_core::values::{CountryCode, InvalidCountryCode};

use crate::error_chain::describe_error;
use std::net::Ipv4Addr;
use std::time::Duration;

/// One keyless `GeoIP` service: where to ask about an address and where
/// the answer keeps the country code.
#[derive(Debug)]
struct GeoSource {
    name: &'static str,
    /// The request URL, with [`GeoSource::IP`] where the address goes.
    url_template: String,
    pointer: &'static str,
}

impl GeoSource {
    const IP: &'static str = "{ip}";

    fn new(
        name: &'static str,
        url_template: impl Into<String>,
        pointer: &'static str,
    ) -> Self {
        Self {
            name,
            url_template: url_template.into(),
            pointer,
        }
    }

    fn url(&self, ip: Ipv4Addr) -> String {
        self.url_template.replace(Self::IP, &ip.to_string())
    }
}

/// Why a source named no country. It goes to the log; the vote keeps only
/// whether the source answered at all (see [`NoVote::vote`]).
#[derive(Debug, thiserror::Error)]
enum NoVote {
    #[error("no answer within {0:?}")]
    Timeout(Duration),
    #[error("request failed")]
    Request(#[source] reqwest::Error),
    #[error("answered with HTTP {0}")]
    Status(reqwest::StatusCode),
    #[error("answer is not JSON")]
    Body(#[source] reqwest::Error),
    #[error("answer has no string at {0}")]
    MissingField(&'static str),
    #[error("answer has no country code")]
    Country(#[source] InvalidCountryCode),
}

impl NoVote {
    const fn vote(&self) -> GeoVote {
        match self {
            Self::Timeout(_)
            | Self::Request(_)
            | Self::Status(_)
            | Self::Body(_) => GeoVote::NoAnswer,
            Self::MissingField(_) | Self::Country(_) => GeoVote::NoCountryCode,
        }
    }
}

/// Delegates the registry check to `CountryCode::try_from` rather than
/// re-implementing it: a source's free tier answering with a full name
/// (`"Germany"`) or anything else that isn't a valid code is exactly the
/// case that constructor already rejects.
fn extract(
    value: &serde_json::Value,
    pointer: &'static str,
) -> Result<CountryCode, NoVote> {
    let raw = value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .ok_or(NoVote::MissingField(pointer))?;
    CountryCode::try_from(raw).map_err(NoVote::Country)
}

fn default_sources() -> Vec<GeoSource> {
    vec![
        GeoSource::new(
            "ripe-rdap",
            "https://rdap.db.ripe.net/ip/{ip}",
            "/country",
        ),
        GeoSource::new("ipinfo", "https://ipinfo.io/{ip}/json", "/country"),
        GeoSource::new("country.is", "https://api.country.is/{ip}", "/country"),
        GeoSource::new(
            "geojs",
            "https://get.geojs.io/v1/ip/country.json?ip={ip}",
            "/0/country",
        ),
        GeoSource::new("ipwho", "https://ipwho.is/{ip}", "/country_code"),
        GeoSource::new("ipapi.co", "https://ipapi.co/{ip}/json/", "/country"),
        GeoSource::new(
            "ipquery",
            "https://api.ipquery.io/{ip}",
            "/location/country_code",
        ),
        GeoSource::new(
            "ipbase",
            "https://api.ipbase.com/v2/info?ip={ip}",
            "/data/location/country/alpha2",
        ),
        // ipapi.is used to sit here. Its free tier answers `country` with a
        // full country name ("Finland"), never an alpha-2 code, so it never
        // cast a vote and only cost a request per scan. Verified 2026-09-20
        // against four addresses in three countries.
    ]
}

#[derive(Debug)]
pub struct GeoIpClient {
    http: reqwest::Client,
    timeout: Duration,
    sources: Vec<GeoSource>,
}

impl GeoIpClient {
    pub fn new(http: reqwest::Client, timeout: Duration) -> Self {
        Self {
            http,
            timeout,
            sources: default_sources(),
        }
    }

    #[cfg(test)]
    const fn with_sources(
        http: reqwest::Client,
        timeout: Duration,
        sources: Vec<GeoSource>,
    ) -> Self {
        Self {
            http,
            timeout,
            sources,
        }
    }

    /// Asks every source at once and returns their votes in source order.
    /// A source that fails to answer is a missing vote, not an error.
    pub async fn consensus(&self, ip: Ipv4Addr) -> GeoConsensusFacts {
        let queries = self.sources.iter().map(|source| self.vote(source, ip));
        GeoConsensusFacts {
            votes: futures::future::join_all(queries).await,
        }
    }

    async fn vote(&self, source: &GeoSource, ip: Ipv4Addr) -> GeoVote {
        Self::query_one(
            &self.http,
            self.timeout,
            &source.url(ip),
            source.pointer,
        )
        .await
        .map_or_else(
            |error| {
                tracing::debug!(
                    source = source.name,
                    error = %describe_error(&error),
                    "geo source named no country"
                );
                error.vote()
            },
            GeoVote::Country,
        )
    }

    async fn query_one(
        http: &reqwest::Client,
        timeout: Duration,
        url: &str,
        pointer: &'static str,
    ) -> Result<CountryCode, NoVote> {
        tokio::time::timeout(timeout, async {
            let response =
                http.get(url).send().await.map_err(NoVote::Request)?;
            let status = response.status();
            if !status.is_success() {
                return Err(NoVote::Status(status));
            }
            let value: serde_json::Value =
                response.json().await.map_err(NoVote::Body)?;
            extract(&value, pointer)
        })
        .await
        .unwrap_or(Err(NoVote::Timeout(timeout)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chip_core::values::CountryCode;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cc(code: &str) -> CountryCode {
        code.parse().unwrap()
    }

    #[rstest::rstest]
    #[case::a_plain_top_level_field(
        serde_json::json!({"country": "fi"}),
        "/country",
        "FI"
    )]
    #[case::an_array_index_then_an_object_key(
        serde_json::json!([{"country": "de"}]),
        "/0/country",
        "DE"
    )]
    fn a_vote_is_the_country_code_found_at_the_source_pointer(
        #[case] answer: serde_json::Value,
        #[case] pointer: &'static str,
        #[case] expected: &str,
    ) {
        let actual = extract(&answer, pointer).unwrap();

        assert_eq!(actual, cc(expected));
    }

    /// ipapi.is's free tier answers with a full name, not a 2-letter code.
    #[test]
    fn a_full_country_name_is_no_country_code() {
        let answer = serde_json::json!({"country": "Germany"});

        let error = extract(&answer, "/country").unwrap_err();

        assert!(matches!(error, NoVote::Country(_)), "{error:?}");
    }

    #[test]
    fn an_answer_without_the_pointer_names_the_missing_field() {
        let answer = serde_json::json!({"unrelated": "value"});

        let error = extract(&answer, "/country").unwrap_err();

        assert!(matches!(error, NoVote::MissingField("/country")), "{error:?}");
    }

    #[tokio::test]
    async fn a_failing_source_casts_no_vote_and_the_others_keep_their_order() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ok"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"country": "fi"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/broken"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let sources = vec![
            source_at("first", format!("{}/ok", server.uri())),
            source_at("second", format!("{}/broken", server.uri())),
        ];
        let sut = GeoIpClient::with_sources(
            reqwest::Client::new(),
            std::time::Duration::from_secs(5),
            sources,
        );

        let facts = sut.consensus("203.0.113.1".parse().unwrap()).await;

        assert_eq!(
            facts.votes,
            [GeoVote::Country(cc("FI")), GeoVote::NoAnswer]
        );
    }

    #[tokio::test]
    async fn a_full_country_name_counts_as_an_answer_without_a_country_code() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/name"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"country": "Germany"})),
            )
            .mount(&server)
            .await;
        let sut = GeoIpClient::with_sources(
            reqwest::Client::new(),
            std::time::Duration::from_secs(5),
            vec![source_at("named", format!("{}/name", server.uri()))],
        );

        let facts = sut.consensus("203.0.113.1".parse().unwrap()).await;

        assert_eq!(facts.votes, [GeoVote::NoCountryCode]);
    }

    fn source_at(name: &'static str, url: String) -> GeoSource {
        GeoSource::new(name, url, "/country")
    }

    /// A server that sends the headers and the first byte of a 100-byte body,
    /// then stalls until `release` fires.
    async fn stalled_body_server()
    -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (release, hold) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _bytes_read = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")
                .await
                .unwrap();
            // A dropped sender ends the stall the same way a release does.
            let _released = hold.await;
        });
        (address, release)
    }

    #[tokio::test]
    async fn source_timeout_includes_reading_the_response_body() {
        let (address, _release) = stalled_body_server().await;
        let http = reqwest::Client::new();

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            GeoIpClient::query_one(
                &http,
                Duration::from_millis(100),
                &format!("http://{address}"),
                "/country",
            ),
        )
        .await;

        assert!(matches!(result, Ok(Err(NoVote::Timeout(_)))), "{result:?}");
    }
}
