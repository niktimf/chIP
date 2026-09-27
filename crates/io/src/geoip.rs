use chip_core::model::{CountryCode, GeoConsensusFacts};
use std::net::Ipv4Addr;
use std::time::Duration;

pub struct GeoSource {
    pub name: &'static str,
    pub url: Box<dyn Fn(Ipv4Addr) -> String + Send + Sync>,
    pub pointer: &'static str,
}

/// Delegates the registry check to `CountryCode::try_from` rather than
/// re-implementing it: a source's free tier answering with a full name
/// (`"Germany"`) or anything else that isn't a valid code is exactly the
/// case that constructor already turns into `Err`, which becomes `None`
/// here — one no-vote path, not two.
fn extract(value: &serde_json::Value, pointer: &str) -> Option<CountryCode> {
    CountryCode::try_from(value.pointer(pointer)?.as_str()?).ok()
}

fn default_sources() -> Vec<GeoSource> {
    fn s(
        name: &'static str,
        url: impl Fn(Ipv4Addr) -> String + Send + Sync + 'static,
        pointer: &'static str,
    ) -> GeoSource {
        GeoSource {
            name,
            url: Box::new(url),
            pointer,
        }
    }
    vec![
        s(
            "ripe-rdap",
            |ip| format!("https://rdap.db.ripe.net/ip/{ip}"),
            "/country",
        ),
        s("ipinfo", |ip| format!("https://ipinfo.io/{ip}/json"), "/country"),
        s(
            "country.is",
            |ip| format!("https://api.country.is/{ip}"),
            "/country",
        ),
        s(
            "geojs",
            |ip| format!("https://get.geojs.io/v1/ip/country.json?ip={ip}"),
            "/0/country",
        ),
        s("ipwho", |ip| format!("https://ipwho.is/{ip}"), "/country_code"),
        s("ipapi.co", |ip| format!("https://ipapi.co/{ip}/json/"), "/country"),
        s(
            "ipquery",
            |ip| format!("https://api.ipquery.io/{ip}"),
            "/location/country_code",
        ),
        s(
            "ipbase",
            |ip| format!("https://api.ipbase.com/v2/info?ip={ip}"),
            "/data/location/country/alpha2",
        ),
        // ipapi.is used to sit here. Its free tier answers `country` with a
        // full country name ("Finland"), never an alpha-2 code, so it never
        // cast a vote and only cost a request per scan. Verified 2026-09-20
        // against four addresses in three countries.
    ]
}

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

    pub async fn consensus(
        &self,
        ip: Ipv4Addr,
    ) -> Result<GeoConsensusFacts, tokio::task::JoinError> {
        let mut tasks = tokio::task::JoinSet::new();
        for (index, source) in self.sources.iter().enumerate() {
            let http = self.http.clone();
            let timeout = self.timeout;
            let url = (source.url)(ip);
            let pointer = source.pointer;
            tasks.spawn(async move {
                let vote = Self::query_one(&http, timeout, &url, pointer).await;
                (index, vote)
            });
        }
        let mut votes = vec![None; self.sources.len()];
        for (index, vote) in crate::tasks::collect(tasks).await? {
            votes[index] = vote;
        }
        Ok(GeoConsensusFacts { votes })
    }

    async fn query_one(
        http: &reqwest::Client,
        timeout: Duration,
        url: &str,
        pointer: &str,
    ) -> Option<CountryCode> {
        tokio::time::timeout(timeout, async {
            let response = http.get(url).send().await.ok()?;
            if !response.status().is_success() {
                return None;
            }
            let value: serde_json::Value = response.json().await.ok()?;
            extract(&value, pointer)
        })
        .await
        .ok()
        .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chip_core::model::CountryCode;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cc(code: &str) -> CountryCode {
        code.parse().unwrap()
    }

    #[rstest::rstest]
    #[case::a_plain_top_level_field(
        serde_json::json!({"country": "fi"}),
        "/country",
        Some("FI")
    )]
    #[case::an_array_index_then_an_object_key(
        serde_json::json!([{"country": "de"}]),
        "/0/country",
        Some("DE")
    )]
    // ipapi.is's free tier answers with a full name, not a 2-letter code.
    #[case::a_full_country_name_is_no_vote(
        serde_json::json!({"country": "Germany"}),
        "/country",
        None
    )]
    #[case::a_missing_path(
        serde_json::json!({"unrelated": "value"}),
        "/country",
        None
    )]
    fn extract_reads_the_country_code_at_the_pointer(
        #[case] sut: serde_json::Value,
        #[case] pointer: &str,
        #[case] expected: Option<&str>,
    ) {
        let actual = extract(&sut, pointer);

        assert_eq!(actual, expected.map(cc));
    }

    #[tokio::test]
    async fn consensus_keeps_going_after_one_source_fails_and_preserves_order()
    {
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
            GeoSource {
                name: "first",
                url: {
                    let base = server.uri();
                    Box::new(move |_ip: Ipv4Addr| format!("{base}/ok"))
                },
                pointer: "/country",
            },
            GeoSource {
                name: "second",
                url: {
                    let base = server.uri();
                    Box::new(move |_ip: Ipv4Addr| format!("{base}/broken"))
                },
                pointer: "/country",
            },
        ];
        let sut = GeoIpClient::with_sources(
            reqwest::Client::new(),
            std::time::Duration::from_secs(5),
            sources,
        );

        let facts =
            sut.consensus("203.0.113.1".parse().unwrap()).await.unwrap();

        assert_eq!(facts.votes, vec![Some(cc("FI")), None]);
    }
    #[tokio::test]
    async fn source_timeout_includes_reading_the_response_body() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (release, hold) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")
                .await
                .unwrap();
            let _ = hold.await;
        });
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
        let _ = release.send(());
        server.await.unwrap();
        assert_eq!(result.unwrap(), None);
    }
}
