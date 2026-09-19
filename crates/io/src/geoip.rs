use chip_core::model::{CountryCode, GeoConsensusFacts};
use std::time::Duration;

pub struct GeoSource {
    pub name: &'static str,
    pub url: Box<dyn Fn(&str) -> String + Send + Sync>,
    pub path: &'static [&'static str],
}

/// Delegates the two-letter check to `CountryCode::try_from` rather than
/// re-implementing it: a source's free tier answering with a full name
/// (`"Germany"`) or anything else that isn't a valid code is exactly the
/// case that constructor already turns into `Err`, which becomes `None`
/// here — one no-vote path, not two.
fn extract(value: &serde_json::Value, path: &[&str]) -> Option<CountryCode> {
    let mut current = value;
    for segment in path {
        current = match segment.parse::<usize>() {
            Ok(index) => current.get(index)?,
            Err(_) => current.get(*segment)?,
        };
    }
    CountryCode::try_from(current.as_str()?).ok()
}

fn default_sources() -> Vec<GeoSource> {
    fn s(
        name: &'static str,
        url: impl Fn(&str) -> String + Send + Sync + 'static,
        path: &'static [&'static str],
    ) -> GeoSource {
        GeoSource {
            name,
            url: Box::new(url),
            path,
        }
    }
    vec![
        s(
            "ripe-rdap",
            |ip| format!("https://rdap.db.ripe.net/ip/{ip}"),
            &["country"],
        ),
        s(
            "ipinfo",
            |ip| format!("https://ipinfo.io/{ip}/json"),
            &["country"],
        ),
        s(
            "country.is",
            |ip| format!("https://api.country.is/{ip}"),
            &["country"],
        ),
        s(
            "geojs",
            |ip| format!("https://get.geojs.io/v1/ip/country.json?ip={ip}"),
            &["0", "country"],
        ),
        s(
            "ipwho",
            |ip| format!("https://ipwho.is/{ip}"),
            &["country_code"],
        ),
        s(
            "ipapi.co",
            |ip| format!("https://ipapi.co/{ip}/json/"),
            &["country"],
        ),
        s(
            "ipquery",
            |ip| format!("https://api.ipquery.io/{ip}"),
            &["location", "country_code"],
        ),
        s(
            "ipbase",
            |ip| format!("https://api.ipbase.com/v2/info?ip={ip}"),
            &["data", "location", "country", "alpha2"],
        ),
        // ipapi.is's free tier sometimes returns a full country name here
        // instead of a code — `extract`'s two-letter check turns that into
        // a graceful "no vote" rather than a wrong one.
        s(
            "ipapi.is",
            |ip| format!("https://api.ipapi.is/?q={ip}"),
            &["country"],
        ),
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
    fn with_sources(http: reqwest::Client, timeout: Duration, sources: Vec<GeoSource>) -> Self {
        Self {
            http,
            timeout,
            sources,
        }
    }

    pub async fn consensus(&self, ip: &str) -> GeoConsensusFacts {
        let mut votes = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            let vote = self.query_one(source, ip).await;
            votes.push(vote);
        }
        GeoConsensusFacts { votes }
    }

    async fn query_one(&self, source: &GeoSource, ip: &str) -> Option<CountryCode> {
        let url = (source.url)(ip);
        let response = tokio::time::timeout(self.timeout, self.http.get(&url).send())
            .await
            .ok()?
            .ok()?;
        let value: serde_json::Value = response.json().await.ok()?;
        extract(&value, source.path)
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

    #[test]
    fn extract_reads_a_plain_top_level_field() {
        let sut = serde_json::json!({"country": "fi"});

        assert_eq!(extract(&sut, &["country"]), Some(cc("FI")));
    }

    #[test]
    fn extract_walks_into_an_array_index_then_an_object_key() {
        let sut = serde_json::json!([{"country": "de"}]);

        assert_eq!(extract(&sut, &["0", "country"]), Some(cc("DE")));
    }

    #[test]
    fn extract_rejects_a_full_country_name_as_no_vote() {
        // ipapi.is's free tier answers with a full name, not a 2-letter code.
        let sut = serde_json::json!({"country": "Germany"});

        assert_eq!(extract(&sut, &["country"]), None);
    }

    #[test]
    fn extract_returns_none_when_the_path_does_not_exist() {
        let sut = serde_json::json!({"unrelated": "value"});

        assert_eq!(extract(&sut, &["country"]), None);
    }

    #[tokio::test]
    async fn consensus_keeps_going_after_one_source_fails_and_preserves_order() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ok"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"country": "fi"})),
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
                    Box::new(move |_ip: &str| format!("{base}/ok"))
                },
                path: &["country"],
            },
            GeoSource {
                name: "second",
                url: {
                    let base = server.uri();
                    Box::new(move |_ip: &str| format!("{base}/broken"))
                },
                path: &["country"],
            },
        ];
        let sut = GeoIpClient::with_sources(
            reqwest::Client::new(),
            std::time::Duration::from_secs(5),
            sources,
        );

        let facts = sut.consensus("203.0.113.1").await;

        assert_eq!(facts.votes, vec![Some(cc("FI")), None]);
    }
}
