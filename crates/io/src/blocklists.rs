use chip_core::ip_lists::{BlockLists, FetchedList, NetworkList};
use ipnet::Ipv4Net;
use serde::Deserialize;

use crate::netset;

const SPAMHAUS_URL: &str = "https://www.spamhaus.org/drop/drop_v4.json";
const FIREHOL_URL: &str = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset";

/// One line of the Spamhaus DROP export. The trailing metadata line has no
/// `cidr` and does not parse as an entry.
#[derive(Deserialize)]
struct DropEntry {
    cidr: Ipv4Net,
}

pub struct BlockListsClient {
    http: reqwest::Client,
    spamhaus_url: String,
    firehol_url: String,
}

impl BlockListsClient {
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            spamhaus_url: SPAMHAUS_URL.to_owned(),
            firehol_url: FIREHOL_URL.to_owned(),
        }
    }

    pub async fn fetch(&self) -> BlockLists {
        let (spamhaus, firehol) = tokio::join!(
            self.fetch_list(&self.spamhaus_url, Self::parse_spamhaus),
            self.fetch_list(&self.firehol_url, netset::parse)
        );
        BlockLists { spamhaus, firehol }
    }

    /// A failed download and one that parsed to nothing both leave the list
    /// unavailable rather than clean.
    async fn fetch_list(
        &self,
        url: &str,
        parse: fn(&str) -> Vec<Ipv4Net>,
    ) -> FetchedList {
        self.get_text(url)
            .await
            .map_or(FetchedList::Unavailable, |body| {
                NetworkList::new(parse(&body))
                    .map_or(FetchedList::Unavailable, FetchedList::Fetched)
            })
    }

    fn parse_spamhaus(body: &str) -> Vec<Ipv4Net> {
        body.lines()
            .filter_map(|line| serde_json::from_str::<DropEntry>(line).ok())
            .map(|entry| entry.cidr)
            .collect()
    }

    async fn get_text(&self, url: &str) -> Result<String, reqwest::Error> {
        self.http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Shaped like the real export, trailing metadata line included.
    const SPAMHAUS_SAMPLE: &str = r#"{"cidr":"203.0.113.0/24","sblid":"SBL1","rir":"ripencc"}
{"cidr":"198.51.100.0/24","sblid":"SBL2","rir":"ripencc"}
{"type":"metadata","timestamp":1790419442,"records":2}
"#;

    fn client(server: &MockServer) -> BlockListsClient {
        BlockListsClient {
            http: reqwest::Client::new(),
            spamhaus_url: format!("{}/spamhaus", server.uri()),
            firehol_url: format!("{}/firehol", server.uri()),
        }
    }

    fn fetched_list(cidrs: &[&str]) -> FetchedList {
        let networks = cidrs.iter().map(|cidr| cidr.parse().unwrap()).collect();
        FetchedList::Fetched(NetworkList::new(networks).unwrap())
    }

    /// `FireHOL` level1 mixes networks with bare addresses.
    const FIREHOL_SAMPLE: &str = "\
# Maintainer : FireHOL
192.0.2.0/24

203.0.113.0/25
198.51.100.7
";

    #[test]
    fn spamhaus_entries_are_read_and_the_metadata_line_is_skipped() {
        let sut = SPAMHAUS_SAMPLE;

        let actual = BlockListsClient::parse_spamhaus(sut);

        assert_eq!(
            actual,
            vec![
                "203.0.113.0/24".parse::<Ipv4Net>().unwrap(),
                "198.51.100.0/24".parse().unwrap(),
            ]
        );
    }

    #[tokio::test]
    async fn fetch_populates_both_lists_when_both_succeed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/spamhaus"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(SPAMHAUS_SAMPLE),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/firehol"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(FIREHOL_SAMPLE),
            )
            .mount(&server)
            .await;

        let sut = client(&server);

        let actual = sut.fetch().await;

        assert_eq!(
            actual.spamhaus,
            fetched_list(&["203.0.113.0/24", "198.51.100.0/24"])
        );
        assert_eq!(
            actual.firehol,
            fetched_list(&[
                "192.0.2.0/24",
                "203.0.113.0/25",
                "198.51.100.7/32"
            ])
        );
    }

    #[tokio::test]
    async fn fetch_marks_a_failed_list_unavailable_without_failing_the_other() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/spamhaus"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/firehol"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(FIREHOL_SAMPLE),
            )
            .mount(&server)
            .await;

        let sut = client(&server);

        let actual = sut.fetch().await;

        assert_eq!(actual.spamhaus, FetchedList::Unavailable);
        assert_eq!(
            actual.firehol,
            fetched_list(&[
                "192.0.2.0/24",
                "203.0.113.0/25",
                "198.51.100.7/32"
            ])
        );
    }

    #[tokio::test]
    async fn a_200_response_that_parses_to_no_entries_is_marked_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/spamhaus"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("<html>error</html>"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/firehol"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(FIREHOL_SAMPLE),
            )
            .mount(&server)
            .await;

        let sut = client(&server);

        let actual = sut.fetch().await;

        assert_eq!(actual.spamhaus, FetchedList::Unavailable);
        assert_eq!(
            actual.firehol,
            fetched_list(&[
                "192.0.2.0/24",
                "203.0.113.0/25",
                "198.51.100.7/32"
            ])
        );
    }
}
