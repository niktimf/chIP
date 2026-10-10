use chip_core::checks::direct::ip_lists::{
    BlockLists, FetchedList, NetworkList,
};
use ipnet::Ipv4Net;
use serde::Deserialize;

use crate::error_chain::describe_error;
use crate::netset::{self, Garbage, Line, ParsedList};

/// One line of the Spamhaus DROP export: an entry, or the trailing
/// `{"type": "metadata", ...}` line.
#[derive(Deserialize)]
#[serde(untagged)]
enum DropLine {
    Entry {
        cidr: Ipv4Net,
    },
    Metadata {
        #[serde(rename = "type")]
        _kind: DropLineType,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum DropLineType {
    Metadata,
}

impl DropLine {
    fn read(line: &str) -> Result<Line<Ipv4Net>, Garbage> {
        if line.is_empty() {
            return Ok(Line::Skip);
        }
        match serde_json::from_str::<Self>(line) {
            Ok(Self::Entry { cidr }) => Ok(Line::Entry(cidr)),
            Ok(Self::Metadata { .. }) => Ok(Line::Skip),
            // The caller counts garbage lines; the decode error of one line
            // adds nothing to that count.
            Err(_) => Err(Garbage),
        }
    }
}

#[derive(Debug)]
pub struct BlockListsClient {
    http: reqwest::Client,
    spamhaus_url: String,
    firehol_url: String,
}

impl BlockListsClient {
    pub fn new(http: reqwest::Client) -> Self {
        const SPAMHAUS_URL: &str = "https://www.spamhaus.org/drop/drop_v4.json";
        const FIREHOL_URL: &str = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset";
        Self {
            http,
            spamhaus_url: SPAMHAUS_URL.to_owned(),
            firehol_url: FIREHOL_URL.to_owned(),
        }
    }

    pub async fn fetch(&self) -> BlockLists {
        let (spamhaus, firehol) = tokio::join!(
            self.fetch_list(
                "spamhaus",
                &self.spamhaus_url,
                Self::parse_spamhaus
            ),
            self.fetch_list("firehol", &self.firehol_url, netset::parse)
        );
        BlockLists { spamhaus, firehol }
    }

    /// A failed download and one that parsed to nothing both leave the list
    /// unavailable rather than clean. `FetchedList::Unavailable` has no
    /// place for the cause, so it goes to the log.
    async fn fetch_list(
        &self,
        list: &'static str,
        url: &str,
        parse: fn(&str) -> ParsedList<Vec<Ipv4Net>>,
    ) -> FetchedList {
        let body = match self.get_text(url).await {
            Ok(body) => body,
            Err(error) => {
                tracing::warn!(
                    list,
                    error = %describe_error(&error),
                    "block list download failed"
                );
                return FetchedList::Unavailable;
            }
        };
        let networks = parse(&body).into_logged_entries(list);
        NetworkList::new(networks).map_or_else(
            |error| {
                tracing::warn!(
                    list,
                    url,
                    %error,
                    "block list parsed to no networks"
                );
                FetchedList::Unavailable
            },
            FetchedList::Fetched,
        )
    }

    fn parse_spamhaus(body: &str) -> ParsedList<Vec<Ipv4Net>> {
        ParsedList::parse(body, DropLine::read)
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
        let actual = BlockListsClient::parse_spamhaus(SPAMHAUS_SAMPLE);

        assert_eq!(
            actual.into_logged_entries("spamhaus"),
            vec![
                "203.0.113.0/24".parse::<Ipv4Net>().unwrap(),
                "198.51.100.0/24".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn a_spamhaus_line_that_is_neither_entry_nor_metadata_is_garbage() {
        let actual = DropLine::read(r#"{"type":"something-else"}"#);

        assert_eq!(actual, Err(Garbage));
    }

    #[tokio::test]
    async fn both_lists_are_read_when_both_sources_answer() {
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
    async fn a_failed_list_is_unavailable_and_the_other_is_still_read() {
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
    }
}
