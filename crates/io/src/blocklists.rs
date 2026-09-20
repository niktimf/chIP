use chip_core::model::{BlockListFacts, BlockListStatus};
use ipnet::Ipv4Net;
use serde::Deserialize;
use std::net::Ipv4Addr;

const SPAMHAUS_URL: &str = "https://www.spamhaus.org/drop/drop_v4.json";
const FIREHOL_URL: &str = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset";

fn parse_spamhaus(body: &str) -> Vec<Ipv4Net> {
    #[derive(Deserialize)]
    struct Entry {
        cidr: String,
    }

    body.lines()
        .filter_map(|line| serde_json::from_str::<Entry>(line).ok())
        .filter_map(|entry| entry.cidr.parse().ok())
        .collect()
}

fn parse_firehol(body: &str) -> Vec<Ipv4Net> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.parse().ok())
        .collect()
}

pub struct BlockLists {
    spamhaus: Option<Vec<Ipv4Net>>,
    firehol: Option<Vec<Ipv4Net>>,
}

impl BlockLists {
    pub async fn fetch(http: &reqwest::Client) -> Self {
        Self::fetch_from(http, SPAMHAUS_URL, FIREHOL_URL).await
    }

    async fn fetch_from(
        http: &reqwest::Client,
        spamhaus_url: &str,
        firehol_url: &str,
    ) -> Self {
        let (spamhaus, firehol) = tokio::join!(
            Self::get_text(http, spamhaus_url),
            Self::get_text(http, firehol_url)
        );
        // A real list is never empty; an empty parse means a corrupted
        // response and is therefore unavailable, not a clean list.
        let spamhaus = spamhaus
            .map(|body| parse_spamhaus(&body))
            .filter(|nets| !nets.is_empty());
        let firehol = firehol
            .map(|body| parse_firehol(&body))
            .filter(|nets| !nets.is_empty());
        Self { spamhaus, firehol }
    }

    async fn get_text(http: &reqwest::Client, url: &str) -> Option<String> {
        let response = http.get(url).send().await.ok()?;
        response.status().is_success().then_some(())?;
        response.text().await.ok()
    }

    pub fn check(&self, ip: Ipv4Addr) -> BlockListFacts {
        fn status(nets: Option<&[Ipv4Net]>, ip: Ipv4Addr) -> BlockListStatus {
            match nets {
                None => BlockListStatus::Unavailable,
                Some(nets) if nets.iter().any(|net| net.contains(&ip)) => {
                    BlockListStatus::Listed
                }
                Some(_) => BlockListStatus::Clear,
            }
        }

        BlockListFacts {
            spamhaus: status(self.spamhaus.as_deref(), ip),
            firehol: status(self.firehol.as_deref(), ip),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SPAMHAUS_SAMPLE: &str = "{\"cidr\":\"203.0.113.0/24\",\"sblid\":\"SBL1\",\"rir\":\"ripencc\"}\n{\"cidr\":\"198.51.100.0/24\",\"sblid\":\"SBL2\",\"rir\":\"ripencc\"}\n";

    const FIREHOL_SAMPLE: &str =
        "# Maintainer : FireHOL\n# comment\n192.0.2.0/24\n\n203.0.113.0/25\n";

    #[test]
    fn parse_spamhaus_reads_one_cidr_per_json_line() {
        let nets = parse_spamhaus(SPAMHAUS_SAMPLE);
        assert_eq!(nets.len(), 2);
        assert!(nets.contains(&"203.0.113.0/24".parse().unwrap()));
    }

    #[test]
    fn parse_firehol_skips_comments_and_blank_lines() {
        let nets = parse_firehol(FIREHOL_SAMPLE);
        assert_eq!(
            nets,
            vec![
                "192.0.2.0/24".parse().unwrap(),
                "203.0.113.0/25".parse().unwrap()
            ]
        );
    }

    #[tokio::test]
    async fn fetch_from_populates_both_lists_when_both_succeed() {
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

        let lists = BlockLists::fetch_from(
            &reqwest::Client::new(),
            &format!("{}/spamhaus", server.uri()),
            &format!("{}/firehol", server.uri()),
        )
        .await;
        let hit = lists.check(Ipv4Addr::new(203, 0, 113, 5));
        let clean = lists.check(Ipv4Addr::new(8, 8, 8, 8));

        assert_eq!(hit.spamhaus, BlockListStatus::Listed);
        assert_eq!(hit.firehol, BlockListStatus::Listed);
        assert_eq!(clean.spamhaus, BlockListStatus::Clear);
        assert_eq!(clean.firehol, BlockListStatus::Clear);
    }

    #[tokio::test]
    async fn fetch_from_marks_a_failed_list_unavailable_without_failing_the_other()
     {
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

        let lists = BlockLists::fetch_from(
            &reqwest::Client::new(),
            &format!("{}/spamhaus", server.uri()),
            &format!("{}/firehol", server.uri()),
        )
        .await;
        let facts = lists.check(Ipv4Addr::new(192, 0, 2, 1));

        assert_eq!(facts.spamhaus, BlockListStatus::Unavailable);
        assert_eq!(facts.firehol, BlockListStatus::Listed);
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

        let lists = BlockLists::fetch_from(
            &reqwest::Client::new(),
            &format!("{}/spamhaus", server.uri()),
            &format!("{}/firehol", server.uri()),
        )
        .await;
        let facts = lists.check(Ipv4Addr::new(192, 0, 2, 1));

        assert_eq!(facts.spamhaus, BlockListStatus::Unavailable);
        assert_eq!(facts.firehol, BlockListStatus::Listed);
    }
}
