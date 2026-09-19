use chip_core::model::BlockListFacts;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

const SPAMHAUS_URL: &str = "https://www.spamhaus.org/drop/drop_v4.json";
const FIREHOL_URL: &str =
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset";

fn parse_spamhaus(body: &str) -> Vec<Ipv4Net> {
    body.lines()
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            value["cidr"].as_str()?.parse().ok()
        })
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
    spamhaus: Vec<Ipv4Net>,
    spamhaus_available: bool,
    firehol: Vec<Ipv4Net>,
    firehol_available: bool,
}

impl BlockLists {
    pub async fn fetch(http: &reqwest::Client) -> Self {
        Self::fetch_from(http, SPAMHAUS_URL, FIREHOL_URL).await
    }

    async fn fetch_from(http: &reqwest::Client, spamhaus_url: &str, firehol_url: &str) -> Self {
        let (spamhaus, spamhaus_available) = match Self::get_text(http, spamhaus_url).await {
            Some(body) => {
                let nets = parse_spamhaus(&body);
                // A real list is never empty; empty parse means corrupted
                // response.
                (nets.clone(), !nets.is_empty())
            }
            None => (Vec::new(), false),
        };
        let (firehol, firehol_available) = match Self::get_text(http, firehol_url).await {
            Some(body) => {
                let nets = parse_firehol(&body);
                // A real list is never empty; empty parse means corrupted
                // response.
                (nets.clone(), !nets.is_empty())
            }
            None => (Vec::new(), false),
        };
        Self {
            spamhaus,
            spamhaus_available,
            firehol,
            firehol_available,
        }
    }

    async fn get_text(http: &reqwest::Client, url: &str) -> Option<String> {
        let response = http.get(url).send().await.ok()?;
        response.status().is_success().then_some(())?;
        response.text().await.ok()
    }

    pub fn check(&self, ip: Ipv4Addr) -> BlockListFacts {
        BlockListFacts {
            spamhaus_hit: self.spamhaus.iter().any(|net| net.contains(&ip)),
            spamhaus_available: self.spamhaus_available,
            firehol_hit: self.firehol.iter().any(|net| net.contains(&ip)),
            firehol_available: self.firehol_available,
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
            .respond_with(ResponseTemplate::new(200).set_body_string(SPAMHAUS_SAMPLE))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/firehol"))
            .respond_with(ResponseTemplate::new(200).set_body_string(FIREHOL_SAMPLE))
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

        assert!(
            hit.spamhaus_hit && hit.firehol_hit && hit.spamhaus_available && hit.firehol_available
        );
        assert!(!clean.spamhaus_hit && !clean.firehol_hit);
    }

    #[tokio::test]
    async fn fetch_from_marks_a_failed_list_unavailable_without_failing_the_other() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/spamhaus"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/firehol"))
            .respond_with(ResponseTemplate::new(200).set_body_string(FIREHOL_SAMPLE))
            .mount(&server)
            .await;

        let lists = BlockLists::fetch_from(
            &reqwest::Client::new(),
            &format!("{}/spamhaus", server.uri()),
            &format!("{}/firehol", server.uri()),
        )
        .await;
        let facts = lists.check(Ipv4Addr::new(192, 0, 2, 1));

        assert!(!facts.spamhaus_available);
        assert!(facts.firehol_available && facts.firehol_hit);
    }

    #[tokio::test]
    async fn a_200_response_that_parses_to_no_entries_is_marked_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/spamhaus"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>error</html>"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/firehol"))
            .respond_with(ResponseTemplate::new(200).set_body_string(FIREHOL_SAMPLE))
            .mount(&server)
            .await;

        let lists = BlockLists::fetch_from(
            &reqwest::Client::new(),
            &format!("{}/spamhaus", server.uri()),
            &format!("{}/firehol", server.uri()),
        )
        .await;
        let facts = lists.check(Ipv4Addr::new(192, 0, 2, 1));

        assert!(!facts.spamhaus_available);
        assert!(!facts.spamhaus_hit);
        assert!(facts.firehol_available);
    }
}
