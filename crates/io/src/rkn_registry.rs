use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use chip_core::ip_lists::{AddressList, NetworkList, RknRegistry};
use thiserror::Error;

use crate::netset;

/// Single addresses from the RKN registry, exported by antifilter.download
/// several times a day.
const ADDRESS_LIST_URL: &str = "https://antifilter.download/list/ip.lst";
/// Networks the registry blocks as a whole.
const SUBNET_LIST_URL: &str = "https://antifilter.download/list/subnet.lst";

#[derive(Debug, Error)]
pub enum RknRegistryError {
    #[error("could not fetch the RKN registry from {url}: {source}")]
    Fetch { url: String, source: reqwest::Error },
    #[error("the RKN registry export at {url} has no IPv4 entries")]
    Empty { url: String },
}

pub struct RknRegistryClient {
    http: reqwest::Client,
    address_list_url: String,
    subnet_list_url: String,
}

impl RknRegistryClient {
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            address_list_url: ADDRESS_LIST_URL.to_owned(),
            subnet_list_url: SUBNET_LIST_URL.to_owned(),
        }
    }

    pub async fn fetch(&self) -> Result<RknRegistry, RknRegistryError> {
        let (addresses, subnets) = tokio::join!(
            self.get_text(&self.address_list_url),
            self.get_text(&self.subnet_list_url)
        );
        let addresses = AddressList::new(Self::parse_addresses(&addresses?))
            .map_err(|_| RknRegistryError::Empty {
                url: self.address_list_url.clone(),
            })?;
        let subnets =
            NetworkList::new(netset::parse(&subnets?)).map_err(|_| {
                RknRegistryError::Empty {
                    url: self.subnet_list_url.clone(),
                }
            })?;
        Ok(RknRegistry::new(addresses, subnets))
    }

    /// Lines that are not a single IPv4 address (IPv6, garbage) are skipped.
    fn parse_addresses(body: &str) -> BTreeSet<Ipv4Addr> {
        body.lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect()
    }

    async fn get_text(&self, url: &str) -> Result<String, RknRegistryError> {
        let fetch = async {
            self.http
                .get(url)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await
        };
        fetch.await.map_err(|source| RknRegistryError::Fetch {
            url: url.to_owned(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ADDRESS_LIST: &str = "\
203.0.113.7
203.0.113.8
2001:db8::1
";

    const SUBNET_LIST: &str = "198.51.100.0/24\n2001:db8::/32\n\n";

    async fn serve(address_list: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ip.lst"))
            .respond_with(address_list)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/subnet.lst"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(SUBNET_LIST),
            )
            .mount(&server)
            .await;
        server
    }

    fn client(server: &MockServer) -> RknRegistryClient {
        RknRegistryClient {
            http: reqwest::Client::new(),
            address_list_url: format!("{}/ip.lst", server.uri()),
            subnet_list_url: format!("{}/subnet.lst", server.uri()),
        }
    }

    #[test]
    fn ipv6_lines_are_skipped_in_the_address_list() {
        let sut = ADDRESS_LIST;

        let actual = RknRegistryClient::parse_addresses(sut);

        assert_eq!(
            actual,
            BTreeSet::from([
                Ipv4Addr::new(203, 0, 113, 7),
                Ipv4Addr::new(203, 0, 113, 8),
            ])
        );
    }

    #[tokio::test]
    async fn fetch_reads_both_lists() {
        let server =
            serve(ResponseTemplate::new(200).set_body_string(ADDRESS_LIST))
                .await;

        let sut = client(&server);

        let actual = sut.fetch().await.unwrap();

        let expected = RknRegistry::new(
            AddressList::new(BTreeSet::from([
                Ipv4Addr::new(203, 0, 113, 7),
                Ipv4Addr::new(203, 0, 113, 8),
            ]))
            .unwrap(),
            NetworkList::new(vec!["198.51.100.0/24".parse().unwrap()]).unwrap(),
        );
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn a_failed_list_is_an_error_rather_than_a_clean_registry() {
        let server = serve(ResponseTemplate::new(503)).await;

        let sut = client(&server);

        let error = sut.fetch().await.err().unwrap();

        assert!(matches!(error, RknRegistryError::Fetch { .. }), "{error}");
    }

    #[tokio::test]
    async fn a_200_response_without_ipv4_entries_is_an_error() {
        let server = serve(
            ResponseTemplate::new(200).set_body_string("<html>error</html>"),
        )
        .await;

        let sut = client(&server);

        let error = sut.fetch().await.err().unwrap();

        assert!(matches!(error, RknRegistryError::Empty { .. }), "{error}");
    }
}
