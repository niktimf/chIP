use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use chip_core::checks::direct::ip_lists::{
    AddressList, NetworkList, RknRegistry,
};
use thiserror::Error;

use crate::netset::{self, Garbage, Line, ParsedList};

#[derive(Debug, Error)]
pub enum RknRegistryError {
    #[error("could not fetch the RKN registry from {url}")]
    Fetch { url: String, source: reqwest::Error },
    #[error("the RKN registry export at {url} has no IPv4 entries")]
    Empty { url: String },
}

#[derive(Debug)]
pub struct RknRegistryClient {
    http: reqwest::Client,
    address_list_url: String,
    subnet_list_url: String,
}

impl RknRegistryClient {
    pub fn new(http: reqwest::Client) -> Self {
        /// Single addresses from the RKN registry, exported by
        /// antifilter.download several times a day.
        const ADDRESS_LIST_URL: &str =
            "https://antifilter.download/list/ip.lst";
        /// Networks the registry blocks as a whole.
        const SUBNET_LIST_URL: &str =
            "https://antifilter.download/list/subnet.lst";
        Self {
            http,
            address_list_url: ADDRESS_LIST_URL.to_owned(),
            subnet_list_url: SUBNET_LIST_URL.to_owned(),
        }
    }

    /// # Errors
    ///
    /// Returns `RknRegistryError::Fetch` when a list cannot be downloaded, and
    /// `RknRegistryError::Empty` when a list has no IPv4 entries.
    #[expect(
        clippy::map_err_ignore,
        reason = "EmptyList is a unit marker, and Empty { url } states the \
                  same fact with the URL added"
    )]
    pub async fn fetch(&self) -> Result<RknRegistry, RknRegistryError> {
        let (addresses, subnets) = tokio::join!(
            self.get_text(&self.address_list_url),
            self.get_text(&self.subnet_list_url)
        );
        let addresses = Self::parse_addresses(&addresses?)
            .into_logged_entries("rkn addresses");
        let subnets =
            netset::parse(&subnets?).into_logged_entries("rkn subnets");
        let addresses = AddressList::new(addresses).map_err(|_| {
            RknRegistryError::Empty {
                url: self.address_list_url.clone(),
            }
        })?;
        let subnets =
            NetworkList::new(subnets).map_err(|_| RknRegistryError::Empty {
                url: self.subnet_list_url.clone(),
            })?;
        Ok(RknRegistry::new(addresses, subnets))
    }

    /// The IPv4 addresses of the address list; blank and IPv6 lines hold no
    /// entry.
    fn parse_addresses(body: &str) -> ParsedList<BTreeSet<Ipv4Addr>> {
        ParsedList::parse(body, |line| match line.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) => Ok(Line::Entry(address)),
            Ok(IpAddr::V6(_)) => Ok(Line::Skip),
            Err(_) if line.is_empty() => Ok(Line::Skip),
            Err(_) => Err(Garbage),
        })
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
        let actual = RknRegistryClient::parse_addresses(ADDRESS_LIST);

        assert_eq!(
            actual.into_logged_entries("rkn addresses"),
            BTreeSet::from([
                Ipv4Addr::new(203, 0, 113, 7),
                Ipv4Addr::new(203, 0, 113, 8),
            ])
        );
    }

    #[tokio::test]
    async fn the_registry_holds_the_ipv4_entries_of_both_lists() {
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
