//! Live check against the real RKN registry export on antifilter.download.
//! Ignored by default: it needs the public internet.
//!
//! ```sh
//! cargo test -p chip-io --test live_rkn_registry -- --ignored
//! ```
//!
//! Uses public addresses whose status has not changed for years: Google
//! Public DNS is not blocked, and Meta's networks have been blocked as whole
//! subnets since 2022. If the second test starts failing, check the export
//! before the parser: the registry may have changed.

use std::net::Ipv4Addr;

use chip_core::ip_lists::RknRegistry;
use chip_core::model::RknListing;
use chip_io::rkn_registry::RknRegistryClient;
use rstest::rstest;

async fn registry() -> RknRegistry {
    RknRegistryClient::new(reqwest::Client::new())
        .fetch()
        .await
        .expect("antifilter.download should serve both lists")
}

#[rstest]
#[case::google_public_dns(
    Ipv4Addr::new(8, 8, 8, 8),
    |listing| listing == RknListing::NotListed
)]
// Only the variant: the registry may re-slice Meta's networks at any time.
#[case::meta(
    Ipv4Addr::new(157, 240, 0, 35),
    |listing| matches!(listing, RknListing::Subnet(_))
)]
#[tokio::test]
#[ignore = "needs the public internet"]
async fn a_public_address_has_its_long_standing_registry_entry(
    #[case] ip: Ipv4Addr,
    #[case] expected: fn(RknListing) -> bool,
) {
    let sut = registry().await;

    let facts = sut.check(ip).unwrap();

    assert!(expected(facts.listing()), "{facts:?}");
}
