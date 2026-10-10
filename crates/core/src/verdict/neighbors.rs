use crate::Verdict;
use crate::model::{
    NeighborHttps, NeighborProbe, PtrLookup, PtrName, TlsHandshake,
    TlsHandshakeFacts,
};
use itertools::Itertools as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborBucket {
    RealityBrand,
    RealityGoogle,
    OwnDomain,
    SelfSigned,
    NoHandshake,
    Closed,
}

/// Brand substrings whose certificate on a hosting IP proves a Reality node
/// forwarding to that brand's real site. Taken from the shell prototype this
/// sweep replaces; keep the two in sync if either changes.
const BRANDS: &[&str] = &[
    "microsoft.com",
    "apple.com",
    "icloud.com",
    "cloudflare.com",
    "google.com",
    "gstatic.com",
    "googleapis.com",
    "yandex",
    "vk.com",
    "vk.ru",
    "max.ru",
    "x5.ru",
    "rutube",
    "gosuslugi",
    "ozon",
    "wildberries",
    "amazon",
    "akamai",
    "samsung",
    "sony",
    "nvidia",
    "mail.ru",
    "sber",
    "tinkoff",
    "tbank",
    "whatsapp",
    "telegram",
    "speedtest",
    "github",
    "mozilla",
    "ubuntu",
    "debian",
    "yahoo",
    "bing.com",
    "itunes",
    "playstation",
    "xbox",
    "steam",
    "discord",
    "dell.com",
    "cisco",
    "oracle",
    "ibm.com",
    "intel",
    "amd.com",
    "nginx.org",
    "swift.org",
    "tesla",
    "mts.ru",
    "beeline",
    "megafon",
    "tele2",
    "2ip",
    "avito",
    "dzen",
    "kinopoisk",
    "ok.ru",
    "mos.ru",
    "nalog",
    "pochta",
    "rzd",
    "aeroflot",
    "mvideo",
    "dns-shop",
    "citilink",
    "lenta",
    "magnit",
    "wikipedia",
    "fandom",
    "reddit",
    "twitch",
    "tiktok",
    "instagram",
    "facebook",
    "netflix",
    "spotify",
    "office.com",
    "live.com",
    "skype",
    "linkedin",
    "adobe",
    "zoom.us",
    "dropbox",
    "paypal",
    "ebay",
    "aliexpress",
    "alibaba",
    "baidu",
    "qq.com",
    "bilibili",
    "huawei",
    "xiaomi",
    "lenovo",
    "asus",
    "ngenix",
    "edgecdn",
];

/// Words that make a PTR record advertise a VPN or proxy service, for the
/// candidate's own record and for its neighbors alike.
const SELF_DESCRIBING_PTR_WORDS: &[&str] = &["vpn", "proxy", "tunnel"];

impl PtrName {
    fn is_self_describing(&self) -> bool {
        let name = self.as_str().to_lowercase();
        SELF_DESCRIBING_PTR_WORDS
            .iter()
            .any(|word| name.contains(word))
    }
}

impl NeighborProbe {
    pub fn bucket(&self) -> NeighborBucket {
        let h = match &self.https {
            NeighborHttps::Closed => return NeighborBucket::Closed,
            NeighborHttps::Open {
                handshake:
                    TlsHandshake::NoCertificate | TlsHandshake::Unavailable(_),
            } => {
                return NeighborBucket::NoHandshake;
            }
            NeighborHttps::Open {
                handshake: TlsHandshake::Presented(handshake),
            } => handshake,
        };
        let cn = h.cert_cn.as_deref().unwrap_or("");
        let issuer = h.cert_issuer.as_deref().unwrap_or("");
        let blob = format!("{cn} {}", h.cert_san.join(" ")).to_lowercase();
        if blob.contains("invalid2.invalid") {
            return NeighborBucket::RealityGoogle;
        }
        if BRANDS.iter().any(|b| blob.contains(b)) {
            return NeighborBucket::RealityBrand;
        }
        let looks_default = (cn.is_empty() && h.cert_san.is_empty())
            || cn.eq_ignore_ascii_case("localhost")
            || cn.eq_ignore_ascii_case("example.com")
            || (!cn.is_empty()
                && cn.chars().all(|c| c.is_ascii_digit() || c == '.'))
            || cn.to_lowercase().contains("traefik")
            || issuer.to_lowercase().contains("caddy local")
            || issuer.is_empty();
        if looks_default {
            NeighborBucket::SelfSigned
        } else {
            NeighborBucket::OwnDomain
        }
    }

    /// The certificate this neighbor presented, if the handshake ran and
    /// produced one.
    const fn presented_certificate(&self) -> Option<&TlsHandshakeFacts> {
        match &self.https {
            NeighborHttps::Open {
                handshake: TlsHandshake::Presented(handshake),
            } => Some(handshake),
            NeighborHttps::Closed
            | NeighborHttps::Open {
                handshake:
                    TlsHandshake::NoCertificate | TlsHandshake::Unavailable(_),
            } => None,
        }
    }

    fn has_self_describing_ptr(&self) -> bool {
        match &self.ptr {
            PtrLookup::Resolved(ptr) => ptr.is_self_describing(),
            PtrLookup::NotFound | PtrLookup::Unavailable(_) => false,
        }
    }
}

pub fn judge_candidate_ptr(ptr: &PtrLookup) -> Verdict {
    match ptr {
        PtrLookup::Resolved(p) if p.is_self_describing() => Verdict::warn(
            format!("candidate's own PTR is self-describing: {p}"),
        ),
        PtrLookup::Resolved(p) => Verdict::ok(format!("PTR: {p}")),
        PtrLookup::NotFound => Verdict::ok("no PTR record"),
        PtrLookup::Unavailable(reason) => {
            Verdict::error(format!("PTR lookup unavailable: {reason}"))
        }
    }
}

// The three thresholds below came with the bucket heuristic ported from
// `neighbors.sh`; they were not calibrated against a measured sweep.

/// Responding neighbors with no real site among them that make a proxy farm.
const PROXY_FARM_MIN_RESPONDING: usize = 20;
/// Neighbors sharing one default certificate that point to one operator
/// holding the `/24`.
const ONE_OPERATOR_MIN_SHARED_CERTIFICATE: usize = 20;
/// Neighbor PTR records advertising a VPN, proxy or tunnel that warn on
/// their own.
const MIN_SELF_DESCRIBING_PTRS: usize = 5;

fn largest_identical_default_certificate_group(
    classified: &[(&NeighborProbe, NeighborBucket)],
) -> Option<usize> {
    classified
        .iter()
        .filter(|(_, bucket)| *bucket == NeighborBucket::SelfSigned)
        .filter_map(|(probe, _)| probe.presented_certificate())
        .counts_by(|handshake| {
            (
                handshake.cert_cn.clone().unwrap_or_default(),
                handshake.cert_issuer.clone().unwrap_or_default(),
            )
        })
        .into_values()
        .max()
}

pub fn judge_neighbor_extremes(probes: &[NeighborProbe]) -> Verdict {
    let classified: Vec<(&NeighborProbe, NeighborBucket)> =
        probes.iter().map(|probe| (probe, probe.bucket())).collect();
    let count_buckets = |wanted: fn(NeighborBucket) -> bool| {
        classified
            .iter()
            .filter(|(_, bucket)| wanted(*bucket))
            .count()
    };
    let responding = count_buckets(|bucket| bucket != NeighborBucket::Closed);
    let own_domain =
        count_buckets(|bucket| bucket == NeighborBucket::OwnDomain);
    let self_describing_ptrs = probes
        .iter()
        .filter(|probe| probe.has_self_describing_ptr())
        .count();
    let largest_shared_certificate =
        largest_identical_default_certificate_group(&classified);

    let proxy_farm = (responding >= PROXY_FARM_MIN_RESPONDING
        && own_domain == 0)
        .then(|| format!("{responding} neighbors respond on :443 and none looks like a real site — possible proxy farm"));
    let one_operator = largest_shared_certificate
    .filter(|count| *count >= ONE_OPERATOR_MIN_SHARED_CERTIFICATE)
    .map(|count| format!("{count} neighbors share one identical default certificate — one operator holds the /24"));
    let vpn_ptrs = (self_describing_ptrs >= MIN_SELF_DESCRIBING_PTRS)
        .then(|| {
            format!("{self_describing_ptrs} neighbor PTR records mention vpn/proxy/tunnel")
        });
    let warnings: Vec<String> = [proxy_farm, one_operator, vpn_ptrs]
        .into_iter()
        .flatten()
        .collect();

    if warnings.is_empty() {
        Verdict::ok(format!(
            "{responding} of {} neighbors responding, no extreme pattern",
            probes.len()
        ))
    } else {
        Verdict::warn(warnings.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn ptr(name: &str) -> PtrLookup {
        PtrLookup::Resolved(PtrName::try_from(name).unwrap())
    }

    fn closed(ip: &str) -> NeighborProbe {
        NeighborProbe {
            ip: ip.parse().unwrap(),
            ptr: PtrLookup::NotFound,
            https: NeighborHttps::Closed,
        }
    }
    fn no_certificate(ip: &str) -> NeighborProbe {
        NeighborProbe {
            ip: ip.parse().unwrap(),
            ptr: PtrLookup::NotFound,
            https: NeighborHttps::Open {
                handshake: TlsHandshake::NoCertificate,
            },
        }
    }

    fn handshake_unavailable(ip: &str) -> NeighborProbe {
        NeighborProbe {
            ip: ip.parse().unwrap(),
            ptr: PtrLookup::NotFound,
            https: NeighborHttps::Open {
                handshake: TlsHandshake::Unavailable(
                    "openssl handshake timed out".to_string(),
                ),
            },
        }
    }
    fn handshake(
        ip: &str,
        cn: &str,
        issuer: &str,
        san: &[&str],
    ) -> NeighborProbe {
        NeighborProbe {
            ip: ip.parse().unwrap(),
            ptr: PtrLookup::NotFound,
            https: NeighborHttps::Open {
                handshake: TlsHandshake::Presented(TlsHandshakeFacts {
                    cert_cn: Some(cn.into()),
                    cert_issuer: Some(issuer.into()),
                    cert_san: san.iter().map(ToString::to_string).collect(),
                }),
            },
        }
    }

    #[rstest::rstest]
    #[case::closed(closed("203.0.113.1"), NeighborBucket::Closed)]
    #[case::no_certificate(
        no_certificate("203.0.113.2"),
        NeighborBucket::NoHandshake
    )]
    #[case::handshake_unavailable(
        handshake_unavailable("203.0.113.9"),
        NeighborBucket::NoHandshake
    )]
    #[case::reality_google(
        handshake("203.0.113.3", "invalid2.invalid", "", &[]),
        NeighborBucket::RealityGoogle
    )]
    #[case::reality_brand(
        handshake("203.0.113.4", "www.microsoft.com", "DigiCert", &[]),
        NeighborBucket::RealityBrand
    )]
    #[case::own_domain(
        handshake(
            "203.0.113.5",
            "blog.example.org",
            "R3",
            &["blog.example.org"]
        ),
        NeighborBucket::OwnDomain
    )]
    // example.com is a default-page CN (same as neighbors.sh), not a real site
    #[case::default_page_cn(
        handshake("203.0.113.8", "example.com", "R3", &["example.com"]),
        NeighborBucket::SelfSigned
    )]
    #[case::empty_cn(
        handshake("203.0.113.6", "", "", &[]),
        NeighborBucket::SelfSigned
    )]
    #[case::cn_is_the_address(
        handshake("203.0.113.7", "203.0.113.7", "", &[]),
        NeighborBucket::SelfSigned
    )]
    fn a_neighbor_falls_into_one_bucket(
        #[case] sut: NeighborProbe,
        #[case] expected: NeighborBucket,
    ) {
        let actual = sut.bucket();

        assert_eq!(actual, expected);
    }

    #[rstest::rstest]
    #[case::a_hoster_name(ptr("host.example-hoster.net"), Severity::Ok)]
    #[case::no_record(PtrLookup::NotFound, Severity::Ok)]
    #[case::a_vpn_name(ptr("vpn123.example-hoster.net"), Severity::Warn)]
    #[case::a_proxy_name(ptr("client.proxy-pool.example.net"), Severity::Warn)]
    #[case::a_tunnel_name(ptr("Tunnel-7.example.net"), Severity::Warn)]
    fn a_self_describing_ptr_warns_and_any_other_is_ok(
        #[case] sut: PtrLookup,
        #[case] expected: Severity,
    ) {
        let verdict = judge_candidate_ptr(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[test]
    fn an_unavailable_ptr_lookup_is_not_reported_as_no_record() {
        let verdict = judge_candidate_ptr(&PtrLookup::Unavailable(
            "dig is not installed".to_string(),
        ));

        assert_eq!(verdict.severity, Severity::Error);
        assert!(verdict.detail.contains("dig is not installed"));
    }

    #[test]
    fn no_extreme_pattern_among_ordinary_neighbors_is_ok() {
        let sut = vec![
            handshake("203.0.113.10", "blog.example.org", "R3", &[]),
            handshake("203.0.113.11", "www.apple.com", "DigiCert", &[]),
            no_certificate("203.0.113.12"),
            closed("203.0.113.13"),
        ];

        let verdict = judge_neighbor_extremes(&sut);

        assert_eq!(verdict.severity, Severity::Ok, "{}", verdict.detail);
    }

    #[test]
    fn twenty_plus_responding_with_zero_real_sites_warns_as_a_proxy_farm() {
        let sut: Vec<NeighborProbe> = (0..22)
            .map(|i| {
                handshake(
                    &format!("203.0.113.{i}"),
                    "invalid2.invalid",
                    "",
                    &[],
                )
            })
            .collect();

        let verdict = judge_neighbor_extremes(&sut);

        assert_eq!(verdict.severity, Severity::Warn, "{}", verdict.detail);
        assert!(verdict.detail.contains("proxy farm"), "{}", verdict.detail);
    }

    #[test]
    fn twenty_plus_identical_self_signed_certs_warns_as_one_operator() {
        // One real site keeps the proxy-farm warning out of the detail.
        let real_site =
            handshake("203.0.113.99", "blog.example.org", "R3", &[]);
        let sut: Vec<NeighborProbe> = (0..22)
            .map(|i| handshake(&format!("203.0.113.{i}"), "", "", &[]))
            .chain([real_site])
            .collect();

        let verdict = judge_neighbor_extremes(&sut);

        assert_eq!(verdict.severity, Severity::Warn, "{}", verdict.detail);
        assert!(verdict.detail.contains("one operator"), "{}", verdict.detail);
    }

    fn named_neighbor(ip: &str, name: &str) -> NeighborProbe {
        NeighborProbe {
            ip: ip.parse().unwrap(),
            ptr: ptr(name),
            https: NeighborHttps::Open {
                handshake: TlsHandshake::NoCertificate,
            },
        }
    }

    #[test]
    fn five_plus_vpn_labeled_ptrs_among_neighbors_warns() {
        let sut = vec![
            named_neighbor("203.0.113.1", "vpn1.example.net"),
            named_neighbor("203.0.113.2", "vpn2.example.net"),
            named_neighbor("203.0.113.3", "vpn3.example.net"),
            named_neighbor("203.0.113.4", "vpn4.example.net"),
            named_neighbor("203.0.113.5", "vpn5.example.net"),
            handshake("203.0.113.99", "blog.example.org", "R3", &[]),
        ];

        let verdict = judge_neighbor_extremes(&sut);

        assert_eq!(verdict.severity, Severity::Warn, "{}", verdict.detail);
    }

    #[test]
    fn tunnel_labeled_neighbor_ptrs_count_like_the_candidate_s_own() {
        let sut = vec![
            named_neighbor("203.0.113.1", "tunnel1.example.net"),
            named_neighbor("203.0.113.2", "tunnel2.example.net"),
            named_neighbor("203.0.113.3", "vpn3.example.net"),
            named_neighbor("203.0.113.4", "proxy4.example.net"),
            named_neighbor("203.0.113.5", "tunnel5.example.net"),
        ];

        let verdict = judge_neighbor_extremes(&sut);

        assert_eq!(
            verdict.detail,
            "5 neighbor PTR records mention vpn/proxy/tunnel"
        );
    }
}
