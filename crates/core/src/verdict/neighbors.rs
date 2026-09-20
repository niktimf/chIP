use crate::Verdict;
use crate::model::{NeighborHttps, NeighborProbe, PtrLookup};
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
/// forwarding to that brand's real site. Verbatim from
/// the shell prototype this sweep replaces
/// — keep the two in sync if either changes.
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

pub fn classify(probe: &NeighborProbe) -> NeighborBucket {
    let h = match &probe.https {
        NeighborHttps::Closed => return NeighborBucket::Closed,
        NeighborHttps::Open { handshake: None } => {
            return NeighborBucket::NoHandshake;
        }
        NeighborHttps::Open {
            handshake: Some(handshake),
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

pub fn judge_candidate_ptr(ptr: &PtrLookup) -> Verdict {
    match ptr {
        PtrLookup::Resolved(p)
            if ["vpn", "proxy", "tunnel"]
                .iter()
                .any(|k| p.as_str().to_lowercase().contains(k)) =>
        {
            Verdict::warn(format!(
                "candidate's own PTR is self-describing: {p}"
            ))
        }
        PtrLookup::Resolved(p) => Verdict::ok(format!("PTR: {p}")),
        PtrLookup::NotFound => Verdict::ok("no PTR record"),
        PtrLookup::Unavailable(reason) => {
            Verdict::error(format!("PTR lookup unavailable: {reason}"))
        }
    }
}

fn largest_identical_default_certificate_group(
    probes: &[NeighborProbe],
    buckets: &[NeighborBucket],
) -> Option<usize> {
    probes
        .iter()
        .zip(buckets)
        .filter(|(_, bucket)| **bucket == NeighborBucket::SelfSigned)
        .filter_map(|(probe, _)| match &probe.https {
            NeighborHttps::Open {
                handshake: Some(handshake),
            } => Some(handshake),
            NeighborHttps::Closed | NeighborHttps::Open { handshake: None } => {
                None
            }
        })
        .counts_by(|handshake| {
            (
                handshake.cert_cn.clone().unwrap_or_default(),
                handshake.cert_issuer.clone().unwrap_or_default(),
            )
        })
        .into_values()
        .max()
}

fn vpn_ptr_count(probes: &[NeighborProbe]) -> usize {
    probes
        .iter()
        .filter(|probe| {
            let PtrLookup::Resolved(ptr) = &probe.ptr else {
                return false;
            };
            let ptr = ptr.as_str().to_lowercase();
            ptr.contains("vpn") || ptr.contains("proxy")
        })
        .count()
}

pub fn judge_neighbor_extremes(probes: &[NeighborProbe]) -> Verdict {
    let buckets: Vec<NeighborBucket> = probes.iter().map(classify).collect();
    let responding = buckets
        .iter()
        .filter(|b| **b != NeighborBucket::Closed)
        .count();
    let own_domain = buckets
        .iter()
        .filter(|b| **b == NeighborBucket::OwnDomain)
        .count();
    let mut warnings = Vec::new();

    if responding >= 20 && own_domain == 0 {
        warnings.push(format!("{responding} neighbors respond on :443 and none looks like a real site — possible proxy farm"));
    }

    if let Some(count) =
        largest_identical_default_certificate_group(probes, &buckets)
            .filter(|count| *count >= 20)
    {
        warnings.push(format!("{count} neighbors share one identical default certificate — one operator holds the /24"));
    }

    let vpn_ptrs = vpn_ptr_count(probes);
    if vpn_ptrs >= 5 {
        warnings
            .push(format!("{vpn_ptrs} neighbor PTR records mention vpn/proxy"));
    }

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
    use crate::model::{PtrName, Severity, TlsHandshakeFacts};

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
    fn no_handshake(ip: &str) -> NeighborProbe {
        NeighborProbe {
            ip: ip.parse().unwrap(),
            ptr: PtrLookup::NotFound,
            https: NeighborHttps::Open { handshake: None },
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
                handshake: Some(TlsHandshakeFacts {
                    cert_cn: Some(cn.into()),
                    cert_issuer: Some(issuer.into()),
                    cert_san: san.iter().map(ToString::to_string).collect(),
                }),
            },
        }
    }

    #[test]
    fn classify_reads_the_four_buckets() {
        assert_eq!(classify(&closed("203.0.113.1")), NeighborBucket::Closed);
        assert_eq!(
            classify(&no_handshake("203.0.113.2")),
            NeighborBucket::NoHandshake
        );
        assert_eq!(
            classify(&handshake("203.0.113.3", "invalid2.invalid", "", &[])),
            NeighborBucket::RealityGoogle
        );
        assert_eq!(
            classify(&handshake(
                "203.0.113.4",
                "www.microsoft.com",
                "DigiCert",
                &[]
            )),
            NeighborBucket::RealityBrand
        );
        assert_eq!(
            classify(&handshake(
                "203.0.113.5",
                "blog.example.org",
                "R3",
                &["blog.example.org"]
            )),
            NeighborBucket::OwnDomain
        );
        // example.com is a default-page CN (same as neighbors.sh), not a real site
        assert_eq!(
            classify(&handshake(
                "203.0.113.8",
                "example.com",
                "R3",
                &["example.com"]
            )),
            NeighborBucket::SelfSigned
        );
        assert_eq!(
            classify(&handshake("203.0.113.6", "", "", &[])),
            NeighborBucket::SelfSigned
        );
        assert_eq!(
            classify(&handshake("203.0.113.7", "203.0.113.7", "", &[])),
            NeighborBucket::SelfSigned
        );
    }

    #[test]
    fn a_clean_ptr_is_ok() {
        assert_eq!(
            judge_candidate_ptr(&ptr("host.example-hoster.net")).severity,
            Severity::Ok
        );
        assert_eq!(
            judge_candidate_ptr(&PtrLookup::NotFound).severity,
            Severity::Ok
        );
    }

    #[test]
    fn a_self_describing_ptr_warns() {
        assert_eq!(
            judge_candidate_ptr(&ptr("vpn123.example-hoster.net")).severity,
            Severity::Warn
        );
        assert_eq!(
            judge_candidate_ptr(&ptr("client.proxy-pool.example.net")).severity,
            Severity::Warn
        );
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
            no_handshake("203.0.113.12"),
            closed("203.0.113.13"),
        ];
        assert_eq!(judge_neighbor_extremes(&sut).severity, Severity::Ok);
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
        let mut sut: Vec<NeighborProbe> = (0..22)
            .map(|i| handshake(&format!("203.0.113.{i}"), "", "", &[]))
            .collect();
        sut.push(handshake("203.0.113.99", "blog.example.org", "R3", &[])); // keep at least one real site

        let verdict = judge_neighbor_extremes(&sut);

        assert_eq!(verdict.severity, Severity::Warn, "{}", verdict.detail);
        assert!(verdict.detail.contains("one operator"), "{}", verdict.detail);
    }

    #[test]
    fn five_plus_vpn_labeled_ptrs_among_neighbors_warns() {
        let mut sut: Vec<NeighborProbe> = (0..5)
            .map(|i| NeighborProbe {
                ip: format!("203.0.113.{i}").parse().unwrap(),
                ptr: ptr(&format!("vpn{i}.example.net")),
                https: NeighborHttps::Open { handshake: None },
            })
            .collect();
        sut.push(handshake("203.0.113.99", "blog.example.org", "R3", &[]));

        let verdict = judge_neighbor_extremes(&sut);

        assert_eq!(verdict.severity, Severity::Warn, "{}", verdict.detail);
    }
}
