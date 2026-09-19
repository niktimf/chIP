use crate::Verdict;
use crate::model::NeighborProbe;
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
    if !probe.tcp_open {
        return NeighborBucket::Closed;
    }
    let Some(h) = &probe.handshake else {
        return NeighborBucket::NoHandshake;
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
        || (!cn.is_empty() && cn.chars().all(|c| c.is_ascii_digit() || c == '.'))
        || cn.to_lowercase().contains("traefik")
        || issuer.to_lowercase().contains("caddy local")
        || issuer.is_empty();
    if looks_default {
        NeighborBucket::SelfSigned
    } else {
        NeighborBucket::OwnDomain
    }
}

pub fn judge_candidate_ptr(ptr: Option<&str>) -> Verdict {
    match ptr {
        Some(p)
            if ["vpn", "proxy", "tunnel"]
                .iter()
                .any(|k| p.to_lowercase().contains(k)) =>
        {
            Verdict::warn(format!("candidate's own PTR is self-describing: {p}"))
        }
        Some(p) => Verdict::ok(format!("PTR: {p}")),
        None => Verdict::ok("no PTR record"),
    }
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

    // How many self-signed neighbors share the exact same (CN, issuer) —
    // `counts_by` groups and counts in one pass, replacing what would
    // otherwise be a manual `HashMap::entry().or_insert()` accumulator.
    let identical_counts = probes
        .iter()
        .zip(&buckets)
        .filter(|(_, bucket)| **bucket == NeighborBucket::SelfSigned)
        .filter_map(|(probe, _)| probe.handshake.as_ref())
        .counts_by(|h| {
            (
                h.cert_cn.clone().unwrap_or_default(),
                h.cert_issuer.clone().unwrap_or_default(),
            )
        });
    if let Some(&count) = identical_counts.values().max() {
        if count >= 20 {
            warnings.push(format!("{count} neighbors share one identical default certificate — one operator holds the /24"));
        }
    }

    let vpn_ptrs = probes
        .iter()
        .filter(|p| {
            p.ptr.as_deref().is_some_and(|s| {
                let l = s.to_lowercase();
                l.contains("vpn") || l.contains("proxy")
            })
        })
        .count();
    if vpn_ptrs >= 5 {
        warnings.push(format!("{vpn_ptrs} neighbor PTR records mention vpn/proxy"));
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
