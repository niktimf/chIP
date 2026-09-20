use std::time::Duration;

use chip_core::model::{CaptchaObservation, CountryCode, ServiceCountryVote};
use regex::regex;

use super::client::{TunnelClient, TunnelResponse};
use super::services::BROWSER_UA;

const FAST_API_URL: &str = "https://api.fast.com/netflix/speedtest/v2?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=1";
const RU_IATA_CODES: &[&str] = &[
    "SVO", "DME", "VKO", "MOW", "LED", "KZN", "SVX", "OVB", "KJA", "ROV",
    "AER", "KHV", "VVO",
];

fn country(raw: &str) -> Option<CountryCode> {
    CountryCode::try_from(raw.trim()).ok()
}

fn json_string(body: &str, pointer: &str) -> Option<String> {
    let owned = serde_json::from_str::<serde_json::Value>(body).ok()?;
    owned.pointer(pointer)?.as_str().map(ToString::to_string)
}

fn google_country(body: &str) -> Option<CountryCode> {
    regex!(r#""[a-z]{2}_([A-Z]{2})""#)
        .captures(body)
        .and_then(|captures| captures.get(1))
        .and_then(|matched| country(matched.as_str()))
        .or_else(|| {
            regex!(r#""[a-z]{2}-([A-Z]{2})""#)
                .captures_iter(body)
                .last()
                .and_then(|captures| captures.get(1))
                .and_then(|matched| country(matched.as_str()))
        })
}

fn youtube_country(body: &str) -> Option<CountryCode> {
    regex!(r#""countryCode":"(\w+)""#)
        .captures(body)?
        .get(1)
        .and_then(|matched| country(matched.as_str()))
}

fn spotify_country(body: &str) -> Option<CountryCode> {
    regex!(r#""geoLocationCountryCode":"([^"]*)""#)
        .captures(body)?
        .get(1)
        .and_then(|matched| country(matched.as_str()))
}

fn bing_country(body: &str) -> Option<CountryCode> {
    if body.contains("cn.bing.com") {
        return country("CN");
    }
    let value = regex!(r#"Region\s*:\s*"([^"]+)""#)
        .captures(body)?
        .get(1)?
        .as_str();
    (value != "WW").then(|| country(value)).flatten()
}

async fn response(client: &TunnelClient, url: &str) -> Option<TunnelResponse> {
    client.get(url, &[("User-Agent", BROWSER_UA)]).await.ok()
}

pub async fn probe_country_votes(
    client: &TunnelClient,
) -> Vec<ServiceCountryVote> {
    let (google, youtube, apple, spotify, netflix, tiktok, bing) = tokio::join!(
        response(client, "https://www.google.com"),
        response(client, "https://www.youtube.com"),
        response(client, "https://gspe1-ssl.ls.apple.com/pep/gcc"),
        response(client, "https://accounts.spotify.com/status"),
        response(client, FAST_API_URL),
        response(
            client,
            "https://www.tiktok.com/api/v1/web-cookie-privacy/config?appId=1988"
        ),
        response(client, "https://www.bing.com/search?q=cats")
    );

    let google = google.as_ref().and_then(|item| google_country(&item.body));
    let youtube = youtube
        .as_ref()
        .and_then(|item| youtube_country(&item.body))
        .or(google);
    vec![
        ServiceCountryVote {
            service: "google",
            country: google,
        },
        ServiceCountryVote {
            service: "youtube",
            country: youtube,
        },
        ServiceCountryVote {
            service: "apple",
            country: apple.as_ref().and_then(|item| country(&item.body)),
        },
        ServiceCountryVote {
            service: "spotify",
            country: spotify
                .as_ref()
                .and_then(|item| spotify_country(&item.body)),
        },
        ServiceCountryVote {
            service: "netflix",
            country: netflix
                .as_ref()
                .and_then(|item| {
                    json_string(&item.body, "/client/location/country")
                })
                .and_then(|value| country(&value)),
        },
        ServiceCountryVote {
            service: "tiktok",
            country: tiktok
                .as_ref()
                .and_then(|item| {
                    json_string(&item.body, "/body/appProps/region")
                })
                .and_then(|value| country(&value)),
        },
        ServiceCountryVote {
            service: "bing",
            country: bing.as_ref().and_then(|item| bing_country(&item.body)),
        },
    ]
}

async fn captcha_observation(
    client: &TunnelClient,
    url: &str,
) -> CaptchaObservation {
    match client
        .get(
            url,
            &[
                ("User-Agent", BROWSER_UA),
                ("Accept-Language", "en-US,en;q=0.9"),
            ],
        )
        .await
    {
        Err(error) => CaptchaObservation::Unavailable(error.to_string()),
        Ok(response)
            if response.status == 429
                || regex!(
                    r"(?i)unusual traffic from|is blocked|unaddressed abuse"
                )
                .is_match(&response.body) =>
        {
            CaptchaObservation::Triggered
        }
        Ok(_) => CaptchaObservation::Clear,
    }
}

pub async fn probe_search_captcha(
    client: &TunnelClient,
) -> (CaptchaObservation, CaptchaObservation) {
    let url = "https://www.google.com/search?q=cats";
    let first = captcha_observation(client, url).await;
    tokio::time::sleep(Duration::from_secs(30)).await;
    let second = captcha_observation(client, url).await;
    (first, second)
}

fn value_from_lines(body: &str, key: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate == key).then(|| value.trim().to_string())
    })
}

fn ggc_iata(body: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let cluster = line.split_whitespace().nth(2)?;
        let cluster = cluster
            .rsplit_once('-')
            .map_or(cluster, |(_, suffix)| suffix);
        let code = cluster.get(..3)?.to_ascii_uppercase();
        (code.bytes().all(|byte| byte.is_ascii_uppercase())).then_some(code)
    })
}

fn iata_country(code: &str) -> Option<CountryCode> {
    if RU_IATA_CODES.contains(&code) {
        return country("RU");
    }
    let mapped = match code {
        "HEL" => "FI",
        "FRA" | "BER" | "MUC" | "DUS" | "HAM" => "DE",
        "AMS" => "NL",
        "ARN" | "STO" => "SE",
        "LHR" | "LON" => "GB",
        "CDG" | "PAR" => "FR",
        "WAW" => "PL",
        "RIX" => "LV",
        "TLL" => "EE",
        "VNO" => "LT",
        _ => return None,
    };
    country(mapped)
}

pub async fn probe_cdn_edges(
    client: &TunnelClient,
) -> Vec<(&'static str, Option<CountryCode>)> {
    let (cloudflare, youtube, netflix) = tokio::join!(
        response(client, "https://www.cloudflare.com/cdn-cgi/trace"),
        response(
            client,
            "https://redirector.googlevideo.com/report_mapping?di=no"
        ),
        response(client, FAST_API_URL)
    );
    vec![
        (
            "cloudflare",
            cloudflare
                .as_ref()
                .and_then(|item| value_from_lines(&item.body, "colo"))
                .and_then(|code| iata_country(&code)),
        ),
        (
            "youtube_ggc",
            youtube
                .as_ref()
                .and_then(|item| ggc_iata(&item.body))
                .and_then(|code| iata_country(&code)),
        ),
        (
            "netflix_oca",
            netflix
                .as_ref()
                .and_then(|item| {
                    json_string(&item.body, "/targets/0/location/country")
                })
                .and_then(|value| country(&value)),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsers_read_the_upstream_wire_shapes() {
        assert_eq!(google_country(r#"x "en_FI" y"#).unwrap().as_str(), "FI");
        assert_eq!(
            youtube_country(r#"{"countryCode":"DE"}"#).unwrap().as_str(),
            "DE"
        );
        assert_eq!(
            spotify_country(r#"{"geoLocationCountryCode":"NL"}"#)
                .unwrap()
                .as_str(),
            "NL"
        );
        assert_eq!(
            ggc_iata("192.0.2.0/24 => fra16s52").as_deref(),
            Some("FRA")
        );
    }

    #[test]
    fn russian_iata_codes_are_recognized() {
        assert_eq!(iata_country("SVO").unwrap().as_str(), "RU");
    }
}
