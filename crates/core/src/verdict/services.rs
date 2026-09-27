//! Classification for the ChatGPT/Gemini/YouTube Premium/Netflix/Claude/
//! TikTok/NotebookLM probes, ported from `remnawave/geocheck` v0.3.0
//! (`internal/access/checks.go`, v0.3.0).
//!
//! This module only classifies an already-fetched response. The I/O crate does
//! the actual fetching through the SOCKS tunnel and calls the matching
//! `classify_*` function.

use crate::Verdict;
use crate::model::ServiceState;
use http::StatusCode;
use regex::regex;
use url::Url;

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

pub fn classify_chatgpt_web(body: &str) -> ServiceState {
    if contains_ci(body, "unsupported_country") {
        ServiceState::Blocked
    } else {
        ServiceState::Available
    }
}

fn is_cloudflare_challenge(status: StatusCode, body_lower: &str) -> bool {
    [
        StatusCode::FORBIDDEN,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::SERVICE_UNAVAILABLE,
    ]
    .contains(&status)
        && [
            "cf_chl_opt",
            "_cf_chl",
            "just a moment",
            "cf-browser-verification",
            "enable javascript and cookies to continue",
            "cf-mitigated",
            "checking your browser",
        ]
        .iter()
        .any(|marker| body_lower.contains(marker))
}

pub fn classify_chatgpt_app(status: StatusCode, body: &str) -> ServiceState {
    let lower = body.to_lowercase();
    if is_cloudflare_challenge(status, &lower) {
        return ServiceState::Error("Cloudflare challenged the request".into());
    }
    if lower.contains("disallowed isp") {
        return ServiceState::Blocked;
    }
    if lower.contains("been blocked") {
        return ServiceState::Blocked;
    }
    ServiceState::Available
}

pub fn classify_youtube_premium(body: &str) -> ServiceState {
    let lower = body.to_lowercase();
    if lower.contains("youtube premium is not available in your country") {
        ServiceState::Blocked
    } else if lower.contains("ad-free") {
        ServiceState::Available
    } else {
        ServiceState::Error(
            "neither the offer nor the refusal wording was present".into(),
        )
    }
}

/// Pulls the ISO 3166-1 alpha-3 region code out of the configuration block
/// Google's account bar embeds in every one of its pages, mirroring
/// geocheck's `reGeminiRegion` regex (`,\d+,\d+,200,"([A-Z]{3})"`,
/// `internal/access/checks.go`).
fn extract_gemini_region(body: &str) -> Option<&str> {
    regex!(r#",\d+,\d+,200,"([A-Z]{3})""#)
        .captures(body)?
        .get(1)
        .map(|matched| matched.as_str())
}

/// Countries where Google does not offer Gemini, ported verbatim from
/// geocheck's `geminiUnsupported` map (`internal/access/checks.go`, v0.3.0,
/// confirmed against v0.3.0).
///
/// The upstream mechanism is not a body-marker match: it extracts a region
/// code and checks it against this list.
pub const fn gemini_unsupported_regions() -> &'static [&'static str] {
    &["RUS", "BLR", "CHN", "PRK", "IRN", "CUB", "SYR"]
}

/// Classifies a Gemini probe. Unlike `classify_claude`/`classify_tiktok`,
/// this is not a body-marker match — geocheck's real `classifyGemini`
///
/// extracts the region Google's own page says it served and checks that
/// against [`gemini_unsupported_regions`], so there is no `markers`
/// parameter here (see that function's doc comment).
pub fn classify_gemini(status: StatusCode, body: &str) -> ServiceState {
    let lower = body.to_lowercase();
    if is_cloudflare_challenge(status, &lower) {
        return ServiceState::Error(
            "Cloudflare challenged the request, so availability was never tested".into(),
        );
    }
    if !(status.is_success() || status.is_redirection()) {
        return ServiceState::Error(format!("unexpected HTTP {status}"));
    }
    match extract_gemini_region(body) {
        Some(region) if gemini_unsupported_regions().contains(&region) => {
            ServiceState::Blocked
        }
        Some(_) => ServiceState::Available,
        None => ServiceState::Error(
            "could not read the served region from the page".into(),
        ),
    }
}

pub fn classify_notebooklm(
    status: StatusCode,
    final_url: &Url,
    body: &str,
) -> ServiceState {
    if is_cloudflare_challenge(status, &body.to_lowercase()) {
        return ServiceState::Error(
            "Cloudflare challenged the request, so availability was never tested".into(),
        );
    }
    if final_url
        .query_pairs()
        .any(|(key, value)| key == "location" && value == "unsupported")
    {
        return ServiceState::Blocked;
    }
    let host = final_url.host_str().unwrap_or_default();
    let is_google_signin = host == "accounts.google.com"
        || (host.ends_with(".google.com")
            && final_url.path().contains("/login"));
    if is_google_signin {
        return ServiceState::Available;
    }
    if status.is_success() || status.is_redirection() {
        ServiceState::Error(format!("unexpected destination: {final_url}"))
    } else {
        ServiceState::Error(format!("unexpected HTTP {status}"))
    }
}

/// HTTP statuses of the two Netflix title probes. Named fields, because the
/// two probes have the same type and swapping them silently turns
/// "originals only" into a full catalogue.
#[derive(Debug, Clone, Copy)]
pub struct NetflixTitleStatuses {
    /// A licensed (non-Netflix-produced) title: present only where the full
    /// catalogue is.
    pub licensed: StatusCode,
    /// A Netflix original: present wherever Netflix works at all.
    pub original: StatusCode,
}

pub fn classify_netflix(statuses: NetflixTitleStatuses) -> ServiceState {
    match (
        statuses.licensed == StatusCode::OK,
        statuses.original == StatusCode::OK,
    ) {
        (true, _) => ServiceState::Available,
        (false, true) => ServiceState::Restricted,
        (false, false) => ServiceState::Blocked,
    }
}

/// geocheck's literal `claudeUnavailableMarkers` list (`internal/access/checks.go`,
/// v0.3.0). The apostrophe appears both
///
/// literally and HTML-escaped depending on how the page is rendered, so both
/// forms are matched, same as upstream.
pub const fn claude_unavailable_markers() -> &'static [&'static str] {
    &[
        "app unavailable in region",
        "/app-unavailable-in-region",
        "unfortunately, claude isn't available here.",
        "unfortunately, claude isn&apos;t available here.",
        "unfortunately, claude isn&#39;t available here.",
    ]
}

pub fn classify_claude(
    status: StatusCode,
    body: &str,
    markers: &[&str],
) -> ServiceState {
    let lower = body.to_lowercase();
    if is_cloudflare_challenge(status, &lower) {
        return ServiceState::Error("Cloudflare challenged the request".into());
    }
    if markers.iter().any(|m| lower.contains(&m.to_lowercase())) {
        return ServiceState::Blocked;
    }
    if status == StatusCode::FORBIDDEN {
        return ServiceState::Error(
            "HTTP 403 without the region page, so the cause is unknown".into(),
        );
    }
    if status.is_success() || status.is_redirection() {
        ServiceState::Available
    } else {
        ServiceState::Error(format!("unexpected HTTP {status}"))
    }
}

pub fn classify_tiktok(status: StatusCode, body: &str) -> ServiceState {
    if [
        "service is currently unavailable in your region",
        "tiktok is not available in your country",
        "tiktok is unavailable in your country",
        "not available in your region",
    ]
    .iter()
    .any(|marker| contains_ci(body, marker))
    {
        ServiceState::Blocked
    } else if status.is_success() || status.is_redirection() {
        ServiceState::Available
    } else {
        ServiceState::Error(format!("unexpected HTTP {status}"))
    }
}

/// Judges one primary service (a `service:*` gate that may FAIL the scan).
/// The gate id already names the service, so the detail carries only the
/// state and, for an unjudgeable probe, the reason.
pub fn judge_service_fail(state: &ServiceState) -> Verdict {
    match state {
        ServiceState::Available => Verdict::ok("available"),
        ServiceState::Restricted => Verdict::warn("restricted"),
        ServiceState::Blocked => Verdict::fail("blocked"),
        ServiceState::Error(reason) => {
            Verdict::warn(format!("could not be judged: {reason}"))
        }
        ServiceState::Unavailable(reason) => {
            Verdict::error(format!("unavailable: {reason}"))
        }
    }
}

/// Judges one secondary service: a block is worth a warning, never a FAIL,
/// because losing it does not disqualify the exit on its own.
pub fn judge_service_warn(state: &ServiceState) -> Verdict {
    match state {
        ServiceState::Available => Verdict::ok("available"),
        ServiceState::Restricted => Verdict::warn("restricted"),
        ServiceState::Blocked => Verdict::warn("blocked"),
        ServiceState::Error(reason) => {
            Verdict::warn(format!("could not be judged: {reason}"))
        }
        ServiceState::Unavailable(reason) => {
            Verdict::error(format!("unavailable: {reason}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use rstest::rstest;

    const CLOUDFLARE_CHALLENGE: &str =
        "Checking your browser before accessing... cf-mitigated";

    fn url(raw: &str) -> Url {
        Url::parse(raw).unwrap()
    }

    fn status(code: u16) -> StatusCode {
        StatusCode::from_u16(code).unwrap()
    }

    #[rstest]
    #[case::unsupported_country_in_any_case(
        "...Unsupported_Country_Region_Territory...",
        ServiceState::Blocked
    )]
    #[case::no_marker("{}", ServiceState::Available)]
    fn chatgpt_web_reads_the_unsupported_country_marker(
        #[case] sut: &str,
        #[case] expected: ServiceState,
    ) {
        let actual = classify_chatgpt_web(sut);

        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case::disallowed_isp("Disallowed ISP detected", ServiceState::Blocked)]
    #[case::been_blocked("you have been blocked", ServiceState::Blocked)]
    #[case::no_marker("hello", ServiceState::Available)]
    fn chatgpt_app_reads_disallowed_isp_and_been_blocked(
        #[case] sut: &str,
        #[case] expected: ServiceState,
    ) {
        let actual = classify_chatgpt_app(status(200), sut);

        assert_eq!(actual, expected);
    }

    #[test]
    fn chatgpt_app_treats_a_cloudflare_challenge_as_unproven_not_blocked() {
        let sut = CLOUDFLARE_CHALLENGE;

        let actual = classify_chatgpt_app(status(403), sut);

        assert!(matches!(actual, ServiceState::Error(_)), "{actual:?}");
    }

    #[rstest]
    #[case::not_available(
        "YouTube Premium is not available in your country",
        ServiceState::Blocked
    )]
    #[case::ad_free_offer("Enjoy ad-free videos", ServiceState::Available)]
    fn youtube_premium_reads_its_own_two_markers(
        #[case] sut: &str,
        #[case] expected: ServiceState,
    ) {
        let actual = classify_youtube_premium(sut);

        assert_eq!(actual, expected);
    }

    #[test]
    fn youtube_premium_unrecognized_body_is_an_error_not_a_verdict() {
        let sut = "neither marker present";

        let actual = classify_youtube_premium(sut);

        assert!(matches!(actual, ServiceState::Error(_)), "{actual:?}");
    }

    // Real body shape (geocheck's `reGeminiRegion`): a config array entry
    // `,<n>,<n>,200,"<ISO-3166-1 alpha-3>"` embedded in Google's account bar.
    #[rstest]
    #[case::unsupported_region(
        r#"...,7,42,200,"RUS",..."#,
        ServiceState::Blocked
    )]
    #[case::supported_region(
        r#"...,7,42,200,"USA",..."#,
        ServiceState::Available
    )]
    // `,200,"ABC"` lacks the `,\d+,\d+,` prefix the real regex requires, so
    // the later account-bar entry must win.
    #[case::a_decoy_before_the_real_entry(
        r#",200,"ABC" junk ,7,42,200,"RUS" tail"#,
        ServiceState::Blocked
    )]
    fn gemini_reads_the_embedded_region_against_googles_unsupported_list(
        #[case] sut: &str,
        #[case] expected: ServiceState,
    ) {
        let actual = classify_gemini(status(200), sut);

        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case::no_region(200, "no region code embedded here")]
    // With no valid match anywhere the body stays unreadable.
    #[case::only_a_decoy(200, r#"preamble ,200,"ABC" trailer"#)]
    #[case::cloudflare_challenge(403, CLOUDFLARE_CHALLENGE)]
    fn gemini_without_a_readable_region_is_an_error_not_a_verdict(
        #[case] code: u16,
        #[case] sut: &str,
    ) {
        let actual = classify_gemini(status(code), sut);

        assert!(matches!(actual, ServiceState::Error(_)), "{actual:?}");
    }

    #[rstest]
    #[case::unsupported_location(
        "https://notebooklm.google.com/?location=unsupported",
        ServiceState::Blocked
    )]
    #[case::sign_in_redirect(
        "https://accounts.google.com/signin",
        ServiceState::Available
    )]
    fn notebooklm_reads_the_redirect_reason_directly(
        #[case] sut: &str,
        #[case] expected: ServiceState,
    ) {
        let actual = classify_notebooklm(status(302), &url(sut), "");

        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case::unexpected_page(200, "https://notebooklm.google.com/weird", "")]
    #[case::cloudflare_page(
        503,
        "https://notebooklm.google.com/",
        "<title>Just a moment</title>"
    )]
    #[case::lookalike_host(
        302,
        "https://accounts.google.com.attacker.example/signin",
        ""
    )]
    #[case::reason_in_the_path_instead_of_the_query(
        302,
        "https://attacker.example/location=unsupported",
        ""
    )]
    fn notebooklm_does_not_trust_anything_but_the_structured_redirect(
        #[case] code: u16,
        #[case] sut: &str,
        #[case] body: &str,
    ) {
        let actual = classify_notebooklm(status(code), &url(sut), body);

        assert!(matches!(actual, ServiceState::Error(_)), "{actual:?}");
    }

    #[rstest]
    #[case::full_catalogue(
        NetflixTitleStatuses { licensed: status(200), original: status(200) },
        ServiceState::Available
    )]
    #[case::originals_only(
        NetflixTitleStatuses { licensed: status(404), original: status(200) },
        ServiceState::Restricted
    )]
    #[case::nothing(
        NetflixTitleStatuses { licensed: status(404), original: status(404) },
        ServiceState::Blocked
    )]
    fn netflix_distinguishes_full_catalogue_from_originals_only(
        #[case] sut: NetflixTitleStatuses,
        #[case] expected: ServiceState,
    ) {
        let actual = classify_netflix(sut);

        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case::app_unavailable(
        "App unavailable in region right now",
        ServiceState::Blocked
    )]
    #[case::not_available_here(
        "Unfortunately, Claude isn&#39;t available here.",
        ServiceState::Blocked
    )]
    #[case::no_marker("welcome back", ServiceState::Available)]
    fn claude_reads_the_real_geocheck_region_refusal_markers(
        #[case] sut: &str,
        #[case] expected: ServiceState,
    ) {
        let actual =
            classify_claude(status(200), sut, claude_unavailable_markers());

        assert_eq!(actual, expected);
    }

    #[test]
    fn claude_403_without_the_region_page_is_unproven_not_blocked() {
        let sut = "generic forbidden";

        let actual =
            classify_claude(status(403), sut, claude_unavailable_markers());

        assert!(matches!(actual, ServiceState::Error(_)), "{actual:?}");
    }

    #[rstest]
    #[case::not_available(
        "TikTok is not available in your country",
        ServiceState::Blocked
    )]
    #[case::no_marker("welcome", ServiceState::Available)]
    fn tiktok_reads_blocked_by_region(
        #[case] sut: &str,
        #[case] expected: ServiceState,
    ) {
        let actual = classify_tiktok(status(200), sut);

        assert_eq!(actual, expected);
    }

    #[rstest]
    #[case::available(ServiceState::Available, Severity::Ok)]
    #[case::blocked(ServiceState::Blocked, Severity::Fail)]
    #[case::inconclusive(
        ServiceState::Error("challenge".into()),
        Severity::Warn
    )]
    #[case::unreachable_is_an_error_not_a_weak_verdict(
        ServiceState::Unavailable("timeout".into()),
        Severity::Error
    )]
    fn judge_service_fail_fails_on_blocked_and_warns_on_an_unjudged_probe(
        #[case] sut: ServiceState,
        #[case] expected: Severity,
    ) {
        let verdict = judge_service_fail(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    #[rstest]
    #[case::available(ServiceState::Available, Severity::Ok)]
    #[case::restricted(ServiceState::Restricted, Severity::Warn)]
    #[case::blocked_only_warns(ServiceState::Blocked, Severity::Warn)]
    #[case::inconclusive(
        ServiceState::Error("challenge".into()),
        Severity::Warn
    )]
    #[case::unreachable_is_an_error_not_a_weak_verdict(
        ServiceState::Unavailable("timeout".into()),
        Severity::Error
    )]
    fn judge_service_warn_never_fails_whatever_the_state(
        #[case] sut: ServiceState,
        #[case] expected: Severity,
    ) {
        let verdict = judge_service_warn(&sut);

        assert_eq!(verdict.severity, expected, "{}", verdict.detail);
    }

    /// The reason a probe could not be judged used to be dropped on the
    /// floor; the single-service judges carry it into the report row.
    #[test]
    fn an_unjudged_probe_carries_its_reason_into_the_detail() {
        let sut = ServiceState::Error("Cloudflare challenged".into());

        let verdict = judge_service_fail(&sut);

        assert_eq!(
            verdict.detail,
            "could not be judged: Cloudflare challenged"
        );
    }
}
