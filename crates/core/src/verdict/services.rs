//! Classification for the ChatGPT/Gemini/YouTube Premium/Netflix/Claude/
//! TikTok/NotebookLM probes, ported from `remnawave/geocheck` v0.3.0
//! (`internal/access/checks.go`, fetched via `gh api` 2026-09-17).
//!
//! This module only classifies an already-fetched response; `io::tunnel`
//! (Task 27) does the actual fetching through the SOCKS tunnel and calls the
//! `classify_*` function that matches each service.

use crate::model::ServiceState;
use crate::Verdict;

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

pub fn classify_chatgpt_web(body: &str) -> ServiceState {
    if contains_ci(body, "unsupported_country") { ServiceState::Blocked } else { ServiceState::Available }
}

fn is_cloudflare_challenge(status: u16, body_lower: &str) -> bool {
    status == 403 && (body_lower.contains("checking your browser") || body_lower.contains("cf-mitigated"))
}

pub fn classify_chatgpt_app(status: u16, body: &str) -> ServiceState {
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
        ServiceState::Error("neither the offer nor the refusal wording was present".into())
    }
}

/// Returns whether `bytes[..marker_pos]` ends with the `,\d+,\d+` digit-group
/// prefix that `reGeminiRegion` requires immediately before its `,200,"`
/// literal (`marker_pos` is the index of that literal's leading comma). Each
/// digit group only needs to be one-or-more digits; like upstream, the
/// digits' actual *values* are never pinned to anything.
fn has_digit_group_prefix(bytes: &[u8], marker_pos: usize) -> bool {
    let mut pos = marker_pos;

    let digit2_end = pos;
    while pos > 0 && bytes[pos - 1].is_ascii_digit() {
        pos -= 1;
    }
    if pos == digit2_end || pos == 0 || bytes[pos - 1] != b',' {
        return false;
    }
    pos -= 1; // consume the comma before the second digit group

    let digit1_end = pos;
    while pos > 0 && bytes[pos - 1].is_ascii_digit() {
        pos -= 1;
    }
    if pos == digit1_end || pos == 0 || bytes[pos - 1] != b',' {
        return false;
    }
    true
}

/// Pulls the ISO 3166-1 alpha-3 region code out of the configuration block
/// Google's account bar embeds in every one of its pages, mirroring
/// geocheck's `reGeminiRegion` regex (`,\d+,\d+,200,"([A-Z]{3})"`,
/// `internal/access/checks.go`, confirmed via `gh api` 2026-09-17) without
/// pulling in a `regex` dependency for a single call site. Like the upstream
/// comment says of its own regex, the two leading digit groups' *values* are
/// not re-verified here — "matched loosely rather than pinned" — but their
/// *presence* (each is one-or-more digits) is still required, same as the
/// real regex. A candidate `,200,"..."` occurrence that fails validation
/// (missing digit-group prefix, or the quoted body isn't exactly three
/// uppercase ASCII letters) is skipped in favor of the next occurrence
/// further in the body, mirroring how a real regex search backtracks/retries
/// rather than giving up at the first failed attempt.
fn extract_gemini_region(body: &str) -> Option<&str> {
    let bytes = body.as_bytes();
    let marker = ",200,\"";
    let mut search_start = 0usize;

    while let Some(rel_pos) = body[search_start..].find(marker) {
        let marker_pos = search_start + rel_pos;
        let candidate_start = marker_pos + marker.len();

        if let Some(candidate) = body.get(candidate_start..candidate_start + 3) {
            let closes_with_quote = bytes.get(candidate_start + 3) == Some(&b'"');
            if closes_with_quote
                && candidate.bytes().all(|b| b.is_ascii_uppercase())
                && has_digit_group_prefix(bytes, marker_pos)
            {
                return Some(candidate);
            }
        }

        // `marker_pos` is the byte index of the marker's leading comma (a
        // single-byte ASCII char), so `marker_pos + 1` is always a valid
        // char-boundary to resume the search from.
        search_start = marker_pos + 1;
    }

    None
}

/// Countries where Google does not offer Gemini, ported verbatim from
/// geocheck's `geminiUnsupported` map (`internal/access/checks.go`, v0.3.0,
/// confirmed via `gh api` 2026-09-17).
///
/// This replaces the design-time placeholder `gemini_unavailable_markers()`
/// name: the real upstream mechanism is not a body-marker match at all, it
/// extracts a region code and checks it against this list.
pub fn gemini_unsupported_regions() -> &'static [&'static str] {
    &["RUS", "BLR", "CHN", "PRK", "IRN", "CUB", "SYR"]
}

/// Classifies a Gemini probe. Unlike `classify_claude`/`classify_tiktok`,
/// this is not a body-marker match — geocheck's real `classifyGemini`
/// extracts the region Google's own page says it served and checks that
/// against [`gemini_unsupported_regions`], so there is no `markers`
/// parameter here (see that function's doc comment).
pub fn classify_gemini(status: u16, body: &str) -> ServiceState {
    let lower = body.to_lowercase();
    if is_cloudflare_challenge(status, &lower) {
        return ServiceState::Error("Cloudflare challenged the request, so availability was never tested".into());
    }
    if !(200..400).contains(&status) {
        return ServiceState::Error(format!("unexpected HTTP {status}"));
    }
    match extract_gemini_region(body) {
        Some(region) if gemini_unsupported_regions().contains(&region) => ServiceState::Blocked,
        Some(_) => ServiceState::Available,
        None => ServiceState::Error("could not read the served region from the page".into()),
    }
}

pub fn classify_notebooklm(status: u16, final_url: &str) -> ServiceState {
    if final_url.contains("location=unsupported") {
        return ServiceState::Blocked;
    }
    let is_google_signin = final_url.contains("accounts.google.com")
        || (final_url.contains(".google.com") && final_url.contains("/login"));
    if is_google_signin {
        return ServiceState::Available;
    }
    if (200..400).contains(&status) {
        ServiceState::Error(format!("unexpected destination: {final_url}"))
    } else {
        ServiceState::Error(format!("unexpected HTTP {status}"))
    }
}

pub fn classify_netflix(licensed_status: u16, _licensed_body: &str, original_status: u16, _original_body: &str) -> ServiceState {
    match (licensed_status == 200, original_status == 200) {
        (true, _) => ServiceState::Available,
        (false, true) => ServiceState::Restricted,
        (false, false) => ServiceState::Blocked,
    }
}

/// geocheck's literal `claudeUnavailableMarkers` list (`internal/access/checks.go`,
/// v0.3.0, confirmed via `gh api` 2026-09-17). The apostrophe appears both
/// literally and HTML-escaped depending on how the page is rendered, so both
/// forms are matched, same as upstream.
pub fn claude_unavailable_markers() -> &'static [&'static str] {
    &[
        "app unavailable in region",
        "/app-unavailable-in-region",
        "unfortunately, claude isn't available here.",
        "unfortunately, claude isn&apos;t available here.",
        "unfortunately, claude isn&#39;t available here.",
    ]
}

pub fn classify_claude(status: u16, body: &str, markers: &[&str]) -> ServiceState {
    let lower = body.to_lowercase();
    if is_cloudflare_challenge(status, &lower) {
        return ServiceState::Error("Cloudflare challenged the request".into());
    }
    if markers.iter().any(|m| lower.contains(&m.to_lowercase())) {
        return ServiceState::Blocked;
    }
    if status == 403 {
        return ServiceState::Error("HTTP 403 without the region page, so the cause is unknown".into());
    }
    if (200..400).contains(&status) {
        ServiceState::Available
    } else {
        ServiceState::Error(format!("unexpected HTTP {status}"))
    }
}

pub fn classify_tiktok(status: u16, body: &str) -> ServiceState {
    if contains_ci(body, "blocked by region") {
        ServiceState::Blocked
    } else if (200..400).contains(&status) {
        ServiceState::Available
    } else {
        ServiceState::Error(format!("unexpected HTTP {status}"))
    }
}

pub fn judge_services_fail(states: &[(&str, ServiceState)]) -> Verdict {
    let blocked: Vec<&str> = states.iter().filter(|(_, s)| *s == ServiceState::Blocked).map(|(n, _)| *n).collect();
    if !blocked.is_empty() {
        return Verdict::fail(format!("blocked: {}", blocked.join(", ")));
    }
    let errored: Vec<&str> = states.iter().filter(|(_, s)| matches!(s, ServiceState::Error(_))).map(|(n, _)| *n).collect();
    if !errored.is_empty() {
        return Verdict::warn(format!("could not be judged (likely a challenge page): {}", errored.join(", ")));
    }
    Verdict::ok(format!("available: {}", states.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")))
}

pub fn judge_services_warn(states: &[(&str, ServiceState)]) -> Verdict {
    let flagged: Vec<String> = states
        .iter()
        .filter(|(_, s)| matches!(s, ServiceState::Blocked | ServiceState::Restricted))
        .map(|(n, s)| format!("{n} ({})", if matches!(s, ServiceState::Restricted) { "restricted" } else { "blocked" }))
        .collect();
    if flagged.is_empty() {
        Verdict::ok(format!("clean: {}", states.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")))
    } else {
        Verdict::warn(flagged.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    #[test]
    fn chatgpt_web_names_unsupported_country_case_insensitively() {
        assert_eq!(classify_chatgpt_web("...Unsupported_Country_Region_Territory..."), ServiceState::Blocked);
        assert_eq!(classify_chatgpt_web("{}"), ServiceState::Available);
    }

    #[test]
    fn chatgpt_app_reads_disallowed_isp_and_been_blocked() {
        assert_eq!(classify_chatgpt_app(200, "Disallowed ISP detected"), ServiceState::Blocked);
        assert_eq!(classify_chatgpt_app(200, "you have been blocked"), ServiceState::Blocked);
        assert_eq!(classify_chatgpt_app(200, "hello"), ServiceState::Available);
    }

    #[test]
    fn chatgpt_app_treats_a_cloudflare_challenge_as_unproven_not_blocked() {
        let state = classify_chatgpt_app(403, "Checking your browser before accessing... cf-mitigated");
        assert!(matches!(state, ServiceState::Error(_)), "{state:?}");
    }

    #[test]
    fn youtube_premium_reads_its_own_two_markers() {
        assert_eq!(classify_youtube_premium("YouTube Premium is not available in your country"), ServiceState::Blocked);
        assert_eq!(classify_youtube_premium("Enjoy ad-free videos"), ServiceState::Available);
    }

    #[test]
    fn youtube_premium_unrecognized_body_is_an_error_not_a_verdict() {
        assert!(matches!(classify_youtube_premium("neither marker present"), ServiceState::Error(_)));
    }

    #[test]
    fn gemini_reads_the_embedded_region_code_against_googles_unsupported_list() {
        // Real body shape (geocheck's `reGeminiRegion`): a config array entry
        // `,<n>,<n>,200,"<ISO-3166-1 alpha-3>"` embedded in Google's account bar.
        let blocked_body = r#"...preamble...,7,42,200,"RUS",...trailer..."#;
        assert_eq!(classify_gemini(200, blocked_body), ServiceState::Blocked);

        let available_body = r#"...preamble...,7,42,200,"USA",...trailer..."#;
        assert_eq!(classify_gemini(200, available_body), ServiceState::Available);
    }

    #[test]
    fn gemini_with_no_readable_region_is_an_error_not_a_verdict() {
        assert!(matches!(classify_gemini(200, "no region code embedded here"), ServiceState::Error(_)));
    }

    #[test]
    fn gemini_skips_a_decoy_200_quote_match_lacking_the_digit_group_prefix() {
        // "ABC" is shaped like a match (`,200,"ABC"`) but is not preceded by
        // the `,\d+,\d+,` structural prefix the real regex requires, so it is
        // a decoy. The real account-bar entry (`,7,42,200,"RUS"`) comes later
        // in the body and must be the one that wins.
        let body = r#",200,"ABC" junk ,7,42,200,"RUS" tail"#;
        assert_eq!(classify_gemini(200, body), ServiceState::Blocked);
    }

    #[test]
    fn gemini_with_only_an_invalid_looking_match_is_still_an_error() {
        // The only `,200,"..."`-shaped substring here is missing the digit
        // group prefix entirely, so there is no valid match anywhere in the
        // body and this must still fall back to the "could not read" error.
        let body = r#"preamble ,200,"ABC" trailer"#;
        assert!(matches!(classify_gemini(200, body), ServiceState::Error(_)));
    }

    #[test]
    fn gemini_treats_a_cloudflare_challenge_as_unproven_not_blocked() {
        let state = classify_gemini(403, "Checking your browser before accessing... cf-mitigated");
        assert!(matches!(state, ServiceState::Error(_)), "{state:?}");
    }

    #[test]
    fn notebooklm_reads_the_redirect_reason_directly() {
        assert_eq!(classify_notebooklm(302, "https://notebooklm.google.com/?location=unsupported"), ServiceState::Blocked);
        assert_eq!(classify_notebooklm(302, "https://accounts.google.com/signin"), ServiceState::Available);
        assert!(matches!(classify_notebooklm(200, "https://notebooklm.google.com/weird"), ServiceState::Error(_)));
    }

    #[test]
    fn netflix_distinguishes_full_catalogue_from_originals_only() {
        assert_eq!(classify_netflix(200, "ok", 200, "ok"), ServiceState::Available);
        assert_eq!(classify_netflix(404, "not found", 200, "ok"), ServiceState::Restricted);
        assert_eq!(classify_netflix(404, "not found", 404, "not found"), ServiceState::Blocked);
    }

    #[test]
    fn claude_reads_the_real_geocheck_region_refusal_markers() {
        let markers = claude_unavailable_markers();
        assert_eq!(classify_claude(200, "App unavailable in region right now", markers), ServiceState::Blocked);
        assert_eq!(classify_claude(200, "Unfortunately, Claude isn&#39;t available here.", markers), ServiceState::Blocked);
        assert_eq!(classify_claude(200, "welcome back", markers), ServiceState::Available);
    }

    #[test]
    fn claude_403_without_the_region_page_is_unproven_not_blocked() {
        let markers = claude_unavailable_markers();
        let state = classify_claude(403, "generic forbidden", markers);
        assert!(matches!(state, ServiceState::Error(_)), "{state:?}");
    }

    #[test]
    fn tiktok_reads_blocked_by_region() {
        assert_eq!(classify_tiktok(200, "This content is blocked by region"), ServiceState::Blocked);
        assert_eq!(classify_tiktok(200, "welcome"), ServiceState::Available);
    }

    #[test]
    fn judge_services_fail_fails_on_any_blocked_and_warns_on_any_error() {
        let all_available = [("chatgpt_web", ServiceState::Available), ("gemini", ServiceState::Available)];
        assert_eq!(judge_services_fail(&all_available).severity, Severity::Ok);

        let one_blocked = [("chatgpt_web", ServiceState::Blocked), ("gemini", ServiceState::Available)];
        assert_eq!(judge_services_fail(&one_blocked).severity, Severity::Fail);

        let one_errored = [("chatgpt_web", ServiceState::Error("challenge".into())), ("gemini", ServiceState::Available)];
        assert_eq!(judge_services_fail(&one_errored).severity, Severity::Warn);
    }

    #[test]
    fn judge_services_warn_never_fails_only_warns_on_blocked_or_restricted() {
        let mixed = [("netflix", ServiceState::Restricted), ("claude", ServiceState::Blocked)];
        assert_eq!(judge_services_warn(&mixed).severity, Severity::Warn);
        let clean = [("netflix", ServiceState::Available)];
        assert_eq!(judge_services_warn(&clean).severity, Severity::Ok);
    }
}
