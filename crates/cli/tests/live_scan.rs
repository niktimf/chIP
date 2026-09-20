//! One end-to-end scan against a real candidate. Ignored by default: it
//! needs a throwaway machine that is not serving traffic yet, its SSH key,
//! Globalping quota (~84 tests) and several minutes.
//!
//! ```sh
//! CHIP_LIVE_IP=203.0.113.42 CHIP_LIVE_COUNTRY=FI CHIP_LIVE_CITY=Helsinki \
//!     SSH_PRIVATE_KEY="$(cat ./candidate_key)" \
//!     cargo test -p chip --test live_scan -- --ignored
//! ```
//!
//! Without `CHIP_LIVE_IP`/`CHIP_LIVE_COUNTRY` the test returns without
//! asserting, so `--ignored` on a machine with no candidate stays quiet.

use std::process::Command;

/// Every gate a full scan owes a row for. A scan that silently drops one is
/// the failure this test exists to catch — a missing row reads as "checked
/// and fine" to whoever runs the rotation.
const EXPECTED_GATES: [&str; 25] = [
    "reputation",
    "blocklists",
    "geo",
    "provenance",
    "latency",
    "reach",
    "steal",
    "neighbors",
    "neighbors-ptr",
    "tampering",
    "service-geo",
    "service-geo:captcha",
    "service-geo:cdn",
    "service:chatgpt_web",
    "service:chatgpt_app",
    "service:gemini",
    "service:youtube_premium",
    "service:netflix",
    "service:claude",
    "service:tiktok",
    "service:notebooklm",
    "ai:openai",
    "ai:anthropic",
    "ai:gemini",
    "ai:deepseek",
];

#[test]
#[ignore = "needs a live candidate in CHIP_LIVE_IP and Globalping quota"]
fn a_full_scan_reports_every_gate_and_exits_with_a_pipeline_code() {
    let (Ok(ip), Ok(country)) =
        (std::env::var("CHIP_LIVE_IP"), std::env::var("CHIP_LIVE_COUNTRY"))
    else {
        return;
    };
    let report = tempfile::NamedTempFile::new().expect("a writable temp dir");

    let mut sut = Command::new(env!("CARGO_BIN_EXE_chip"));
    sut.args(["scan", &ip, "--country", &country]);
    if let Ok(city) = std::env::var("CHIP_LIVE_CITY") {
        sut.args(["--city", &city]);
    }
    let output = sut
        .args(["--json", &report.path().to_string_lossy()])
        .output()
        .expect("the binary runs");

    let code = output.status.code().expect("the process was not signalled");
    assert!(
        (0..=2).contains(&code),
        "exit code {code} is outside the 0/1/2 contract:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value =
        serde_json::from_reader(std::fs::File::open(report.path()).unwrap())
            .expect("the report is valid JSON");
    let reported: Vec<&str> = document["results"]
        .as_array()
        .expect("results is an array")
        .iter()
        .map(|result| result["gate"].as_str().expect("a gate id"))
        .collect();
    for gate in EXPECTED_GATES {
        assert!(reported.contains(&gate), "no row for {gate}: {reported:?}");
    }
    assert_eq!(
        document["exit_code"].as_i64(),
        Some(i64::from(code)),
        "the report and the process disagree on the verdict"
    );
}
