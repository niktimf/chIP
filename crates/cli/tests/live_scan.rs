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
//! Without `CHIP_LIVE_IP` or `CHIP_LIVE_COUNTRY` the test fails and says
//! which one is missing: a run with `--ignored` is meant to scan a candidate.

use std::ffi::OsString;
use std::process::Command;

/// Every gate a full scan owes a row for, straight from the registry that
/// the scan itself is built on. A scan that silently drops one is the
/// failure this test exists to catch — a missing row reads as "checked and
/// fine" to whoever runs the rotation.
fn expected_gates() -> Vec<&'static str> {
    chip_core::gate::scan_gates()
        .map(chip_core::GateId::as_str)
        .collect()
}

#[test]
#[ignore = "needs a live candidate in CHIP_LIVE_IP and Globalping quota"]
fn a_full_scan_reports_every_gate_and_exits_with_a_pipeline_code() {
    let ip = std::env::var("CHIP_LIVE_IP")
        .expect("CHIP_LIVE_IP must name the live candidate");
    let country = std::env::var("CHIP_LIVE_COUNTRY")
        .expect("CHIP_LIVE_COUNTRY must name the candidate's country");
    let city = std::env::var_os("CHIP_LIVE_CITY")
        .map(|city| [OsString::from("--city"), city])
        .into_iter()
        .flatten();
    let report = tempfile::NamedTempFile::new().expect("a writable temp dir");

    // `--no-fail-fast`: a candidate that fails phase A still owes the phase B
    // rows this test checks for.
    let output = Command::new(env!("CARGO_BIN_EXE_chip"))
        .args(["scan", &ip, "--country", &country, "--no-fail-fast"])
        .args(city)
        .arg("--json")
        .arg(report.path())
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
    let missing: Vec<&str> = expected_gates()
        .into_iter()
        .filter(|gate| !reported.contains(gate))
        .collect();
    assert!(missing.is_empty(), "no row for {missing:?}: {reported:?}");
    assert_eq!(
        document["exit_code"].as_i64(),
        Some(i64::from(code)),
        "the report and the process disagree on the verdict"
    );
}
