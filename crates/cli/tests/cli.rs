use std::process::Command;

use rstest::rstest;

fn chip() -> Command {
    Command::new(env!("CARGO_BIN_EXE_chip"))
}

#[test]
fn help_names_both_subcommands() {
    let output = chip().arg("--help").output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scan"), "{stdout}");
    assert!(stdout.contains("calibrate"), "{stdout}");
}

#[test]
fn scan_help_explains_every_flag_and_names_the_secret_variables() {
    let output = chip().args(["scan", "--help"]).output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "excess over the best anchor",
        "probes in Russian home networks",
        "Promote a warning to a failure",
        "SSH_PRIVATE_KEY",
        "GLOBALPING_TOKEN",
        "PROXYCHECK_API_KEY",
    ] {
        assert!(stdout.contains(expected), "{expected} missing:\n{stdout}");
    }
}

#[rstest]
#[case::invalid_ip(
    &["scan", "not-an-ip", "--country", "FI"],
    "invalid IPv4 address syntax"
)]
#[case::invalid_probe_selection(
    &[
        "scan",
        "203.0.113.1",
        "--country",
        "FI",
        "--eyeball-probes",
        "0",
        "--dc-probes",
        "0",
    ],
    "cannot both be 0"
)]
#[case::malformed_calibration_target(
    &["calibrate", "not-a-target"],
    "expected IP=City"
)]
fn invalid_input_exits_two_before_any_network_work(
    #[case] sut: &[&str],
    #[case] expected_error: &str,
) {
    let output = chip().args(sut).output().unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(expected_error), "{stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn secrets_cannot_be_passed_in_process_arguments() {
    let output = chip()
        .args([
            "scan",
            "203.0.113.1",
            "--country",
            "FI",
            "--globalping-token",
            "SECRET123",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unexpected argument '--globalping-token'"));
    assert!(!stderr.contains("SECRET123"), "{stderr}");
}

#[test]
fn calibrate_does_not_read_scan_only_secrets() {
    let output = chip()
        .env("SSH_PRIVATE_KEY", "   ")
        .env("PROXYCHECK_API_KEY", "   ")
        .args(["calibrate", "not-a-target"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("expected IP=City"), "{stderr}");
    assert!(!stderr.contains("SSH_PRIVATE_KEY"), "{stderr}");
    assert!(!stderr.contains("PROXYCHECK_API_KEY"), "{stderr}");
}
