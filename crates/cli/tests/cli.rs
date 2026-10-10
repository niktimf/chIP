use std::process::{Command, Stdio};

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

#[rstest]
#[case::latency_threshold("excess over the best anchor")]
#[case::probe_count("probes in Russian home networks")]
#[case::gate_escalation("Promote a warning to a failure")]
#[case::ssh_key_variable("SSH_PRIVATE_KEY")]
#[case::globalping_token_variable("GLOBALPING_TOKEN")]
#[case::proxycheck_key_variable("PROXYCHECK_API_KEY")]
fn scan_help_explains_the_setting(#[case] expected: &str) {
    let output = chip().args(["scan", "--help"]).output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(expected), "{expected} missing:\n{stdout}");
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
    #[case] args: &[&str],
    #[case] expected_error: &str,
) {
    let output = chip().args(args).output().unwrap();

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

#[test]
fn an_unparsable_rust_log_is_reported_instead_of_silently_replaced() {
    let output = chip()
        .env("RUST_LOG", "chip=loud")
        .args(["calibrate", "not-a-target"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning: ignoring RUST_LOG and logging at info"),
        "{stderr}"
    );
}

/// A scan that never leaves the machine: every HTTP request goes to a proxy
/// on a loopback port with no listener, and SSH and the /24 sweep are off.
/// Every gate whose source is then unreachable is skipped, so the scan
/// itself passes and an exit code of 2 can only come from writing the
/// report.
fn offline_scan() -> Command {
    let mut command = chip();
    for proxy in ["ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY"] {
        command.env(proxy, "http://127.0.0.1:1");
    }
    for variable in [
        "NO_PROXY",
        "no_proxy",
        "GITHUB_STEP_SUMMARY",
        "GLOBALPING_TOKEN",
        "PROXYCHECK_API_KEY",
        "SSH_PRIVATE_KEY",
    ] {
        command.env_remove(variable);
    }
    command.env("RUST_LOG", "off").args([
        "scan",
        "203.0.113.1",
        "--country",
        "FI",
        "--no-ssh",
        "--no-neighbors",
        "--skip-gate",
        "blocklists,geo,globalping-quota,latency,provenance,reputation,\
         reputation:operator,rkn-registry",
    ]);
    command
}

#[test]
fn an_offline_scan_with_its_unreachable_gates_skipped_passes() {
    let output = offline_scan().output().unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("OVERALL: OK"), "{stdout}");
}

#[test]
fn a_reader_closing_the_pipe_early_ends_the_scan_with_exit_two_not_a_panic() {
    let mut sut = offline_scan()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Closing the read end before the report is written is what
    // `chip scan ... | head` does once it has its lines.
    drop(sut.stdout.take());

    let output = sut.wait_with_output().unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(!stderr.lines().any(|line| line.starts_with("error:")), "{stderr}");
}
