use std::process::Command;

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
fn invalid_ip_exits_two_before_any_network_work() {
    let output = chip()
        .args(["scan", "not-an-ip", "--country", "FI"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid IPv4 address syntax"), "{stderr}");
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
