use super::session::{SshError, SshSession};
use chip_core::model::ProcStatSnapshot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerOutcome {
    Listening,
    PortInUse,
    Failed(String),
}

fn parse_proc_stat(text: &str) -> Option<ProcStatSnapshot> {
    let line = text.lines().find(|l| l.starts_with("cpu "))?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|f| f.parse().ok())
        .collect();
    if fields.len() < 8 {
        return None;
    }
    Some(ProcStatSnapshot {
        steal_ticks: fields[7],
        total_ticks: fields.iter().sum(),
    })
}

// The pkill pattern is anchored: the wrapper `sh -c <script>` has the whole
// script in its argv, so an unanchored pattern would match and kill it.
// The listener's own cmdline starts with `timeout` (nohup execs it).
fn listener_start_script(port: u16) -> String {
    format!(
        "C=/tmp/chip-pf.crt; K=/tmp/chip-pf.key; \
         [ -f \"$C\" ] || openssl req -x509 -newkey rsa:2048 -keyout \"$K\" -out \"$C\" -days 1 -nodes -subj /CN=chip >/dev/null 2>&1; \
         (sudo ufw allow {port}/tcp || ufw allow {port}/tcp) >/dev/null 2>&1; \
         pkill -f '^timeout 600 openssl s_server -accept {port}' 2>/dev/null; \
         nohup timeout 600 openssl s_server -accept {port} -cert \"$C\" -key \"$K\" -www -quiet >/dev/null 2>&1 & \
         sleep 1; \
         ss -ltn 2>/dev/null | grep -q ':{port} ' && echo LISTENING || echo FAILED"
    )
}

fn listener_stop_script(port: u16) -> String {
    format!(
        "pkill -f '^timeout 600 openssl s_server -accept {port}' 2>/dev/null; \
         (sudo ufw delete allow {port}/tcp || ufw delete allow {port}/tcp) >/dev/null 2>&1 || true"
    )
}

impl SshSession {
    /// Starts `openssl s_server` on `port` under `timeout 600` (it dies on
    /// its own after 10 minutes even if this process is killed first), after
    /// generating a throwaway self-signed cert if one is not already there
    /// from an earlier run this session. Opens the port in `ufw` if present.
    pub async fn start_listener(&self, port: u16) -> Result<ListenerOutcome, SshError> {
        let timeout = self.command_timeout();
        if !self.preflight().await.port_443_free && port == 443 {
            return Ok(ListenerOutcome::PortInUse);
        }
        let script = listener_start_script(port);
        let output = self.run_shell(&script, timeout).await?;
        if output.contains("LISTENING") {
            Ok(ListenerOutcome::Listening)
        } else {
            Ok(ListenerOutcome::Failed(output.trim().to_string()))
        }
    }

    pub async fn stop_listener(&self, port: u16) -> Result<(), SshError> {
        let timeout = self.command_timeout();
        let script = listener_stop_script(port);
        self.run_shell(&script, timeout).await.map(|_| ())
    }

    pub async fn steal_snapshot(&self) -> Result<ProcStatSnapshot, SshError> {
        let timeout = self.command_timeout();
        let text = self.run("cat /proc/stat", timeout).await?;
        parse_proc_stat(&text)
            .ok_or_else(|| SshError::Command("could not parse /proc/stat".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_STAT_LINE: &str =
        "cpu  1200 30 450 90111 12 0 34 250 0 0\ncpu0 600 15 225 45055 6 0 17 125 0 0\n";

    #[test]
    #[allow(clippy::identity_op)] // zeros mirror the /proc/stat fields
    fn parse_proc_stat_reads_the_aggregate_cpu_line_only() {
        let snap = parse_proc_stat(PROC_STAT_LINE).unwrap();
        // fields after "cpu": 1200 30 450 90111 12 0 34 250 0 0 - steal is
        // the 8th (250), total is their sum (92087).
        assert_eq!(snap.steal_ticks, 250);
        assert_eq!(
            snap.total_ticks,
            1200 + 30 + 450 + 90111 + 12 + 0 + 34 + 250 + 0 + 0
        );
    }

    #[test]
    fn parse_proc_stat_returns_none_for_a_line_with_too_few_fields() {
        assert!(parse_proc_stat("cpu  1 2 3\n").is_none());
    }

    #[test]
    fn parse_proc_stat_returns_none_when_there_is_no_cpu_line() {
        assert!(parse_proc_stat("nonsense\n").is_none());
    }

    #[cfg(unix)]
    fn write_stub(dir: &std::path::Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    fn run_sh(script: &str, dir: &std::path::Path) -> std::process::Output {
        let old = std::env::var("PATH").unwrap_or_default();
        std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .env("PATH", format!("{}:{old}", dir.display()))
            .output()
            .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn start_script_survives_its_own_pkill_and_reports_listening() {
        let dir = tempfile::tempdir().unwrap();
        write_stub(dir.path(), "openssl", "sleep 3");
        write_stub(dir.path(), "ufw", "exit 0");
        write_stub(dir.path(), "sudo", "exit 1");
        write_stub(
            dir.path(),
            "ss",
            "echo \"LISTEN 0 128 0.0.0.0:47443 0.0.0.0:*\"",
        );

        let start = run_sh(&listener_start_script(47443), dir.path());
        let stdout = String::from_utf8_lossy(&start.stdout).to_string();
        let stop = run_sh(&listener_stop_script(47443), dir.path());

        assert!(start.status.success(), "start: {:?} {stdout}", start.status);
        assert!(stdout.contains("LISTENING"), "stdout: {stdout}");
        assert!(stop.status.success(), "stop: {:?}", stop.status);
    }

    #[cfg(unix)]
    #[test]
    fn stop_script_is_valid_shell() {
        for script in [listener_start_script(443), listener_stop_script(443)] {
            let status = std::process::Command::new("sh")
                .arg("-n")
                .arg("-c")
                .arg(&script)
                .status()
                .unwrap();
            assert!(status.success(), "sh -n failed for: {script}");
        }
    }
}
