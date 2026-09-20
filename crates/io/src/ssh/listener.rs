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
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if fields.len() < 8 {
        return None;
    }
    ProcStatSnapshot::new(fields[7], fields.iter().sum()).ok()
}

fn listener_start_script(port: u16) -> String {
    format!(
        "D=$(mktemp -d /tmp/chip-pf-{port}.XXXXXX) || {{ echo TEMP_FAILED; exit 0; }}; \
         trap 'rm -rf -- \"$D\"' EXIT; \
         C=\"$D/cert.pem\"; K=\"$D/key.pem\"; M=\"$D/ufw-added\"; \
         openssl req -x509 -newkey rsa:2048 -keyout \"$K\" -out \"$C\" -days 1 -nodes -subj /CN=chip >/dev/null 2>&1 || {{ echo CERT_FAILED; exit 0; }}; \
         if command -v ufw >/dev/null 2>&1; then \
           if sudo -n true >/dev/null 2>&1; then U='sudo -n ufw'; else U='ufw'; fi; \
           $U status 2>/dev/null | grep -Eq '^{port}/tcp[[:space:]]+ALLOW' || \
             {{ $U allow {port}/tcp >/dev/null 2>&1 && : > \"$M\"; }}; \
         fi; \
         nohup sh -c 'D=$1; P=$2; \
           timeout 600 openssl s_server -accept \"$P\" -cert \"$D/cert.pem\" -key \"$D/key.pem\" -www -quiet; \
           if [ -f \"$D/ufw-added\" ] && command -v ufw >/dev/null 2>&1; then \
             if sudo -n true >/dev/null 2>&1; then sudo -n ufw delete allow \"$P/tcp\" >/dev/null 2>&1 || true; \
             else ufw delete allow \"$P/tcp\" >/dev/null 2>&1 || true; fi; \
           fi; \
           rm -rf -- \"$D\"' chip-listener-{port} \"$D\" {port} >/dev/null 2>&1 & \
         trap - EXIT; \
         sleep 1; \
         ss -ltn 2>/dev/null | grep -q ':{port} ' && echo LISTENING || echo FAILED"
    )
}

fn listener_stop_script(port: u16) -> String {
    format!(
        "pkill -f '^timeout 600 openssl s_server -accept {port}' 2>/dev/null || true; \
         for D in /tmp/chip-pf-{port}.*; do \
           [ -L \"$D\" ] && continue; [ -d \"$D\" ] || continue; \
           [ \"$(stat -c %u \"$D\" 2>/dev/null)\" = \"$(id -u)\" ] || continue; \
           if [ -f \"$D/ufw-added\" ] && command -v ufw >/dev/null 2>&1; then \
             if sudo -n true >/dev/null 2>&1; then U='sudo -n ufw'; else U='ufw'; fi; \
             $U delete allow {port}/tcp >/dev/null 2>&1 || true; \
           fi; \
           rm -rf -- \"$D\"; \
         done"
    )
}

impl SshSession {
    /// Starts `openssl s_server` on `port` under `timeout 600` (it dies on
    /// its own after 10 minutes even if this process is killed first), after
    /// generating a throwaway self-signed cert in a private temporary
    /// directory. Opens the port in `ufw` if present; both the files and a
    /// rule added by this run are removed when the listener exits.
    pub async fn start_listener(
        &self,
        port: u16,
    ) -> Result<ListenerOutcome, SshError> {
        let timeout = self.command_timeout();
        let preflight = self.preflight().await;
        if !preflight.has_openssl {
            return Ok(ListenerOutcome::Failed(
                "openssl is not installed on the candidate".to_string(),
            ));
        }
        let port_free = if port == 443 {
            preflight.port_443_free
        } else {
            self.run_shell(
                &format!("ss -ltn 2>/dev/null | grep -q ':{port} ' && echo BUSY || echo FREE"),
                timeout,
            )
            .await
            .is_ok_and(|output| output.trim() == "FREE")
        };
        if !port_free {
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
        let text = self.run_command("cat", &["/proc/stat"], timeout).await?;
        parse_proc_stat(&text).ok_or_else(|| {
            SshError::Command("could not parse /proc/stat".to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    const PROC_STAT_LINE: &str = "cpu  1200 30 450 90111 12 0 34 250 0 0\ncpu0 600 15 225 45055 6 0 17 125 0 0\n";

    #[test]
    #[allow(clippy::identity_op)] // zeros mirror the /proc/stat fields
    fn parse_proc_stat_reads_the_aggregate_cpu_line_only() {
        let snap = parse_proc_stat(PROC_STAT_LINE).unwrap();
        // fields after "cpu": 1200 30 450 90111 12 0 34 250 0 0 - steal is
        // the 8th (250), total is their sum (92087).
        assert_eq!(snap.steal_ticks(), 250);
        assert_eq!(
            snap.total_ticks(),
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
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .unwrap();
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
    fn listener_state_dirs(port: u16) -> Vec<std::path::PathBuf> {
        let prefix = format!("chip-pf-{port}.");
        std::fs::read_dir("/tmp")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_name().to_string_lossy().starts_with(&prefix)
            })
            .map(|entry| entry.path())
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn listener_uses_private_random_state_and_stop_cleans_it_up() {
        let dir = tempfile::tempdir().unwrap();
        let reservation =
            std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        write_stub(
            dir.path(),
            "openssl",
            "[ \"$1\" = req ] && exit 0\nexec sleep 30",
        );
        write_stub(dir.path(), "ufw", "exit 0");
        write_stub(dir.path(), "sudo", "exit 1");
        write_stub(
            dir.path(),
            "ss",
            &format!("echo \"LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:*\""),
        );

        let start = run_sh(&listener_start_script(port), dir.path());
        let stdout = String::from_utf8_lossy(&start.stdout).to_string();
        let state_dirs = listener_state_dirs(port);
        let state_mode = state_dirs.first().and_then(|path| {
            std::fs::metadata(path)
                .ok()
                .map(|metadata| metadata.permissions().mode() & 0o777)
        });

        let stop = run_sh(&listener_stop_script(port), dir.path());

        assert!(start.status.success(), "start: {:?} {stdout}", start.status);
        assert!(stdout.contains("LISTENING"), "stdout: {stdout}");
        assert_eq!(state_dirs.len(), 1, "state dirs: {state_dirs:?}");
        assert_eq!(state_mode, Some(0o700));
        assert!(stop.status.success(), "stop: {:?}", stop.status);
        assert!(listener_state_dirs(port).is_empty());
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
