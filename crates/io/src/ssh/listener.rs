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
        let script = format!(
            "C=/tmp/chip-pf.crt; K=/tmp/chip-pf.key; \
             [ -f \"$C\" ] || openssl req -x509 -newkey rsa:2048 -keyout \"$K\" -out \"$C\" -days 1 -nodes -subj /CN=chip >/dev/null 2>&1; \
             (sudo ufw allow {port}/tcp || ufw allow {port}/tcp) >/dev/null 2>&1; \
             pkill -f '[o]penssl s_server -accept {port}' 2>/dev/null; \
             nohup timeout 600 openssl s_server -accept {port} -cert \"$C\" -key \"$K\" -www -quiet >/dev/null 2>&1 & \
             sleep 1; \
             ss -ltn 2>/dev/null | grep -q ':{port} ' && echo LISTENING || echo FAILED"
        );
        let output = self.run_shell(&script, timeout).await?;
        if output.contains("LISTENING") {
            Ok(ListenerOutcome::Listening)
        } else {
            Ok(ListenerOutcome::Failed(output.trim().to_string()))
        }
    }

    pub async fn stop_listener(&self, port: u16) -> Result<(), SshError> {
        let timeout = self.command_timeout();
        let script = format!(
            "pkill -f '[o]penssl s_server -accept {port}' 2>/dev/null; \
             (sudo ufw delete allow {port}/tcp || ufw delete allow {port}/tcp) >/dev/null 2>&1 || true"
        );
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
}
