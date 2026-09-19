use super::session::{SshConfig, SshError, secret_file};
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::process::{Child, Command};

/// A dedicated `ssh -N -D` child process - a SOCKS5 proxy into the
/// candidate, independent of the `SshSession` used for commands. DNS for
/// anything dialed through it resolves on the candidate's side (`socks5h`
/// on the client, Task 27), which is the whole point: services see the
/// candidate's egress, not the runner's.
pub struct SocksTunnel {
    child: Child,
    local_port: u16,
    _key_file: Option<NamedTempFile>,
    _known_hosts_file: Option<NamedTempFile>,
}

impl SocksTunnel {
    pub async fn start(
        address: &str,
        config: &SshConfig,
        local_port: u16,
    ) -> Result<Self, SshError> {
        let key_file = config
            .private_key
            .as_deref()
            .map(secret_file)
            .transpose()
            .map_err(|e| SshError::Connect(e.to_string()))?;
        let known_hosts_file = config
            .known_hosts
            .as_deref()
            .map(secret_file)
            .transpose()
            .map_err(|e| SshError::Connect(e.to_string()))?;

        let mut cmd = Command::new("ssh");
        cmd.arg("-N")
            .arg("-D")
            .arg(format!("127.0.0.1:{local_port}"))
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("ExitOnForwardFailure=yes")
            .arg("-o")
            .arg(format!(
                "ConnectTimeout={}",
                config.connect_timeout.as_secs()
            ))
            .arg("-p")
            .arg(config.port.to_string());
        match &known_hosts_file {
            Some(f) => {
                cmd.arg("-o")
                    .arg("StrictHostKeyChecking=yes")
                    .arg("-o")
                    .arg(format!("UserKnownHostsFile={}", f.path().display()));
            }
            None => {
                cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
            }
        }
        if let Some(key) = &key_file {
            cmd.arg("-i").arg(key.path());
        }
        if let Some(user) = &config.user {
            cmd.arg("-l").arg(user);
        }
        cmd.arg(address);
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        cmd.kill_on_drop(true);

        let child = cmd
            .spawn()
            .map_err(|e| SshError::Connect(format!("could not spawn ssh: {e}")))?;
        // `-N -D` gives no readiness signal on stdout; a short, fixed wait
        // is the same tradeoff `preflight.sh` already makes elsewhere in
        // this project (`sleep 2` after starting a background listener).
        tokio::time::sleep(Duration::from_millis(800)).await;

        Ok(Self {
            child,
            local_port,
            _key_file: key_file,
            _known_hosts_file: known_hosts_file,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.local_port))
    }

    pub async fn stop(mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}
