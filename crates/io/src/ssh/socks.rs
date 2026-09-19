use super::session::{SshConfig, SshError, secret_file};
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;
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
        Self::start_with_program("ssh", address, config, local_port).await
    }

    async fn start_with_program(
        program: &str,
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

        let mut cmd = Command::new(program);
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
        cmd.arg("--").arg(address);
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        cmd.kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .map_err(|e| SshError::Connect(format!("could not spawn ssh: {e}")))?;
        // `-N -D` gives no readiness signal on stdout; a short, fixed wait
        // is the same tradeoff `preflight.sh` already makes elsewhere in
        // this project (`sleep 2` after starting a background listener).
        tokio::time::sleep(Duration::from_millis(800)).await;

        if let Ok(Some(status)) = child.try_wait() {
            let mut stderr = String::new();
            if let Some(pipe) = child.stderr.take() {
                let _ = pipe.take(4096).read_to_string(&mut stderr).await;
            }
            let msg = stderr
                .lines()
                .map(str::trim)
                .rfind(|l| !l.is_empty())
                .map_or_else(
                    || format!("ssh exited with {status}"),
                    |l| l.chars().take(120).collect::<String>(),
                );
            return Err(SshError::Connect(msg));
        }

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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn config() -> SshConfig {
        SshConfig {
            user: None,
            port: 22,
            private_key: None,
            known_hosts: None,
            connect_timeout: Duration::from_secs(5),
            command_timeout: Duration::from_secs(5),
        }
    }

    fn stub(dir: &std::path::Path, body: &str) -> String {
        let path = dir.join("ssh-stub");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    #[tokio::test]
    async fn a_tunnel_whose_ssh_exits_immediately_is_a_connect_error_with_its_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let program = stub(
            dir.path(),
            "echo 'Permission denied (publickey).' >&2\nexit 255",
        );
        let result =
            SocksTunnel::start_with_program(&program, "203.0.113.5", &config(), 47080).await;
        match result {
            Err(SshError::Connect(msg)) => assert!(msg.contains("Permission denied"), "{msg}"),
            other => panic!("expected Connect error, got {:?}", other.map(|_| ())),
        }
    }

    #[tokio::test]
    async fn a_tunnel_whose_ssh_stays_up_is_ok_and_stop_kills_it() {
        let dir = tempfile::tempdir().unwrap();
        let program = stub(dir.path(), "sleep 30");
        let tunnel = SocksTunnel::start_with_program(&program, "203.0.113.5", &config(), 47081)
            .await
            .unwrap();
        assert_eq!(
            tunnel.local_addr(),
            SocketAddr::from(([127, 0, 0, 1], 47081))
        );
        tunnel.stop().await;
    }
}
