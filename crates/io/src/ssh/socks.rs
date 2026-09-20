use super::session::{SshConfig, SshError, secret_file};
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

/// A dedicated `ssh -N -D` child process: a SOCKS5 proxy into the candidate.
///
/// It is independent of the `SshSession` used for commands. DNS for anything
/// dialed through it resolves on the candidate's side (`socks5h`), so services see the
/// candidate's egress, not the runner's.
pub struct SocksTunnel {
    child: Child,
    local_port: NonZeroU16,
    _key_file: Option<NamedTempFile>,
    _known_hosts_file: Option<NamedTempFile>,
}

impl SocksTunnel {
    pub async fn start(
        address: Ipv4Addr,
        config: &SshConfig,
        local_port: NonZeroU16,
    ) -> Result<Self, SshError> {
        Self::start_with_program("ssh", address, config, local_port).await
    }

    async fn start_with_program(
        program: &str,
        address: Ipv4Addr,
        config: &SshConfig,
        local_port: NonZeroU16,
    ) -> Result<Self, SshError> {
        let key_file = config
            .private_key
            .as_ref()
            .map(|key| secret_file(key.expose()))
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
            .arg(format!("ConnectTimeout={}", config.connect_timeout.as_secs()))
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
        cmd.arg("--").arg(address.to_string());
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        cmd.kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| {
            SshError::Connect(format!("could not spawn ssh: {e}"))
        })?;
        let ready_deadline = tokio::time::Instant::now()
            + config.connect_timeout.min(Duration::from_secs(5));
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                return Err(SshError::Connect(
                    child_error(&mut child, status).await,
                ));
            }
            if socks5_ready(local_port).await {
                break;
            }
            if tokio::time::Instant::now() >= ready_deadline {
                let _ = child.kill().await;
                child.wait().await.map_err(|error| {
                    SshError::Connect(format!(
                        "SOCKS listener did not become ready and ssh could not be reaped: {error}"
                    ))
                })?;
                return Err(SshError::Connect(
                    "SOCKS listener did not become ready".to_string(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Ok(Self {
            child,
            local_port,
            _key_file: key_file,
            _known_hosts_file: known_hosts_file,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.local_port.get()))
    }

    pub async fn stop(mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

async fn socks5_ready(local_port: NonZeroU16) -> bool {
    tokio::time::timeout(Duration::from_millis(200), async {
        let mut stream =
            tokio::net::TcpStream::connect(("127.0.0.1", local_port.get()))
                .await?;
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut response = [0_u8; 2];
        stream.read_exact(&mut response).await?;
        Ok::<bool, std::io::Error>(response == [0x05, 0x00])
    })
    .await
    .is_ok_and(|result| result.unwrap_or(false))
}

async fn child_error(
    child: &mut Child,
    status: std::process::ExitStatus,
) -> String {
    let mut stderr = String::new();
    if let Some(pipe) = child.stderr.take() {
        let _ = pipe.take(4096).read_to_string(&mut stderr).await;
    }
    stderr
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .map_or_else(
            || format!("ssh exited with {status}"),
            |line| line.chars().take(120).collect(),
        )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const fn config() -> SshConfig {
        SshConfig {
            user: None,
            port: NonZeroU16::new(22).unwrap(),
            private_key: None,
            known_hosts: None,
            connect_timeout: Duration::from_secs(5),
            command_timeout: Duration::from_secs(5),
        }
    }

    fn stub(dir: &std::path::Path, body: &str) -> String {
        let path = dir.join("ssh-stub");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        path.display().to_string()
    }

    #[tokio::test]
    async fn a_tunnel_whose_ssh_exits_immediately_is_a_connect_error_with_its_stderr()
     {
        let dir = tempfile::tempdir().unwrap();
        let program = stub(
            dir.path(),
            "echo 'Permission denied (publickey).' >&2\nexit 255",
        );
        let result = SocksTunnel::start_with_program(
            &program,
            "203.0.113.5".parse().unwrap(),
            &config(),
            NonZeroU16::new(47080).unwrap(),
        )
        .await;
        match result {
            Err(SshError::Connect(msg)) => {
                assert!(msg.contains("Permission denied"), "{msg}");
            }
            other => {
                panic!("expected Connect error, got {:?}", other.map(|_| ()))
            }
        }
    }

    #[tokio::test]
    async fn a_tunnel_is_ready_only_after_a_socks5_handshake() {
        let dir = tempfile::tempdir().unwrap();
        let program = stub(dir.path(), "exec sleep 30");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port =
            NonZeroU16::new(listener.local_addr().unwrap().port()).unwrap();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).await.unwrap();
        });

        let sut = SocksTunnel::start_with_program(
            &program,
            "203.0.113.5".parse().unwrap(),
            &config(),
            port,
        )
        .await
        .unwrap();

        assert_eq!(
            sut.local_addr(),
            SocketAddr::from(([127, 0, 0, 1], port.get()))
        );
        responder.await.unwrap();
        sut.stop().await;
    }

    #[tokio::test]
    async fn an_unrelated_listener_is_not_mistaken_for_the_socks_tunnel() {
        let dir = tempfile::tempdir().unwrap();
        let program = stub(dir.path(), "exec sleep 30");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port =
            NonZeroU16::new(listener.local_addr().unwrap().port()).unwrap();
        let mut short_config = config();
        short_config.connect_timeout = Duration::from_millis(250);
        let responder = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                if stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() {
                    break;
                }
            }
        });

        let result = SocksTunnel::start_with_program(
            &program,
            "203.0.113.5".parse().unwrap(),
            &short_config,
            port,
        )
        .await;

        responder.abort();
        assert!(
            matches!(result, Err(SshError::Connect(ref detail)) if detail.contains("did not become ready")),
            "unexpected result: {:?}",
            result.map(|_| ())
        );
    }
}
