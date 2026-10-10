use super::credential_files::SshCredentialFiles;
use super::session::{SshConfig, SshError, SshSession};
use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

/// Why a SOCKS tunnel did not start.
#[derive(Debug, Error)]
pub enum SocksError {
    #[error("SOCKS listener did not become ready")]
    NotReady,
    #[error(transparent)]
    Ssh(#[from] SshError),
}

/// A dedicated `ssh -N -D` child process: a SOCKS5 proxy into the candidate.
///
/// It is a second ssh process next to the `SshSession` used for commands
/// and reads the session's credential files: under trust on first use it
/// accepts only the host key the session accepted. DNS for anything dialed
/// through it resolves on the candidate's side (`socks5h`), so services see
/// the candidate's egress, not the runner's.
#[derive(Debug)]
pub struct SocksTunnel {
    child: Child,
    local_port: NonZeroU16,
    _credentials: Arc<SshCredentialFiles>,
}

impl SocksTunnel {
    /// Opens a tunnel to the candidate of `session` with its config and
    /// credential files.
    ///
    /// # Errors
    ///
    /// Returns `SocksError::NotReady` when the SOCKS port does not answer a
    /// handshake in time, and `SocksError::Ssh` when `ssh` cannot be spawned
    /// or exits.
    pub async fn start(
        session: &SshSession,
        local_port: NonZeroU16,
    ) -> Result<Self, SocksError> {
        Self::start_with_program(
            "ssh",
            session.address(),
            session.config(),
            session.credentials(),
            local_port,
        )
        .await
    }

    async fn start_with_program(
        program: &str,
        address: Ipv4Addr,
        config: &SshConfig,
        credentials: Arc<SshCredentialFiles>,
        local_port: NonZeroU16,
    ) -> Result<Self, SocksError> {
        let mut command =
            tunnel_command(program, address, config, &credentials, local_port);
        let mut child =
            command.spawn().map_err(|e| SshError::io("spawn ssh", e))?;
        wait_for_socks(&mut child, local_port, config.socks_ready_timeout())
            .await?;

        Ok(Self {
            child,
            local_port,
            _credentials: credentials,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.local_port.get()))
    }

    /// Best-effort teardown: the caller has no recovery, so a failed kill is
    /// logged and the tunnel is dropped anyway. `Child::kill` also waits for
    /// the process, so a killed ssh is reaped.
    pub async fn stop(mut self) {
        if let Err(error) = self.child.kill().await {
            let port = self.local_port.get();
            tracing::warn!(port, %error, "ssh tunnel kill failed");
        }
    }
}

fn tunnel_command(
    program: &str,
    address: Ipv4Addr,
    config: &SshConfig,
    credentials: &SshCredentialFiles,
    local_port: NonZeroU16,
) -> Command {
    let mut command = base_tunnel_command(program, config, local_port);
    configure_authentication(&mut command, config, credentials);
    command
        .arg("--")
        .arg(address.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    command
}

fn base_tunnel_command(
    program: &str,
    config: &SshConfig,
    local_port: NonZeroU16,
) -> Command {
    let mut command = Command::new(program);
    command
        .arg("-N")
        .arg("-D")
        .arg(format!("127.0.0.1:{local_port}"))
        .args(["-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes"])
        .arg("-o")
        .arg(format!("ConnectTimeout={}", config.connect_timeout_secs()))
        .arg("-p")
        .arg(config.port.to_string());
    command
}

fn configure_authentication(
    command: &mut Command,
    config: &SshConfig,
    credentials: &SshCredentialFiles,
) {
    let host_key_checking = format!(
        "StrictHostKeyChecking={}",
        config.host_keys.strict_host_key_checking()
    );
    let mut known_hosts_option = OsString::from("UserKnownHostsFile=");
    known_hosts_option.push(credentials.known_hosts().option_value());
    command
        .arg("-o")
        .arg(host_key_checking)
        .arg("-o")
        .arg(known_hosts_option);
    if let Some(key) = credentials.key() {
        command.arg("-i").arg(key);
    }
    if let Some(user) = &config.user {
        command.arg("-l").arg(user);
    }
}

async fn wait_for_socks(
    child: &mut Child,
    local_port: NonZeroU16,
    ready_timeout: Duration,
) -> Result<(), SocksError> {
    let ready_deadline = tokio::time::Instant::now() + ready_timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| SshError::io("inspect ssh process", error))?
        {
            return Err(child_error(child, status).await.into());
        }
        if socks5_ready(local_port).await {
            return Ok(());
        }
        if tokio::time::Instant::now() >= ready_deadline {
            // The readiness timeout stays the reported error; a failed kill
            // is only logged. `Child::kill` also reaps a killed process.
            if let Err(error) = child.kill().await {
                tracing::warn!(
                    port = local_port.get(),
                    %error,
                    "ssh tunnel kill after the readiness timeout failed"
                );
            }
            return Err(SocksError::NotReady);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
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
) -> SshError {
    let mut stderr = Vec::new();
    if let Some(pipe) = child.stderr.take() {
        // A grandchild that inherited stderr can hold the pipe open after
        // ssh exits; keep what arrived within the limit and report the exit.
        let read = tokio::time::timeout(
            Duration::from_secs(1),
            pipe.take(4096).read_to_end(&mut stderr),
        )
        .await;
        if let Ok(Err(error)) = read {
            return SshError::io("read ssh stderr", error);
        }
    }
    SshError::Exit {
        status,
        output: String::from_utf8_lossy(&stderr).into_owned(),
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use crate::ssh::HostKeyPolicy;
    use std::os::unix::fs::PermissionsExt;

    fn args(command: &Command) -> Vec<String> {
        command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    const fn config() -> SshConfig {
        SshConfig {
            user: None,
            port: NonZeroU16::new(22).unwrap(),
            private_key: None,
            host_keys: HostKeyPolicy::TrustOnFirstUse {
                user_known_hosts: None,
            },
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

    /// A stub written moments ago can fail to exec with `ETXTBSY` while a
    /// process forked by a parallel test still holds its write descriptor.
    /// That window closes at the fork's `exec`, so retrying is enough.
    fn is_text_file_busy(error: &SocksError) -> bool {
        matches!(
            error,
            SocksError::Ssh(SshError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::ExecutableFileBusy
        )
    }

    /// Credential files as `SshSession::connect` prepares them.
    fn session_credentials(config: &SshConfig) -> Arc<SshCredentialFiles> {
        Arc::new(SshCredentialFiles::prepare(config).unwrap())
    }

    async fn start_stub(
        program: &str,
        config: &SshConfig,
        local_port: NonZeroU16,
    ) -> Result<SocksTunnel, SocksError> {
        start_stub_with(
            program,
            config,
            session_credentials(config),
            local_port,
        )
        .await
    }

    async fn start_stub_with(
        program: &str,
        config: &SshConfig,
        credentials: Arc<SshCredentialFiles>,
        local_port: NonZeroU16,
    ) -> Result<SocksTunnel, SocksError> {
        let address = "203.0.113.5".parse().unwrap();
        for _ in 0..50 {
            match SocksTunnel::start_with_program(
                program,
                address,
                config,
                Arc::clone(&credentials),
                local_port,
            )
            .await
            {
                Err(error) if is_text_file_busy(&error) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                other => return other,
            }
        }
        panic!("{program} stayed busy");
    }

    /// A port that was free a moment ago, so a stub tunnel that never
    /// listens cannot meet a stray listener on it.
    fn free_port() -> NonZeroU16 {
        let reservation =
            std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        NonZeroU16::new(reservation.local_addr().unwrap().port()).unwrap()
    }

    async fn spawn_stub(program: &str) -> Child {
        for _ in 0..50 {
            match Command::new(program).kill_on_drop(true).spawn() {
                Err(error)
                    if error.kind()
                        == std::io::ErrorKind::ExecutableFileBusy =>
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                other => return other.unwrap(),
            }
        }
        panic!("{program} stayed busy");
    }

    #[tokio::test]
    async fn a_tunnel_whose_ssh_exits_immediately_reports_the_ssh_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let program = stub(
            dir.path(),
            "echo 'Permission denied (publickey).' >&2\nexit 255",
        );

        let result = start_stub(&program, &config(), free_port()).await;

        let Err(SocksError::Ssh(SshError::Exit { output, .. })) = result else {
            panic!("expected an ssh exit, got {result:?}");
        };
        assert!(output.contains("Permission denied"), "{output}");
    }

    #[test]
    fn ssh_options_precede_end_of_options_and_destination() {
        let user_config = SshConfig {
            user: Some("admin".to_owned()),
            ..config()
        };

        let sut = tunnel_command(
            "ssh",
            "203.0.113.5".parse().unwrap(),
            &user_config,
            &session_credentials(&user_config),
            NonZeroU16::new(47080).unwrap(),
        );

        let arguments = args(&sut);
        assert!(
            arguments.ends_with(&[
                "-l".to_owned(),
                "admin".to_owned(),
                "--".to_owned(),
                "203.0.113.5".to_owned(),
            ]),
            "{arguments:?}"
        );
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

        let sut = start_stub(&program, &config(), port).await.unwrap();

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
        let responder = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                if stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() {
                    break;
                }
            }
        });
        let mut child = spawn_stub(&program).await;

        let result =
            wait_for_socks(&mut child, port, Duration::from_millis(250)).await;

        responder.abort();
        assert!(
            matches!(result, Err(SocksError::NotReady)),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn the_tunnel_appends_to_the_sessions_learned_file_and_checks_the_users() {
        let tofu_config = SshConfig {
            host_keys: HostKeyPolicy::TrustOnFirstUse {
                user_known_hosts: Some("/home/a user/.ssh/known_hosts".into()),
            },
            ..config()
        };
        let session_files = session_credentials(&tofu_config);

        let sut = tunnel_command(
            "ssh",
            "203.0.113.5".parse().unwrap(),
            &tofu_config,
            &session_files,
            NonZeroU16::new(47080).unwrap(),
        );

        let arguments = args(&sut);
        let expected = format!(
            r#"UserKnownHostsFile="{}" "/home/a user/.ssh/known_hosts""#,
            session_files.known_hosts().learned().display()
        );
        assert!(arguments.contains(&expected), "{arguments:?}");
        assert!(
            arguments.contains(&"StrictHostKeyChecking=accept-new".to_owned()),
            "{arguments:?}"
        );
    }

    #[tokio::test]
    async fn the_tunnel_ssh_checks_the_host_key_the_session_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let program = stub(
            dir.path(),
            r#"for argument
do
  case $argument in
    UserKnownHostsFile=*)
      first=${argument#UserKnownHostsFile=\"}
      first=${first%%\"*}
      echo "reads $first" >&2
      cat "$first" >&2
      ;;
  esac
done
exit 255"#,
        );
        let session_files = session_credentials(&config());
        let learned = session_files.known_hosts().learned().to_owned();
        std::fs::write(&learned, "203.0.113.5 ssh-ed25519 AAAAsession\n")
            .unwrap();

        let result =
            start_stub_with(&program, &config(), session_files, free_port())
                .await;

        let Err(SocksError::Ssh(SshError::Exit { output, .. })) = result else {
            panic!("expected an ssh exit, got {result:?}");
        };
        assert!(
            output.contains(&format!("reads {}\n", learned.display())),
            "{output}"
        );
        assert!(output.contains("ssh-ed25519 AAAAsession"), "{output}");
    }

    #[test]
    fn a_sub_second_connect_timeout_still_reaches_ssh_as_one_second() {
        let short_config = SshConfig {
            connect_timeout: Duration::from_millis(250),
            ..config()
        };

        let sut = tunnel_command(
            "ssh",
            "203.0.113.5".parse().unwrap(),
            &short_config,
            &session_credentials(&short_config),
            NonZeroU16::new(47080).unwrap(),
        );

        assert!(
            args(&sut).contains(&"ConnectTimeout=1".to_owned()),
            "{:?}",
            args(&sut)
        );
    }

    #[tokio::test]
    async fn an_exited_ssh_with_a_lingering_stderr_reports_its_exit_status() {
        let dir = tempfile::tempdir().unwrap();
        let program = stub(
            dir.path(),
            "echo 'Connection closed' >&2\nsleep 5 &\nexit 255",
        );

        let result = start_stub(&program, &config(), free_port()).await;

        let Err(SocksError::Ssh(SshError::Exit { status, output })) = result
        else {
            panic!("expected an ssh exit, got {result:?}");
        };
        assert_eq!(status.code(), Some(255));
        assert!(output.contains("Connection closed"), "{output}");
    }

    #[tokio::test]
    async fn non_utf8_stderr_is_reported_instead_of_failing_the_read() {
        let dir = tempfile::tempdir().unwrap();
        let program =
            stub(dir.path(), "printf '\\377Permission denied' >&2\nexit 255");

        let result = start_stub(&program, &config(), free_port()).await;

        let Err(SocksError::Ssh(SshError::Exit { output, .. })) = result else {
            panic!("expected an ssh exit, got {result:?}");
        };
        assert!(output.contains("Permission denied"), "{output}");
    }
}
