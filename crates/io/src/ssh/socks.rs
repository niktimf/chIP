use super::known_hosts::{HostKeyPolicy, KnownHostsFiles};
use super::session::{SshConfig, SshError, secret_file};
use std::ffi::OsString;
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
#[derive(Debug)]
pub struct SocksTunnel {
    child: Child,
    local_port: NonZeroU16,
    _key_file: Option<NamedTempFile>,
    _known_hosts: KnownHostsFiles,
}

struct PreparedTunnelCommand {
    command: Command,
    key_file: Option<NamedTempFile>,
    known_hosts: KnownHostsFiles,
}

impl SocksTunnel {
    /// # Errors
    ///
    /// Returns `SshError` when the credential files cannot be written, `ssh`
    /// cannot be spawned or exits, or the SOCKS port does not become ready.
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
        let PreparedTunnelCommand {
            mut command,
            key_file,
            known_hosts,
        } = prepare_tunnel_command(program, address, config, local_port)?;
        let mut child =
            command.spawn().map_err(|e| SshError::io("spawn ssh", e))?;
        wait_for_socks(&mut child, local_port, config.socks_ready_timeout())
            .await?;

        Ok(Self {
            child,
            local_port,
            _key_file: key_file,
            _known_hosts: known_hosts,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.local_port.get()))
    }

    #[expect(
        clippy::let_underscore_must_use,
        reason = "best-effort teardown: a tunnel whose ssh already exited \
                  has nothing to kill, and the caller has no recovery"
    )]
    pub async fn stop(mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

fn prepare_tunnel_command(
    program: &str,
    address: Ipv4Addr,
    config: &SshConfig,
    local_port: NonZeroU16,
) -> Result<PreparedTunnelCommand, SshError> {
    let key_file = config
        .private_key
        .as_ref()
        .map(|key| secret_file(key.expose()))
        .transpose()
        .map_err(|error| SshError::io("prepare SSH credentials", error))?;
    let known_hosts = config.host_keys.known_hosts_files()?;
    let mut command = base_tunnel_command(program, config, local_port);
    configure_authentication(
        &mut command,
        config,
        key_file.as_ref(),
        &known_hosts,
    );
    command
        .arg("--")
        .arg(address.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    Ok(PreparedTunnelCommand {
        command,
        key_file,
        known_hosts,
    })
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
    key_file: Option<&NamedTempFile>,
    known_hosts: &KnownHostsFiles,
) {
    let host_key_checking = match config.host_keys {
        HostKeyPolicy::Pinned(_) => "StrictHostKeyChecking=yes",
        HostKeyPolicy::TrustOnFirstUse { .. } => {
            "StrictHostKeyChecking=accept-new"
        }
    };
    let mut known_hosts_option = OsString::from("UserKnownHostsFile=");
    known_hosts_option.push(known_hosts.option_value());
    command
        .args(["-o", host_key_checking, "-o"])
        .arg(known_hosts_option);
    if let Some(key) = key_file {
        command.arg("-i").arg(key.path());
    }
    if let Some(user) = &config.user {
        command.arg("-l").arg(user);
    }
}

async fn wait_for_socks(
    child: &mut Child,
    local_port: NonZeroU16,
    ready_timeout: Duration,
) -> Result<(), SshError> {
    let ready_deadline = tokio::time::Instant::now() + ready_timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| SshError::io("inspect ssh process", error))?
        {
            return Err(child_error(child, status).await);
        }
        if socks5_ready(local_port).await {
            return Ok(());
        }
        if tokio::time::Instant::now() >= ready_deadline {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "kill fails only for an ssh that already exited, \
                          which the wait below reaps; the readiness timeout \
                          stays the reported error"
            )]
            let _ = child.kill().await;
            child
                .wait()
                .await
                .map_err(|error| SshError::io("reap ssh process", error))?;
            return Err(SshError::SocksNotReady);
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
    fn is_text_file_busy(error: &SshError) -> bool {
        matches!(
            error,
            SshError::Io { source, .. }
                if source.kind() == std::io::ErrorKind::ExecutableFileBusy
        )
    }

    async fn start_stub(
        program: &str,
        config: &SshConfig,
        local_port: NonZeroU16,
    ) -> Result<SocksTunnel, SshError> {
        let address = "203.0.113.5".parse().unwrap();
        for _ in 0..50 {
            match SocksTunnel::start_with_program(
                program, address, config, local_port,
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
    async fn a_tunnel_whose_ssh_exits_immediately_is_a_connect_error_with_its_stderr()
     {
        let dir = tempfile::tempdir().unwrap();
        let program = stub(
            dir.path(),
            "echo 'Permission denied (publickey).' >&2\nexit 255",
        );
        let result =
            start_stub(&program, &config(), NonZeroU16::new(47080).unwrap())
                .await;
        match result {
            Err(SshError::Exit { output: msg, .. }) => {
                assert!(msg.contains("Permission denied"), "{msg}");
            }
            other => {
                panic!("expected Connect error, got {:?}", other.map(|_| ()))
            }
        }
    }

    #[tokio::test]
    async fn ssh_options_precede_end_of_options_and_destination() {
        let dir = tempfile::tempdir().unwrap();
        let program = stub(
            dir.path(),
            "penultimate=\nlast=\nfor argument\ndo\n  penultimate=$last\n  last=$argument\ndone\nif [ \"$penultimate\" = \"--\" ] && [ \"$last\" = \"203.0.113.5\" ]; then\n  echo 'arguments accepted' >&2\nelse\n  echo 'destination was not last' >&2\nfi\nexit 255",
        );

        let sut =
            start_stub(&program, &config(), NonZeroU16::new(47080).unwrap())
                .await;

        match sut {
            Err(SshError::Exit { output: detail, .. }) => {
                assert!(detail.contains("arguments accepted"), "{detail}");
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
            matches!(result, Err(SshError::SocksNotReady)),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn trust_on_first_use_appends_to_a_private_file_and_checks_the_users() {
        let tofu_config = SshConfig {
            host_keys: HostKeyPolicy::TrustOnFirstUse {
                user_known_hosts: Some("/home/a user/.ssh/known_hosts".into()),
            },
            ..config()
        };

        let sut = prepare_tunnel_command(
            "ssh",
            "203.0.113.5".parse().unwrap(),
            &tofu_config,
            NonZeroU16::new(47080).unwrap(),
        )
        .unwrap();

        let arguments = args(&sut.command);
        let expected = format!(
            r#"UserKnownHostsFile="{}" "/home/a user/.ssh/known_hosts""#,
            sut.known_hosts.learned().display()
        );
        assert!(arguments.contains(&expected), "{arguments:?}");
        assert!(
            arguments.contains(&"StrictHostKeyChecking=accept-new".to_owned()),
            "{arguments:?}"
        );
    }

    #[test]
    fn a_sub_second_connect_timeout_still_reaches_ssh_as_one_second() {
        let mut short_config = config();
        short_config.connect_timeout = Duration::from_millis(250);

        let sut = prepare_tunnel_command(
            "ssh",
            "203.0.113.5".parse().unwrap(),
            &short_config,
            NonZeroU16::new(47080).unwrap(),
        )
        .unwrap();

        assert!(
            args(&sut.command).contains(&"ConnectTimeout=1".to_owned()),
            "{:?}",
            args(&sut.command)
        );
    }

    #[tokio::test]
    async fn an_exited_ssh_with_a_lingering_stderr_reports_its_exit_status() {
        let dir = tempfile::tempdir().unwrap();
        let program = stub(
            dir.path(),
            "echo 'Connection closed' >&2\nsleep 5 &\nexit 255",
        );

        let result =
            start_stub(&program, &config(), NonZeroU16::new(47081).unwrap())
                .await;

        match result {
            Err(SshError::Exit { status, output }) => {
                assert_eq!(status.code(), Some(255));
                assert!(output.contains("Connection closed"), "{output}");
            }
            other => panic!("expected Exit, got {:?}", other.map(|_| ())),
        }
    }

    #[tokio::test]
    async fn non_utf8_stderr_is_reported_instead_of_failing_the_read() {
        let dir = tempfile::tempdir().unwrap();
        let program =
            stub(dir.path(), "printf '\\377Permission denied' >&2\nexit 255");

        let result =
            start_stub(&program, &config(), NonZeroU16::new(47082).unwrap())
                .await;

        match result {
            Err(SshError::Exit { output, .. }) => {
                assert!(output.contains("Permission denied"), "{output}");
            }
            other => panic!("expected Exit, got {:?}", other.map(|_| ())),
        }
    }
}
