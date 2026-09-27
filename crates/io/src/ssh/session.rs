use crate::credentials::SshPrivateKey;
use openssh::{KnownHosts, Session, SessionBuilder, Stdio};
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tempfile::NamedTempFile;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("ssh connect failed: {0}")]
    Connect(#[source] openssh::Error),
    #[error("ssh command failed: {0}")]
    Command(#[source] openssh::Error),
    #[error("{operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("ssh process exited with {status}: {output}")]
    Exit {
        status: std::process::ExitStatus,
        output: String,
    },
    #[error("ssh command timed out")]
    Timeout,
    #[error("SOCKS listener did not become ready")]
    SocksNotReady,
    #[error("could not parse /proc/stat")]
    InvalidSnapshot,
    #[error("a temporary listener is already owned by this session")]
    ListenerAlreadyStarted,
    #[error("listener port cannot be zero")]
    InvalidListenerPort,
    #[error("unexpected listener preflight response: {0}")]
    InvalidPreflightResponse(String),
}

impl SshError {
    pub(super) const fn io(
        operation: &'static str,
        source: std::io::Error,
    ) -> Self {
        Self::Io { operation, source }
    }
}

pub(super) fn secret_file(content: &str) -> std::io::Result<NamedTempFile> {
    let mut file = tempfile::Builder::new()
        .prefix("chip-")
        .permissions(std::fs::Permissions::from_mode(0o600))
        .tempfile()?;
    file.write_all(content.as_bytes())?;
    if !content.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    file.flush()?;
    Ok(file)
}

#[derive(Clone)]
pub struct SshConfig {
    pub user: Option<String>,
    pub port: NonZeroU16,
    pub private_key: Option<SshPrivateKey>,
    pub known_hosts: Option<String>,
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
}

#[derive(Debug)]
pub struct SshSession {
    session: Session,
    default_timeout: Duration,
    pub(super) listener_port: std::sync::atomic::AtomicU16,
    _key_file: Option<NamedTempFile>,
    _known_hosts_file: Option<NamedTempFile>,
}

impl SshSession {
    pub async fn connect(
        address: Ipv4Addr,
        config: &SshConfig,
    ) -> Result<Self, SshError> {
        let key_file = config
            .private_key
            .as_ref()
            .map(|key| secret_file(key.expose()))
            .transpose()
            .map_err(|e| SshError::io("prepare SSH credentials", e))?;
        let known_hosts_file = config
            .known_hosts
            .as_deref()
            .map(secret_file)
            .transpose()
            .map_err(|e| SshError::io("prepare SSH credentials", e))?;
        let mut builder = SessionBuilder::default();
        if let Some(user) = &config.user {
            builder.user(user.clone());
        }
        builder
            .port(config.port.get())
            .connect_timeout(config.connect_timeout);
        match &known_hosts_file {
            Some(f) => {
                builder
                    .known_hosts_check(KnownHosts::Strict)
                    .user_known_hosts_file(f.path());
            }
            None => {
                builder.known_hosts_check(KnownHosts::Add);
            }
        }
        if let Some(key) = &key_file {
            builder.keyfile(key.path());
        }
        let session = builder
            .connect(address.to_string())
            .await
            .map_err(SshError::Connect)?;
        Ok(Self {
            session,
            default_timeout: config.command_timeout,
            listener_port: std::sync::atomic::AtomicU16::new(0),
            _key_file: key_file,
            _known_hosts_file: known_hosts_file,
        })
    }

    pub async fn run_command(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<String, SshError> {
        let mut cmd = self.session.command(program);
        for arg in args {
            cmd.arg(arg);
        }
        cmd.stdin(Stdio::null());
        Self::collect(cmd.output(), timeout).await
    }

    pub async fn run_shell(
        &self,
        command: &str,
        timeout: Duration,
    ) -> Result<String, SshError> {
        let mut cmd = self.session.shell(command);
        cmd.stdin(Stdio::null());
        Self::collect(cmd.output(), timeout).await
    }

    async fn collect(
        fut: impl Future<Output = Result<std::process::Output, openssh::Error>>,
        timeout: Duration,
    ) -> Result<String, SshError> {
        match tokio::time::timeout(timeout, fut).await {
            Err(_) => Err(SshError::Timeout),
            Ok(Err(e)) => Err(SshError::Command(e)),
            Ok(Ok(out)) => {
                let mut text =
                    String::from_utf8_lossy(&out.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                if out.status.success() {
                    Ok(text)
                } else {
                    Err(SshError::Exit {
                        status: out.status,
                        output: text,
                    })
                }
            }
        }
    }

    /// Port whose remote startup or listener still needs cleanup.
    pub fn listener_port(&self) -> Option<u16> {
        NonZeroU16::new(
            self.listener_port
                .load(std::sync::atomic::Ordering::Relaxed),
        )
        .map(NonZeroU16::get)
    }

    pub const fn command_timeout(&self) -> Duration {
        self.default_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_file_is_readable_only_by_its_owner_and_ends_with_a_newline() {
        let file =
            secret_file("-----BEGIN KEY-----\nabc\n-----END KEY-----").unwrap();

        let mode = std::fs::metadata(file.path()).unwrap().permissions().mode()
            & 0o777;
        let text = std::fs::read_to_string(file.path()).unwrap();

        assert_eq!(mode, 0o600);
        assert!(text.ends_with("-----END KEY-----\n"));
    }
    #[test]
    fn io_errors_retain_their_typed_source_and_full_detail() {
        use std::error::Error as _;
        let detail = "x".repeat(300);
        let error = SshError::io(
            "spawn ssh",
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                detail.clone(),
            ),
        );
        let source = error
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(source.to_string(), detail);
    }
    #[tokio::test]
    async fn remote_command_errors_keep_the_complete_source_chain() {
        use std::error::Error as _;
        let source = openssh::Error::Remote(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "remote execution denied",
        ));
        let error =
            SshSession::collect(async { Err(source) }, Duration::from_secs(1))
                .await
                .unwrap_err();
        let io = error
            .source()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(io.to_string(), "remote execution denied");
    }
}
