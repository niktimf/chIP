use crate::credentials::SshPrivateKey;
use openssh::{KnownHosts, Session, SessionBuilder, Stdio};
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::num::{NonZeroU16, NonZeroU64};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tempfile::NamedTempFile;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("ssh connect failed")]
    Connect(#[source] openssh::Error),
    #[error("ssh command failed")]
    Command(#[source] openssh::Error),
    #[error("{operation}")]
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
    #[error(
        "a temporary listener on port {port} is already owned by this session"
    )]
    ListenerAlreadyStarted { port: u16 },
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

fn private_file() -> std::io::Result<NamedTempFile> {
    tempfile::Builder::new()
        .prefix("chip-")
        .permissions(std::fs::Permissions::from_mode(0o600))
        .tempfile()
}

pub(super) fn secret_file(content: &str) -> std::io::Result<NamedTempFile> {
    let mut file = private_file()?;
    file.write_all(content.as_bytes())?;
    if !content.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    file.flush()?;
    Ok(file)
}

/// How ssh decides whether to trust the candidate's host key.
///
/// Both policies hand ssh a private temporary `UserKnownHostsFile`, so a
/// scan never writes to the user's `~/.ssh/known_hosts`.
#[derive(Clone, Debug)]
pub enum HostKeyPolicy {
    /// Accept only keys listed in this `known_hosts` content.
    Pinned(String),
    /// Accept whatever key the candidate presents on this connection.
    TrustOnFirstUse,
}

impl HostKeyPolicy {
    /// The `UserKnownHostsFile` for one connection: the pinned keys, or an
    /// empty file that ssh may append the first-seen key to.
    pub(super) fn known_hosts_file(&self) -> std::io::Result<NamedTempFile> {
        match self {
            Self::Pinned(known_hosts) => secret_file(known_hosts),
            Self::TrustOnFirstUse => private_file(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SshConfig {
    pub user: Option<String>,
    pub port: NonZeroU16,
    pub private_key: Option<SshPrivateKey>,
    pub host_keys: HostKeyPolicy,
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
}

impl SshConfig {
    /// Time the SOCKS handshake may take beyond ssh's `ConnectTimeout`:
    /// that limit covers TCP connect and the banner, not key exchange,
    /// authentication and opening the forward.
    const SOCKS_READY_MARGIN: Duration = Duration::from_secs(5);

    /// `ConnectTimeout` in whole seconds, rounded up: ssh takes only
    /// seconds, and `0` would disable the timeout.
    pub(super) fn connect_timeout_secs(&self) -> NonZeroU64 {
        let whole = self.connect_timeout.as_secs();
        let rounded = if self.connect_timeout.subsec_nanos() == 0 {
            whole
        } else {
            whole.saturating_add(1)
        };
        NonZeroU64::new(rounded).unwrap_or(NonZeroU64::MIN)
    }

    /// How long a fresh `ssh -D` may take to answer a SOCKS handshake.
    pub(super) fn socks_ready_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs().get())
            .saturating_add(Self::SOCKS_READY_MARGIN)
    }
}

#[derive(Debug)]
pub struct SshSession {
    session: Session,
    default_timeout: Duration,
    pub(super) listener_port: std::sync::atomic::AtomicU16,
    _key_file: Option<NamedTempFile>,
    _known_hosts_file: NamedTempFile,
}

impl SshSession {
    /// # Errors
    ///
    /// Returns `SshError` when the credential files cannot be written or the
    /// SSH connection fails.
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
            .host_keys
            .known_hosts_file()
            .map_err(|e| SshError::io("prepare SSH credentials", e))?;
        let mut builder = SessionBuilder::default();
        if let Some(user) = &config.user {
            builder.user(user.clone());
        }
        builder
            .port(config.port.get())
            .connect_timeout(Duration::from_secs(
                config.connect_timeout_secs().get(),
            ))
            .known_hosts_check(match config.host_keys {
                HostKeyPolicy::Pinned(_) => KnownHosts::Strict,
                HostKeyPolicy::TrustOnFirstUse => KnownHosts::Add,
            })
            .user_known_hosts_file(known_hosts_file.path());
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

    /// # Errors
    ///
    /// Returns `SshError` when the command cannot run, exceeds `timeout`, or
    /// exits with a non-zero status.
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

    /// # Errors
    ///
    /// Returns `SshError` when the command cannot run, exceeds `timeout`, or
    /// exits with a non-zero status.
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
    pub fn listener_port(&self) -> Option<NonZeroU16> {
        NonZeroU16::new(
            self.listener_port
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    pub const fn command_timeout(&self) -> Duration {
        self.default_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn config_with_connect_timeout(connect_timeout: Duration) -> SshConfig {
        SshConfig {
            user: None,
            port: NonZeroU16::new(22).unwrap(),
            private_key: None,
            host_keys: HostKeyPolicy::TrustOnFirstUse,
            connect_timeout,
            command_timeout: Duration::from_secs(5),
        }
    }

    #[rstest]
    #[case::sub_second_rounds_up_to_one(Duration::from_millis(250), 1)]
    #[case::zero_still_bounds_the_connect(Duration::ZERO, 1)]
    #[case::fraction_rounds_up(Duration::from_millis(1500), 2)]
    #[case::whole_seconds_stay(Duration::from_secs(15), 15)]
    fn the_ssh_connect_timeout_is_never_shorter_than_configured_nor_zero(
        #[case] configured: Duration,
        #[case] expected_secs: u64,
    ) {
        let sut = config_with_connect_timeout(configured);

        let secs = sut.connect_timeout_secs();

        assert_eq!(secs.get(), expected_secs);
    }

    #[test]
    fn the_socks_wait_outlasts_the_ssh_connect_timeout() {
        let sut = config_with_connect_timeout(Duration::from_secs(15));

        let wait = sut.socks_ready_timeout();

        assert_eq!(wait, Duration::from_secs(20));
    }

    #[test]
    fn trust_on_first_use_records_keys_in_a_fresh_empty_file() {
        let sut = HostKeyPolicy::TrustOnFirstUse;

        let file = sut.known_hosts_file().unwrap();

        let content = std::fs::read(file.path()).unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn a_pinned_policy_writes_its_known_hosts_to_the_file() {
        let sut = HostKeyPolicy::Pinned("203.0.113.5 ssh-ed25519 AAAA".into());

        let file = sut.known_hosts_file().unwrap();

        let content = std::fs::read_to_string(file.path()).unwrap();
        assert_eq!(content, "203.0.113.5 ssh-ed25519 AAAA\n");
    }

    #[test]
    fn an_io_error_message_names_the_operation_without_repeating_the_cause() {
        let error = SshError::io(
            "spawn ssh",
            std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
        );

        let message = error.to_string();

        assert_eq!(message, "spawn ssh");
    }

    #[tokio::test]
    async fn a_command_error_message_does_not_repeat_its_cause() {
        let source = openssh::Error::Remote(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "remote execution denied",
        ));

        let error =
            SshSession::collect(async { Err(source) }, Duration::from_secs(1))
                .await
                .unwrap_err();

        assert_eq!(error.to_string(), "ssh command failed");
    }

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
