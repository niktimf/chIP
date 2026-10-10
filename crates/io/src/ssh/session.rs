use super::credential_files::SshCredentialFiles;
use super::known_hosts::HostKeyPolicy;
use super::listener::ListenerSlot;
use crate::credentials::SshPrivateKey;
use openssh::{KnownHosts, Session, SessionBuilder, Stdio};
use std::net::Ipv4Addr;
use std::num::{NonZeroU16, NonZeroU64};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// A failure of the SSH transport: preparing the connection files,
/// connecting, or running a remote command. Operations with failures of
/// their own wrap it in their error type.
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
    #[error(
        "ssh would expand `${{...}}` or a leading `~` in known_hosts path {}",
        path.display()
    )]
    UnquotableKnownHostsPath { path: std::path::PathBuf },
}

impl SshError {
    pub(super) const fn io(
        operation: &'static str,
        source: std::io::Error,
    ) -> Self {
        Self::Io { operation, source }
    }
}

#[derive(Debug)]
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

/// An SSH connection to one candidate.
///
/// The session owns the candidate's credential files. The SOCKS tunnel
/// started from it shares them, so under trust on first use the tunnel
/// checks the host key this session accepted.
#[derive(Debug)]
pub struct SshSession {
    session: Session,
    address: Ipv4Addr,
    config: SshConfig,
    pub(super) listener: ListenerSlot,
    credentials: Arc<SshCredentialFiles>,
}

impl SshSession {
    /// # Errors
    ///
    /// Returns `SshError` when the credential files cannot be written or the
    /// SSH connection fails.
    pub async fn connect(
        address: Ipv4Addr,
        config: SshConfig,
    ) -> Result<Self, SshError> {
        let credentials = SshCredentialFiles::prepare(&config)?;
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
                HostKeyPolicy::TrustOnFirstUse { .. } => KnownHosts::Add,
            })
            // openssh appends this "path" verbatim after
            // `UserKnownHostsFile=` and has no raw option setter, so the
            // quoted list of files goes through it unchanged.
            .user_known_hosts_file(Path::new(
                &credentials.known_hosts().option_value(),
            ));
        if let Some(key) = credentials.key() {
            builder.keyfile(key);
        }
        let session = builder
            .connect(address.to_string())
            .await
            .map_err(SshError::Connect)?;
        Ok(Self {
            session,
            address,
            config,
            listener: ListenerSlot::default(),
            credentials: Arc::new(credentials),
        })
    }

    pub(super) const fn address(&self) -> Ipv4Addr {
        self.address
    }

    pub(super) const fn config(&self) -> &SshConfig {
        &self.config
    }

    /// The credential files of this session, for a second connection to
    /// the same candidate.
    pub(super) fn credentials(&self) -> Arc<SshCredentialFiles> {
        Arc::clone(&self.credentials)
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
        self.listener.owned()
    }

    pub const fn command_timeout(&self) -> Duration {
        self.config.command_timeout
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
            host_keys: HostKeyPolicy::TrustOnFirstUse {
                user_known_hosts: None,
            },
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
