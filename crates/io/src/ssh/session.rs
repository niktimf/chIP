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
    Connect(String),
    #[error("ssh command failed: {0}")]
    Command(String),
    #[error("ssh command timed out")]
    Timeout,
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

#[derive(Debug, Clone, Copy, Default)]
pub struct Preflight {
    pub has_openssl: bool,
    pub port_443_free: bool,
    pub can_sudo: bool,
}

#[derive(Debug)]
pub struct SshSession {
    session: Session,
    default_timeout: Duration,
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
            .map_err(|e| SshError::Connect(e.to_string()))?;
        let known_hosts_file = config
            .known_hosts
            .as_deref()
            .map(secret_file)
            .transpose()
            .map_err(|e| SshError::Connect(e.to_string()))?;
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
            .map_err(|e| SshError::Connect(error_detail(&e)))?;
        Ok(Self {
            session,
            default_timeout: config.command_timeout,
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
        fut: impl std::future::Future<
            Output = Result<std::process::Output, openssh::Error>,
        >,
        timeout: Duration,
    ) -> Result<String, SshError> {
        match tokio::time::timeout(timeout, fut).await {
            Err(_) => Err(SshError::Timeout),
            Ok(Err(e)) => Err(SshError::Command(error_detail(&e))),
            Ok(Ok(out)) => {
                let mut text =
                    String::from_utf8_lossy(&out.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                if out.status.success() {
                    Ok(text)
                } else {
                    let detail = text
                        .lines()
                        .rev()
                        .find(|line| !line.trim().is_empty())
                        .map_or_else(
                            || {
                                format!(
                                    "remote command exited with {}",
                                    out.status
                                )
                            },
                            |line| line.trim().chars().take(120).collect(),
                        );
                    Err(SshError::Command(detail))
                }
            }
        }
    }

    /// Lets sibling SSH operations use the same bounded command duration
    /// without exposing the backing field.
    pub const fn command_timeout(&self) -> Duration {
        self.default_timeout
    }

    pub async fn preflight(&self) -> Preflight {
        let timeout = self.default_timeout;
        let openssl = self
            .run_command("openssl", &["version"], timeout)
            .await
            .is_ok_and(|s| !s.trim().is_empty());
        let port_free = self
            .run_shell(
                "ss -ltn 2>/dev/null | grep -q ':443 ' && echo BUSY || echo FREE",
                timeout,
            )
            .await
            .is_ok_and(|s| s.trim() == "FREE");
        let can_sudo = self
            .run_command("sudo", &["-n", "true"], timeout)
            .await
            .is_ok();
        Preflight {
            has_openssl: openssl,
            port_443_free: port_free,
            can_sudo,
        }
    }
}

/// The deepest source's last non-empty line, capped so it fits a report row
/// - identical technique to an earlier tool of ours's `error_detail`.
fn error_detail(err: &openssh::Error) -> String {
    let deepest =
        std::iter::successors(Some(err as &dyn std::error::Error), |e| {
            e.source()
        })
        .last()
        .unwrap_or(err);
    let text = deepest.to_string();
    let reason = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    let reason = if reason.is_empty() {
        err.to_string()
    } else {
        reason.to_string()
    };
    reason.chars().take(120).collect()
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
}
