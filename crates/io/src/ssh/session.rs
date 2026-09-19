use openssh::{KnownHosts, Session, SessionBuilder, Stdio};
use std::io::Write as _;
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

pub fn quote(value: &str) -> String {
    shlex::try_quote(value).map_or_else(|_| "''".to_string(), std::borrow::Cow::into_owned)
}

pub(crate) fn secret_file(content: &str) -> anyhow::Result<NamedTempFile> {
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

#[derive(Debug, Clone)]
pub struct SshConfig {
    pub user: Option<String>,
    pub port: u16,
    pub private_key: Option<String>,
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
    pub async fn connect(address: &str, config: &SshConfig) -> Result<Self, SshError> {
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
        let mut builder = SessionBuilder::default();
        if let Some(user) = &config.user {
            builder.user(user.clone());
        }
        builder
            .port(config.port)
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
            .connect(address)
            .await
            .map_err(|e| SshError::Connect(error_detail(&e)))?;
        Ok(Self {
            session,
            default_timeout: config.command_timeout,
            _key_file: key_file,
            _known_hosts_file: known_hosts_file,
        })
    }

    pub async fn run(&self, command: &str, timeout: Duration) -> Result<String, SshError> {
        let mut cmd = self.session.raw_command("sh");
        cmd.arg("-c").arg(command).stdin(Stdio::null());
        Self::collect(cmd.output(), timeout).await
    }

    pub async fn run_shell(&self, command: &str, timeout: Duration) -> Result<String, SshError> {
        let mut cmd = self.session.shell(command);
        cmd.stdin(Stdio::null());
        Self::collect(cmd.output(), timeout).await
    }

    async fn collect(
        fut: impl std::future::Future<Output = Result<std::process::Output, openssh::Error>>,
        timeout: Duration,
    ) -> Result<String, SshError> {
        match tokio::time::timeout(timeout, fut).await {
            Err(_) => Err(SshError::Timeout),
            Ok(Err(e)) => Err(SshError::Command(error_detail(&e))),
            Ok(Ok(out)) => {
                let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                Ok(text)
            }
        }
    }

    /// Task 26's listener/steal code lives in a sibling module and needs
    /// this to size its own `run`/`run_shell` calls the same way `preflight`
    /// does - a getter rather than a `pub(crate)` field keeps the field
    /// itself private to this module.
    pub fn command_timeout(&self) -> Duration {
        self.default_timeout
    }

    pub async fn preflight(&self) -> Preflight {
        let timeout = self.default_timeout;
        let openssl = self
            .run("command -v openssl", timeout)
            .await
            .is_ok_and(|s| !s.trim().is_empty());
        let port_free = self
            .run(
                "ss -ltn 2>/dev/null | grep -q ':443 ' && echo BUSY || echo FREE",
                timeout,
            )
            .await
            .is_ok_and(|s| s.trim() == "FREE");
        let can_sudo = self
            .run("sudo -n true 2>/dev/null && echo YES || echo NO", timeout)
            .await
            .is_ok_and(|s| s.trim() == "YES");
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
    let deepest = std::iter::successors(Some(err as &dyn std::error::Error), |e| e.source())
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
    fn quote_wraps_a_value_with_a_space_in_single_quotes() {
        assert_eq!(quote("hello world"), "'hello world'");
    }

    #[test]
    fn quote_leaves_a_simple_value_alone() {
        assert_eq!(quote("plain"), "plain");
    }

    #[test]
    fn a_secret_file_is_readable_only_by_its_owner_and_ends_with_a_newline() {
        let file = secret_file("-----BEGIN KEY-----\nabc\n-----END KEY-----").unwrap();

        let mode = std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777;
        let text = std::fs::read_to_string(file.path()).unwrap();

        assert_eq!(mode, 0o600);
        assert!(text.ends_with("-----END KEY-----\n"));
    }

    #[test]
    fn a_secret_file_vanishes_when_dropped() {
        let file = secret_file("k").unwrap();
        let path = file.path().to_path_buf();

        drop(file);

        assert!(!path.exists());
    }

    #[tokio::test]
    #[ignore = "needs a real ssh binary and a reachable host; see README for a local sshd setup"]
    async fn an_unreachable_host_reports_the_reason_in_sshs_own_words() {
        let config = SshConfig {
            user: Some("root".into()),
            port: 22,
            private_key: None,
            known_hosts: None,
            connect_timeout: Duration::from_secs(3),
            command_timeout: Duration::from_secs(3),
        };

        let err = SshSession::connect("127.0.0.1", &config).await.unwrap_err();

        assert!(matches!(err, SshError::Connect(_)));
    }
}
