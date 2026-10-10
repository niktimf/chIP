use super::credential_files::{private_file, secret_file};
use super::session::SshError;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tempfile::NamedTempFile;
use thiserror::Error;

/// `known_hosts` content that pins the candidate's host key.
///
/// It is never blank: ssh with an empty known-hosts file rejects every key,
/// and the scan would report that as "Host key verification failed".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownHostsEntries(String);

impl KnownHostsEntries {
    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("known-hosts entries must not be empty")]
pub struct EmptyKnownHosts;

impl TryFrom<String> for KnownHostsEntries {
    type Error = EmptyKnownHosts;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.trim().is_empty() {
            Err(EmptyKnownHosts)
        } else {
            Ok(Self(value))
        }
    }
}

impl FromStr for KnownHostsEntries {
    type Err = EmptyKnownHosts;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

/// How ssh decides whether to trust the candidate's host key.
///
/// A scan never writes to the user's `~/.ssh/known_hosts`: ssh appends a
/// newly accepted key only to the first `UserKnownHostsFile`, and that file
/// is always a private temporary one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Accept only keys listed in this `known_hosts` content.
    Pinned(KnownHostsEntries),
    /// Accept the key of a host that no known-hosts file lists yet.
    ///
    /// ssh reads `user_known_hosts` too, so a host recorded there must still
    /// present the recorded key: under `StrictHostKeyChecking=accept-new` a
    /// changed key fails the connection. The file itself is never written.
    TrustOnFirstUse { user_known_hosts: Option<PathBuf> },
}

/// ssh's `StrictHostKeyChecking` for a `HostKeyPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display)]
pub(super) enum StrictHostKeyChecking {
    #[strum(to_string = "yes")]
    Yes,
    #[strum(to_string = "accept-new")]
    AcceptNew,
}

impl HostKeyPolicy {
    /// One mapping for the session (through openssh) and the SOCKS tunnel
    /// (through ssh arguments), so both connections check keys alike.
    pub(super) const fn strict_host_key_checking(
        &self,
    ) -> StrictHostKeyChecking {
        match self {
            Self::Pinned(_) => StrictHostKeyChecking::Yes,
            Self::TrustOnFirstUse { .. } => StrictHostKeyChecking::AcceptNew,
        }
    }

    /// The known-hosts files for one connection: the pinned keys, or an
    /// empty file that ssh may append the first-seen key to, followed by
    /// the user's file.
    pub(super) fn known_hosts_files(
        &self,
    ) -> Result<KnownHostsFiles, SshError> {
        let (learned, consulted) = match self {
            Self::Pinned(entries) => (secret_file(entries.as_str()), None),
            Self::TrustOnFirstUse { user_known_hosts } => {
                (private_file(), user_known_hosts.clone())
            }
        };
        let learned = learned
            .map_err(|error| SshError::io("prepare SSH credentials", error))?;
        reject_expanded(learned.path())?;
        consulted.as_deref().map(reject_expanded).transpose()?;
        Ok(KnownHostsFiles { learned, consulted })
    }
}

/// The known-hosts files of one connection. The temporary file is removed
/// when this value is dropped, so it lives as long as the ssh process.
#[derive(Debug)]
pub(super) struct KnownHostsFiles {
    learned: NamedTempFile,
    consulted: Option<PathBuf>,
}

impl KnownHostsFiles {
    /// The private file ssh appends newly accepted keys to.
    pub(super) fn learned(&self) -> &Path {
        self.learned.path()
    }

    /// The value of ssh's `UserKnownHostsFile`: every file, each quoted.
    ///
    /// ssh checks the host key against all listed files and appends a new
    /// key to the first one, so the private file comes first.
    pub(super) fn option_value(&self) -> OsString {
        let quoted: Vec<Vec<u8>> = std::iter::once(self.learned())
            .chain(self.consulted.as_deref())
            .map(quote)
            .collect();
        OsString::from_vec(quoted.join(&b' '))
    }
}

/// Refuses a path that ssh would rewrite with no way to escape it: ssh
/// expands `${VAR}` and a leading `~` in `UserKnownHostsFile`.
fn reject_expanded(path: &Path) -> Result<(), SshError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.starts_with(b"~") || bytes.windows(2).any(|pair| pair == b"${") {
        return Err(SshError::UnquotableKnownHostsPath {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// Writes `path` as one double-quoted `ssh_config` argument.
///
/// ssh splits the value on whitespace outside quotes, unescapes `\\` and
/// `\"` inside them, and turns `%%` into `%`.
fn quote(path: &Path) -> Vec<u8> {
    const QUOTE: u8 = b'"';
    let escaped = path.as_os_str().as_bytes().iter().flat_map(|&byte| {
        let escape = match byte {
            b'"' | b'\\' => Some(b'\\'),
            b'%' => Some(b'%'),
            _ => None,
        };
        escape.into_iter().chain(std::iter::once(byte))
    });
    std::iter::once(QUOTE)
        .chain(escaped)
        .chain(std::iter::once(QUOTE))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned(entries: &str) -> HostKeyPolicy {
        HostKeyPolicy::Pinned(entries.parse().unwrap())
    }

    fn trust_on_first_use(user_known_hosts: &str) -> HostKeyPolicy {
        HostKeyPolicy::TrustOnFirstUse {
            user_known_hosts: Some(PathBuf::from(user_known_hosts)),
        }
    }

    #[test]
    fn trust_on_first_use_records_keys_in_a_fresh_empty_file() {
        let sut = HostKeyPolicy::TrustOnFirstUse {
            user_known_hosts: None,
        };

        let files = sut.known_hosts_files().unwrap();

        let content = std::fs::read(files.learned()).unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn a_pinned_policy_writes_its_known_hosts_to_the_file() {
        let sut = pinned("203.0.113.5 ssh-ed25519 AAAA");

        let files = sut.known_hosts_files().unwrap();

        let content = std::fs::read_to_string(files.learned()).unwrap();
        assert_eq!(content, "203.0.113.5 ssh-ed25519 AAAA\n");
    }

    #[test]
    fn a_pinned_policy_lists_only_its_own_file() {
        let sut = pinned("203.0.113.5 ssh-ed25519 AAAA");

        let files = sut.known_hosts_files().unwrap();

        let expected = format!("\"{}\"", files.learned().display());
        assert_eq!(files.option_value(), OsString::from(expected));
    }

    #[test]
    fn the_users_known_hosts_is_consulted_after_the_file_ssh_appends_to() {
        let sut = trust_on_first_use("/home/user/.ssh/known_hosts");

        let files = sut.known_hosts_files().unwrap();

        let expected = format!(
            "\"{}\" \"/home/user/.ssh/known_hosts\"",
            files.learned().display()
        );
        assert_eq!(files.option_value(), OsString::from(expected));
    }

    #[test]
    fn spaces_quotes_backslashes_and_percents_survive_ssh_config_parsing() {
        let sut = trust_on_first_use(r#"/home/a b/"q"\x/100%/known_hosts"#);

        let files = sut.known_hosts_files().unwrap();

        let expected = format!(
            r#""{}" "/home/a b/\"q\"\\x/100%%/known_hosts""#,
            files.learned().display()
        );
        assert_eq!(files.option_value(), OsString::from(expected));
    }

    #[rstest::rstest]
    #[case::empty("")]
    #[case::whitespace(" \n\t ")]
    fn blank_known_hosts_entries_are_rejected(#[case] raw: &str) {
        let actual = raw.parse::<KnownHostsEntries>();

        assert_eq!(actual, Err(EmptyKnownHosts));
    }

    #[rstest::rstest]
    #[case::environment_variable("/home/${USER}/.ssh/known_hosts")]
    #[case::leading_tilde("~/.ssh/known_hosts")]
    fn a_path_that_ssh_would_expand_is_refused(#[case] path: &str) {
        let sut = trust_on_first_use(path);

        let error = sut.known_hosts_files().unwrap_err();

        assert!(
            matches!(
                &error,
                SshError::UnquotableKnownHostsPath { path: refused }
                    if refused == Path::new(path)
            ),
            "{error:?}"
        );
    }
}
