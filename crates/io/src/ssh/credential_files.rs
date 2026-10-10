use super::known_hosts::KnownHostsFiles;
use super::session::{SshConfig, SshError};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use tempfile::NamedTempFile;

pub(super) fn private_file() -> std::io::Result<NamedTempFile> {
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

/// The temporary files one ssh connection reads: the private key, when the
/// config has one, and the known-hosts files.
///
/// The files are removed when this value is dropped, so its owner keeps it
/// as long as the ssh process runs.
#[derive(Debug)]
pub(super) struct SshCredentialFiles {
    key: Option<NamedTempFile>,
    known_hosts: KnownHostsFiles,
}

impl SshCredentialFiles {
    pub(super) fn prepare(config: &SshConfig) -> Result<Self, SshError> {
        let key = config
            .private_key
            .as_ref()
            .map(|key| secret_file(key.expose()))
            .transpose()
            .map_err(|error| SshError::io("prepare SSH credentials", error))?;
        let known_hosts = config.host_keys.known_hosts_files()?;
        Ok(Self { key, known_hosts })
    }

    pub(super) fn key(&self) -> Option<&Path> {
        self.key.as_ref().map(NamedTempFile::path)
    }

    pub(super) const fn known_hosts(&self) -> &KnownHostsFiles {
        &self.known_hosts
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
}
