use super::session::{SshError, SshSession};
use chip_core::checks::ssh::steal::ProcStatSnapshot;
use thiserror::Error;

/// Why the CPU steal counters could not be read from the candidate.
#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("could not parse /proc/stat")]
    Unparsable,
    #[error(transparent)]
    Ssh(#[from] SshError),
}

fn parse_proc_stat(text: &str) -> Option<ProcStatSnapshot> {
    let line = text.lines().find(|l| l.starts_with("cpu "))?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if fields.len() < 8 {
        return None;
    }
    ProcStatSnapshot::new(fields[7], fields.iter().sum()).ok()
}

impl SshSession {
    /// # Errors
    ///
    /// Returns `SnapshotError::Unparsable` when the `cpu` line of
    /// `/proc/stat` cannot be parsed.
    pub async fn steal_snapshot(
        &self,
    ) -> Result<ProcStatSnapshot, SnapshotError> {
        let timeout = self.command_timeout();
        let text = self.run_command("cat", &["/proc/stat"], timeout).await?;
        parse_proc_stat(&text).ok_or(SnapshotError::Unparsable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steal_and_total_ticks_come_from_the_aggregate_cpu_line_only() {
        let text = "cpu  1200 30 450 90111 12 0 34 250 0 0\n\
                    cpu0 600 15 225 45055 6 0 17 125 0 0\n";

        let sut = parse_proc_stat(text).unwrap();

        assert_eq!(sut.steal_ticks(), 250);
        assert_eq!(sut.total_ticks(), 92087);
    }

    #[rstest::rstest]
    #[case::too_few_fields("cpu  1 2 3\n")]
    #[case::no_cpu_line("nonsense\n")]
    fn an_unreadable_proc_stat_gives_no_snapshot(#[case] text: &str) {
        let actual = parse_proc_stat(text);

        assert!(actual.is_none());
    }
}
