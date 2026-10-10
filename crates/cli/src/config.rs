use std::ffi::OsString;
use std::net::{AddrParseError, Ipv4Addr};
use std::num::{NonZeroU16, NonZeroU64};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use chip_core::model::InvalidCityName;
use chip_core::verdict::latency::{
    InvalidLatencyThresholds, LatencyThresholds,
};
use chip_core::{
    CheckResult, CityName, CountryCode, GateId, GateOverrides, ScanProfile,
    Severity,
};
use chip_io::credentials::{
    EmptySecret, GlobalpingToken, ProxycheckApiKey, SshPrivateKey,
};
use chip_io::globalping::{EmptyProbeSelection, ProbeSelection};
use chip_io::ssh::{HostKeyPolicy, KnownHostsEntries};
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "chip",
    version,
    about = "Vets a candidate cloud IP before it becomes an exit node"
)]
pub struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

/// Credentials are read from the environment only: there are deliberately no
/// flags for them, so they stay out of shell history and `ps` output.
const SCAN_AFTER_HELP: &str = "\
Credentials (environment only):
  SSH_PRIVATE_KEY     private key for the candidate, the key itself, not a path
  SSH_KNOWN_HOSTS     host key entries; without them a host's first key is
                      accepted unless ~/.ssh/known_hosts already lists it
  GLOBALPING_TOKEN    raises the Globalping quota from 250 to 500 tests/hour
  PROXYCHECK_API_KEY  raises the proxycheck.io limit to 1000 queries/day

Exit codes: 0 nothing failed, 1 a gate failed (rotate the IP), 2 a gate could \
not be judged (retry).";

#[derive(Subcommand)]
enum CliCommand {
    /// Run all enabled vetting gates for one candidate.
    #[command(after_help = SCAN_AFTER_HELP)]
    Scan(Box<ScanArgs>),
    /// Measure known-good nodes and suggest latency thresholds.
    Calibrate(CalibrateArgs),
}

pub enum Command {
    Scan(Box<ScanCommand>),
    Calibrate(CalibrateCommand),
}

/// Why the command line and the environment do not make a valid command.
/// Malformed single values are rejected earlier, by clap.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The secret is not shown: the error names only the variable.
    #[error("{name} must be valid UTF-8")]
    SecretNotUtf8 { name: &'static str },
    #[error("{name}")]
    EmptySecret {
        name: &'static str,
        #[source]
        source: EmptySecret,
    },
    #[error(transparent)]
    LatencyThresholds(#[from] InvalidLatencyThresholds),
    #[error("--eyeball-probes and --dc-probes cannot both be 0")]
    ProbeSelection(#[from] EmptyProbeSelection),
}

#[expect(
    clippy::map_err_ignore,
    reason = "the rejected value is a secret, so the error names only the \
              variable"
)]
fn secret_from_env<T>(
    name: &'static str,
    environment: impl Fn(&str) -> Option<OsString>,
) -> Result<Option<T>, ConfigError>
where
    T: TryFrom<String, Error = EmptySecret>,
{
    let Some(value) = environment(name) else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| ConfigError::SecretNotUtf8 { name })?;
    T::try_from(value)
        .map(Some)
        .map_err(|source| ConfigError::EmptySecret { name, source })
}

/// Values `scan` takes from the environment instead of its flags. `None`
/// means the variable is not set. `calibrate` reads only the Globalping
/// token and takes it as a plain `Option<GlobalpingToken>`.
struct ScanEnvironment {
    ssh_private_key: Option<SshPrivateKey>,
    globalping_token: Option<GlobalpingToken>,
    proxycheck_api_key: Option<ProxycheckApiKey>,
    home: Option<PathBuf>,
    /// The file GitHub Actions shows as the job summary. The path need not
    /// be UTF-8, so the `OsString` from the environment becomes a `PathBuf`
    /// unchanged.
    step_summary: Option<PathBuf>,
}

impl ScanEnvironment {
    fn read(
        environment: impl Fn(&str) -> Option<OsString>,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            ssh_private_key: secret_from_env("SSH_PRIVATE_KEY", &environment)?,
            globalping_token: secret_from_env(
                "GLOBALPING_TOKEN",
                &environment,
            )?,
            proxycheck_api_key: secret_from_env(
                "PROXYCHECK_API_KEY",
                &environment,
            )?,
            home: environment("HOME").map(PathBuf::from),
            step_summary: environment("GITHUB_STEP_SUMMARY").map(PathBuf::from),
        })
    }

    /// The user's `~/.ssh/known_hosts`, which ssh still checks known hosts
    /// against under trust-on-first-use. A relative or empty `HOME` names no
    /// usable directory. A missing file needs no check here: ssh skips it.
    fn user_known_hosts(&self) -> Option<PathBuf> {
        self.home
            .as_deref()
            .filter(|home| home.is_absolute())
            .map(|home| home.join(".ssh").join("known_hosts"))
    }
}

impl Cli {
    /// Combines the flags with the variables `environment` looks up by name.
    /// `main` passes the process environment, tests pass a fixed table, and
    /// both take this one path.
    pub fn into_command(
        self,
        environment: impl Fn(&str) -> Option<OsString>,
    ) -> Result<Command, ConfigError> {
        match self.command {
            CliCommand::Scan(args) => ScanCommand::try_from((
                *args,
                ScanEnvironment::read(environment)?,
            ))
            .map(|command| Command::Scan(Box::new(command))),
            CliCommand::Calibrate(args) => CalibrateCommand::try_from((
                args,
                secret_from_env("GLOBALPING_TOKEN", &environment)?,
            ))
            .map(Command::Calibrate),
        }
    }
}

#[derive(Args, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "CLI arguments: each flag is an independent switch"
)]
struct ScanArgs {
    /// The candidate IPv4 address to vet.
    ip: Ipv4Addr,
    /// Country the address was ordered in; the geo gate fails when the public
    /// sources disagree with it.
    #[arg(long)]
    country: CountryCode,
    /// City the address was ordered in; picks the RIPE Atlas anchors the
    /// latency gate compares against. Without it, anchors of the country are
    /// used.
    #[arg(long)]
    city: Option<CityName>,
    /// SSH user on the candidate.
    #[arg(long, env = "SSH_USER", default_value = "root")]
    ssh_user: String,
    /// SSH port on the candidate.
    #[arg(long, env = "SSH_PORT", default_value = "22")]
    ssh_port: NonZeroU16,
    /// Known-hosts entries for strict host key checking; without them the
    /// first key seen is accepted, unless `~/.ssh/known_hosts` already lists
    /// a key for the host. That file is read, never written.
    #[arg(long, env = "SSH_KNOWN_HOSTS")]
    ssh_known_hosts: Option<KnownHostsEntries>,
    /// Fail the latency gate above this median excess over the best anchor of
    /// the candidate's city, in milliseconds.
    #[arg(long, default_value_t = 14.0)]
    max_excess_ms: f64,
    /// Fail the latency gate when packet loss exceeds the anchors' own loss by
    /// more than this many percentage points.
    #[arg(long, default_value_t = 2.0)]
    max_loss_pct: f64,
    /// City the candidate's city is priced against in the report. Reported for
    /// choosing a country, never a gate.
    #[arg(long, default_value = "Helsinki")]
    reference_city: CityName,
    /// How many probes in Russian home networks to measure from.
    #[arg(long, default_value_t = 8)]
    eyeball_probes: u8,
    /// How many probes in Russian datacenters to measure from.
    #[arg(long, default_value_t = 4)]
    dc_probes: u8,
    /// Deadline for phase B. What is still unmeasured when it passes is
    /// reported as an error; the listener and tunnel are cleaned up anyway.
    #[arg(long, default_value = "300")]
    deadline_secs: NonZeroU64,
    /// Promote a warning to a failure for this gate id, e.g.
    /// `--gate service:claude`. An id the scan does not know is rejected
    /// here rather than silently never matching. Repeatable and
    /// comma-separated.
    #[arg(long = "gate", value_delimiter = ',')]
    gate: Vec<GateId>,
    /// Turn this gate off, e.g. `--skip-gate reach`. It is reported as SKIP
    /// and cannot change the exit code. Repeatable and comma-separated.
    #[arg(long = "skip-gate", value_delimiter = ',')]
    skip_gate: Vec<GateId>,
    /// Compare latency against this address instead of the RIPE Atlas anchors
    /// picked for the city.
    #[arg(long)]
    anchor: Option<Ipv4Addr>,
    /// Do not sweep the candidate's /24; both neighbor gates report SKIP.
    #[arg(long)]
    no_neighbors: bool,
    /// Do not touch the candidate over SSH; every gate that needs the listener
    /// or the tunnel reports SKIP.
    #[arg(long)]
    no_ssh: bool,
    /// Run phase B even when a phase-A gate already failed.
    #[arg(long)]
    no_fail_fast: bool,
    /// Write the machine-readable report to this path.
    #[arg(long)]
    json: Option<PathBuf>,
}

#[derive(Args)]
struct CalibrateArgs {
    /// One or more `IP=City` targets.
    #[arg(required = true, value_parser = parse_calibration_target)]
    targets: Vec<CalibrationTarget>,
    /// How many probes in Russian home networks to measure from.
    #[arg(long, default_value_t = 8)]
    eyeball_probes: u8,
    /// How many probes in Russian datacenters to measure from.
    #[arg(long, default_value_t = 4)]
    dc_probes: u8,
}

/// Whether phase B still runs after a phase-A gate failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePolicy {
    /// A failed phase-A gate already rules the candidate out, so phase B is
    /// not started.
    FailFast,
    /// Phase B runs whatever phase A reported.
    RunAll,
}

impl FailurePolicy {
    /// Whether the scan stops after these results. Only a failure stops it:
    /// an unjudged gate may still pass on retry.
    pub fn stops_after(self, results: &[CheckResult]) -> bool {
        match self {
            Self::FailFast => results
                .iter()
                .any(|result| result.severity() == Severity::Fail),
            Self::RunAll => false,
        }
    }
}

/// Whether the candidate's /24 is swept for neighbors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborSweep {
    Enabled,
    Disabled,
}

/// How the scan reaches the candidate over SSH.
#[derive(Debug, Clone)]
pub enum SshAccess {
    /// `--no-ssh`: every gate that needs the listener or the tunnel is
    /// skipped.
    Disabled,
    Enabled(SshSettings),
}

#[derive(Debug, Clone)]
pub struct SshSettings {
    user: String,
    port: NonZeroU16,
    host_keys: HostKeyPolicy,
    private_key: Option<SshPrivateKey>,
}

impl SshSettings {
    pub fn user(&self) -> &str {
        &self.user
    }

    pub const fn port(&self) -> NonZeroU16 {
        self.port
    }

    pub const fn host_keys(&self) -> &HostKeyPolicy {
        &self.host_keys
    }

    pub const fn private_key(&self) -> Option<&SshPrivateKey> {
        self.private_key.as_ref()
    }
}

pub struct ScanCommand {
    ip: Ipv4Addr,
    country: CountryCode,
    city: Option<CityName>,
    ssh_access: SshAccess,
    globalping_token: Option<GlobalpingToken>,
    proxycheck_api_key: Option<ProxycheckApiKey>,
    latency_thresholds: LatencyThresholds,
    reference_city: CityName,
    probes: ProbeSelection,
    deadline: std::time::Duration,
    gate_overrides: GateOverrides,
    anchor: Option<Ipv4Addr>,
    neighbor_sweep: NeighborSweep,
    failure_policy: FailurePolicy,
    json: Option<PathBuf>,
    step_summary: Option<PathBuf>,
}

impl TryFrom<(ScanArgs, ScanEnvironment)> for ScanCommand {
    type Error = ConfigError;

    fn try_from(
        (args, environment): (ScanArgs, ScanEnvironment),
    ) -> Result<Self, Self::Error> {
        let latency_thresholds = LatencyThresholds::from_millis_and_points(
            args.max_excess_ms,
            args.max_loss_pct,
        )?;
        let probes = ProbeSelection::new(args.eyeball_probes, args.dc_probes)?;
        let ssh_access = if args.no_ssh {
            SshAccess::Disabled
        } else {
            let host_keys = args.ssh_known_hosts.map_or_else(
                || HostKeyPolicy::TrustOnFirstUse {
                    user_known_hosts: environment.user_known_hosts(),
                },
                HostKeyPolicy::Pinned,
            );
            SshAccess::Enabled(SshSettings {
                user: args.ssh_user,
                port: args.ssh_port,
                host_keys,
                private_key: environment.ssh_private_key,
            })
        };
        let neighbor_sweep = if args.no_neighbors {
            NeighborSweep::Disabled
        } else {
            NeighborSweep::Enabled
        };
        let failure_policy = if args.no_fail_fast {
            FailurePolicy::RunAll
        } else {
            FailurePolicy::FailFast
        };
        Ok(Self {
            ip: args.ip,
            country: args.country,
            city: args.city,
            ssh_access,
            globalping_token: environment.globalping_token,
            proxycheck_api_key: environment.proxycheck_api_key,
            latency_thresholds,
            reference_city: args.reference_city,
            probes,
            deadline: std::time::Duration::from_secs(args.deadline_secs.get()),
            gate_overrides: GateOverrides {
                escalate: args.gate.into_iter().collect(),
                skip: args.skip_gate.into_iter().collect(),
            },
            anchor: args.anchor,
            neighbor_sweep,
            failure_policy,
            json: args.json,
            step_summary: environment.step_summary,
        })
    }
}

impl ScanCommand {
    pub const fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    pub const fn country(&self) -> &CountryCode {
        &self.country
    }

    pub fn profile(&self) -> ScanProfile {
        ScanProfile::for_country(&self.country)
    }

    pub const fn city(&self) -> Option<&CityName> {
        self.city.as_ref()
    }

    pub const fn ssh_access(&self) -> &SshAccess {
        &self.ssh_access
    }

    pub const fn globalping_token(&self) -> Option<&GlobalpingToken> {
        self.globalping_token.as_ref()
    }

    pub const fn proxycheck_api_key(&self) -> Option<&ProxycheckApiKey> {
        self.proxycheck_api_key.as_ref()
    }

    pub const fn latency_thresholds(&self) -> &LatencyThresholds {
        &self.latency_thresholds
    }

    pub const fn reference_city(&self) -> &CityName {
        &self.reference_city
    }

    pub const fn probes(&self) -> ProbeSelection {
        self.probes
    }

    pub const fn deadline(&self) -> std::time::Duration {
        self.deadline
    }

    pub const fn gate_overrides(&self) -> &GateOverrides {
        &self.gate_overrides
    }

    pub const fn anchor(&self) -> Option<Ipv4Addr> {
        self.anchor
    }

    pub const fn neighbor_sweep(&self) -> NeighborSweep {
        self.neighbor_sweep
    }

    pub const fn failure_policy(&self) -> FailurePolicy {
        self.failure_policy
    }

    pub fn json_path(&self) -> Option<&Path> {
        self.json.as_deref()
    }

    pub fn step_summary_path(&self) -> Option<&Path> {
        self.step_summary.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalibrationTarget {
    ip: Ipv4Addr,
    city: CityName,
}

impl CalibrationTarget {
    pub const fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    pub const fn city(&self) -> &CityName {
        &self.city
    }
}

/// Why an `IP=City` calibration target was rejected. Each variant keeps the
/// whole rejected argument, since a run takes several targets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CalibrationTargetError {
    #[error("expected IP=City, got '{raw}'")]
    MissingSeparator { raw: String },
    #[error("invalid IPv4 address in '{raw}'")]
    Ip {
        raw: String,
        #[source]
        source: AddrParseError,
    },
    #[error("invalid city in '{raw}'")]
    City {
        raw: String,
        #[source]
        source: InvalidCityName,
    },
}

/// clap prints only the `Display` of a value's parse error, not its source
/// chain, so the parser hands clap the whole chain joined by ": ".
fn parse_calibration_target(raw: &str) -> Result<CalibrationTarget, String> {
    raw.parse::<CalibrationTarget>()
        .map_err(|error| chip_io::describe_error(&error))
}

impl FromStr for CalibrationTarget {
    type Err = CalibrationTargetError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (ip, city) = raw.split_once('=').ok_or_else(|| {
            CalibrationTargetError::MissingSeparator {
                raw: raw.to_owned(),
            }
        })?;
        let ip = ip.parse().map_err(|source| CalibrationTargetError::Ip {
            raw: raw.to_owned(),
            source,
        })?;
        let city =
            city.parse()
                .map_err(|source| CalibrationTargetError::City {
                    raw: raw.to_owned(),
                    source,
                })?;
        Ok(Self { ip, city })
    }
}

pub struct CalibrateCommand {
    targets: Vec<CalibrationTarget>,
    globalping_token: Option<GlobalpingToken>,
    probes: ProbeSelection,
}

impl TryFrom<(CalibrateArgs, Option<GlobalpingToken>)> for CalibrateCommand {
    type Error = ConfigError;

    fn try_from(
        (args, globalping_token): (CalibrateArgs, Option<GlobalpingToken>),
    ) -> Result<Self, Self::Error> {
        let probes = ProbeSelection::new(args.eyeball_probes, args.dc_probes)?;
        Ok(Self {
            targets: args.targets,
            globalping_token,
            probes,
        })
    }
}

impl CalibrateCommand {
    pub fn targets(&self) -> &[CalibrationTarget] {
        &self.targets
    }

    pub const fn globalping_token(&self) -> Option<&GlobalpingToken> {
        self.globalping_token.as_ref()
    }

    pub const fn probes(&self) -> ProbeSelection {
        self.probes
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use chip_core::{Verdict, gate};

    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("chip").chain(args.iter().copied()))
            .unwrap()
    }

    /// A lookup over a fixed table, standing in for the process environment.
    fn environment<'a>(
        variables: &'a [(&str, &str)],
    ) -> impl Fn(&str) -> Option<OsString> + 'a {
        |name| {
            variables
                .iter()
                .find(|(variable, _)| *variable == name)
                .map(|(_, value)| OsString::from(value))
        }
    }

    fn scan_command_with(
        args: &[&str],
        variables: &[(&str, &str)],
    ) -> Result<Box<ScanCommand>, ConfigError> {
        parse(args)
            .into_command(environment(variables))
            .map(into_scan)
    }

    fn into_scan(command: Command) -> Box<ScanCommand> {
        let Command::Scan(command) = command else {
            panic!("expected scan command")
        };
        command
    }

    fn scan_command(args: &[&str]) -> Result<Box<ScanCommand>, ConfigError> {
        scan_command_with(args, &[])
    }

    fn ssh_settings(command: &ScanCommand) -> &SshSettings {
        let SshAccess::Enabled(settings) = command.ssh_access() else {
            panic!("expected SSH access to be enabled")
        };
        settings
    }

    #[test]
    fn scan_parses_domain_values_and_defaults() {
        let command =
            scan_command(&["scan", "203.0.113.1", "--country", "fi"]).unwrap();

        assert_eq!(command.ip(), Ipv4Addr::new(203, 0, 113, 1));
        assert_eq!(command.country().as_str(), "FI");
        assert_eq!(ssh_settings(&command).user(), "root");
        assert_eq!(command.reference_city().as_str(), "Helsinki");
        assert_eq!(command.probes(), ProbeSelection::new(8, 4).unwrap());
        assert_eq!(command.neighbor_sweep(), NeighborSweep::Enabled);
        assert_eq!(command.failure_policy(), FailurePolicy::FailFast);
    }

    #[test]
    fn no_ssh_turns_off_every_ssh_connection() {
        let command = scan_command_with(
            &["scan", "203.0.113.1", "--country", "FI", "--no-ssh"],
            &[("SSH_PRIVATE_KEY", "key-value")],
        )
        .unwrap();

        assert!(
            matches!(command.ssh_access(), SshAccess::Disabled),
            "{:?}",
            command.ssh_access()
        );
    }

    #[test]
    fn ssh_settings_combine_the_flags_with_the_key_from_the_environment() {
        let command = scan_command_with(
            &[
                "scan",
                "203.0.113.1",
                "--country",
                "FI",
                "--ssh-user",
                "admin",
                "--ssh-port",
                "2222",
            ],
            &[("SSH_PRIVATE_KEY", "key-value")],
        )
        .unwrap();

        let settings = ssh_settings(&command);
        assert_eq!(settings.user(), "admin");
        assert_eq!(settings.port().get(), 2222);
        assert!(settings.private_key().is_some());
    }

    #[test]
    fn known_hosts_entries_pin_the_candidate_host_key() {
        let command = scan_command(&[
            "scan",
            "203.0.113.1",
            "--country",
            "FI",
            "--ssh-known-hosts",
            "203.0.113.1 ssh-ed25519 AAAA",
        ])
        .unwrap();

        assert_eq!(
            ssh_settings(&command).host_keys(),
            &HostKeyPolicy::Pinned(
                "203.0.113.1 ssh-ed25519 AAAA".parse().unwrap()
            )
        );
    }

    #[test]
    fn without_known_hosts_the_first_key_is_trusted_unless_home_records_it() {
        let command = scan_command_with(
            &["scan", "203.0.113.1", "--country", "FI"],
            &[("HOME", "/home/a user")],
        )
        .unwrap();

        assert_eq!(
            ssh_settings(&command).host_keys(),
            &HostKeyPolicy::TrustOnFirstUse {
                user_known_hosts: Some(PathBuf::from(
                    "/home/a user/.ssh/known_hosts"
                )),
            }
        );
    }

    #[rstest::rstest]
    #[case::no_home(&[])]
    #[case::empty_home(&[("HOME", "")])]
    #[case::relative_home(&[("HOME", "home/user")])]
    fn without_a_usable_home_only_the_first_key_seen_is_trusted(
        #[case] variables: &[(&str, &str)],
    ) {
        let command = scan_command_with(
            &["scan", "203.0.113.1", "--country", "FI"],
            variables,
        )
        .unwrap();

        assert_eq!(
            ssh_settings(&command).host_keys(),
            &HostKeyPolicy::TrustOnFirstUse {
                user_known_hosts: None
            }
        );
    }

    #[test]
    fn no_fail_fast_runs_phase_b_after_a_failure() {
        let command = scan_command(&[
            "scan",
            "203.0.113.1",
            "--country",
            "FI",
            "--no-fail-fast",
        ])
        .unwrap();

        assert_eq!(command.failure_policy(), FailurePolicy::RunAll);
    }

    #[test]
    fn no_neighbors_turns_off_the_neighbor_sweep() {
        let command = scan_command(&[
            "scan",
            "203.0.113.1",
            "--country",
            "FI",
            "--no-neighbors",
        ])
        .unwrap();

        assert_eq!(command.neighbor_sweep(), NeighborSweep::Disabled);
    }

    #[rstest::rstest]
    #[case::fail_fast_on_fail(
        FailurePolicy::FailFast,
        Verdict::fail("wrong country"),
        true
    )]
    #[case::error_is_not_fail(
        FailurePolicy::FailFast,
        Verdict::error("unavailable"),
        false
    )]
    #[case::run_all_after_fail(
        FailurePolicy::RunAll,
        Verdict::fail("wrong country"),
        false
    )]
    fn only_a_failure_under_fail_fast_stops_the_scan(
        #[case] sut: FailurePolicy,
        #[case] verdict: Verdict,
        #[case] expected: bool,
    ) {
        let results = [CheckResult::new(gate::GEO, verdict)];

        let actual = sut.stops_after(&results);

        assert_eq!(actual, expected);
    }

    #[rstest::rstest]
    #[case::invalid_ip(
        &["scan", "not-an-ip", "--country", "FI"],
        "invalid IPv4 address syntax"
    )]
    #[case::unknown_country(
        &["scan", "203.0.113.1", "--country", "ZZ"],
        "not a recognized country code"
    )]
    #[case::empty_city(
        &["scan", "203.0.113.1", "--country", "FI", "--city", "   "],
        "city name must not be empty"
    )]
    #[case::blank_known_hosts(
        &["scan", "203.0.113.1", "--country", "FI", "--ssh-known-hosts", " "],
        "known-hosts entries must not be empty"
    )]
    #[case::misspelled_gate(
        &["scan", "203.0.113.1", "--country", "FI", "--gate", "service:clade"],
        "'service:clade' is not a known gate id"
    )]
    #[case::misspelled_skip_gate(
        &["scan", "203.0.113.1", "--country", "FI", "--skip-gate", "raech"],
        "'raech' is not a known gate id"
    )]
    fn malformed_values_are_rejected_during_parsing(
        #[case] args: &[&str],
        #[case] expected_detail: &str,
    ) {
        let error = Cli::try_parse_from(
            std::iter::once("chip").chain(args.iter().copied()),
        )
        .err()
        .expect("input must be rejected");

        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
        assert!(error.to_string().contains(expected_detail), "{error}");
    }

    #[test]
    fn repeated_and_comma_separated_gate_flags_accumulate() {
        let command = scan_command(&[
            "scan",
            "203.0.113.1",
            "--country",
            "FI",
            "--gate",
            "service:claude,neighbors",
            "--gate",
            "reputation:operator",
        ])
        .unwrap();

        assert_eq!(
            command.gate_overrides().escalate,
            HashSet::from([
                gate::SERVICE_CLAUDE,
                gate::NEIGHBORS,
                gate::REPUTATION_OPERATOR,
            ])
        );
    }

    #[test]
    fn a_non_finite_latency_excess_threshold_is_rejected() {
        let args = [
            "scan",
            "203.0.113.1",
            "--country",
            "FI",
            "--max-excess-ms",
            "NaN",
        ];

        let error = scan_command(&args).err().expect("input must be rejected");

        assert!(
            matches!(
                error,
                ConfigError::LatencyThresholds(
                    InvalidLatencyThresholds::MaxExcess(value)
                ) if value.is_nan()
            ),
            "{error:?}"
        );
    }

    #[test]
    fn a_negative_loss_threshold_is_rejected() {
        let args = [
            "scan",
            "203.0.113.1",
            "--country",
            "FI",
            "--max-loss-pct=-0.1",
        ];

        let error = scan_command(&args).err().expect("input must be rejected");

        assert!(
            matches!(
                error,
                ConfigError::LatencyThresholds(
                    InvalidLatencyThresholds::MaxLossDelta(-0.1)
                )
            ),
            "{error:?}"
        );
    }

    #[test]
    fn a_scan_without_any_probes_is_rejected() {
        let args = [
            "scan",
            "203.0.113.1",
            "--country",
            "FI",
            "--eyeball-probes",
            "0",
            "--dc-probes",
            "0",
        ];

        let error = scan_command(&args).err().expect("input must be rejected");

        assert!(
            matches!(error, ConfigError::ProbeSelection(EmptyProbeSelection)),
            "{error:?}"
        );
    }

    #[test]
    fn calibration_targets_are_parsed_before_orchestration() {
        let command =
            parse(&["calibrate", "203.0.113.7=Helsinki", "198.51.100.9=Turku"])
                .into_command(environment(&[]))
                .unwrap();
        let Command::Calibrate(calibration) = command else {
            panic!("expected calibrate command")
        };

        assert_eq!(calibration.targets().len(), 2);
        assert_eq!(
            calibration.targets()[0].ip(),
            Ipv4Addr::new(203, 0, 113, 7)
        );
        assert_eq!(calibration.targets()[0].city().as_str(), "Helsinki");
    }

    #[test]
    fn a_malformed_calibration_target_is_rejected_by_the_parser() {
        let args = ["chip", "calibrate", "not-an-ip=Helsinki"];

        let error = Cli::try_parse_from(args)
            .err()
            .expect("target must be rejected");

        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
        assert!(
            error.to_string().contains(
                "invalid IPv4 address in 'not-an-ip=Helsinki': invalid IPv4 \
                 address syntax"
            ),
            "{error}"
        );
    }

    #[test]
    fn an_ip_and_a_city_joined_by_equals_make_a_target() {
        let actual = "203.0.113.7=Helsinki".parse::<CalibrationTarget>();

        assert_eq!(
            actual,
            Ok(CalibrationTarget {
                ip: Ipv4Addr::new(203, 0, 113, 7),
                city: "Helsinki".parse().unwrap(),
            })
        );
    }

    #[test]
    fn a_target_without_equals_is_missing_its_separator() {
        let actual = "203.0.113.7".parse::<CalibrationTarget>();

        assert!(
            matches!(
                &actual,
                Err(CalibrationTargetError::MissingSeparator { raw })
                    if raw == "203.0.113.7"
            ),
            "{actual:?}"
        );
    }

    #[test]
    fn a_target_with_a_malformed_ip_is_rejected_for_its_ip() {
        let actual = "203.0.113=Helsinki".parse::<CalibrationTarget>();

        assert!(
            matches!(
                &actual,
                Err(CalibrationTargetError::Ip { raw, .. })
                    if raw == "203.0.113=Helsinki"
            ),
            "{actual:?}"
        );
    }

    #[rstest::rstest]
    #[case::empty_city("203.0.113.7=")]
    #[case::blank_city("203.0.113.7=   ")]
    fn a_target_without_a_city_name_is_rejected_for_its_city(
        #[case] target: &str,
    ) {
        let actual = target.parse::<CalibrationTarget>();

        assert!(
            matches!(
                &actual,
                Err(CalibrationTargetError::City { raw, .. }) if raw == target
            ),
            "{actual:?}"
        );
    }

    #[test]
    fn an_owned_environment_value_becomes_a_typed_secret() {
        let secret = secret_from_env::<GlobalpingToken>(
            "GLOBALPING_TOKEN",
            environment(&[("GLOBALPING_TOKEN", "token-value")]),
        )
        .unwrap();

        assert!(secret.is_some());
    }

    #[test]
    fn a_blank_environment_secret_names_the_setting_in_its_error() {
        let error = secret_from_env::<ProxycheckApiKey>(
            "PROXYCHECK_API_KEY",
            environment(&[("PROXYCHECK_API_KEY", "   ")]),
        )
        .unwrap_err();

        assert!(
            matches!(
                error,
                ConfigError::EmptySecret {
                    name: "PROXYCHECK_API_KEY",
                    ..
                }
            ),
            "{error:?}"
        );
        assert_eq!(error.to_string(), "PROXYCHECK_API_KEY");
    }
}
