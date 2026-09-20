use std::ffi::OsString;
use std::fmt;
use std::net::Ipv4Addr;
use std::num::{NonZeroU16, NonZeroU64};
use std::path::PathBuf;
use std::str::FromStr;

use chip_core::verdict::latency::LatencyThresholds;
use chip_core::{CityName, CountryCode, GateId, GateOverrides};
use chip_io::credentials::{GlobalpingToken, ProxycheckApiKey, SshPrivateKey};
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CandidateIp(Ipv4Addr);

impl CandidateIp {
    const fn as_ipv4(self) -> Ipv4Addr {
        self.0
    }
}

impl FromStr for CandidateIp {
    type Err = std::net::AddrParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse().map(Self)
    }
}

impl fmt::Display for CandidateIp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

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

#[derive(Subcommand)]
enum CliCommand {
    /// Run all enabled vetting gates for one candidate.
    Scan(Box<ScanArgs>),
    /// Measure known-good nodes and suggest latency thresholds.
    Calibrate(CalibrateArgs),
}

pub enum Command {
    Scan(Box<ScanCommand>),
    Calibrate(CalibrateCommand),
}

fn secret_from_env<T>(
    name: &'static str,
    value: Option<OsString>,
) -> anyhow::Result<Option<T>>
where
    T: TryFrom<String>,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("{name} must be valid UTF-8"))?;
    T::try_from(value)
        .map(Some)
        .map_err(anyhow::Error::new)
        .map_err(|error| error.context(name))
}

#[derive(Default)]
struct SecretInputs {
    ssh_private_key: Option<SshPrivateKey>,
    globalping_token: Option<GlobalpingToken>,
    proxycheck_api_key: Option<ProxycheckApiKey>,
}

impl SecretInputs {
    fn for_scan_environment() -> anyhow::Result<Self> {
        Ok(Self {
            ssh_private_key: secret_from_env(
                "SSH_PRIVATE_KEY",
                std::env::var_os("SSH_PRIVATE_KEY"),
            )?,
            globalping_token: secret_from_env(
                "GLOBALPING_TOKEN",
                std::env::var_os("GLOBALPING_TOKEN"),
            )?,
            proxycheck_api_key: secret_from_env(
                "PROXYCHECK_API_KEY",
                std::env::var_os("PROXYCHECK_API_KEY"),
            )?,
        })
    }

    fn for_calibrate_environment() -> anyhow::Result<Self> {
        Ok(Self {
            globalping_token: secret_from_env(
                "GLOBALPING_TOKEN",
                std::env::var_os("GLOBALPING_TOKEN"),
            )?,
            ..Self::default()
        })
    }
}

impl Cli {
    pub fn into_command(self) -> anyhow::Result<Command> {
        match self.command {
            CliCommand::Scan(args) => ScanCommand::try_from((
                *args,
                SecretInputs::for_scan_environment()?,
            ))
            .map(|command| Command::Scan(Box::new(command))),
            CliCommand::Calibrate(args) => CalibrateCommand::try_from((
                args,
                SecretInputs::for_calibrate_environment()?,
            ))
            .map(Command::Calibrate),
        }
    }

    #[cfg(test)]
    fn into_command_with(
        self,
        secrets: SecretInputs,
    ) -> anyhow::Result<Command> {
        match self.command {
            CliCommand::Scan(args) => ScanCommand::try_from((*args, secrets))
                .map(|command| Command::Scan(Box::new(command))),
            CliCommand::Calibrate(args) => {
                CalibrateCommand::try_from((args, secrets))
                    .map(Command::Calibrate)
            }
        }
    }
}

#[derive(Args, Clone)]
struct ScanArgs {
    ip: CandidateIp,
    #[arg(long)]
    country: CountryCode,
    #[arg(long)]
    city: Option<CityName>,
    #[arg(long, env = "SSH_USER", default_value = "root")]
    ssh_user: String,
    #[arg(long, env = "SSH_PORT", default_value = "22")]
    ssh_port: NonZeroU16,
    #[arg(long, env = "SSH_KNOWN_HOSTS")]
    ssh_known_hosts: Option<String>,
    #[arg(long, default_value_t = 14.0)]
    max_excess_ms: f64,
    #[arg(long, default_value_t = 2.0)]
    max_loss_pct: f64,
    #[arg(long, default_value = "Helsinki")]
    reference_city: CityName,
    #[arg(long, default_value_t = 8)]
    eyeball_probes: u8,
    #[arg(long, default_value_t = 4)]
    dc_probes: u8,
    #[arg(long, default_value = "300")]
    deadline_secs: NonZeroU64,
    #[arg(long = "gate", value_delimiter = ',')]
    gate: Vec<String>,
    #[arg(long = "skip-gate", value_delimiter = ',')]
    skip_gate: Vec<String>,
    #[arg(long)]
    anchor: Option<Ipv4Addr>,
    #[arg(long)]
    no_neighbors: bool,
    #[arg(long)]
    no_ssh: bool,
    #[arg(long)]
    no_fail_fast: bool,
    #[arg(long)]
    json: Option<PathBuf>,
}

#[derive(Args)]
struct CalibrateArgs {
    /// One or more `IP=City` targets.
    #[arg(required = true)]
    targets: Vec<String>,
    #[arg(long, default_value_t = 8)]
    eyeball_probes: u8,
    #[arg(long, default_value_t = 4)]
    dc_probes: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeSelection {
    eyeball: u8,
    datacenter: u8,
}

impl ProbeSelection {
    fn new(eyeball: u8, datacenter: u8) -> anyhow::Result<Self> {
        if eyeball == 0 && datacenter == 0 {
            anyhow::bail!("--eyeball-probes and --dc-probes cannot both be 0");
        }
        Ok(Self {
            eyeball,
            datacenter,
        })
    }

    pub const fn eyeball(self) -> u8 {
        self.eyeball
    }

    pub const fn datacenter(self) -> u8 {
        self.datacenter
    }
}

pub struct ScanCommand {
    ip: Ipv4Addr,
    country: CountryCode,
    city: Option<CityName>,
    ssh_private_key: Option<SshPrivateKey>,
    ssh_user: String,
    ssh_port: NonZeroU16,
    ssh_known_hosts: Option<String>,
    globalping_token: Option<GlobalpingToken>,
    proxycheck_api_key: Option<ProxycheckApiKey>,
    latency_thresholds: LatencyThresholds,
    reference_city: CityName,
    probes: ProbeSelection,
    deadline: std::time::Duration,
    gate_overrides: GateOverrides,
    anchor: Option<Ipv4Addr>,
    neighbors_enabled: bool,
    ssh_enabled: bool,
    fail_fast: bool,
    json: Option<PathBuf>,
}

impl TryFrom<(ScanArgs, SecretInputs)> for ScanCommand {
    type Error = anyhow::Error;

    fn try_from(
        (args, secrets): (ScanArgs, SecretInputs),
    ) -> Result<Self, Self::Error> {
        let latency_thresholds =
            LatencyThresholds::new(args.max_excess_ms, args.max_loss_pct)
                .map_err(|error| anyhow::anyhow!(error))?;
        let probes = ProbeSelection::new(args.eyeball_probes, args.dc_probes)?;
        Ok(Self {
            ip: args.ip.as_ipv4(),
            country: args.country,
            city: args.city,
            ssh_private_key: secrets.ssh_private_key,
            ssh_user: args.ssh_user,
            ssh_port: args.ssh_port,
            ssh_known_hosts: args.ssh_known_hosts,
            globalping_token: secrets.globalping_token,
            proxycheck_api_key: secrets.proxycheck_api_key,
            latency_thresholds,
            reference_city: args.reference_city,
            probes,
            deadline: std::time::Duration::from_secs(args.deadline_secs.get()),
            gate_overrides: GateOverrides {
                escalate: args.gate.into_iter().map(GateId::from).collect(),
                skip: args.skip_gate.into_iter().map(GateId::from).collect(),
            },
            anchor: args.anchor,
            neighbors_enabled: !args.no_neighbors,
            ssh_enabled: !args.no_ssh,
            fail_fast: !args.no_fail_fast,
            json: args.json,
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

    pub const fn city(&self) -> Option<&CityName> {
        self.city.as_ref()
    }

    pub const fn ssh_private_key(&self) -> Option<&SshPrivateKey> {
        self.ssh_private_key.as_ref()
    }

    pub fn ssh_user(&self) -> &str {
        &self.ssh_user
    }

    pub const fn ssh_port(&self) -> NonZeroU16 {
        self.ssh_port
    }

    pub fn ssh_known_hosts(&self) -> Option<&str> {
        self.ssh_known_hosts.as_deref()
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

    pub const fn neighbors_enabled(&self) -> bool {
        self.neighbors_enabled
    }

    pub const fn ssh_enabled(&self) -> bool {
        self.ssh_enabled
    }

    pub const fn fail_fast(&self) -> bool {
        self.fail_fast
    }

    pub fn json_path(&self) -> Option<&std::path::Path> {
        self.json.as_deref()
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

fn parse_target(raw: &str) -> anyhow::Result<CalibrationTarget> {
    let (ip, city) = raw
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("expected IP=City, got '{raw}'"))?;
    let ip = ip.parse().map_err(|error| {
        anyhow::anyhow!("invalid IPv4 address in '{raw}': {error}")
    })?;
    let city = city
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid city in '{raw}': {error}"))?;
    Ok(CalibrationTarget { ip, city })
}

pub struct CalibrateCommand {
    targets: Vec<CalibrationTarget>,
    globalping_token: Option<GlobalpingToken>,
    probes: ProbeSelection,
}

impl TryFrom<(CalibrateArgs, SecretInputs)> for CalibrateCommand {
    type Error = anyhow::Error;

    fn try_from(
        (args, secrets): (CalibrateArgs, SecretInputs),
    ) -> Result<Self, Self::Error> {
        let targets = args
            .targets
            .iter()
            .map(|target| parse_target(target))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let probes = ProbeSelection::new(args.eyeball_probes, args.dc_probes)?;
        Ok(Self {
            targets,
            globalping_token: secrets.globalping_token,
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
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("chip").chain(args.iter().copied()))
            .unwrap()
    }

    fn scan_command(args: &[&str]) -> anyhow::Result<Box<ScanCommand>> {
        let command = parse(args).into_command_with(SecretInputs::default())?;
        let Command::Scan(command) = command else {
            panic!("expected scan command")
        };
        Ok(command)
    }

    #[test]
    fn scan_parses_domain_values_and_defaults() {
        let command =
            scan_command(&["scan", "203.0.113.1", "--country", "fi"]).unwrap();

        assert_eq!(command.ip(), Ipv4Addr::new(203, 0, 113, 1));
        assert_eq!(command.country().as_str(), "FI");
        assert_eq!(command.ssh_user(), "root");
        assert_eq!(command.reference_city().as_str(), "Helsinki");
        assert_eq!(
            (command.probes().eyeball(), command.probes().datacenter()),
            (8, 4)
        );
        assert!(command.ssh_enabled());
        assert!(command.neighbors_enabled());
        assert!(command.fail_fast());
    }

    #[test]
    fn invalid_ip_is_rejected_during_parsing() {
        let error = Cli::try_parse_from([
            "chip",
            "scan",
            "not-an-ip",
            "--country",
            "FI",
        ])
        .err()
        .expect("input must be rejected");

        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn unknown_country_is_rejected_during_parsing() {
        let error = Cli::try_parse_from([
            "chip",
            "scan",
            "203.0.113.1",
            "--country",
            "ZZ",
        ])
        .err()
        .expect("input must be rejected");

        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
        assert!(error.to_string().contains("not a recognized country code"));
    }

    #[test]
    fn an_empty_city_is_rejected_during_parsing() {
        let error = Cli::try_parse_from([
            "chip",
            "scan",
            "203.0.113.1",
            "--country",
            "FI",
            "--city",
            "   ",
        ])
        .err()
        .expect("input must be rejected");

        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
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
            ["service:claude", "neighbors", "reputation:operator"]
                .into_iter()
                .map(GateId::from)
                .collect()
        );
    }

    #[test]
    fn validation_rejects_a_non_finite_latency_threshold() {
        let error = scan_command(&[
            "scan",
            "203.0.113.1",
            "--country",
            "FI",
            "--max-excess-ms",
            "NaN",
        ])
        .err()
        .expect("threshold must be rejected");

        assert!(error.to_string().contains("finite and positive"));
    }

    #[test]
    fn validation_rejects_a_negative_loss_threshold() {
        let error = scan_command(&[
            "scan",
            "203.0.113.1",
            "--country",
            "FI",
            "--max-loss-pct=-0.1",
        ])
        .err()
        .expect("threshold must be rejected");

        assert!(error.to_string().contains("finite and non-negative"));
    }

    #[test]
    fn validation_rejects_an_empty_probe_selection() {
        let error = scan_command(&[
            "scan",
            "203.0.113.1",
            "--country",
            "FI",
            "--eyeball-probes",
            "0",
            "--dc-probes",
            "0",
        ])
        .err()
        .expect("probe selection must be rejected");

        assert_eq!(
            error.to_string(),
            "--eyeball-probes and --dc-probes cannot both be 0"
        );
    }

    #[test]
    fn calibration_targets_are_parsed_before_orchestration() {
        let command =
            parse(&["calibrate", "203.0.113.7=Helsinki", "198.51.100.9=Turku"])
                .into_command_with(SecretInputs::default())
                .unwrap();
        let Command::Calibrate(command) = command else {
            panic!("expected calibrate command")
        };

        assert_eq!(command.targets().len(), 2);
        assert_eq!(command.targets()[0].ip(), Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(command.targets()[0].city().as_str(), "Helsinki");
    }

    #[rstest::rstest]
    #[case::empty_city("203.0.113.7=", "invalid city")]
    #[case::invalid_ip("not-an-ip=Helsinki", "invalid IPv4 address")]
    #[case::missing_separator("203.0.113.7", "expected IP=City")]
    fn malformed_calibration_targets_never_reach_orchestration(
        #[case] raw: &str,
        #[case] expected_detail: &str,
    ) {
        let error = parse(&["calibrate", raw])
            .into_command_with(SecretInputs::default())
            .err()
            .expect("target must be rejected");

        assert!(error.to_string().contains(expected_detail), "{error:#}");
    }

    #[test]
    fn an_owned_environment_value_becomes_a_typed_secret() {
        let secret = secret_from_env::<GlobalpingToken>(
            "GLOBALPING_TOKEN",
            Some(OsString::from("token-value")),
        )
        .unwrap();

        assert!(secret.is_some());
    }

    #[test]
    fn a_blank_environment_secret_names_the_setting_in_its_error() {
        let error = secret_from_env::<ProxycheckApiKey>(
            "PROXYCHECK_API_KEY",
            Some(OsString::from("   ")),
        )
        .unwrap_err();

        assert!(error.to_string().contains("PROXYCHECK_API_KEY"), "{error:#}");
        assert!(!error.to_string().contains("   "));
    }
}
