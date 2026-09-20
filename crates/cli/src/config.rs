use std::ffi::OsString;
use std::fmt;
use std::net::Ipv4Addr;
use std::num::{NonZeroU16, NonZeroU64};
use std::path::PathBuf;
use std::str::FromStr;

use chip_core::{CityName, CountryCode, GateId, GateOverrides};
use chip_io::credentials::{GlobalpingToken, ProxycheckApiKey, SshPrivateKey};
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateIp(Ipv4Addr);

impl CandidateIp {
    pub const fn as_ipv4(self) -> Ipv4Addr {
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
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run all enabled vetting gates for one candidate.
    Scan(Box<ScanArgs>),
    /// Measure known-good nodes and suggest latency thresholds.
    Calibrate(CalibrateArgs),
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

impl Cli {
    pub fn load_secrets_from_env(&mut self) -> anyhow::Result<()> {
        match &mut self.command {
            Command::Scan(args) => {
                args.ssh_private_key = secret_from_env(
                    "SSH_PRIVATE_KEY",
                    std::env::var_os("SSH_PRIVATE_KEY"),
                )?;
                args.globalping_token = secret_from_env(
                    "GLOBALPING_TOKEN",
                    std::env::var_os("GLOBALPING_TOKEN"),
                )?;
                args.proxycheck_api_key = secret_from_env(
                    "PROXYCHECK_API_KEY",
                    std::env::var_os("PROXYCHECK_API_KEY"),
                )?;
            }
            Command::Calibrate(args) => {
                args.globalping_token = secret_from_env(
                    "GLOBALPING_TOKEN",
                    std::env::var_os("GLOBALPING_TOKEN"),
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Args, Clone)]
pub struct ScanArgs {
    pub ip: CandidateIp,
    #[arg(long)]
    pub country: CountryCode,
    #[arg(long)]
    pub city: Option<CityName>,
    #[arg(skip)]
    pub ssh_private_key: Option<SshPrivateKey>,
    #[arg(long, env = "SSH_USER", default_value = "root")]
    pub ssh_user: String,
    #[arg(long, env = "SSH_PORT", default_value = "22")]
    pub ssh_port: NonZeroU16,
    #[arg(long, env = "SSH_KNOWN_HOSTS")]
    pub ssh_known_hosts: Option<String>,
    #[arg(skip)]
    pub globalping_token: Option<GlobalpingToken>,
    #[arg(skip)]
    pub proxycheck_api_key: Option<ProxycheckApiKey>,
    #[arg(long, default_value_t = 14.0)]
    pub max_excess_ms: f64,
    #[arg(long, default_value_t = 2.0)]
    pub max_loss_pct: f64,
    #[arg(long, default_value = "Helsinki")]
    pub reference_city: CityName,
    #[arg(long, default_value_t = 8)]
    pub eyeball_probes: u8,
    #[arg(long, default_value_t = 4)]
    pub dc_probes: u8,
    #[arg(long, default_value = "300")]
    pub deadline_secs: NonZeroU64,
    #[arg(long = "gate", value_delimiter = ',')]
    pub gate: Vec<String>,
    #[arg(long = "skip-gate", value_delimiter = ',')]
    pub skip_gate: Vec<String>,
    #[arg(long)]
    pub anchor: Option<Ipv4Addr>,
    #[arg(long)]
    pub no_neighbors: bool,
    #[arg(long)]
    pub no_ssh: bool,
    #[arg(long)]
    pub no_fail_fast: bool,
    #[arg(long)]
    pub json: Option<PathBuf>,
}

impl ScanArgs {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.max_excess_ms.is_finite() || self.max_excess_ms <= 0.0 {
            anyhow::bail!(
                "--max-excess-ms must be a finite positive number, got {}",
                self.max_excess_ms
            );
        }
        if !self.max_loss_pct.is_finite() || self.max_loss_pct < 0.0 {
            anyhow::bail!(
                "--max-loss-pct must be a finite non-negative number, got {}",
                self.max_loss_pct
            );
        }
        if self.eyeball_probes == 0 && self.dc_probes == 0 {
            anyhow::bail!("--eyeball-probes and --dc-probes cannot both be 0");
        }
        Ok(())
    }

    pub fn gate_overrides(&self) -> GateOverrides {
        GateOverrides {
            escalate: self.gate.iter().cloned().map(GateId::from).collect(),
            skip: self.skip_gate.iter().cloned().map(GateId::from).collect(),
        }
    }
}

#[derive(Args)]
pub struct CalibrateArgs {
    /// One or more `IP=City` targets.
    #[arg(required = true)]
    pub targets: Vec<String>,
    #[arg(skip)]
    pub globalping_token: Option<GlobalpingToken>,
    #[arg(long, default_value_t = 8)]
    pub eyeball_probes: u8,
    #[arg(long, default_value_t = 4)]
    pub dc_probes: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("chip").chain(args.iter().copied()))
            .unwrap()
    }

    fn scan_args() -> Box<ScanArgs> {
        let Command::Scan(args) =
            parse(&["scan", "203.0.113.1", "--country", "FI"]).command
        else {
            panic!("expected scan command")
        };
        args
    }

    #[test]
    fn scan_parses_domain_values_and_defaults() {
        let cli = parse(&["scan", "203.0.113.1", "--country", "fi"]);
        let Command::Scan(args) = cli.command else {
            panic!("expected scan command")
        };

        assert_eq!(args.ip.to_string(), "203.0.113.1");
        assert_eq!(args.country.as_str(), "FI");
        assert_eq!(args.ssh_user, "root");
        assert!((args.max_excess_ms - 14.0).abs() < f64::EPSILON);
        assert!((args.max_loss_pct - 2.0).abs() < f64::EPSILON);
        assert_eq!(args.reference_city.as_str(), "Helsinki");
        assert_eq!((args.eyeball_probes, args.dc_probes), (8, 4));
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
        let cli = parse(&[
            "scan",
            "203.0.113.1",
            "--country",
            "FI",
            "--gate",
            "service:claude,neighbors",
            "--gate",
            "reputation:operator",
        ]);
        let Command::Scan(args) = cli.command else {
            panic!("expected scan command")
        };

        assert_eq!(
            args.gate,
            ["service:claude", "neighbors", "reputation:operator"]
        );
    }

    #[test]
    fn validation_rejects_a_non_finite_latency_threshold() {
        let mut args = scan_args();
        args.max_excess_ms = f64::NAN;

        let error = args.validate().unwrap_err();

        assert!(error.to_string().contains("finite positive number"));
    }

    #[test]
    fn validation_rejects_a_negative_loss_threshold() {
        let mut args = scan_args();
        args.max_loss_pct = -0.1;

        let error = args.validate().unwrap_err();

        assert!(error.to_string().contains("finite non-negative number"));
    }

    #[test]
    fn validation_rejects_an_empty_probe_selection() {
        let mut args = scan_args();
        args.eyeball_probes = 0;
        args.dc_probes = 0;

        let error = args.validate().unwrap_err();

        assert_eq!(
            error.to_string(),
            "--eyeball-probes and --dc-probes cannot both be 0"
        );
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
