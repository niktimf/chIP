use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::process::{Output, Stdio};
use std::time::Duration;

use chip_core::checks::neighbors::{
    NeighborHttps, NeighborProbe, PtrLookup, PtrName, TlsHandshake,
    TlsHandshakeFacts,
};
use futures::{StreamExt as _, stream};
use ipnet::Ipv4Net;
use tokio::process::Command;

/// The port every neighbor is probed on, by TCP connect and TLS handshake.
const HTTPS_PORT: u16 = 443;

#[derive(Debug, Clone, Copy)]
pub struct SweepConfig {
    concurrency: NonZeroUsize,
    timeout: Duration,
}

impl SweepConfig {
    const DEFAULT_CONCURRENCY: NonZeroUsize =
        NonZeroUsize::new(16).expect("16 is non-zero");
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

    pub const fn new(concurrency: NonZeroUsize, timeout: Duration) -> Self {
        Self {
            concurrency,
            timeout,
        }
    }
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CONCURRENCY, Self::DEFAULT_TIMEOUT)
    }
}

async fn tcp_open(ip: Ipv4Addr, timeout: Duration) -> bool {
    tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect((ip, HTTPS_PORT)),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}

fn parse_cert_block(raw: &str) -> Option<TlsHandshakeFacts> {
    let pem = x509_parser::pem::Pem::iter_from_buffer(raw.as_bytes())
        .filter_map(Result::ok)
        .find(|pem| pem.label == "CERTIFICATE")?;
    let cert = pem.parse_x509().ok()?;
    let cert_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|entry| entry.as_str().ok())
        .map(str::to_string);
    let cert_issuer = cert
        .issuer()
        .iter_organization()
        .next()
        .and_then(|entry| entry.as_str().ok())
        .map(str::to_string);
    let cert_san = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    x509_parser::extensions::GeneralName::DNSName(dns) => {
                        Some((*dns).to_string())
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Some(TlsHandshakeFacts {
        cert_cn,
        cert_issuer,
        cert_san,
    })
}

async fn handshake(ip: Ipv4Addr, timeout: Duration) -> TlsHandshake {
    let mut command = Command::new("openssl");
    command
        .args([
            "s_client",
            "-showcerts",
            "-connect",
            &format!("{ip}:{HTTPS_PORT}"),
        ])
        .stdin(Stdio::null())
        .kill_on_drop(true);
    match tokio::time::timeout(timeout, command.output()).await {
        Err(_) => {
            TlsHandshake::Unavailable("openssl handshake timed out".to_string())
        }
        Ok(Err(error)) => {
            TlsHandshake::Unavailable(format!("openssl could not run: {error}"))
        }
        Ok(Ok(output)) => handshake_from_openssl(&output),
    }
}

/// Reads what `openssl s_client` printed, without any I/O of its own. A
/// certificate in the output counts whatever the exit status; without one, a
/// failed run (refused connection, reset, TLS alert) is reported by its first
/// stderr line, and only a successful run means the handshake gave no
/// certificate.
fn handshake_from_openssl(output: &Output) -> TlsHandshake {
    if let Some(facts) =
        parse_cert_block(&String::from_utf8_lossy(&output.stdout))
    {
        return TlsHandshake::Presented(facts);
    }
    if output.status.success() {
        return TlsHandshake::NoCertificate;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reason = first_nonempty_line(&stderr).map_or_else(
        || format!("openssl exited with {}", output.status),
        str::to_owned,
    );
    TlsHandshake::Unavailable(reason)
}

async fn reverse_dns(ip: Ipv4Addr, timeout: Duration) -> PtrLookup {
    /// dig's wait for one answer, in whole seconds as dig takes it; the
    /// probe `timeout` bounds the whole lookup.
    const DIG_WAIT: &str = "+time=2";
    /// One try: a retry would not fit in the probe timeout.
    const DIG_TRIES: &str = "+tries=1";
    let dig = Command::new("dig")
        .args(["+short", DIG_WAIT, DIG_TRIES, "-x", &ip.to_string()])
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(timeout, dig).await {
        Err(_) => PtrLookup::Unavailable("lookup timed out".to_string()),
        Ok(Err(error)) => PtrLookup::Unavailable(error.to_string()),
        Ok(Ok(output)) => ptr_from_dig(&output),
    }
}

/// Reads what dig printed, without any I/O of its own: a failed run is
/// reported by its first stderr line, a successful one by the first PTR name
/// it listed.
fn ptr_from_dig(output: &Output) -> PtrLookup {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let reason = first_nonempty_line(&stderr).map_or_else(
            || format!("dig exited with {}", output.status),
            str::to_owned,
        );
        return PtrLookup::Unavailable(reason);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(name) = first_nonempty_line(&stdout) else {
        return PtrLookup::NotFound;
    };
    PtrName::try_from(name).map_or_else(
        |_| {
            PtrLookup::Unavailable("resolver returned an empty PTR".to_string())
        },
        PtrLookup::Resolved,
    )
}

fn first_nonempty_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|line| !line.is_empty())
}

/// Surveys every host in a subnet, at most `config.concurrency` hosts at
/// once, and returns one probe per host, sorted by address.
pub async fn sweep(
    network: Ipv4Net,
    config: &SweepConfig,
) -> Vec<NeighborProbe> {
    let timeout = config.timeout;
    let mut probes: Vec<NeighborProbe> = stream::iter(network.hosts())
        .map(|ip| probe(ip, timeout))
        .buffer_unordered(config.concurrency.get())
        .collect()
        .await;
    probes.sort_by_key(|probe| probe.ip);
    probes
}

/// The TCP, TLS and PTR sequence of one host.
async fn probe(ip: Ipv4Addr, timeout: Duration) -> NeighborProbe {
    let (https, ptr) = if tcp_open(ip, timeout).await {
        let (handshake, ptr) =
            tokio::join!(handshake(ip, timeout), reverse_dns(ip, timeout));
        (NeighborHttps::Open { handshake }, ptr)
    } else {
        (NeighborHttps::Closed, reverse_dns(ip, timeout).await)
    };
    NeighborProbe { ip, ptr, https }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt as _;

    use super::*;

    #[test]
    fn a_certificate_in_openssl_output_yields_its_common_name_and_dns_names() {
        let raw = format!(
            "CONNECTED(00000003)\n{}\n---\nhandshake details",
            include_str!("testdata/neighbor-cert.pem")
        );

        let facts = parse_cert_block(&raw).unwrap();

        assert_eq!(facts.cert_cn.as_deref(), Some("neighbor-test.example.net"));
        assert_eq!(
            facts.cert_san,
            ["neighbor-test.example.net", "www.microsoft.com"]
        );
    }

    #[test]
    fn text_without_a_certificate_is_not_a_handshake() {
        let facts = parse_cert_block("connect: Connection refused\n");

        assert!(facts.is_none());
    }

    /// What a command printed, as `Command::output` returns it. `exit_code`
    /// is shifted into the wait status the way the kernel reports an exit.
    fn command_output(exit_code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(exit_code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn a_failed_dig_is_unavailable_for_its_first_stderr_line() {
        let output = command_output(
            9,
            "",
            "\n;; communications error to 192.0.2.53#53: timed out\n\
             ;; no servers could be reached\n",
        );

        let lookup = ptr_from_dig(&output);

        assert_eq!(
            lookup,
            PtrLookup::Unavailable(
                ";; communications error to 192.0.2.53#53: timed out"
                    .to_owned()
            )
        );
    }

    #[test]
    fn a_successful_dig_without_names_finds_no_ptr() {
        let output = command_output(0, "\n", "");

        let lookup = ptr_from_dig(&output);

        assert_eq!(lookup, PtrLookup::NotFound);
    }

    #[test]
    fn a_name_of_only_the_root_dot_leaves_the_lookup_unavailable() {
        let output = command_output(0, ".\n", "");

        let lookup = ptr_from_dig(&output);

        assert_eq!(
            lookup,
            PtrLookup::Unavailable("resolver returned an empty PTR".to_owned())
        );
    }

    #[test]
    fn a_failed_handshake_without_a_certificate_is_unavailable_for_its_first_stderr_line()
     {
        let output = command_output(
            1,
            "CONNECTED(00000003)\n---\nno peer certificate available\n",
            "\n40C7E1B4:error:0A000410:SSL routines:ssl3_read_bytes:\
             sslv3 alert handshake failure\n",
        );

        let handshake = handshake_from_openssl(&output);

        let TlsHandshake::Unavailable(reason) = handshake else {
            panic!("expected an unavailable handshake, got {handshake:?}");
        };
        assert_eq!(
            reason,
            "40C7E1B4:error:0A000410:SSL routines:ssl3_read_bytes:\
             sslv3 alert handshake failure"
        );
    }

    #[test]
    fn a_failed_run_with_a_silent_stderr_is_unavailable_for_its_exit_status() {
        let output = command_output(1, "", "");

        let handshake = handshake_from_openssl(&output);

        let TlsHandshake::Unavailable(reason) = handshake else {
            panic!("expected an unavailable handshake, got {handshake:?}");
        };
        assert_eq!(reason, "openssl exited with exit status: 1");
    }

    #[test]
    fn a_successful_handshake_without_a_certificate_presents_none() {
        let output = command_output(
            0,
            "CONNECTED(00000003)\n---\nno peer certificate available\n",
            "",
        );

        let handshake = handshake_from_openssl(&output);

        assert!(
            matches!(handshake, TlsHandshake::NoCertificate),
            "{handshake:?}"
        );
    }

    #[test]
    fn a_certificate_counts_even_when_openssl_exits_with_an_error() {
        let stdout = format!(
            "CONNECTED(00000003)\n{}\n---\n",
            include_str!("testdata/neighbor-cert.pem")
        );
        let output = command_output(1, &stdout, "read:errno=104\n");

        let handshake = handshake_from_openssl(&output);

        assert!(
            matches!(handshake, TlsHandshake::Presented(_)),
            "{handshake:?}"
        );
    }
}
