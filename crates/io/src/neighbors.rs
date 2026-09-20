use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use chip_core::model::{
    NeighborHttps, NeighborProbe, PtrLookup, PtrName, TlsHandshakeFacts,
};
use ipnet::Ipv4Net;
use tokio::process::Command;
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Copy)]
pub struct SweepConfig {
    concurrency: NonZeroUsize,
    timeout: Duration,
}

impl SweepConfig {
    pub const fn new(concurrency: NonZeroUsize, timeout: Duration) -> Self {
        Self {
            concurrency,
            timeout,
        }
    }
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self::new(
            NonZeroUsize::new(16).expect("16 is non-zero"),
            Duration::from_secs(3),
        )
    }
}

async fn tcp_open(ip: Ipv4Addr, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, tokio::net::TcpStream::connect((ip, 443)))
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

async fn handshake(
    ip: Ipv4Addr,
    timeout: Duration,
) -> Option<TlsHandshakeFacts> {
    let mut command = Command::new("openssl");
    command
        .args(["s_client", "-showcerts", "-connect", &format!("{ip}:443")])
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(timeout, command.output())
        .await
        .ok()?
        .ok()?;
    parse_cert_block(&String::from_utf8_lossy(&output.stdout))
}

async fn reverse_dns(ip: Ipv4Addr, timeout: Duration) -> PtrLookup {
    let mut command = Command::new("dig");
    command
        .args(["+short", "+time=2", "+tries=1", "-x", &ip.to_string()])
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = match tokio::time::timeout(timeout, command.output()).await {
        Err(_) => {
            return PtrLookup::Unavailable("lookup timed out".to_string());
        }
        Ok(Err(error)) => return PtrLookup::Unavailable(error.to_string()),
        Ok(Ok(output)) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let reason = stderr
                .lines()
                .find(|line| !line.trim().is_empty())
                .map_or_else(
                    || format!("dig exited with {}", output.status),
                    |line| line.trim().to_string(),
                );
            return PtrLookup::Unavailable(reason);
        }
        Ok(Ok(output)) => output,
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let Some(name) = text.lines().map(str::trim).find(|line| !line.is_empty())
    else {
        return PtrLookup::NotFound;
    };
    PtrName::try_from(name).map_or_else(
        |_| {
            PtrLookup::Unavailable("resolver returned an empty PTR".to_string())
        },
        PtrLookup::Resolved,
    )
}

/// Surveys every host in a subnet with bounded concurrency. A task owns its
/// permit for its complete TCP/TLS/PTR sequence and every task is joined.
pub async fn sweep(
    network: Ipv4Net,
    config: &SweepConfig,
) -> Vec<NeighborProbe> {
    let semaphore = Arc::new(Semaphore::new(config.concurrency.get()));
    let mut tasks = tokio::task::JoinSet::new();
    for ip in network.hosts() {
        let semaphore = Arc::clone(&semaphore);
        let timeout = config.timeout;
        tasks.spawn(async move {
            let Ok(_permit) = semaphore.acquire_owned().await else {
                return None;
            };
            let tcp_open = tcp_open(ip, timeout).await;
            let (handshake, ptr) = if tcp_open {
                tokio::join!(handshake(ip, timeout), reverse_dns(ip, timeout))
            } else {
                (None, reverse_dns(ip, timeout).await)
            };
            let https = if tcp_open {
                NeighborHttps::Open { handshake }
            } else {
                NeighborHttps::Closed
            };
            Some(NeighborProbe { ip, ptr, https })
        });
    }

    let mut probes = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(Some(probe)) = result {
            probes.push(probe);
        }
    }
    probes.sort_by_key(|probe| probe.ip);
    probes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_is_read_from_openssl_output_without_manual_pem_slicing() {
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
        assert!(parse_cert_block("connect: Connection refused\n").is_none());
    }
}
