//! Live checks against one real candidate. Ignored by default: they need a
//! throwaway machine that is not serving traffic yet, its SSH key, and the
//! public internet.
//!
//! ```sh
//! CHIP_LIVE_IP=203.0.113.42 SSH_PRIVATE_KEY="$(cat ./candidate_key)" \
//!     cargo test -p chip-io --test live_candidate -- --ignored --test-threads 1
//! ```
//!
//! With `CHIP_LIVE_IP` unset each test returns without asserting, so
//! `--ignored` on a machine with no candidate is quiet rather than red.

use std::net::{Ipv4Addr, TcpStream};
use std::num::NonZeroU16;
use std::time::Duration;

use chip_io::credentials::SshPrivateKey;
use chip_io::ssh::{ListenerOutcome, SocksTunnel, SshConfig, SshSession};
use chip_io::tunnel::TunnelClient;

fn candidate() -> Option<Ipv4Addr> {
    std::env::var("CHIP_LIVE_IP").ok()?.parse().ok()
}

fn listener_port() -> NonZeroU16 {
    std::env::var("CHIP_LIVE_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| NonZeroU16::new(8443).expect("8443 is non-zero"))
}

fn config() -> SshConfig {
    SshConfig {
        user: Some(
            std::env::var("SSH_USER").unwrap_or_else(|_| "root".to_string()),
        ),
        port: std::env::var("SSH_PORT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| NonZeroU16::new(22).expect("22 is non-zero")),
        private_key: std::env::var("SSH_PRIVATE_KEY")
            .ok()
            .and_then(|key| SshPrivateKey::try_from(key).ok()),
        known_hosts: std::env::var("SSH_KNOWN_HOSTS").ok(),
        connect_timeout: Duration::from_secs(15),
        command_timeout: Duration::from_secs(20),
    }
}

fn free_local_port() -> NonZeroU16 {
    let reservation = std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("the loopback interface always has a free port");
    let port = reservation.local_addr().expect("a bound socket").port();
    NonZeroU16::new(port).expect("a bound port is never zero")
}

fn port_is_open(ip: Ipv4Addr, port: NonZeroU16) -> bool {
    TcpStream::connect_timeout(&(ip, port.get()).into(), Duration::from_secs(5))
        .is_ok()
}

#[tokio::test]
#[ignore = "needs a live candidate in CHIP_LIVE_IP"]
async fn the_candidate_carries_what_a_scan_needs_over_ssh() {
    let Some(ip) = candidate() else { return };

    let sut = SshSession::connect(ip, &config())
        .await
        .expect("the candidate accepts our key");
    let preflight = sut.preflight().await;

    assert!(preflight.has_openssl, "the listener needs openssl remotely");
}

#[tokio::test]
#[ignore = "needs a live candidate in CHIP_LIVE_IP"]
async fn traffic_through_the_tunnel_leaves_from_the_candidate() {
    let Some(ip) = candidate() else { return };

    let tunnel = SocksTunnel::start(ip, &config(), free_local_port())
        .await
        .expect("ssh -D opens a SOCKS proxy into the candidate");
    let sut = TunnelClient::new(tunnel.local_addr(), Duration::from_secs(20))
        .expect("a SOCKS-bound client");
    let seen = sut
        .get("https://api.ipify.org", &[])
        .await
        .expect("the echo service answers through the tunnel");
    tunnel.stop().await;

    assert_eq!(seen.body.trim(), ip.to_string());
}

#[tokio::test]
#[ignore = "needs a live candidate in CHIP_LIVE_IP"]
async fn the_temporary_listener_opens_its_port_and_stopping_closes_it() {
    let Some(ip) = candidate() else { return };
    let port = listener_port();

    let sut = SshSession::connect(ip, &config())
        .await
        .expect("the candidate accepts our key");
    let outcome = sut.start_listener(port.get()).await.expect("ssh answered");
    let open_while_running = port_is_open(ip, port);
    sut.stop_listener(port.get()).await.expect("ssh answered");
    let open_after_stop = port_is_open(ip, port);

    assert_eq!(outcome, ListenerOutcome::Listening);
    assert!(open_while_running, "the listener must be reachable");
    assert!(!open_after_stop, "the listener must leave nothing behind");
}
