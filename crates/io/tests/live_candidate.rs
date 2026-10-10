//! Live checks against one real candidate. Ignored by default: they need a
//! throwaway machine that is not serving traffic yet, its SSH key, and the
//! public internet.
//!
//! ```sh
//! CHIP_LIVE_IP=203.0.113.42 SSH_PRIVATE_KEY="$(cat ./candidate_key)" \
//!     cargo test -p chip-io --test live_candidate -- --ignored --test-threads 1
//! ```
//!
//! With `CHIP_LIVE_IP` unset or not an IPv4 address each test fails and
//! says so: a run with `--ignored` is meant to check a candidate.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers fail fast on broken setup"
)]

use std::net::{Ipv4Addr, TcpStream};
use std::num::NonZeroU16;
use std::str::FromStr;
use std::time::Duration;

use chip_io::credentials::SshPrivateKey;
use chip_io::ssh::{
    HostKeyPolicy, ListenerOutcome, ListenerReadiness, SocksTunnel, SshConfig,
    SshSession,
};
use chip_io::tunnel::TunnelClient;

fn candidate() -> Ipv4Addr {
    std::env::var("CHIP_LIVE_IP")
        .expect("CHIP_LIVE_IP must name the live candidate")
        .parse()
        .expect("CHIP_LIVE_IP must be an IPv4 address")
}

/// The value of the variable `name`; `None` only when it is unset. A value
/// that is set but not Unicode fails the test instead of reading as unset.
fn env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => panic!("{name} must be Unicode: {error}"),
    }
}

/// The variable `name` parsed as `T`; `None` only when it is unset. A
/// value that does not parse fails the test, so a typo is not replaced by
/// the default.
fn env_parsed<T: FromStr>(name: &str) -> Option<T>
where
    T::Err: std::fmt::Display,
{
    env(name).map(|value| {
        value.parse().unwrap_or_else(|error| {
            panic!("{name}={value:?} must parse: {error}")
        })
    })
}

fn listener_port() -> NonZeroU16 {
    env_parsed("CHIP_LIVE_PORT")
        .unwrap_or_else(|| NonZeroU16::new(8443).expect("8443 is non-zero"))
}

fn config() -> SshConfig {
    SshConfig {
        user: Some(
            std::env::var("SSH_USER").unwrap_or_else(|_| "root".to_string()),
        ),
        port: env_parsed("SSH_PORT")
            .unwrap_or_else(|| NonZeroU16::new(22).expect("22 is non-zero")),
        private_key: env("SSH_PRIVATE_KEY").map(|key| {
            SshPrivateKey::try_from(key)
                .expect("SSH_PRIVATE_KEY, when set, must not be empty")
        }),
        host_keys: env_parsed("SSH_KNOWN_HOSTS").map_or(
            HostKeyPolicy::TrustOnFirstUse {
                user_known_hosts: None,
            },
            HostKeyPolicy::Pinned,
        ),
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
    let ip = candidate();

    let sut = SshSession::connect(ip, config())
        .await
        .expect("the candidate accepts our key");
    let readiness = sut
        .listener_readiness(listener_port())
        .await
        .expect("preflight succeeds");

    assert!(
        matches!(
            readiness,
            ListenerReadiness::Ready | ListenerReadiness::PortInUse
        ),
        "listener prerequisites: {readiness:?}"
    );
}

#[tokio::test]
#[ignore = "needs a live candidate in CHIP_LIVE_IP"]
async fn traffic_through_the_tunnel_leaves_from_the_candidate() {
    let ip = candidate();

    let session = SshSession::connect(ip, config())
        .await
        .expect("the candidate accepts our key");
    let tunnel = SocksTunnel::start(&session, free_local_port())
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
    let ip = candidate();
    let port = listener_port();

    let sut = SshSession::connect(ip, config())
        .await
        .expect("the candidate accepts our key");
    let outcome = sut.start_listener(port).await.expect("ssh answered");
    let open_while_running = port_is_open(ip, port);
    sut.stop_listener().await.expect("ssh answered");
    let open_after_stop = port_is_open(ip, port);

    assert_eq!(outcome, ListenerOutcome::Listening);
    assert!(open_while_running, "the listener must be reachable");
    assert!(!open_after_stop, "the listener must leave nothing behind");
}
