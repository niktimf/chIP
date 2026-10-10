use super::session::{SshError, SshSession};
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;
use thiserror::Error;

/// Why a temporary listener operation could not report an outcome.
#[derive(Debug, Error)]
pub enum ListenerError {
    #[error(
        "a temporary listener on port {port} is already owned by this session"
    )]
    AlreadyStarted { port: NonZeroU16 },
    #[error("unexpected listener preflight response: {0}")]
    InvalidPreflightResponse(String),
    #[error("unexpected listener start response: {0}")]
    InvalidStartResponse(String),
    #[error(transparent)]
    Ssh(#[from] SshError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerOutcome {
    Listening,
    PortInUse,
    Failed(ListenerFailure),
}

/// Why the candidate could not start a temporary listener. The texts are
/// the details a scan reports after "listener failed: ".
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display)]
pub enum ListenerFailure {
    #[strum(to_string = "openssl is not installed on the candidate")]
    MissingOpenSsl,
    #[strum(to_string = "ss is not installed on the candidate")]
    MissingSocketInspector,
    #[strum(to_string = "could not create a private temporary directory")]
    TempDir,
    #[strum(to_string = "could not generate the throwaway certificate")]
    Certificate,
    #[strum(to_string = "openssl s_server started but no socket listens on \
                         the port")]
    NotListening,
}

impl ListenerOutcome {
    /// Reads the stdout of `listener_start_script`, which is exactly one
    /// reply line.
    fn parse_start_reply(stdout: &str) -> Result<Self, ListenerError> {
        match stdout.trim() {
            "LISTENING" => Ok(Self::Listening),
            "FAILED" => Ok(Self::Failed(ListenerFailure::NotListening)),
            "CERT_FAILED" => Ok(Self::Failed(ListenerFailure::Certificate)),
            "TEMP_FAILED" => Ok(Self::Failed(ListenerFailure::TempDir)),
            _ => Err(ListenerError::InvalidStartResponse(stdout.to_owned())),
        }
    }
}

/// A successful preflight describes one actionable state. Transport and
/// command failures remain errors, rather than masquerading as a busy port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerReadiness {
    Ready,
    PortInUse,
    MissingOpenSsl,
    MissingSocketInspector,
}

impl ListenerReadiness {
    /// Reads the stdout of `listener_preflight_script`.
    fn parse(stdout: &str) -> Result<Self, ListenerError> {
        match stdout.trim() {
            "READY" => Ok(Self::Ready),
            "BUSY" => Ok(Self::PortInUse),
            "MISSING_OPENSSL" => Ok(Self::MissingOpenSsl),
            "MISSING_SS" => Ok(Self::MissingSocketInspector),
            _ => {
                Err(ListenerError::InvalidPreflightResponse(stdout.to_owned()))
            }
        }
    }
}

fn listener_preflight_script(port: NonZeroU16) -> String {
    format!(
        "command -v openssl >/dev/null 2>&1 || {{ echo MISSING_OPENSSL; exit 0; }}; \
         command -v ss >/dev/null 2>&1 || {{ echo MISSING_SS; exit 0; }}; \
         LISTENERS=$(ss -H -ltn 'sport = :{port}') || exit; \
         if [ -z \"$LISTENERS\" ]; then echo READY; else echo BUSY; fi"
    )
}

/// The port of the remote listener this session has to clean up.
///
/// A port is claimed before the start command runs and released only after
/// a stop command succeeded, so a lost or failed command leaves it claimed
/// for the next cleanup.
#[derive(Debug, Default)]
pub(super) struct ListenerSlot(Mutex<Option<NonZeroU16>>);

impl ListenerSlot {
    pub(super) fn owned(&self) -> Option<NonZeroU16> {
        *self.lock()
    }

    fn claim(&self, port: NonZeroU16) -> Result<(), ListenerError> {
        let mut owned = self.lock();
        if let Some(current) = *owned {
            return Err(ListenerError::AlreadyStarted { port: current });
        }
        *owned = Some(port);
        drop(owned);
        Ok(())
    }

    /// Releases `port` only while it is still the claimed one: a concurrent
    /// stop may have released it already and a newer start claimed another.
    fn release(&self, port: NonZeroU16) {
        let mut owned = self.lock();
        if *owned == Some(port) {
            *owned = None;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<NonZeroU16>> {
        // The guarded value is a plain `Copy` port, so a panic while it was
        // held cannot leave it half-written.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn listener_start_script(port: NonZeroU16) -> String {
    format!(
        "D=$(mktemp -d /tmp/chip-pf-{port}.XXXXXX) || {{ echo TEMP_FAILED; exit 0; }}; \
         trap 'rm -rf -- \"$D\"' EXIT; \
         C=\"$D/cert.pem\"; K=\"$D/key.pem\"; M=\"$D/ufw-added\"; \
         openssl req -x509 -newkey rsa:2048 -keyout \"$K\" -out \"$C\" -days 1 -nodes -subj /CN=chip >/dev/null 2>&1 || {{ echo CERT_FAILED; exit 0; }}; \
         if command -v ufw >/dev/null 2>&1; then \
           if sudo -n true >/dev/null 2>&1; then U='sudo -n ufw'; else U='ufw'; fi; \
           $U status 2>/dev/null | grep -Eq '^{port}/tcp[[:space:]]+ALLOW' || \
             {{ $U allow {port}/tcp >/dev/null 2>&1 && : > \"$M\"; }}; \
         fi; \
         nohup sh -c 'D=$1; P=$2; \
           timeout 600 openssl s_server -accept \"$P\" -cert \"$D/cert.pem\" -key \"$D/key.pem\" -www -quiet; \
           if [ -f \"$D/ufw-added\" ] && command -v ufw >/dev/null 2>&1; then \
             if sudo -n true >/dev/null 2>&1; then sudo -n ufw delete allow \"$P/tcp\" >/dev/null 2>&1 || true; \
             else ufw delete allow \"$P/tcp\" >/dev/null 2>&1 || true; fi; \
           fi; \
           rm -rf -- \"$D\"' chip-listener-{port} \"$D\" {port} >/dev/null 2>&1 & \
         trap - EXIT; \
         sleep 1; \
         ss -ltn 2>/dev/null | grep -q ':{port} ' && echo LISTENING || echo FAILED"
    )
}

/// The `pkill` patterns end at the port: `$` after the startup tag, which
/// is the last argument, and a space after the `-accept` value, which
/// `-cert` follows. Port 443 then does not match 4430.
fn listener_stop_script(port: NonZeroU16) -> String {
    format!(
        "pkill -KILL -u \"$(id -u)\" -f '[c]hip-listener-start-{port}$' 2>/dev/null || true; \
         pkill -u \"$(id -u)\" -f '^timeout 600 openssl s_server -accept {port} ' 2>/dev/null || true; \
         for D in /tmp/chip-pf-{port}.*; do \
           [ -L \"$D\" ] && continue; [ -d \"$D\" ] || continue; \
           [ \"$(stat -c %u \"$D\" 2>/dev/null)\" = \"$(id -u)\" ] || continue; \
           if [ -f \"$D/ufw-added\" ] && command -v ufw >/dev/null 2>&1; then \
             if sudo -n true >/dev/null 2>&1; then U='sudo -n ufw'; else U='ufw'; fi; \
             $U delete allow {port}/tcp >/dev/null 2>&1 || true; \
           fi; \
           rm -rf -- \"$D\"; \
         done"
    )
}

impl SshSession {
    /// # Errors
    ///
    /// Returns `ListenerError::Ssh` when the preflight command fails, and
    /// `ListenerError::InvalidPreflightResponse` when its output is not a
    /// known readiness answer.
    pub async fn listener_readiness(
        &self,
        port: NonZeroU16,
    ) -> Result<ListenerReadiness, ListenerError> {
        let output = self
            .run_shell(&listener_preflight_script(port), self.command_timeout())
            .await?;
        ListenerReadiness::parse(&output)
    }

    /// Starts `openssl s_server` on `port` under `timeout 600` (it dies on
    /// its own after 10 minutes even if this process is killed first), after
    /// generating a throwaway self-signed cert in a private temporary
    /// directory. Opens the port in `ufw` if present; both the files and a
    /// rule added by this run are removed when the listener exits.
    ///
    /// # Errors
    ///
    /// Returns `ListenerError::AlreadyStarted` when this session already
    /// owns a listener, `ListenerError::Ssh` when a remote command fails,
    /// and `ListenerError::InvalidPreflightResponse` or
    /// `ListenerError::InvalidStartResponse` when a remote script replies
    /// with an unknown answer. A listener that does not come up is an `Ok`
    /// outcome.
    pub async fn start_listener(
        &self,
        port: NonZeroU16,
    ) -> Result<ListenerOutcome, ListenerError> {
        if let Some(owned) = self.listener.owned() {
            return Err(ListenerError::AlreadyStarted { port: owned });
        }
        match self.listener_readiness(port).await? {
            ListenerReadiness::Ready => {}
            ListenerReadiness::PortInUse => {
                return Ok(ListenerOutcome::PortInUse);
            }
            ListenerReadiness::MissingOpenSsl => {
                return Ok(ListenerOutcome::Failed(
                    ListenerFailure::MissingOpenSsl,
                ));
            }
            ListenerReadiness::MissingSocketInspector => {
                return Ok(ListenerOutcome::Failed(
                    ListenerFailure::MissingSocketInspector,
                ));
            }
        }
        let timeout = self.command_timeout();
        let script = listener_start_script(port);
        // Ownership is registered before awaiting a command that can create
        // remote state, including when its response is lost or cancelled.
        self.listener.claim(port)?;
        // Give the remote startup shell an identity so cleanup can stop it
        // before removing state, even if the SSH response was cancelled.
        let tag = format!("chip-listener-start-{port}");
        let output = self
            .run_command("sh", &["-c", &script, &tag], timeout)
            .await?;
        ListenerOutcome::parse_start_reply(&output)
    }

    /// Stops the listener this session started and removes its remote
    /// state. Without a started listener nothing runs on the candidate. The
    /// port stays registered until the stop command succeeds, so a failed
    /// stop can be retried.
    ///
    /// # Errors
    ///
    /// Returns `SshError` when the stop command fails.
    pub async fn stop_listener(&self) -> Result<(), SshError> {
        let Some(port) = self.listener.owned() else {
            return Ok(());
        };
        let script = listener_stop_script(port);
        self.run_shell(&script, self.command_timeout()).await?;
        self.listener.release(port);
        Ok(())
    }
}

/// Confirms the temporary listener answers TLS from the runner.
///
/// Runs before any Globalping quota is spent on the listener. It serves a
/// throwaway self-signed certificate, so certificate verification is off on
/// purpose.
///
/// The client is built here rather than taken from the caller because it
/// skips certificate verification, which the shared client must not do.
/// `timeout` bounds the whole request.
///
/// # Errors
///
/// Returns `ListenerProbeError::Unreachable` when the listener does not
/// answer TLS within `timeout`.
pub async fn verify_listener(
    ip: Ipv4Addr,
    port: NonZeroU16,
    timeout: Duration,
) -> Result<(), ListenerProbeError> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(timeout)
        .build()
        .map_err(ListenerProbeError::Client)?;
    client
        .get(format!("https://{ip}:{port}/"))
        .send()
        .await
        .map(drop)
        .map_err(ListenerProbeError::Unreachable)
}

/// Why the runner could not confirm the temporary listener.
#[derive(Debug, Error)]
pub enum ListenerProbeError {
    #[error("could not build the TLS client for the listener probe")]
    Client(#[source] reqwest::Error),
    #[error("temporary TLS listener is not reachable from the runner")]
    Unreachable(#[source] reqwest::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    #[cfg(unix)]
    fn write_stub(dir: &std::path::Path, name: &str, body: &str) {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }

    #[cfg(unix)]
    fn run_sh(script: &str, dir: &std::path::Path) -> std::process::Output {
        let old = std::env::var("PATH").unwrap_or_default();
        std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .env("PATH", format!("{}:{old}", dir.display()))
            .output()
            .unwrap()
    }

    /// A port that was free a moment ago, so parallel tests do not share
    /// remote state paths or `pkill` patterns.
    #[cfg(unix)]
    fn free_port() -> NonZeroU16 {
        let reservation =
            std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        port(reservation.local_addr().unwrap().port())
    }

    /// Starts `timeout 600 openssl s_server -accept {accept} ...` with the
    /// command line the start script gives the server; the `openssl` stub
    /// in `dir` only sleeps.
    #[cfg(unix)]
    fn spawn_server(
        dir: &std::path::Path,
        accept: &str,
    ) -> std::process::Child {
        let path = format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        std::process::Command::new("timeout")
            .args(["600", "openssl", "s_server", "-accept", accept])
            .args(["-cert", "cert.pem", "-key", "key.pem", "-www", "-quiet"])
            .env("PATH", path)
            .spawn()
            .unwrap()
    }

    #[cfg(unix)]
    fn exits_within(child: &mut std::process::Child, limit: Duration) -> bool {
        let deadline = std::time::Instant::now() + limit;
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }

    #[cfg(unix)]
    #[test]
    fn stop_kills_the_server_of_its_port_and_spares_a_longer_port_number() {
        let dir = tempfile::tempdir().unwrap();
        write_stub(dir.path(), "openssl", "exec sleep 30");
        let port = free_port();
        let mut own = spawn_server(dir.path(), &port.to_string());
        let mut neighbor = spawn_server(dir.path(), &format!("{port}0"));

        let stop = run_sh(&listener_stop_script(port), dir.path());

        let own_exited = exits_within(&mut own, Duration::from_secs(3));
        let neighbor_running = neighbor.try_wait().unwrap().is_none();
        neighbor.kill().unwrap();
        neighbor.wait().unwrap();
        assert!(stop.status.success(), "stop: {:?}", stop.status);
        assert!(own_exited, "the server on port {port} kept running");
        assert!(neighbor_running, "the server on port {port}0 was killed");
    }

    #[cfg(unix)]
    fn listener_state_dirs(port: NonZeroU16) -> Vec<std::path::PathBuf> {
        let prefix = format!("chip-pf-{port}.");
        std::fs::read_dir("/tmp")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_name().to_string_lossy().starts_with(&prefix)
            })
            .map(|entry| entry.path())
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn listener_uses_private_random_state_and_stop_cleans_it_up() {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        write_stub(
            dir.path(),
            "openssl",
            "[ \"$1\" = req ] && exit 0\nexec sleep 30",
        );
        write_stub(dir.path(), "ufw", "exit 0");
        write_stub(dir.path(), "sudo", "exit 1");
        write_stub(
            dir.path(),
            "ss",
            &format!("echo \"LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:*\""),
        );

        // Starting is the act of the first step and the arrange of the stop.
        let start = run_sh(&listener_start_script(port), dir.path());
        let stdout = String::from_utf8_lossy(&start.stdout).to_string();
        let state_dirs = listener_state_dirs(port);
        let state_mode = state_dirs.first().and_then(|path| {
            std::fs::metadata(path)
                .ok()
                .map(|metadata| metadata.permissions().mode() & 0o777)
        });
        let stop = run_sh(&listener_stop_script(port), dir.path());

        assert!(start.status.success(), "start: {:?} {stdout}", start.status);
        assert!(stdout.contains("LISTENING"), "stdout: {stdout}");
        assert_eq!(state_dirs.len(), 1, "state dirs: {state_dirs:?}");
        assert_eq!(state_mode, Some(0o700));
        assert!(stop.status.success(), "stop: {:?}", stop.status);
        assert!(listener_state_dirs(port).is_empty());
    }

    #[cfg(unix)]
    #[rstest::rstest]
    #[case::start(listener_start_script(port(443)))]
    #[case::stop(listener_stop_script(port(443)))]
    fn the_listener_script_parses_as_shell(#[case] script: String) {
        let status = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&script)
            .status()
            .unwrap();

        assert!(status.success(), "sh -n failed for: {script}");
    }

    #[rstest::rstest]
    #[case::free_port("READY\n", ListenerReadiness::Ready)]
    #[case::busy_port("BUSY\n", ListenerReadiness::PortInUse)]
    #[case::no_openssl("MISSING_OPENSSL\n", ListenerReadiness::MissingOpenSsl)]
    #[case::no_ss("MISSING_SS\n", ListenerReadiness::MissingSocketInspector)]
    fn preflight_returns_one_actionable_state(
        #[case] response: &str,
        #[case] expected: ListenerReadiness,
    ) {
        let actual = ListenerReadiness::parse(response).unwrap();

        assert_eq!(actual, expected);
    }

    #[rstest::rstest]
    #[case::listening("LISTENING\n", ListenerOutcome::Listening)]
    #[case::no_socket(
        "FAILED\n",
        ListenerOutcome::Failed(ListenerFailure::NotListening)
    )]
    #[case::no_certificate(
        "CERT_FAILED\n",
        ListenerOutcome::Failed(ListenerFailure::Certificate)
    )]
    #[case::no_temp_dir(
        "TEMP_FAILED\n",
        ListenerOutcome::Failed(ListenerFailure::TempDir)
    )]
    fn the_start_reply_names_one_outcome(
        #[case] reply: &str,
        #[case] expected: ListenerOutcome,
    ) {
        let actual = ListenerOutcome::parse_start_reply(reply).unwrap();

        assert_eq!(actual, expected);
    }

    #[rstest::rstest]
    #[case::empty("")]
    #[case::two_replies("LISTENING\nFAILED\n")]
    #[case::reply_inside_a_line("NOT LISTENING\n")]
    fn an_unknown_start_reply_is_an_error_not_a_failed_listener(
        #[case] reply: &str,
    ) {
        let actual = ListenerOutcome::parse_start_reply(reply);

        assert!(
            matches!(&actual, Err(ListenerError::InvalidStartResponse(text)) if text == reply),
            "{actual:?}"
        );
    }

    fn port(value: u16) -> NonZeroU16 {
        NonZeroU16::new(value).unwrap()
    }

    fn slot_owning(value: u16) -> ListenerSlot {
        let slot = ListenerSlot::default();
        slot.claim(port(value)).unwrap();
        slot
    }

    #[test]
    fn a_session_without_a_started_listener_has_nothing_to_stop() {
        let sut = ListenerSlot::default();

        let actual = sut.owned();

        assert_eq!(actual, None);
    }

    #[test]
    fn a_second_listener_is_refused_while_the_first_is_owned() {
        let sut = slot_owning(443);

        let actual = sut.claim(port(8443));

        assert!(
            matches!(
                actual,
                Err(ListenerError::AlreadyStarted { port: owned })
                    if owned == port(443)
            ),
            "{actual:?}"
        );
        assert_eq!(sut.owned(), Some(port(443)));
    }

    #[test]
    fn a_stopped_listener_leaves_nothing_to_clean_up() {
        let sut = slot_owning(443);

        sut.release(port(443));

        assert_eq!(sut.owned(), None);
    }

    #[test]
    fn stopping_another_port_keeps_the_owned_listener_for_cleanup() {
        let sut = slot_owning(8443);

        sut.release(port(443));

        assert_eq!(sut.owned(), Some(port(8443)));
    }

    #[test]
    fn unreadable_preflight_is_not_a_free_or_busy_port() {
        let actual = ListenerReadiness::parse("");

        assert!(
            matches!(actual, Err(ListenerError::InvalidPreflightResponse(_))),
            "{actual:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn socket_inspection_failure_is_not_reported_as_a_free_port() {
        let dir = tempfile::tempdir().unwrap();
        write_stub(dir.path(), "openssl", "exit 0");
        write_stub(dir.path(), "ss", "echo 'inspection denied' >&2; exit 1");

        let result = run_sh(&listener_preflight_script(port(8443)), dir.path());

        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
    }

    #[cfg(unix)]
    fn wait_for_file(path: &std::path::Path) -> bool {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !path.exists() {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        true
    }

    #[cfg(unix)]
    const DELAYED_CERT_GENERATION: &str = r#"
if [ "$1" = req ]; then
    touch "$CHIP_TEST_STATE/started"
    for attempt in $(seq 1 300); do
        [ -f "$CHIP_TEST_STATE/release" ] && break
        sleep 0.01
    done
    touch "$CHIP_TEST_STATE/done"
else
    touch "$CHIP_TEST_STATE/server"
fi
"#;

    #[cfg(unix)]
    #[test]
    fn cleanup_stops_startup_before_it_can_launch_a_late_listener() {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        write_stub(dir.path(), "openssl", DELAYED_CERT_GENERATION);
        write_stub(dir.path(), "ufw", "exit 0");
        write_stub(dir.path(), "sudo", "exit 1");
        write_stub(dir.path(), "ss", "exit 0");
        let mut startup = std::process::Command::new("sh")
            .args([
                "-c",
                &listener_start_script(port),
                &format!("chip-listener-start-{port}"),
            ])
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    dir.path().display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("CHIP_TEST_STATE", dir.path())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let started = wait_for_file(&dir.path().join("started"));

        let stopped = run_sh(&listener_stop_script(port), dir.path());

        std::fs::write(dir.path().join("release"), "").unwrap();
        let status = startup.wait().unwrap();
        let finished = wait_for_file(&dir.path().join("done"));
        assert!(started && finished, "startup fixture did not run");
        assert!(stopped.status.success());
        assert!(!status.success(), "startup must be terminated by cleanup");
        assert!(!dir.path().join("server").exists());
        assert!(listener_state_dirs(port).is_empty());
    }
}
