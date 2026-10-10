use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chip_core::gate;
use chip_core::ip_lists::RknRegistry;
use chip_core::model::{PingSweepFacts, ReputationFacts, ServiceState};
use chip_core::verdict::ai::judge_ai_endpoint;
use chip_core::verdict::blocklists::judge_blocklists;
use chip_core::verdict::geo::judge_geo;
use chip_core::verdict::latency::judge_latency;
use chip_core::verdict::neighbors::{
    judge_candidate_ptr, judge_neighbor_extremes,
};
use chip_core::verdict::provenance::judge_routing;
use chip_core::verdict::reach::judge_reach;
use chip_core::verdict::reputation::{
    judge_reputation, judge_reputation_operator,
};
use chip_core::verdict::rkn_registry::judge_rkn_registry;
use chip_core::verdict::service_geo::{
    judge_cdn_edge, judge_search_captcha, judge_service_country,
};
use chip_core::verdict::services::{judge_service_fail, judge_service_warn};
use chip_core::verdict::steal::{judge_steal, steal_pct};
use chip_core::verdict::tampering::judge_tampering;
use chip_core::{
    CheckResult, CountryCode, GateId, GateScope, Report, ScanProfile, Verdict,
};
use chip_io::atlas::{
    Anchor, AnchorClient, select_for_city, select_for_country,
};
use chip_io::blocklists::BlockListsClient;
use chip_io::geoip::GeoIpClient;
use chip_io::globalping::{
    GlobalpingClient, Locations, MeasurementId, MeasurementKind,
    RawMeasurement, ping_sweep_facts, reach_facts,
};
use chip_io::neighbors::{SweepConfig, sweep};
use chip_io::proxycheck::ProxycheckClient;
use chip_io::ripestat::RipestatClient;
use chip_io::rkn_registry::{RknRegistryClient, RknRegistryError};
use chip_io::ssh::{
    ListenerOutcome, SocksTunnel, SshConfig, SshSession, verify_listener,
};
use chip_io::tunnel::{
    TunnelClient, probe_ai_endpoints, probe_chatgpt_app, probe_chatgpt_web,
    probe_claude, probe_gemini, probe_netflix, probe_notebooklm,
    probe_portal_endpoints, probe_search_captcha, probe_service_geo,
    probe_tiktok, probe_youtube_premium,
};
use ipnet::Ipv4Net;
use itertools::{Either, Itertools as _};

use crate::config::{NeighborSweep, ScanCommand, SshAccess, SshSettings};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const GLOBALPING_DEADLINE: Duration = Duration::from_secs(90);

/// Shared collector for phase B. Every async producer records its rows here
/// as soon as they are known and returns nothing, so what was measured
/// survives the phase deadline cancelling whatever is still in flight. The
/// short lock is never held across an await.
#[derive(Default)]
struct ScanProgress(Mutex<Vec<CheckResult>>);

impl ScanProgress {
    #[expect(
        clippy::expect_used,
        reason = "the lock is held only for a push or extend that cannot \
                  panic, so the mutex cannot be poisoned"
    )]
    fn add(&self, results: impl IntoIterator<Item = CheckResult>) {
        self.0
            .lock()
            .expect("result collector cannot be poisoned")
            .extend(results);
    }

    #[expect(
        clippy::expect_used,
        reason = "the lock is held only for a push or extend that cannot \
                  panic, so the mutex cannot be poisoned"
    )]
    fn finish(self) -> Vec<CheckResult> {
        self.0
            .into_inner()
            .expect("result collector cannot be poisoned")
    }

    #[expect(
        clippy::expect_used,
        reason = "the lock is held only for a push or extend that cannot \
                  panic, so the mutex cannot be poisoned"
    )]
    fn deadline(&self, duration: Duration) {
        let detail = format!(
            "phase B exceeded the {}s overall deadline",
            duration.as_secs()
        );
        let mut results =
            self.0.lock().expect("result collector cannot be poisoned");
        for gate in gate::phase_b_gates() {
            if !results.iter().any(|result| result.gate() == gate) {
                results.push(CheckResult::new(gate, Verdict::error(&detail)));
            }
        }
        results.push(CheckResult::new(
            gate::SCAN_DEADLINE,
            Verdict::error(detail),
        ));
    }
}

fn apply_rules(
    profile: ScanProfile,
    overrides: &chip_core::GateOverrides,
    results: Vec<CheckResult>,
) -> Vec<CheckResult> {
    results
        .into_iter()
        .map(|result| overrides.apply(profile.apply(result)))
        .collect()
}

#[expect(
    clippy::expect_used,
    reason = "24 is a constant prefix length within 0..=32"
)]
pub fn network_24(ip: Ipv4Addr) -> Ipv4Net {
    Ipv4Net::new(ip, 24)
        .expect("24 is a valid IPv4 prefix length")
        .trunc()
}

pub fn globalping_budget(eyeball: u8, datacenter: u8) -> u32 {
    7 * (u32::from(eyeball) + u32::from(datacenter))
}

pub fn pick_free_port() -> std::io::Result<NonZeroU16> {
    let port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
        .local_addr()?
        .port();
    NonZeroU16::new(port).ok_or_else(|| {
        std::io::Error::other("OS assigned port zero to an ephemeral listener")
    })
}

/// Renders an error for a verdict detail with its whole `source()` chain.
///
/// The io error types keep their cause out of their own message, so
/// `to_string()` would show only the top layer. Context for the operation is
/// added with `anyhow::Context` before the call.
fn error_detail(error: impl Into<anyhow::Error>) -> String {
    format!("{:#}", error.into())
}

fn error_verdict(error: impl Into<anyhow::Error>) -> Verdict {
    Verdict::error(error_detail(error))
}

fn reputation_results(
    reputation: Result<ReputationFacts, impl Into<anyhow::Error>>,
) -> Vec<CheckResult> {
    let (flags, operator) = reputation.map_or_else(
        |error| {
            let detail = error_detail(error);
            (Verdict::error(detail.clone()), Verdict::error(detail))
        },
        |facts| (judge_reputation(&facts), judge_reputation_operator(&facts)),
    );
    vec![
        CheckResult::new(gate::REPUTATION, flags),
        CheckResult::new(gate::REPUTATION_OPERATOR, operator),
    ]
}

fn rkn_registry_verdict(
    registry: Result<RknRegistry, RknRegistryError>,
    ip: Ipv4Addr,
) -> Verdict {
    match registry {
        Ok(registry) => registry
            .check(ip)
            .map_or_else(error_verdict, |facts| judge_rkn_registry(&facts)),
        Err(error) => error_verdict(error),
    }
}

#[tracing::instrument(
    name = "scan.phase_a",
    level = "info",
    skip_all,
    fields(candidate_ip = %command.ip(), country = %command.country())
)]
pub async fn run_phase_a(
    command: &ScanCommand,
    http: &reqwest::Client,
) -> Vec<CheckResult> {
    let ip = command.ip();
    let reputation_client = ProxycheckClient::new(
        http.clone(),
        command.proxycheck_api_key().cloned(),
    );
    let geo_client = GeoIpClient::new(http.clone(), Duration::from_secs(6));
    let ripestat_client = RipestatClient::new(http.clone());
    let block_lists_client = BlockListsClient::new(http.clone());
    let registry_client = RknRegistryClient::new(http.clone());

    let (reputation, block_lists, registry, geo, provenance) = tokio::join!(
        reputation_client.lookup(ip),
        block_lists_client.fetch(),
        registry_client.fetch(),
        geo_result(&geo_client, command),
        ripestat_client.routing_status(ip)
    );

    let mut results = reputation_results(reputation);
    results.extend([
        CheckResult::new(
            gate::BLOCKLISTS,
            judge_blocklists(&block_lists.check(ip)),
        ),
        CheckResult::new(
            gate::RKN_REGISTRY,
            rkn_registry_verdict(registry, ip),
        ),
        CheckResult::new(
            gate::PROVENANCE,
            provenance
                .map_or_else(error_verdict, |routing| judge_routing(&routing)),
        ),
        geo,
    ]);
    results
}

async fn geo_result(
    geo_client: &GeoIpClient,
    command: &ScanCommand,
) -> CheckResult {
    match command.profile().scope(gate::GEO) {
        GateScope::Judged => {
            let verdict = geo_client.consensus(command.ip()).await.map_or_else(
                |error| {
                    error_verdict(
                        anyhow::Error::new(error).context("GeoIP task failed"),
                    )
                },
                |facts| judge_geo(&facts, command.country()),
            );
            CheckResult::new(gate::GEO, verdict)
        }
        GateScope::Skipped(reason) => CheckResult::skipped(gate::GEO, reason),
    }
}

/// One ping destination of the latency gate: a city anchor from Atlas or the
/// `--anchor` override. It carries only what the measurement needs, so the
/// override does not have to fake an Atlas anchor's city and AS metadata.
struct PingTarget {
    label: String,
    ip: Ipv4Addr,
}

impl From<&Anchor> for PingTarget {
    fn from(anchor: &Anchor) -> Self {
        Self {
            label: anchor.fqdn.clone(),
            ip: anchor.ip_v4,
        }
    }
}

/// An anchor ping that produced no measurement, kept so the latency verdict
/// can say which anchors it was computed without.
struct SkippedAnchor {
    label: String,
    cause: anyhow::Error,
}

/// The anchor pings of the latency gate, split into measured and skipped
/// anchors and ordered by label.
struct AnchorRuns {
    measured: Vec<(String, RawMeasurement)>,
    skipped: Vec<SkippedAnchor>,
}

impl FromIterator<(String, anyhow::Result<RawMeasurement>)> for AnchorRuns {
    fn from_iter<I>(runs: I) -> Self
    where
        I: IntoIterator<Item = (String, anyhow::Result<RawMeasurement>)>,
    {
        let (measured, skipped): (Vec<_>, Vec<_>) = runs
            .into_iter()
            .sorted_by(|left, right| left.0.cmp(&right.0))
            .partition_map(|(label, run)| match run {
                Ok(measurement) => Either::Left((label, measurement)),
                Err(cause) => Either::Right(SkippedAnchor { label, cause }),
            });
        Self { measured, skipped }
    }
}

impl AnchorRuns {
    /// Judges the measured anchors with `judge` and names the skipped ones.
    /// With nothing measured there is no latency to judge, so the verdict is
    /// an error carrying every cause.
    fn verdict(
        &self,
        judge: impl FnOnce(&[(String, RawMeasurement)]) -> Verdict,
    ) -> Verdict {
        let skipped = self
            .skipped
            .iter()
            .map(|anchor| format!("{} ({:#})", anchor.label, anchor.cause))
            .join(", ");
        if self.measured.is_empty() && !self.skipped.is_empty() {
            return Verdict::error(format!(
                "every anchor measurement failed: {skipped}"
            ));
        }
        let verdict = judge(&self.measured);
        if self.skipped.is_empty() {
            return verdict;
        }
        let detail = format!("{}; skipped anchors: {skipped}", verdict.detail);
        Verdict { detail, ..verdict }
    }
}

async fn anchor_measurements(
    client: &GlobalpingClient,
    first_measurement_id: &MeasurementId,
    targets: &[PingTarget],
) -> Result<AnchorRuns, tokio::task::JoinError> {
    let client = Arc::new(client.clone());
    let mut tasks = tokio::task::JoinSet::new();
    for target in targets {
        let client = Arc::clone(&client);
        let sample = first_measurement_id.clone();
        let label = target.label.clone();
        let target = target.ip;
        tasks.spawn(async move {
            let measurement: anyhow::Result<RawMeasurement> = async {
                let id = client
                    .create(
                        &MeasurementKind::ping(target),
                        &Locations::reuse(sample),
                    )
                    .await?;
                Ok(client.poll_until_finished(&id, GLOBALPING_DEADLINE).await?)
            }
            .await;
            (label, measurement)
        });
    }
    let mut runs = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let (label, measurement) = joined?;
        if let Err(error) = &measurement {
            tracing::warn!(
                anchor = %label,
                error = %format!("{error:#}"),
                "anchor measurement skipped"
            );
        }
        runs.push((label, measurement));
    }
    Ok(runs.into_iter().collect())
}

async fn reach_verdict(
    client: &GlobalpingClient,
    first_measurement_id: &MeasurementId,
    candidate: Ipv4Addr,
    candidate_port: NonZeroU16,
    control: Option<Ipv4Addr>,
) -> Verdict {
    let Some(control) = control else {
        return Verdict::error("no HTTPS control anchor available");
    };
    let locations = Locations::reuse(first_measurement_id.clone());
    let candidate_kind = MeasurementKind::https(candidate, candidate_port);
    let control_kind = MeasurementKind::https(
        control,
        const { NonZeroU16::new(443).expect("443 is non-zero") },
    );
    let (candidate_id, control_id) = tokio::join!(
        client.create(&candidate_kind, &locations),
        client.create(&control_kind, &locations)
    );
    let (candidate_id, control_id) = match (candidate_id, control_id) {
        (Ok(candidate_id), Ok(control_id)) => (candidate_id, control_id),
        (Err(error), _) | (_, Err(error)) => {
            return error_verdict(error);
        }
    };
    let (candidate, control) = tokio::join!(
        client.poll_until_finished(&candidate_id, GLOBALPING_DEADLINE),
        client.poll_until_finished(&control_id, GLOBALPING_DEADLINE)
    );
    match (candidate, control) {
        (Ok(candidate), Ok(control)) => reach_facts(&candidate, &control)
            .map_or_else(error_verdict, |facts| judge_reach(&facts)),
        (Err(error), _) | (_, Err(error)) => error_verdict(error),
    }
}

async fn record_latency(
    client: &GlobalpingClient,
    command: &ScanCommand,
    candidate_id: &MeasurementId,
    candidate: &RawMeasurement,
    city_targets: &[PingTarget],
    progress: &ScanProgress,
) {
    if !command.profile().judges(gate::LATENCY) {
        progress.add(command.profile().skipped([gate::LATENCY]));
        return;
    }
    let runs =
        match anchor_measurements(client, candidate_id, city_targets).await {
            Ok(runs) => runs,
            Err(error) => {
                progress.add([CheckResult::new(
                    gate::LATENCY,
                    error_verdict(
                        anyhow::Error::new(error).context("anchor task failed"),
                    ),
                )]);
                return;
            }
        };
    let latency = runs.verdict(|anchors| {
        ping_sweep_facts(candidate, anchors).map_or_else(
            error_verdict,
            |facts: PingSweepFacts| {
                judge_latency(&facts, command.latency_thresholds())
            },
        )
    });
    progress.add([CheckResult::new(gate::LATENCY, latency)]);
}

async fn run_globalping_measurements(
    client: &GlobalpingClient,
    command: &ScanCommand,
    city_targets: &[PingTarget],
    listener: Option<NonZeroU16>,
    control: Option<Ipv4Addr>,
    progress: &ScanProgress,
) {
    // Without a listener the candidate ping would only feed the latency gate.
    if listener.is_none() && !command.profile().judges(gate::LATENCY) {
        progress.add(command.profile().skipped([gate::LATENCY]));
        return;
    }
    let probes = command.probes();
    let locations = match Locations::ru(probes.eyeball(), probes.datacenter()) {
        Ok(locations) => locations,
        Err(error) => {
            progress.add(unavailable_globalping_results(error, listener));
            return;
        }
    };
    let candidate_id = match client
        .create(&MeasurementKind::ping(command.ip()), &locations)
        .await
    {
        Ok(id) => id,
        Err(error) => {
            progress.add(unavailable_globalping_results(error, listener));
            return;
        }
    };
    let candidate = match client
        .poll_until_finished(&candidate_id, GLOBALPING_DEADLINE)
        .await
    {
        Ok(measurement) => measurement,
        Err(error) => {
            progress.add(unavailable_globalping_results(error, listener));
            return;
        }
    };
    record_latency(
        client,
        command,
        &candidate_id,
        &candidate,
        city_targets,
        progress,
    )
    .await;
    if let Some(port) = listener {
        let verdict =
            reach_verdict(client, &candidate_id, command.ip(), port, control)
                .await;
        progress.add([CheckResult::new(gate::REACH, verdict)]);
    }
}

fn unavailable_globalping_results(
    error: impl Into<anyhow::Error>,
    listener: Option<NonZeroU16>,
) -> Vec<CheckResult> {
    let detail = error_detail(error);
    let mut results = vec![CheckResult::new(
        gate::LATENCY,
        Verdict::error(detail.clone()),
    )];
    if listener.is_some() {
        results.push(CheckResult::new(gate::REACH, Verdict::error(detail)));
    }
    results
}

fn tunnel_results(verdict: &Verdict) -> Vec<CheckResult> {
    gate::tunnel_gates()
        .map(|gate| CheckResult::new(gate, verdict.clone()))
        .collect()
}

async fn record_service(
    progress: &ScanProgress,
    gate: GateId,
    work: impl std::future::Future<Output = ServiceState>,
    judge: fn(&ServiceState) -> Verdict,
) {
    let state = work.await;
    progress.add([CheckResult::new(gate, judge(&state))]);
}

async fn record_portal(client: &TunnelClient, progress: &ScanProgress) {
    let verdict = probe_portal_endpoints(client).await.map_or_else(
        |error| {
            error_verdict(
                anyhow::Error::new(error).context("portal task failed"),
            )
        },
        |(https, http)| judge_tampering(&https, &http),
    );
    progress.add([CheckResult::new(gate::TAMPERING, verdict)]);
}

async fn run_tunnel_checks(
    client: &TunnelClient,
    expected_country: &CountryCode,
    profile: ScanProfile,
    progress: &ScanProgress,
) {
    if profile == ScanProfile::RuBridge {
        progress.add(profile.skipped(gate::tunnel_gates()));
        record_portal(client, progress).await;
        return;
    }
    tokio::join!(
        record_primary_services(client, progress),
        record_secondary_services(client, progress),
        record_portal(client, progress),
        record_service_geo(client, expected_country, progress),
    );
}

async fn record_primary_services(
    client: &TunnelClient,
    progress: &ScanProgress,
) {
    tokio::join!(
        record_service(
            progress,
            gate::SERVICE_CHATGPT_WEB,
            probe_chatgpt_web(client),
            judge_service_fail
        ),
        record_service(
            progress,
            gate::SERVICE_CHATGPT_APP,
            probe_chatgpt_app(client),
            judge_service_fail
        ),
        record_service(
            progress,
            gate::SERVICE_GEMINI,
            probe_gemini(client),
            judge_service_fail
        ),
        record_service(
            progress,
            gate::SERVICE_YOUTUBE_PREMIUM,
            probe_youtube_premium(client),
            judge_service_fail
        ),
    );
}

async fn record_secondary_services(
    client: &TunnelClient,
    progress: &ScanProgress,
) {
    tokio::join!(
        record_service(
            progress,
            gate::SERVICE_NETFLIX,
            probe_netflix(client),
            judge_service_warn
        ),
        record_service(
            progress,
            gate::SERVICE_CLAUDE,
            probe_claude(client),
            judge_service_warn
        ),
        record_service(
            progress,
            gate::SERVICE_TIKTOK,
            probe_tiktok(client),
            judge_service_warn
        ),
        record_service(
            progress,
            gate::SERVICE_NOTEBOOKLM,
            probe_notebooklm(client),
            judge_service_warn
        ),
    );
}

async fn record_service_geo(
    client: &TunnelClient,
    country: &CountryCode,
    progress: &ScanProgress,
) {
    tokio::join!(
        async {
            let observations = probe_service_geo(client).await;
            progress.add([
                CheckResult::new(
                    gate::SERVICE_GEO,
                    judge_service_country(&observations.votes, country),
                ),
                CheckResult::new(
                    gate::SERVICE_GEO_CDN,
                    judge_cdn_edge(&observations.edges),
                ),
            ]);
        },
        async {
            let (first, retry) = probe_search_captcha(client).await;
            progress.add([CheckResult::new(
                gate::SERVICE_GEO_CAPTCHA,
                judge_search_captcha(&first, &retry),
            )]);
        },
        async {
            let states = probe_ai_endpoints(client).await;
            progress.add([
                CheckResult::new(
                    gate::AI_OPENAI,
                    judge_ai_endpoint(&states.openai),
                ),
                CheckResult::new(
                    gate::AI_ANTHROPIC,
                    judge_ai_endpoint(&states.anthropic),
                ),
                CheckResult::new(
                    gate::AI_GEMINI,
                    judge_ai_endpoint(&states.gemini),
                ),
                CheckResult::new(
                    gate::AI_DEEPSEEK,
                    judge_ai_endpoint(&states.deepseek),
                ),
            ]);
        },
    );
}

fn select_targets(
    command: &ScanCommand,
    anchors: &[Anchor],
) -> (Vec<PingTarget>, Option<Ipv4Addr>) {
    let city = command.anchor().map_or_else(
        || {
            let by_city = command.city().map_or_else(Vec::new, |city| {
                select_for_city(anchors, city, 3)
            });
            let picked = if by_city.is_empty() {
                select_for_country(anchors, command.country(), 3)
            } else {
                by_city
            };
            picked.iter().map(PingTarget::from).collect()
        },
        |ip| {
            vec![PingTarget {
                label: "manual".to_string(),
                ip,
            }]
        },
    );
    let control = select_for_city(anchors, command.reference_city(), 2)
        .first()
        .map(|anchor| anchor.ip_v4);
    (city, control)
}

const LISTENER_PORTS: [NonZeroU16; 2] = [
    NonZeroU16::new(443).expect("443 is non-zero"),
    NonZeroU16::new(8443).expect("8443 is non-zero"),
];

async fn start_listener(
    session: &SshSession,
    ip: Ipv4Addr,
    progress: &ScanProgress,
) -> Option<NonZeroU16> {
    for port in LISTENER_PORTS {
        match session.start_listener(port).await {
            Ok(ListenerOutcome::Listening) => {
                match verify_listener(ip, port).await {
                    Ok(()) => return Some(port),
                    Err(error) => {
                        // A failed stop keeps the port in the session, so the
                        // final cleanup retries it and reports
                        // `LISTENER_CLEANUP` once; here it is only logged.
                        let _logged: Option<CheckResult> =
                            stop_listener(session).await;
                        progress.add([CheckResult::new(
                            gate::REACH,
                            error_verdict(anyhow::Error::new(error).context(
                                "temporary TLS listener is not reachable from the runner",
                            )),
                        )]);
                        return None;
                    }
                }
            }
            Ok(ListenerOutcome::PortInUse) => {}
            Ok(ListenerOutcome::Failed(detail)) => {
                progress.add([CheckResult::new(
                    gate::REACH,
                    Verdict::error(format!("listener failed: {detail}")),
                )]);
                return None;
            }
            Err(error) => {
                progress
                    .add([CheckResult::new(gate::REACH, ssh_failure(error))]);
                return None;
            }
        }
    }
    progress.add([CheckResult::new(
        gate::REACH,
        Verdict::error("candidate ports 443 and 8443 are already in use"),
    )]);
    None
}

struct GlobalpingSources {
    client: GlobalpingClient,
    city_targets: Vec<PingTarget>,
    control: Option<Ipv4Addr>,
}

struct GlobalpingSetupError {
    gate: GateId,
    detail: String,
}

/// An open SSH session and the config it was opened with; the SOCKS tunnel
/// reuses the config for its own connection.
struct SshConnection {
    session: SshSession,
    config: SshConfig,
}

struct SshSetup {
    connection: Option<SshConnection>,
    listener_port: Option<NonZeroU16>,
}

impl SshSetup {
    const fn disconnected() -> Self {
        Self {
            connection: None,
            listener_port: None,
        }
    }

    async fn stop_listener(&self) -> Option<CheckResult> {
        stop_listener(&self.connection.as_ref()?.session).await
    }
}

/// Stops the temporary listener; a failure becomes a `LISTENER_CLEANUP` row,
/// because the candidate may keep a stray listener and firewall rule.
async fn stop_listener(session: &SshSession) -> Option<CheckResult> {
    let port = session.listener_port()?;
    match session.stop_listener().await {
        Ok(()) => {
            tracing::debug!(port = port.get(), "temporary listener stopped");
            None
        }
        Err(error) => {
            let detail = error_detail(error);
            tracing::warn!(
                port = port.get(),
                error = %detail,
                "temporary listener cleanup failed"
            );
            Some(CheckResult::new(
                gate::LISTENER_CLEANUP,
                Verdict::error(detail),
            ))
        }
    }
}

fn skipped_ssh_results() -> Vec<CheckResult> {
    const REASON: &str = "--no-ssh: nothing was measured from the candidate";
    gate::ssh_gates()
        .map(|gate| CheckResult::skipped(gate, REASON))
        .collect()
}

fn ssh_failure(error: chip_io::ssh::SshError) -> Verdict {
    // Formatting belongs to the CLI boundary; the adapter retains typed causes.
    error_verdict(error)
}

fn unavailable_ssh_results(error: chip_io::ssh::SshError) -> Vec<CheckResult> {
    let detail =
        error_detail(anyhow::Error::new(error).context("SSH unavailable"));
    std::iter::once(CheckResult::new(gate::SSH, Verdict::error(detail.clone())))
        .chain(
            gate::ssh_gates().map(|gate| {
                CheckResult::new(gate, Verdict::error(detail.clone()))
            }),
        )
        .collect()
}

#[tracing::instrument(
    name = "scan.prepare_globalping",
    level = "debug",
    skip_all,
    fields(candidate_ip = %command.ip())
)]
async fn prepare_globalping(
    command: &ScanCommand,
    http: &reqwest::Client,
) -> Result<GlobalpingSources, GlobalpingSetupError> {
    let globalping = GlobalpingClient::new(
        http.clone(),
        command.globalping_token().cloned(),
    );
    let probes = command.probes();
    match globalping.limits().await {
        Ok(limits)
            if limits.remaining
                < globalping_budget(probes.eyeball(), probes.datacenter()) =>
        {
            return Err(GlobalpingSetupError {
                gate: gate::GLOBALPING_QUOTA,
                detail: format!(
                    "only {} Globalping tests remain; need approximately {}",
                    limits.remaining,
                    globalping_budget(probes.eyeball(), probes.datacenter())
                ),
            });
        }
        Err(error) => {
            return Err(GlobalpingSetupError {
                gate: gate::GLOBALPING_QUOTA,
                detail: error_detail(
                    anyhow::Error::new(error)
                        .context("could not read Globalping quota"),
                ),
            });
        }
        Ok(_) => {}
    }

    let anchors =
        AnchorClient::new(http.clone())
            .anchors()
            .await
            .map_err(|error| GlobalpingSetupError {
                gate: gate::LATENCY,
                detail: error_detail(
                    anyhow::Error::new(error)
                        .context("could not load RIPE Atlas anchors"),
                ),
            })?;
    let (city_targets, control) = select_targets(command, &anchors);
    Ok(GlobalpingSources {
        client: globalping,
        city_targets,
        control,
    })
}

fn ssh_config(settings: &SshSettings) -> SshConfig {
    SshConfig {
        user: Some(settings.user().to_owned()),
        port: settings.port(),
        private_key: settings.private_key().cloned(),
        host_keys: settings.host_keys().clone(),
        connect_timeout: Duration::from_secs(15),
        command_timeout: Duration::from_secs(20),
    }
}

#[tracing::instrument(
    name = "scan.prepare_ssh",
    level = "debug",
    skip_all,
    fields(candidate_ip = %command.ip())
)]
async fn prepare_ssh(
    command: &ScanCommand,
    setup: &mut SshSetup,
    progress: &ScanProgress,
) {
    let SshAccess::Enabled(settings) = command.ssh_access() else {
        return;
    };
    let config = ssh_config(settings);
    let session = match SshSession::connect(command.ip(), &config).await {
        Ok(session) => session,
        Err(error) => {
            progress.add(unavailable_ssh_results(error));
            return;
        }
    };
    // Store the owner before any remote listener can be created. The session
    // records a pending port before starting the mutating remote command.
    let connection = setup.connection.insert(SshConnection { session, config });
    setup.listener_port =
        start_listener(&connection.session, command.ip(), progress).await;
}

async fn run_globalping_branch(
    sources: Result<GlobalpingSources, GlobalpingSetupError>,
    command: &ScanCommand,
    listener_port: Option<NonZeroU16>,
    progress: &ScanProgress,
) {
    match sources {
        Ok(sources) => {
            run_globalping_measurements(
                &sources.client,
                command,
                &sources.city_targets,
                listener_port,
                sources.control,
                progress,
            )
            .await;
        }
        Err(error) => {
            let mut results = vec![CheckResult::new(
                error.gate,
                Verdict::error(error.detail.clone()),
            )];
            if error.gate != gate::LATENCY {
                results.push(CheckResult::new(
                    gate::LATENCY,
                    Verdict::error(error.detail.clone()),
                ));
            }
            if listener_port.is_some() {
                results.push(CheckResult::new(
                    gate::REACH,
                    Verdict::error(error.detail),
                ));
            }
            progress.add(results);
        }
    }
}

async fn run_socks_checks(
    command: &ScanCommand,
    setup: &SshSetup,
    progress: &ScanProgress,
) {
    let Some(connection) = &setup.connection else {
        return;
    };
    let port = match pick_free_port() {
        Ok(port) => port,
        Err(error) => {
            progress.add(tunnel_results(&error_verdict(
                anyhow::Error::new(error)
                    .context("could not reserve a local SOCKS port"),
            )));
            return;
        }
    };
    let tunnel = match SocksTunnel::start(
        command.ip(),
        &connection.config,
        port,
    )
    .await
    {
        Ok(tunnel) => tunnel,
        Err(error) => {
            progress.add(tunnel_results(&ssh_failure(error)));
            return;
        }
    };
    match TunnelClient::new(tunnel.local_addr(), REQUEST_TIMEOUT) {
        Ok(client) => {
            Box::pin(run_tunnel_checks(
                &client,
                command.country(),
                command.profile(),
                progress,
            ))
            .await;
        }
        Err(error) => {
            progress.add(tunnel_results(&error_verdict(error)));
        }
    }
    tunnel.stop().await;
}

async fn run_steal_check(session: &SshSession, progress: &ScanProgress) {
    let verdict = match session.steal_snapshot().await {
        Ok(before) => {
            tokio::time::sleep(Duration::from_secs(5)).await;
            session
                .steal_snapshot()
                .await
                .map_or_else(ssh_failure, |after| {
                    judge_steal(steal_pct(&before, &after))
                })
        }
        Err(error) => ssh_failure(error),
    };
    progress.add([CheckResult::new(gate::STEAL, verdict)]);
}

async fn run_ssh_checks(
    command: &ScanCommand,
    setup: &SshSetup,
    progress: &ScanProgress,
) {
    let Some(connection) = &setup.connection else {
        return;
    };
    tokio::join!(
        run_socks_checks(command, setup, progress),
        run_steal_check(&connection.session, progress),
    );
}

#[tracing::instrument(
    name = "scan.neighbors",
    level = "debug",
    skip_all,
    fields(candidate_ip = %command.ip())
)]
async fn run_neighbor_checks(command: &ScanCommand, progress: &ScanProgress) {
    if command.neighbor_sweep() == NeighborSweep::Disabled {
        return;
    }
    let ip = command.ip();
    let probes = match sweep(network_24(ip), &SweepConfig::default()).await {
        Ok(probes) => probes,
        Err(error) => {
            let detail = error_detail(
                anyhow::Error::new(error).context("neighbor task failed"),
            );
            progress.add(gate::neighbor_gates().map(|gate| {
                CheckResult::new(gate, Verdict::error(detail.clone()))
            }));
            return;
        }
    };
    let candidate_ptr = probes.iter().find(|probe| probe.ip == ip).map_or_else(
        || {
            chip_core::model::PtrLookup::Unavailable(
                "candidate was not surveyed".to_string(),
            )
        },
        |probe| probe.ptr.clone(),
    );
    progress.add([
        CheckResult::new(
            gate::NEIGHBORS_PTR,
            judge_candidate_ptr(&candidate_ptr),
        ),
        CheckResult::new(gate::NEIGHBORS, judge_neighbor_extremes(&probes)),
    ]);
}

#[tracing::instrument(
    name = "scan.phase_b",
    level = "info",
    skip_all,
    fields(
        candidate_ip = %command.ip(),
        country = %command.country(),
        deadline_secs = command.deadline().as_secs()
    )
)]
pub async fn run_phase_b(
    command: &ScanCommand,
    http: &reqwest::Client,
) -> Vec<CheckResult> {
    let deadline = tokio::time::Instant::now() + command.deadline();
    let progress = ScanProgress::default();
    if matches!(command.ssh_access(), SshAccess::Disabled) {
        progress.add(skipped_ssh_results());
    }
    if command.neighbor_sweep() == NeighborSweep::Disabled {
        progress.add(gate::neighbor_gates().map(|gate| {
            CheckResult::skipped(gate, "--no-neighbors: the /24 was not swept")
        }));
    }
    let mut ssh = SshSetup::disconnected();
    let work = async {
        let (sources, ()) = tokio::join!(
            prepare_globalping(command, http),
            prepare_ssh(command, &mut ssh, &progress),
        );
        tokio::join!(
            run_globalping_branch(
                sources,
                command,
                ssh.listener_port,
                &progress
            ),
            run_ssh_checks(command, &ssh, &progress),
            run_neighbor_checks(command, &progress),
        );
    };
    if tokio::time::timeout_at(deadline, Box::pin(work))
        .await
        .is_err()
    {
        tracing::warn!("phase B deadline exceeded");
        progress.deadline(command.deadline());
    }
    // Cleanup has its own bounded SSH command timeout and runs even when
    // preparation or measurements were cancelled by the phase deadline.
    if let Some(error) = ssh.stop_listener().await {
        progress.add([error]);
    }
    progress.finish()
}

#[tracing::instrument(
    name = "scan",
    level = "info",
    skip_all,
    fields(candidate_ip = %command.ip(), country = %command.country())
)]
pub async fn run_scan(command: &ScanCommand) -> Report {
    let http = match reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("chip/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return Report {
                results: vec![CheckResult::new(
                    gate::HTTP_CLIENT,
                    error_verdict(error),
                )],
            };
        }
    };
    let mut results = apply_rules(
        command.profile(),
        command.gate_overrides(),
        run_phase_a(command, &http).await,
    );
    if !command.failure_policy().stops_after(&results) {
        results.extend(apply_rules(
            command.profile(),
            command.gate_overrides(),
            run_phase_b(command, &http).await,
        ));
    }
    let report = Report { results };
    tracing::debug!(
        overall = %report.overall(),
        result_count = report.results.len(),
        "scan completed"
    );
    report
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use chip_core::{ScanOutcome, Severity};

    use super::*;
    use crate::config::FailurePolicy;

    #[derive(Debug)]
    struct RegistryDownloadFailed(std::io::Error);

    impl std::fmt::Display for RegistryDownloadFailed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("registry download failed")
        }
    }

    impl std::error::Error for RegistryDownloadFailed {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn an_error_verdict_names_the_cause_below_the_top_message() {
        let sut = RegistryDownloadFailed(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ));

        let verdict = error_verdict(sut);

        assert_eq!(verdict.severity, Severity::Error);
        assert_eq!(
            verdict.detail,
            "registry download failed: connection refused"
        );
    }

    fn measured(label: &str) -> (String, anyhow::Result<RawMeasurement>) {
        let measurement = RawMeasurement {
            id: format!("ping-{label}"),
            status: "finished".to_string(),
            results: Vec::new(),
        };
        (label.to_string(), Ok(measurement))
    }

    fn failed(
        label: &str,
        cause: &str,
    ) -> (String, anyhow::Result<RawMeasurement>) {
        let error = anyhow::anyhow!(cause.to_string())
            .context("globalping request failed");
        (label.to_string(), Err(error))
    }

    fn latency_ok(_: &[(String, RawMeasurement)]) -> Verdict {
        Verdict::ok("excess 3 ms")
    }

    #[test]
    fn every_anchor_failing_is_an_error_naming_each_cause() {
        let sut: AnchorRuns = [
            failed("hel.anchor", "HTTP 429"),
            failed("ams.anchor", "timed out"),
        ]
        .into_iter()
        .collect();

        let verdict = sut.verdict(latency_ok);

        assert_eq!(verdict.severity, Severity::Error);
        assert_eq!(
            verdict.detail,
            "every anchor measurement failed: \
             ams.anchor (globalping request failed: timed out), \
             hel.anchor (globalping request failed: HTTP 429)"
        );
    }

    #[test]
    fn a_failed_anchor_is_named_beside_the_verdict_of_the_measured_ones() {
        let sut: AnchorRuns =
            [measured("ams.anchor"), failed("hel.anchor", "HTTP 429")]
                .into_iter()
                .collect();

        let verdict = sut.verdict(latency_ok);

        assert_eq!(verdict.severity, Severity::Ok);
        assert_eq!(
            verdict.detail,
            "excess 3 ms; skipped anchors: \
             hel.anchor (globalping request failed: HTTP 429)"
        );
    }

    #[test]
    fn the_verdict_is_unchanged_when_every_anchor_was_measured() {
        let sut: AnchorRuns = [measured("ams.anchor"), measured("hel.anchor")]
            .into_iter()
            .collect();

        let verdict = sut.verdict(latency_ok);

        assert_eq!(verdict, Verdict::ok("excess 3 ms"));
    }

    #[test]
    fn host_bits_are_dropped_from_the_swept_network() {
        let candidate = Ipv4Addr::new(203, 0, 113, 42);

        let network = network_24(candidate);

        assert_eq!(network.to_string(), "203.0.113.0/24");
    }

    #[test]
    fn no_ssh_reports_its_gates_as_skipped_rather_than_as_passing() {
        let sut = Report {
            results: skipped_ssh_results(),
        };

        let table = sut.table();

        assert_eq!(sut.outcome(), ScanOutcome::Passed);
        assert_eq!(sut.results.len(), gate::ssh_gates().count());
        assert!(sut.results.iter().all(CheckResult::is_skipped), "{table}");
        assert!(!table.contains("OK "), "{table}");
    }

    #[test]
    fn a_bridge_reports_every_tunnel_gate_but_tampering_as_skipped() {
        let sut = ScanProfile::RuBridge;

        let skipped = sut.skipped(gate::tunnel_gates());

        let gates: HashSet<GateId> =
            skipped.iter().map(CheckResult::gate).collect();
        assert_eq!(
            gates,
            HashSet::from([
                gate::SERVICE_CHATGPT_WEB,
                gate::SERVICE_CHATGPT_APP,
                gate::SERVICE_GEMINI,
                gate::SERVICE_YOUTUBE_PREMIUM,
                gate::SERVICE_NETFLIX,
                gate::SERVICE_CLAUDE,
                gate::SERVICE_TIKTOK,
                gate::SERVICE_NOTEBOOKLM,
                gate::SERVICE_GEO,
                gate::SERVICE_GEO_CAPTCHA,
                gate::SERVICE_GEO_CDN,
                gate::AI_OPENAI,
                gate::AI_ANTHROPIC,
                gate::AI_GEMINI,
                gate::AI_DEEPSEEK,
            ])
        );
    }

    #[test]
    fn a_full_scan_of_8_eyeball_and_4_datacenter_probes_needs_84_tests() {
        let budget = globalping_budget(8, 4);

        assert_eq!(budget, 84);
    }

    #[test]
    fn deadline_keeps_completed_failures_and_marks_only_missing_gates() {
        let sut = ScanProgress::default();
        sut.add([CheckResult::new(gate::REACH, Verdict::fail("blocked"))]);

        sut.deadline(Duration::from_secs(1));

        let results = sut.finish();
        let reach: Vec<_> = results
            .iter()
            .filter(|result| result.gate() == gate::REACH)
            .map(CheckResult::severity)
            .collect();
        let latency: Vec<_> = results
            .iter()
            .filter(|result| result.gate() == gate::LATENCY)
            .map(CheckResult::severity)
            .collect();
        assert_eq!(reach, [Severity::Fail]);
        assert_eq!(latency, [Severity::Error]);
    }

    fn reputation_result(
        verdict: Verdict,
        overrides: &chip_core::GateOverrides,
    ) -> Vec<CheckResult> {
        apply_rules(
            ScanProfile::Exit,
            overrides,
            vec![CheckResult::new(gate::REPUTATION, verdict)],
        )
    }

    fn skipping(id: GateId) -> chip_core::GateOverrides {
        let mut overrides = chip_core::GateOverrides::default();
        overrides.skip.insert(id);
        overrides
    }

    fn escalating(id: GateId) -> chip_core::GateOverrides {
        let mut overrides = chip_core::GateOverrides::default();
        overrides.escalate.insert(id);
        overrides
    }

    #[test]
    fn a_skipped_failure_does_not_stop_a_fail_fast_scan() {
        let sut = FailurePolicy::FailFast;
        let results = reputation_result(
            Verdict::fail("blocked"),
            &skipping(gate::REPUTATION),
        );

        let stops = sut.stops_after(&results);

        assert!(!stops);
    }

    #[test]
    fn a_skipped_failure_does_not_fail_the_report() {
        let sut = Report {
            results: reputation_result(
                Verdict::fail("blocked"),
                &skipping(gate::REPUTATION),
            ),
        };

        let outcome = sut.outcome();

        assert_eq!(outcome, ScanOutcome::Passed);
    }

    #[test]
    fn an_escalated_warning_stops_a_fail_fast_scan() {
        let sut = FailurePolicy::FailFast;
        let results = reputation_result(
            Verdict::warn("suspicious"),
            &escalating(gate::REPUTATION),
        );

        let stops = sut.stops_after(&results);

        assert!(stops);
    }

    #[test]
    fn an_escalated_warning_fails_the_report() {
        let sut = Report {
            results: reputation_result(
                Verdict::warn("suspicious"),
                &escalating(gate::REPUTATION),
            ),
        };

        let outcome = sut.outcome();

        assert_eq!(outcome, ScanOutcome::Failed);
    }
}
