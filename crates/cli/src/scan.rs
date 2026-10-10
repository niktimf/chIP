use std::net::Ipv4Addr;
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::Mutex;
use std::time::Duration;

use chip_core::checks::direct::blocklists::judge_blocklists;
use chip_core::checks::direct::geo::judge_geo;
use chip_core::checks::direct::ip_lists::RknRegistry;
use chip_core::checks::direct::provenance::judge_routing;
use chip_core::checks::direct::reputation::{
    ReputationFacts, judge_reputation, judge_reputation_operator,
};
use chip_core::checks::direct::rkn_registry::judge_rkn_registry;
use chip_core::checks::globalping::latency::anchor::{
    Anchor, select_for_city, select_for_country,
};
use chip_core::checks::globalping::latency::{
    AnchorSeries, PingSample, PingSweepFacts, judge_latency,
};
use chip_core::checks::globalping::reach::{ReachFacts, judge_reach};
use chip_core::checks::neighbors::{
    judge_candidate_ptr, judge_neighbor_extremes,
};
use chip_core::checks::ssh::steal::judge_steal;
use chip_core::checks::tunnel::ServiceState;
use chip_core::checks::tunnel::ai::judge_ai_endpoint;
use chip_core::checks::tunnel::service_geo::{
    judge_cdn_edge, judge_search_captcha, judge_service_country,
};
use chip_core::checks::tunnel::services::ServiceTier;
use chip_core::checks::tunnel::tampering::judge_tampering;
use chip_core::report::gate;
use chip_core::{
    CheckResult, CountryCode, GateId, GateScope, Report, ScanProfile, Verdict,
};
use chip_io::atlas::{AnchorClient, AtlasError};
use chip_io::blocklists::BlockListsClient;
use chip_io::geoip::GeoIpClient;
use chip_io::globalping::{
    GlobalpingClient, GlobalpingError, Locations, MeasurementId, Ping,
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
use futures::{TryStreamExt as _, stream};
use ipnet::Ipv4Net;
use itertools::{Either, Itertools as _};

use crate::config::{NeighborSweep, ScanCommand, SshAccess, SshSettings};
use crate::{CITY_ANCHORS, GLOBALPING_DEADLINE, REQUEST_TIMEOUT};

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

/// Globalping measurements one scan runs on every probe, which the quota
/// check multiplies by the probe count.
const SCAN_MEASUREMENTS_PER_PROBE: u32 = {
    /// The candidate ping, which also picks the probes the rest reuse.
    const CANDIDATE_PING: u32 = 1;
    /// One ping per city anchor, at most [`CITY_ANCHORS`].
    const CITY_ANCHOR_PINGS: u32 = 3;
    /// HTTPS to the candidate's listener and to the control anchor.
    const REACH_MEASUREMENTS: u32 = 2;
    assert!(CITY_ANCHOR_PINGS as usize == CITY_ANCHORS.get());
    CANDIDATE_PING + CITY_ANCHOR_PINGS + REACH_MEASUREMENTS
};

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
/// added with `anyhow::Context` before the call, which is why the argument
/// is anything that converts into `anyhow::Error`.
fn error_detail(error: impl Into<anyhow::Error>) -> String {
    let error: anyhow::Error = error.into();
    let detail = chip_io::describe_error(&*error);
    match globalping_rate_limit_hint(&error) {
        Some(hint) => format!("{detail} ({hint})"),
        None => detail,
    }
}

/// What the user can do about a Globalping rate limit somewhere in the
/// chain of `error`. The io client does not know the variable that holds
/// the token, so the remedy is named here.
pub fn globalping_rate_limit_hint(
    error: &anyhow::Error,
) -> Option<&'static str> {
    error
        .chain()
        .any(|cause| {
            matches!(
                cause.downcast_ref::<GlobalpingError>(),
                Some(GlobalpingError::RateLimited)
            )
        })
        .then_some("try again next hour, or set GLOBALPING_TOKEN")
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
        Ok(registry) => judge_rkn_registry(&registry.check(ip)),
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
    /// How long each geolocation source gets to answer; a source that
    /// times out casts no vote in the consensus.
    const GEOIP_TIMEOUT: Duration = Duration::from_secs(6);
    let ip = command.ip();
    let reputation_client = ProxycheckClient::new(
        http.clone(),
        command.proxycheck_api_key().cloned(),
    );
    let geo_client = GeoIpClient::new(http.clone(), GEOIP_TIMEOUT);
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
            let facts = geo_client.consensus(command.ip()).await;
            let verdict = judge_geo(&facts, command.country());
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
            label: anchor.fqdn().to_owned(),
            ip: anchor.ip_v4(),
        }
    }
}

/// An anchor ping that produced no measurement, kept so the latency verdict
/// can say which anchors it was computed without.
struct SkippedAnchor {
    label: String,
    cause: GlobalpingError,
}

/// The anchor pings of the latency gate, split into measured and skipped
/// anchors and ordered by label.
struct AnchorRuns {
    measured: Vec<AnchorSeries>,
    skipped: Vec<SkippedAnchor>,
}

/// The per-probe ping samples of one anchor, or why it has none.
struct AnchorRun {
    label: String,
    samples: Result<Vec<Option<PingSample>>, GlobalpingError>,
}

impl FromIterator<AnchorRun> for AnchorRuns {
    fn from_iter<I>(runs: I) -> Self
    where
        I: IntoIterator<Item = AnchorRun>,
    {
        let (measured, skipped): (Vec<_>, Vec<_>) = runs
            .into_iter()
            .sorted_by(|left, right| left.label.cmp(&right.label))
            .partition_map(|AnchorRun { label, samples }| match samples {
                Ok(samples) => Either::Left(AnchorSeries::new(label, samples)),
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
        self,
        judge: impl FnOnce(Vec<AnchorSeries>) -> Verdict,
    ) -> Verdict {
        if self.skipped.is_empty() {
            return judge(self.measured);
        }
        // Each cause is rendered like every other error row, with its
        // source chain and remedy.
        let skipped = self
            .skipped
            .into_iter()
            .map(|anchor| {
                format!("{} ({})", anchor.label, error_detail(anchor.cause))
            })
            .join(", ");
        if self.measured.is_empty() {
            return Verdict::error(format!(
                "every anchor measurement failed: {skipped}"
            ));
        }
        let verdict = judge(self.measured);
        let detail = format!("{}; skipped anchors: {skipped}", verdict.detail);
        Verdict { detail, ..verdict }
    }
}

async fn anchor_measurements(
    client: &GlobalpingClient,
    first_measurement_id: &MeasurementId<Ping>,
    targets: &[PingTarget],
) -> Result<AnchorRuns, tokio::task::JoinError> {
    let mut tasks: tokio::task::JoinSet<AnchorRun> = targets
        .iter()
        .map(|target| {
            let client = client.clone();
            let locations = Locations::reuse(first_measurement_id);
            let label = target.label.clone();
            let ip = target.ip;
            async move {
                let samples = async {
                    let id = client.create_ping(ip, &locations).await?;
                    client.poll_ping(&id, GLOBALPING_DEADLINE).await
                }
                .await;
                AnchorRun { label, samples }
            }
        })
        .collect();
    let runs: Vec<AnchorRun> =
        stream::poll_fn(|context| tasks.poll_join_next(context))
            .inspect_ok(|run| {
                if let Err(error) = &run.samples {
                    tracing::warn!(
                        anchor = %run.label,
                        error = %chip_io::describe_error(error),
                        "anchor measurement skipped"
                    );
                }
            })
            .try_collect()
            .await?;
    Ok(runs.into_iter().collect())
}

async fn reach_verdict(
    client: &GlobalpingClient,
    first_measurement_id: &MeasurementId<Ping>,
    candidate: Ipv4Addr,
    candidate_port: NonZeroU16,
    control: Option<Ipv4Addr>,
) -> Verdict {
    let Some(control) = control else {
        return Verdict::error("no HTTPS control anchor available");
    };
    let locations = Locations::reuse(first_measurement_id);
    let control_port = const { NonZeroU16::new(443).expect("443 is non-zero") };
    let (candidate_id, control_id) = tokio::join!(
        client.create_https(candidate, candidate_port, &locations),
        client.create_https(control, control_port, &locations)
    );
    let (candidate_id, control_id) = match (candidate_id, control_id) {
        (Ok(candidate_id), Ok(control_id)) => (candidate_id, control_id),
        (Err(error), _) | (_, Err(error)) => {
            return error_verdict(error);
        }
    };
    let (candidate, control) = tokio::join!(
        client.poll_https(&candidate_id, GLOBALPING_DEADLINE),
        client.poll_https(&control_id, GLOBALPING_DEADLINE)
    );
    match (candidate, control) {
        (Ok(candidate), Ok(control)) => ReachFacts::new(candidate, control)
            .map_or_else(error_verdict, |facts| judge_reach(&facts)),
        (Err(error), _) | (_, Err(error)) => error_verdict(error),
    }
}

async fn record_latency(
    client: &GlobalpingClient,
    command: &ScanCommand,
    candidate_id: &MeasurementId<Ping>,
    candidate: Vec<Option<PingSample>>,
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
        PingSweepFacts::new(candidate, anchors).map_or_else(
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
    let locations = Locations::ru(command.probes());
    let candidate_id = match client.create_ping(command.ip(), &locations).await
    {
        Ok(id) => id,
        Err(error) => {
            progress.add(globalping_failure_results(
                gate::LATENCY,
                error,
                listener,
            ));
            return;
        }
    };
    let candidate =
        match client.poll_ping(&candidate_id, GLOBALPING_DEADLINE).await {
            Ok(samples) => samples,
            Err(error) => {
                progress.add(globalping_failure_results(
                    gate::LATENCY,
                    error,
                    listener,
                ));
                return;
            }
        };
    record_latency(
        client,
        command,
        &candidate_id,
        candidate,
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

/// The rows of a Globalping branch that stopped before its measurements:
/// the gate whose step failed, the latency gate, which needs every step, and
/// the reach gate when a verified listener was waiting to be measured.
fn globalping_failure_results(
    failed: GateId,
    error: impl Into<anyhow::Error>,
    listener: Option<NonZeroU16>,
) -> Vec<CheckResult> {
    let detail = error_detail(error);
    [failed, gate::LATENCY]
        .into_iter()
        .chain(listener.map(|_| gate::REACH))
        .unique()
        .map(|gate| CheckResult::new(gate, Verdict::error(detail.clone())))
        .collect()
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
    tier: ServiceTier,
) {
    let state = work.await;
    progress.add([CheckResult::new(gate, tier.judge(&state))]);
}

async fn record_portal(client: &TunnelClient, progress: &ScanProgress) {
    let verdict = judge_tampering(&probe_portal_endpoints(client).await);
    progress.add([CheckResult::new(gate::TAMPERING, verdict)]);
}

async fn run_tunnel_checks(
    client: &TunnelClient,
    expected_country: &CountryCode,
    profile: ScanProfile,
    progress: &ScanProgress,
) {
    let skipped = profile.skipped(gate::tunnel_gates());
    if !skipped.is_empty() {
        progress.add(skipped);
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
            ServiceTier::Primary
        ),
        record_service(
            progress,
            gate::SERVICE_CHATGPT_APP,
            probe_chatgpt_app(client),
            ServiceTier::Primary
        ),
        record_service(
            progress,
            gate::SERVICE_GEMINI,
            probe_gemini(client),
            ServiceTier::Primary
        ),
        record_service(
            progress,
            gate::SERVICE_YOUTUBE_PREMIUM,
            probe_youtube_premium(client),
            ServiceTier::Primary
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
            ServiceTier::Secondary
        ),
        record_service(
            progress,
            gate::SERVICE_CLAUDE,
            probe_claude(client),
            ServiceTier::Secondary
        ),
        record_service(
            progress,
            gate::SERVICE_TIKTOK,
            probe_tiktok(client),
            ServiceTier::Secondary
        ),
        record_service(
            progress,
            gate::SERVICE_NOTEBOOKLM,
            probe_notebooklm(client),
            ServiceTier::Secondary
        ),
    );
}

async fn record_service_geo(
    client: &TunnelClient,
    country: &CountryCode,
    progress: &ScanProgress,
) {
    /// The pause before the captcha retry; the verdict detail names it.
    const CAPTCHA_RETRY_AFTER: Duration = Duration::from_secs(30);

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
            let captcha =
                probe_search_captcha(client, CAPTCHA_RETRY_AFTER).await;
            progress.add([CheckResult::new(
                gate::SERVICE_GEO_CAPTCHA,
                judge_search_captcha(&captcha),
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
    const CONTROL_ANCHORS: NonZeroUsize =
        NonZeroUsize::new(2).expect("2 is non-zero");
    let city = command.anchor().map_or_else(
        || {
            let by_city = command.city().map_or_else(Vec::new, |city| {
                select_for_city(anchors, city, CITY_ANCHORS)
            });
            let picked = if by_city.is_empty() {
                select_for_country(anchors, command.country(), CITY_ANCHORS)
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
    let control =
        select_for_city(anchors, command.reference_city(), CONTROL_ANCHORS)
            .first()
            .map(Anchor::ip_v4);
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
    /// How long the runner waits for the temporary listener's TLS answer.
    const LISTENER_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
    for port in LISTENER_PORTS {
        match session.start_listener(port).await {
            Ok(ListenerOutcome::Listening) => {
                match verify_listener(ip, port, LISTENER_PROBE_TIMEOUT).await {
                    Ok(()) => return Some(port),
                    Err(error) => {
                        // A failed stop keeps the port in the session, so the
                        // final cleanup retries it and reports
                        // `LISTENER_CLEANUP` once; here it is only logged.
                        let _logged: Option<CheckResult> =
                            stop_listener(session).await;
                        progress.add([CheckResult::new(
                            gate::REACH,
                            error_verdict(error),
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
                    .add([CheckResult::new(gate::REACH, error_verdict(error))]);
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

/// Why the Globalping measurements could not start.
#[derive(Debug, thiserror::Error)]
enum GlobalpingSetupError {
    #[error(
        "only {remaining} Globalping tests remain; need approximately {needed}"
    )]
    QuotaExhausted { remaining: u32, needed: u32 },
    #[error("could not read Globalping quota")]
    QuotaUnavailable(#[source] GlobalpingError),
    #[error("could not load RIPE Atlas anchors")]
    AnchorsUnavailable(#[source] AtlasError),
}

impl GlobalpingSetupError {
    /// The gate whose own step failed: the quota check has a gate of its
    /// own, the anchors are needed only by the latency gate.
    const fn gate(&self) -> GateId {
        match self {
            Self::QuotaExhausted { .. } | Self::QuotaUnavailable(_) => {
                gate::GLOBALPING_QUOTA
            }
            Self::AnchorsUnavailable(_) => gate::LATENCY,
        }
    }
}

/// What phase B has of the SSH access to the candidate.
enum SshState {
    /// `--no-ssh`: the SSH gates are reported as skipped.
    Disabled,
    /// SSH is enabled but no session is open: connecting failed, and its
    /// error rows are recorded, or the phase deadline cancelled it.
    Unavailable,
    /// The open session; it also records the temporary listener port that
    /// still needs cleanup.
    Connected(SshSession),
}

impl SshState {
    const fn for_access(access: &SshAccess) -> Self {
        match access {
            SshAccess::Disabled => Self::Disabled,
            SshAccess::Enabled(_) => Self::Unavailable,
        }
    }

    const fn session(&self) -> Option<&SshSession> {
        match self {
            Self::Connected(session) => Some(session),
            Self::Disabled | Self::Unavailable => None,
        }
    }

    /// Stores the open session and lends it back.
    #[expect(
        clippy::unreachable,
        reason = "the state is set to `Connected` on the line above"
    )]
    fn connected(&mut self, session: SshSession) -> &SshSession {
        *self = Self::Connected(session);
        match self {
            Self::Connected(session) => session,
            Self::Disabled | Self::Unavailable => {
                unreachable!("the state was just set to `Connected`")
            }
        }
    }

    async fn stop_listener(&self) -> Option<CheckResult> {
        stop_listener(self.session()?).await
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
    let needed = command.probes().tests_for(SCAN_MEASUREMENTS_PER_PROBE);
    let limits = globalping
        .limits()
        .await
        .map_err(GlobalpingSetupError::QuotaUnavailable)?;
    if limits.remaining < needed {
        return Err(GlobalpingSetupError::QuotaExhausted {
            remaining: limits.remaining,
            needed,
        });
    }

    let anchors = AnchorClient::new(http.clone())
        .anchors()
        .await
        .map_err(GlobalpingSetupError::AnchorsUnavailable)?;
    let (city_targets, control) = select_targets(command, &anchors);
    Ok(GlobalpingSources {
        client: globalping,
        city_targets,
        control,
    })
}

fn ssh_config(settings: &SshSettings) -> SshConfig {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
    const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
    SshConfig {
        user: Some(settings.user().to_owned()),
        port: settings.port(),
        private_key: settings.private_key().cloned(),
        host_keys: settings.host_keys().clone(),
        connect_timeout: CONNECT_TIMEOUT,
        command_timeout: COMMAND_TIMEOUT,
    }
}

/// Connects to the candidate and starts the temporary listener.
///
/// Returns the listener port verified from the runner, the port the reach
/// gate measures; `None` when SSH is disabled or unavailable or no listener
/// became reachable.
#[tracing::instrument(
    name = "scan.prepare_ssh",
    level = "debug",
    skip_all,
    fields(candidate_ip = %command.ip())
)]
async fn prepare_ssh(
    command: &ScanCommand,
    ssh: &mut SshState,
    progress: &ScanProgress,
) -> Option<NonZeroU16> {
    let SshAccess::Enabled(settings) = command.ssh_access() else {
        return None;
    };
    let session =
        match SshSession::connect(command.ip(), ssh_config(settings)).await {
            Ok(session) => session,
            Err(error) => {
                progress.add(unavailable_ssh_results(error));
                return None;
            }
        };
    // Store the owner before any remote listener can be created. The session
    // records a pending port before starting the mutating remote command.
    let session = ssh.connected(session);
    start_listener(session, command.ip(), progress).await
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
            let failed = error.gate();
            progress.add(globalping_failure_results(
                failed,
                error,
                listener_port,
            ));
        }
    }
}

async fn run_socks_checks(
    command: &ScanCommand,
    session: &SshSession,
    progress: &ScanProgress,
) {
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
    let tunnel = match SocksTunnel::start(session, port).await {
        Ok(tunnel) => tunnel,
        Err(error) => {
            progress.add(tunnel_results(&error_verdict(error)));
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
    const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
    let verdict = match session.steal_snapshot().await {
        Ok(before) => {
            tokio::time::sleep(SAMPLE_INTERVAL).await;
            session
                .steal_snapshot()
                .await
                .map_or_else(error_verdict, |after| {
                    judge_steal(
                        after.steal_share_since(before),
                        SAMPLE_INTERVAL,
                    )
                })
        }
        Err(error) => error_verdict(error),
    };
    progress.add([CheckResult::new(gate::STEAL, verdict)]);
}

async fn run_ssh_checks(
    command: &ScanCommand,
    ssh: &SshState,
    progress: &ScanProgress,
) {
    let Some(session) = ssh.session() else {
        return;
    };
    tokio::join!(
        run_socks_checks(command, session, progress),
        run_steal_check(session, progress),
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
    let probes = sweep(network_24(ip), &SweepConfig::default()).await;
    let candidate_ptr = probes.iter().find(|probe| probe.ip == ip).map_or_else(
        || {
            chip_core::checks::neighbors::PtrLookup::Unavailable(
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
    let mut ssh = SshState::for_access(command.ssh_access());
    if matches!(ssh, SshState::Disabled) {
        progress.add(skipped_ssh_results());
    }
    if command.neighbor_sweep() == NeighborSweep::Disabled {
        progress.add(gate::neighbor_gates().map(|gate| {
            CheckResult::skipped(gate, "--no-neighbors: the /24 was not swept")
        }));
    }
    let work = async {
        let (sources, listener) = tokio::join!(
            prepare_globalping(command, http),
            prepare_ssh(command, &mut ssh, &progress),
        );
        tokio::join!(
            run_globalping_branch(sources, command, listener, &progress),
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
    let http = match crate::http_client() {
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
    use chip_io::globalping::ProbeSelection;

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
        let error = RegistryDownloadFailed(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ));

        let verdict = error_verdict(error);

        assert_eq!(verdict.severity, Severity::Error);
        assert_eq!(
            verdict.detail,
            "registry download failed: connection refused"
        );
    }

    fn measured(label: &str) -> AnchorRun {
        AnchorRun {
            label: label.to_string(),
            samples: Ok(Vec::new()),
        }
    }

    fn failed(label: &str, cause: GlobalpingError) -> AnchorRun {
        AnchorRun {
            label: label.to_string(),
            samples: Err(cause),
        }
    }

    fn latency_ok(_: Vec<AnchorSeries>) -> Verdict {
        Verdict::ok("excess 3 ms")
    }

    #[test]
    fn every_anchor_failing_is_an_error_naming_each_cause() {
        let sut: AnchorRuns = [
            failed("hel.anchor", GlobalpingError::EmptyMeasurementId),
            failed("ams.anchor", GlobalpingError::NoSuitableProbes),
        ]
        .into_iter()
        .collect();

        let verdict = sut.verdict(latency_ok);

        assert_eq!(verdict.severity, Severity::Error);
        assert_eq!(
            verdict.detail,
            "every anchor measurement failed: \
             ams.anchor (globalping found no suitable probes for this \
             request), \
             hel.anchor (globalping returned an empty measurement id)"
        );
    }

    #[test]
    fn a_failed_anchor_is_named_beside_the_verdict_of_the_measured_ones() {
        let sut: AnchorRuns = [
            measured("ams.anchor"),
            failed("hel.anchor", GlobalpingError::EmptyMeasurementId),
        ]
        .into_iter()
        .collect();

        let verdict = sut.verdict(latency_ok);

        assert_eq!(verdict.severity, Severity::Ok);
        assert_eq!(
            verdict.detail,
            "excess 3 ms; skipped anchors: \
             hel.anchor (globalping returned an empty measurement id)"
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
    fn no_ssh_skips_the_listener_ssh_and_tunnel_gates() {
        let results = skipped_ssh_results();

        let skipped: HashSet<GateId> = results
            .iter()
            .filter(|result| result.is_skipped())
            .map(CheckResult::gate)
            .collect();
        assert_eq!(results.len(), skipped.len());
        assert_eq!(
            skipped,
            HashSet::from([
                gate::REACH,
                gate::STEAL,
                gate::TAMPERING,
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
    fn a_scan_without_ssh_passes() {
        let sut = Report {
            results: skipped_ssh_results(),
        };

        let outcome = sut.outcome();

        assert_eq!(outcome, ScanOutcome::Passed);
    }

    #[test]
    fn the_table_of_a_scan_without_ssh_shows_no_gate_as_ok() {
        let sut = Report {
            results: skipped_ssh_results(),
        };

        let table = sut.table();

        assert!(!table.contains("OK "), "{table}");
    }

    #[test]
    fn a_full_scan_of_8_eyeball_and_4_datacenter_probes_needs_72_tests() {
        let probes = ProbeSelection::new(8, 4).unwrap();

        let budget = probes.tests_for(SCAN_MEASUREMENTS_PER_PROBE);

        assert_eq!(budget, 72);
    }

    #[test]
    fn a_globalping_rate_limit_names_the_token_that_raises_the_quota() {
        let error = anyhow::Error::new(GlobalpingError::RateLimited)
            .context("failed to start a Globalping ping");

        let detail = error_detail(error);

        assert_eq!(
            detail,
            "failed to start a Globalping ping: globalping rate limit \
             exceeded (try again next hour, or set GLOBALPING_TOKEN)"
        );
    }

    fn verified_listener() -> Option<NonZeroU16> {
        NonZeroU16::new(8443)
    }

    #[test]
    fn an_exhausted_quota_fails_quota_latency_and_reach_with_one_detail() {
        let failure = GlobalpingSetupError::QuotaExhausted {
            remaining: 10,
            needed: 84,
        };

        let results = globalping_failure_results(
            gate::GLOBALPING_QUOTA,
            failure,
            verified_listener(),
        );

        let detail = "only 10 Globalping tests remain; need approximately 84";
        assert_eq!(
            results,
            [
                CheckResult::new(
                    gate::GLOBALPING_QUOTA,
                    Verdict::error(detail)
                ),
                CheckResult::new(gate::LATENCY, Verdict::error(detail)),
                CheckResult::new(gate::REACH, Verdict::error(detail)),
            ]
        );
    }

    #[test]
    fn an_unreadable_quota_names_its_cause_and_leaves_reach_without_a_listener()
    {
        let failure =
            GlobalpingSetupError::QuotaUnavailable(GlobalpingError::Status {
                operation: "read limits",
                status: reqwest::StatusCode::TOO_MANY_REQUESTS,
            });

        let results =
            globalping_failure_results(gate::GLOBALPING_QUOTA, failure, None);

        let detail = "could not read Globalping quota: \
                      globalping request failed: read limits: \
                      HTTP 429 Too Many Requests";
        assert_eq!(
            results,
            [
                CheckResult::new(
                    gate::GLOBALPING_QUOTA,
                    Verdict::error(detail)
                ),
                CheckResult::new(gate::LATENCY, Verdict::error(detail)),
            ]
        );
    }

    #[test]
    fn a_failed_latency_step_reports_latency_once_beside_reach() {
        let failure = GlobalpingError::Status {
            operation: "poll measurement",
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
        };

        let results = globalping_failure_results(
            gate::LATENCY,
            failure,
            verified_listener(),
        );

        let detail = "globalping request failed: poll measurement: \
                      HTTP 503 Service Unavailable";
        assert_eq!(
            results,
            [
                CheckResult::new(gate::LATENCY, Verdict::error(detail)),
                CheckResult::new(gate::REACH, Verdict::error(detail)),
            ]
        );
    }

    #[test]
    fn missing_anchors_are_reported_under_the_latency_gate() {
        let sut = GlobalpingSetupError::AnchorsUnavailable(
            AtlasError::TooManyPages { limit: 20 },
        );

        let reported = sut.gate();

        assert_eq!(reported, gate::LATENCY);
    }

    #[test]
    fn quota_problems_are_reported_under_the_quota_gate() {
        let sut = GlobalpingSetupError::QuotaExhausted {
            remaining: 10,
            needed: 84,
        };

        let reported = sut.gate();

        assert_eq!(reported, gate::GLOBALPING_QUOTA);
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
    fn an_escalated_warning_stops_a_fail_fast_scan() {
        let sut = FailurePolicy::FailFast;
        let results = reputation_result(
            Verdict::warn("suspicious"),
            &escalating(gate::REPUTATION),
        );

        let stops = sut.stops_after(&results);

        assert!(stops);
    }
}
