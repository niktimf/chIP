use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chip_core::ip_lists::RknRegistry;
use chip_core::model::{
    PingSweepFacts, ReputationFacts, RiskScore, ServiceState,
};
use chip_core::verdict::ai::judge_ai_endpoints;
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
use chip_core::verdict::services::{judge_services_fail, judge_services_warn};
use chip_core::verdict::steal::{judge_steal, steal_pct};
use chip_core::verdict::tampering::judge_tampering;
use chip_core::{
    CheckResult, CountryCode, GateScope, Report, ScanProfile, Severity, Verdict,
};
use chip_io::atlas::{
    Anchor, AnchorClient, select_for_city, select_for_country,
};
use chip_io::blocklists::BlockListsClient;
use chip_io::geoip::GeoIpClient;
use chip_io::globalping::{
    GlobalpingClient, Locations, MeasurementId, MeasurementKind,
    ping_sweep_facts, reach_facts,
};
use chip_io::neighbors::{SweepConfig, sweep};
use chip_io::proxycheck::ProxycheckClient;
use chip_io::ripestat::RipestatClient;
use chip_io::rkn_registry::{RknRegistryClient, RknRegistryError};
use chip_io::ssh::{ListenerOutcome, SocksTunnel, SshConfig, SshSession};
use chip_io::tunnel::{
    TunnelClient, probe_ai_endpoints, probe_cdn_edges, probe_chatgpt_app,
    probe_chatgpt_web, probe_claude, probe_country_votes, probe_gemini,
    probe_netflix, probe_notebooklm, probe_portal_endpoints,
    probe_search_captcha, probe_tiktok, probe_youtube_premium,
};
use ipnet::Ipv4Net;

use crate::config::ScanCommand;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const GLOBALPING_DEADLINE: Duration = Duration::from_secs(90);
const SERVICE_COUNTRY_FAIL_ON: &[&str] = &["google", "youtube"];

/// All producers are polled in this scope; the short collector lock is never held across await.
#[derive(Default)]
struct ScanProgress(Mutex<Vec<CheckResult>>);

impl ScanProgress {
    fn add(&self, results: impl IntoIterator<Item = CheckResult>) {
        self.0
            .lock()
            .expect("result collector cannot be poisoned")
            .extend(results);
    }

    async fn record(
        &self,
        work: impl std::future::Future<Output = Vec<CheckResult>>,
    ) {
        self.add(work.await);
    }

    fn finish(self) -> Vec<CheckResult> {
        self.0
            .into_inner()
            .expect("result collector cannot be poisoned")
    }

    fn deadline(&self, duration: Duration) {
        let detail = format!(
            "phase B exceeded the {}s overall deadline",
            duration.as_secs()
        );
        let mut results =
            self.0.lock().expect("result collector cannot be poisoned");
        for gate in ["latency", "reach", "steal"]
            .into_iter()
            .chain(TUNNEL_GATES)
            .chain(NEIGHBOR_GATES)
        {
            if !results.iter().any(|result| result.gate == gate) {
                results.push(CheckResult::new(gate, Verdict::error(&detail)));
            }
        }
        results.push(CheckResult::new("scan-deadline", Verdict::error(detail)));
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

pub fn network_24(ip: Ipv4Addr) -> Ipv4Net {
    Ipv4Net::new(ip, 24)
        .expect("24 is a valid IPv4 prefix length")
        .trunc()
}

pub fn should_short_circuit(results: &[CheckResult], fail_fast: bool) -> bool {
    fail_fast
        && results
            .iter()
            .any(|result| result.severity() == Severity::Fail)
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

fn reputation_results(
    reputation: Result<ReputationFacts, impl std::fmt::Display>,
) -> Vec<CheckResult> {
    let (flags, operator) = reputation.map_or_else(
        |error| {
            let detail = error.to_string();
            (Verdict::error(detail.clone()), Verdict::error(detail))
        },
        |facts| {
            (
                judge_reputation(
                    &facts,
                    RiskScore::new(50).expect("50 is a valid risk score"),
                ),
                judge_reputation_operator(&facts),
            )
        },
    );
    vec![
        CheckResult::new("reputation", flags),
        CheckResult::new("reputation:operator", operator),
    ]
}

fn rkn_registry_verdict(
    registry: Result<RknRegistry, RknRegistryError>,
    ip: Ipv4Addr,
) -> Verdict {
    match registry {
        Ok(registry) => registry.check(ip).map_or_else(
            |error| Verdict::error(error.to_string()),
            |facts| judge_rkn_registry(&facts),
        ),
        Err(error) => Verdict::error(error.to_string()),
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
    let profile = command.profile();
    let geo = async {
        match profile.scope("geo") {
            GateScope::Judged => {
                let verdict = geo_client.consensus(ip).await.map_or_else(
                    |error| {
                        Verdict::error(format!("GeoIP task failed: {error}"))
                    },
                    |facts| judge_geo(&facts, command.country()),
                );
                CheckResult::new("geo", verdict)
            }
            GateScope::Skipped(reason) => CheckResult::skipped("geo", reason),
        }
    };

    let (reputation, block_lists, registry, geo, provenance) = tokio::join!(
        reputation_client.lookup(ip),
        block_lists_client.fetch(),
        registry_client.fetch(),
        geo,
        ripestat_client.routing_status(ip)
    );

    let mut results = reputation_results(reputation);
    results.extend([
        CheckResult::new(
            "blocklists",
            judge_blocklists(&block_lists.check(ip)),
        ),
        CheckResult::new("rkn-registry", rkn_registry_verdict(registry, ip)),
        CheckResult::new(
            "provenance",
            provenance.map_or_else(
                |error| Verdict::error(error.to_string()),
                |routing| judge_routing(&routing),
            ),
        ),
        geo,
    ]);
    results
}

fn manual_anchor(ip: Ipv4Addr, country: CountryCode) -> Anchor {
    Anchor {
        fqdn: "manual".to_string(),
        ip_v4: ip,
        city: String::new(),
        country,
        as_v4: 0,
    }
}

async fn anchor_measurements(
    client: &GlobalpingClient,
    first_measurement_id: &MeasurementId,
    anchors: &[Anchor],
) -> Result<
    Vec<(String, chip_io::globalping::RawMeasurement)>,
    tokio::task::JoinError,
> {
    let client = Arc::new(client.clone());
    let mut tasks = tokio::task::JoinSet::new();
    for anchor in anchors {
        let client = Arc::clone(&client);
        let sample = first_measurement_id.clone();
        let label = anchor.fqdn.clone();
        let target = anchor.ip_v4;
        tasks.spawn(async move {
            let id = client
                .create(
                    &MeasurementKind::ping(target),
                    &Locations::reuse(sample),
                )
                .await
                .ok()?;
            let measurement = client
                .poll_until_finished(&id, GLOBALPING_DEADLINE)
                .await
                .ok()?;
            Some((label, measurement))
        });
    }
    let mut measurements = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Some(measurement) = result? {
            measurements.push(measurement);
        }
    }
    measurements.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(measurements)
}

async fn reach_measurement(
    client: &GlobalpingClient,
    first_measurement_id: &MeasurementId,
    candidate: Ipv4Addr,
    candidate_port: u16,
    control: Option<&Anchor>,
) -> CheckResult {
    let Some(control) = control else {
        return CheckResult::new(
            "reach",
            Verdict::error("no HTTPS control anchor available"),
        );
    };
    let locations = Locations::reuse(first_measurement_id.clone());
    let Some(candidate_port) = NonZeroU16::new(candidate_port) else {
        return CheckResult::new(
            "reach",
            Verdict::error("candidate listener port cannot be zero"),
        );
    };
    let candidate_kind = MeasurementKind::https(candidate, candidate_port);
    let control_kind = MeasurementKind::https(
        control.ip_v4,
        NonZeroU16::new(443).expect("443 is non-zero"),
    );
    let (candidate_id, control_id) = tokio::join!(
        client.create(&candidate_kind, &locations),
        client.create(&control_kind, &locations)
    );
    let (candidate_id, control_id) = match (candidate_id, control_id) {
        (Ok(candidate_id), Ok(control_id)) => (candidate_id, control_id),
        (Err(error), _) | (_, Err(error)) => {
            return CheckResult::new(
                "reach",
                Verdict::error(error.to_string()),
            );
        }
    };
    let (candidate, control) = tokio::join!(
        client.poll_until_finished(&candidate_id, GLOBALPING_DEADLINE),
        client.poll_until_finished(&control_id, GLOBALPING_DEADLINE)
    );
    match (candidate, control) {
        (Ok(candidate), Ok(control)) => CheckResult::new(
            "reach",
            judge_reach(&reach_facts(&candidate, &control)),
        ),
        (Err(error), _) | (_, Err(error)) => {
            CheckResult::new("reach", Verdict::error(error.to_string()))
        }
    }
}

async fn latency_results(
    client: &GlobalpingClient,
    command: &ScanCommand,
    candidate_id: &MeasurementId,
    candidate: &chip_io::globalping::RawMeasurement,
    city_anchors: &[Anchor],
) -> Vec<CheckResult> {
    if !command.profile().judges("latency") {
        return command.profile().skipped(["latency"]);
    }
    let anchors =
        match anchor_measurements(client, candidate_id, city_anchors).await {
            Ok(anchors) => anchors,
            Err(error) => {
                return vec![CheckResult::new(
                    "latency",
                    Verdict::error(format!("anchor task failed: {error}")),
                )];
            }
        };
    let latency = ping_sweep_facts(candidate, &anchors).map_or_else(
        |error| Verdict::error(error.to_string()),
        |facts: PingSweepFacts| {
            judge_latency(&facts, command.latency_thresholds())
        },
    );
    vec![CheckResult::new("latency", latency)]
}

async fn run_globalping_measurements(
    client: &GlobalpingClient,
    command: &ScanCommand,
    city_anchors: &[Anchor],
    listener: Option<u16>,
    control_anchor: Option<&Anchor>,
    progress: &ScanProgress,
) -> Vec<CheckResult> {
    // Without a listener the candidate ping would only feed the latency gate.
    if listener.is_none() && !command.profile().judges("latency") {
        return command.profile().skipped(["latency"]);
    }
    let probes = command.probes();
    let locations = match Locations::ru(probes.eyeball(), probes.datacenter()) {
        Ok(locations) => locations,
        Err(error) => return unavailable_globalping_results(&error, listener),
    };
    let candidate_id = match client
        .create(&MeasurementKind::ping(command.ip()), &locations)
        .await
    {
        Ok(id) => id,
        Err(error) => return unavailable_globalping_results(&error, listener),
    };
    let candidate = match client
        .poll_until_finished(&candidate_id, GLOBALPING_DEADLINE)
        .await
    {
        Ok(measurement) => measurement,
        Err(error) => return unavailable_globalping_results(&error, listener),
    };
    progress
        .record(latency_results(
            client,
            command,
            &candidate_id,
            &candidate,
            city_anchors,
        ))
        .await;
    if let Some(port) = listener {
        progress.add([reach_measurement(
            client,
            &candidate_id,
            command.ip(),
            port,
            control_anchor,
        )
        .await]);
    }
    Vec::new()
}

fn unavailable_globalping_results(
    error: &impl ToString,
    listener: Option<u16>,
) -> Vec<CheckResult> {
    let detail = error.to_string();
    let mut results =
        vec![CheckResult::new("latency", Verdict::error(detail.clone()))];
    if listener.is_some() {
        results.push(CheckResult::new("reach", Verdict::error(detail)));
    }
    results
}

async fn verify_listener(ip: Ipv4Addr, port: u16) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| error.to_string())?;
    client
        .get(format!("https://{ip}:{port}/"))
        .send()
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Every gate that can only be judged through the SOCKS tunnel, so they are
/// reported together whether they ran, were skipped, or could not run.
const TUNNEL_GATES: [&str; 16] = [
    "service:chatgpt_web",
    "service:chatgpt_app",
    "service:gemini",
    "service:youtube_premium",
    "service:netflix",
    "service:claude",
    "service:tiktok",
    "service:notebooklm",
    "tampering",
    "service-geo",
    "service-geo:captcha",
    "service-geo:cdn",
    "ai:openai",
    "ai:anthropic",
    "ai:gemini",
    "ai:deepseek",
];

const NEIGHBOR_GATES: [&str; 2] = ["neighbors-ptr", "neighbors"];

fn tunnel_results(verdict: &Verdict) -> Vec<CheckResult> {
    TUNNEL_GATES
        .into_iter()
        .map(|gate| CheckResult::new(gate, verdict.clone()))
        .collect()
}

async fn record_service(
    progress: &ScanProgress,
    name: &str,
    work: impl std::future::Future<Output = ServiceState>,
    judge: fn(&[(&str, ServiceState)]) -> Verdict,
) {
    let state = work.await;
    progress.add([CheckResult::new(
        format!("service:{name}"),
        judge(&[(name, state)]),
    )]);
}

async fn record_portal(client: &TunnelClient, progress: &ScanProgress) {
    let verdict = probe_portal_endpoints(client).await.map_or_else(
        |error| Verdict::error(format!("portal task failed: {error}")),
        |(https, http)| judge_tampering(&https, &http),
    );
    progress.add([CheckResult::new("tampering", verdict)]);
}

async fn run_tunnel_checks(
    client: &TunnelClient,
    expected_country: &CountryCode,
    profile: ScanProfile,
    progress: &ScanProgress,
) {
    if profile == ScanProfile::RuBridge {
        progress.add(profile.skipped(TUNNEL_GATES));
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
            "chatgpt_web",
            probe_chatgpt_web(client),
            judge_services_fail
        ),
        record_service(
            progress,
            "chatgpt_app",
            probe_chatgpt_app(client),
            judge_services_fail
        ),
        record_service(
            progress,
            "gemini",
            probe_gemini(client),
            judge_services_fail
        ),
        record_service(
            progress,
            "youtube_premium",
            probe_youtube_premium(client),
            judge_services_fail
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
            "netflix",
            probe_netflix(client),
            judge_services_warn
        ),
        record_service(
            progress,
            "claude",
            probe_claude(client),
            judge_services_warn
        ),
        record_service(
            progress,
            "tiktok",
            probe_tiktok(client),
            judge_services_warn
        ),
        record_service(
            progress,
            "notebooklm",
            probe_notebooklm(client),
            judge_services_warn
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
            let votes = probe_country_votes(client).await;
            progress.add([CheckResult::new(
                "service-geo",
                judge_service_country(&votes, country, SERVICE_COUNTRY_FAIL_ON),
            )]);
        },
        async {
            let (google, bing) = probe_search_captcha(client).await;
            progress.add([CheckResult::new(
                "service-geo:captcha",
                judge_search_captcha(&google, &bing),
            )]);
        },
        async {
            let edges = probe_cdn_edges(client).await;
            progress.add([CheckResult::new(
                "service-geo:cdn",
                judge_cdn_edge(&edges),
            )]);
        },
        async {
            let states = probe_ai_endpoints(client).await;
            progress.add(states.into_iter().map(|(name, state)| {
                CheckResult::new(
                    format!("ai:{name}"),
                    judge_ai_endpoints(&[(name, state)]),
                )
            }));
        },
    );
}

fn select_anchors(
    command: &ScanCommand,
    anchors: &[Anchor],
) -> (Vec<Anchor>, Vec<Anchor>) {
    let city = command
        .city()
        .map_or_else(Vec::new, |city| select_for_city(anchors, city, 3));
    let city = if city.is_empty() {
        select_for_country(anchors, command.country(), 3)
    } else {
        city
    };
    let city = command
        .anchor()
        .map_or(city, |ip| vec![manual_anchor(ip, *command.country())]);
    let reference = select_for_city(anchors, command.reference_city(), 2);
    (city, reference)
}

async fn start_listener(
    session: &SshSession,
    ip: Ipv4Addr,
) -> (Option<u16>, Vec<CheckResult>) {
    let mut results = Vec::new();
    for port in [443, 8443] {
        match session.start_listener(port).await {
            Ok(ListenerOutcome::Listening) => {
                match verify_listener(ip, port).await {
                    Ok(()) => return (Some(port), results),
                    Err(error) => {
                        let _ = session.stop_listener(port).await;
                        let verdict = Verdict::error(format!(
                            "temporary TLS listener is not reachable from the runner: {error}"
                        ));
                        results.push(CheckResult::new("reach", verdict));
                        return (None, results);
                    }
                }
            }
            Ok(ListenerOutcome::PortInUse) => {}
            Ok(ListenerOutcome::Failed(detail)) => {
                results.push(CheckResult::new(
                    "reach",
                    Verdict::error(format!("listener failed: {detail}")),
                ));
                return (None, results);
            }
            Err(error) => {
                results.push(CheckResult::new("reach", ssh_failure(error)));
                return (None, results);
            }
        }
    }
    results.push(CheckResult::new(
        "reach",
        Verdict::error("candidate ports 443 and 8443 are already in use"),
    ));
    (None, results)
}

struct GlobalpingSources {
    client: GlobalpingClient,
    city_anchors: Vec<Anchor>,
    reference_anchors: Vec<Anchor>,
}

struct GlobalpingSetupError {
    gate: &'static str,
    detail: String,
}

struct SshSetup {
    session: Option<SshSession>,
    config: SshConfig,
    listener_port: Option<u16>,
}

impl SshSetup {
    const fn disconnected(config: SshConfig) -> Self {
        Self {
            session: None,
            config,
            listener_port: None,
        }
    }

    async fn stop_listener(&self) -> Option<CheckResult> {
        let session = self.session.as_ref()?;
        let port = session.listener_port()?;
        match session.stop_listener(port).await {
            Ok(()) => {
                tracing::debug!(port, "temporary listener stopped");
                None
            }
            Err(error) => {
                tracing::warn!(port, error = %error, "temporary listener cleanup failed");
                Some(CheckResult::new("listener-cleanup", ssh_failure(error)))
            }
        }
    }
}

fn skipped_ssh_results() -> Vec<CheckResult> {
    const REASON: &str = "--no-ssh: nothing was measured from the candidate";
    std::iter::once("reach")
        .chain(TUNNEL_GATES)
        .chain(std::iter::once("steal"))
        .map(|gate| CheckResult::skipped(gate, REASON))
        .collect()
}

fn ssh_failure(error: chip_io::ssh::SshError) -> Verdict {
    // Formatting belongs to the CLI boundary; the adapter retains typed causes.
    Verdict::error(format!("{:#}", anyhow::Error::new(error)))
}

fn unavailable_ssh_results(error: chip_io::ssh::SshError) -> Vec<CheckResult> {
    let detail = format!("SSH unavailable: {:#}", anyhow::Error::new(error));
    let mut results =
        vec![CheckResult::new("ssh", Verdict::error(detail.clone()))];
    results.push(CheckResult::new("reach", Verdict::error(detail.clone())));
    results.extend(tunnel_results(&Verdict::error(detail)));
    results.push(CheckResult::new("steal", Verdict::error("SSH unavailable")));
    results
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
                gate: "globalping-quota",
                detail: format!(
                    "only {} Globalping tests remain; need approximately {}",
                    limits.remaining,
                    globalping_budget(probes.eyeball(), probes.datacenter())
                ),
            });
        }
        Err(error) => {
            return Err(GlobalpingSetupError {
                gate: "globalping-quota",
                detail: format!("could not read Globalping quota: {error}"),
            });
        }
        Ok(_) => {}
    }

    let anchors =
        AnchorClient::new(http.clone())
            .anchors()
            .await
            .map_err(|error| GlobalpingSetupError {
                gate: "latency",
                detail: format!("could not load RIPE Atlas anchors: {error}"),
            })?;
    let (city_anchors, reference_anchors) = select_anchors(command, &anchors);
    Ok(GlobalpingSources {
        client: globalping,
        city_anchors,
        reference_anchors,
    })
}

fn ssh_config(command: &ScanCommand) -> SshConfig {
    SshConfig {
        user: Some(command.ssh_user().to_owned()),
        port: command.ssh_port(),
        private_key: command.ssh_private_key().cloned(),
        known_hosts: command.ssh_known_hosts().map(str::to_owned),
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
) -> Vec<CheckResult> {
    if !command.ssh_enabled() {
        return Vec::new();
    }
    let session = match SshSession::connect(command.ip(), &setup.config).await {
        Ok(session) => session,
        Err(error) => return unavailable_ssh_results(error),
    };
    // Store the owner before any remote listener can be created. The session
    // records a pending port before starting the mutating remote command.
    let session = setup.session.insert(session);
    let (listener_port, results) = start_listener(session, command.ip()).await;
    setup.listener_port = listener_port;
    results
}

async fn run_globalping_branch(
    sources: Result<GlobalpingSources, GlobalpingSetupError>,
    command: &ScanCommand,
    listener_port: Option<u16>,
    progress: &ScanProgress,
) -> Vec<CheckResult> {
    match sources {
        Ok(sources) => {
            run_globalping_measurements(
                &sources.client,
                command,
                &sources.city_anchors,
                listener_port,
                sources.reference_anchors.first(),
                progress,
            )
            .await
        }
        Err(error) => {
            let mut results = vec![CheckResult::new(
                error.gate,
                Verdict::error(error.detail.clone()),
            )];
            if error.gate != "latency" {
                results.push(CheckResult::new(
                    "latency",
                    Verdict::error(error.detail.clone()),
                ));
            }
            if listener_port.is_some() {
                results.push(CheckResult::new(
                    "reach",
                    Verdict::error(error.detail),
                ));
            }
            results
        }
    }
}

async fn run_socks_checks(
    command: &ScanCommand,
    setup: &SshSetup,
    progress: &ScanProgress,
) -> Vec<CheckResult> {
    let Some(_session) = &setup.session else {
        return Vec::new();
    };
    let port = match pick_free_port() {
        Ok(port) => port,
        Err(error) => {
            return tunnel_results(&Verdict::error(format!(
                "could not reserve a local SOCKS port: {error}"
            )));
        }
    };
    let tunnel =
        match SocksTunnel::start(command.ip(), &setup.config, port).await {
            Ok(tunnel) => tunnel,
            Err(error) => {
                return tunnel_results(&ssh_failure(error));
            }
        };
    let results = match TunnelClient::new(tunnel.local_addr(), REQUEST_TIMEOUT)
    {
        Ok(client) => {
            Box::pin(run_tunnel_checks(
                &client,
                command.country(),
                command.profile(),
                progress,
            ))
            .await;
            Vec::new()
        }
        Err(error) => tunnel_results(&Verdict::error(error.to_string())),
    };
    tunnel.stop().await;
    results
}

async fn run_steal_check(session: &SshSession) -> CheckResult {
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
    CheckResult::new("steal", verdict)
}

async fn run_ssh_checks(
    command: &ScanCommand,
    setup: &SshSetup,
    progress: &ScanProgress,
) -> Vec<CheckResult> {
    let Some(session) = &setup.session else {
        return Vec::new();
    };
    tokio::join!(
        progress.record(run_socks_checks(command, setup, progress)),
        async {
            progress.add([run_steal_check(session).await]);
        }
    );
    Vec::new()
}

#[tracing::instrument(
    name = "scan.neighbors",
    level = "debug",
    skip_all,
    fields(candidate_ip = %command.ip())
)]
async fn run_neighbor_checks(command: &ScanCommand) -> Vec<CheckResult> {
    if !command.neighbors_enabled() {
        return Vec::new();
    }
    let ip = command.ip();
    let probes = match sweep(network_24(ip), &SweepConfig::default()).await {
        Ok(probes) => probes,
        Err(error) => {
            return NEIGHBOR_GATES
                .into_iter()
                .map(|gate| {
                    CheckResult::new(
                        gate,
                        Verdict::error(format!(
                            "neighbor task failed: {error}"
                        )),
                    )
                })
                .collect();
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
    vec![
        CheckResult::new(
            NEIGHBOR_GATES[0],
            judge_candidate_ptr(&candidate_ptr),
        ),
        CheckResult::new(NEIGHBOR_GATES[1], judge_neighbor_extremes(&probes)),
    ]
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
    if !command.ssh_enabled() {
        progress.add(skipped_ssh_results());
    }
    if !command.neighbors_enabled() {
        progress.add(NEIGHBOR_GATES.into_iter().map(|gate| {
            CheckResult::skipped(gate, "--no-neighbors: the /24 was not swept")
        }));
    }
    let mut ssh = SshSetup::disconnected(ssh_config(command));
    let work = async {
        let (sources, ()) = tokio::join!(
            prepare_globalping(command, http),
            progress.record(prepare_ssh(command, &mut ssh)),
        );
        tokio::join!(
            progress.record(run_globalping_branch(
                sources,
                command,
                ssh.listener_port,
                &progress
            )),
            progress.record(run_ssh_checks(command, &ssh, &progress)),
            progress.record(run_neighbor_checks(command)),
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
                    "http-client",
                    Verdict::error(error.to_string()),
                )],
            };
        }
    };
    let mut results = apply_rules(
        command.profile(),
        command.gate_overrides(),
        run_phase_a(command, &http).await,
    );
    if !should_short_circuit(&results, command.fail_fast()) {
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
    use super::*;

    #[test]
    fn network_24_normalizes_the_host_part() {
        assert_eq!(
            network_24(Ipv4Addr::new(203, 0, 113, 42)).to_string(),
            "203.0.113.0/24"
        );
    }

    #[rstest::rstest]
    #[case::fail_fast_on_fail(Verdict::fail("wrong country"), true, true)]
    #[case::error_is_not_fail(Verdict::error("unavailable"), true, false)]
    #[case::fail_fast_disabled(Verdict::fail("wrong country"), false, false)]
    fn fail_fast_obeys_the_verdict_and_opt_out(
        #[case] verdict: Verdict,
        #[case] fail_fast: bool,
        #[case] expected: bool,
    ) {
        let sut = [CheckResult::new("geo", verdict)];

        let actual = should_short_circuit(&sut, fail_fast);

        assert_eq!(actual, expected);
    }

    #[test]
    fn no_ssh_reports_its_gates_as_skipped_rather_than_as_passing() {
        let sut = Report {
            results: skipped_ssh_results(),
        };

        let table = sut.table();

        assert_eq!(sut.exit_code(), 0);
        assert_eq!(sut.results.len(), TUNNEL_GATES.len() + 2);
        assert!(sut.results.iter().all(CheckResult::is_skipped), "{table}");
        assert!(!table.contains("OK "), "{table}");
    }

    #[test]
    fn a_bridge_reports_every_tunnel_gate_but_tampering_as_skipped() {
        let sut = ScanProfile::RuBridge;

        let skipped = sut.skipped(TUNNEL_GATES);

        let gates: Vec<_> =
            skipped.iter().map(|result| result.gate.as_str()).collect();
        let expected: Vec<_> = TUNNEL_GATES
            .into_iter()
            .filter(|&gate| gate != "tampering")
            .collect();
        assert_eq!(gates, expected);
    }

    #[test]
    fn globalping_budget_matches_the_documented_full_scan() {
        assert_eq!(globalping_budget(8, 4), 84);
    }

    #[tokio::test]
    async fn deadline_keeps_completed_failures_and_marks_only_missing_gates() {
        let progress = ScanProgress::default();
        let work = async {
            tokio::join!(
                progress.record(async {
                    vec![CheckResult::new("reach", Verdict::fail("blocked"))]
                }),
                std::future::pending::<()>(),
            );
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(1), work)
                .await
                .is_err()
        );
        progress.deadline(Duration::from_secs(1));
        let report = Report {
            results: progress.finish(),
        };

        assert_eq!(report.exit_code(), 1);
        let reach: Vec<_> = report
            .results
            .iter()
            .filter(|result| result.gate == "reach")
            .collect();
        assert_eq!(reach.len(), 1);
        assert_eq!(reach[0].severity(), Severity::Fail);
        assert!(report.results.iter().any(|result| result.gate == "latency"
            && result.severity() == Severity::Error));
    }
    #[rstest::rstest]
    #[case::skipped_failure(Verdict::fail("blocked"), true, false)]
    #[case::escalated_warning(Verdict::warn("suspicious"), false, true)]
    fn fail_fast_uses_the_same_rules_as_the_final_report(
        #[case] verdict: Verdict,
        #[case] skip: bool,
        #[case] expected_stop: bool,
    ) {
        let mut overrides = chip_core::GateOverrides::default();
        if skip {
            overrides.skip.insert("reputation".into());
        } else {
            overrides.escalate.insert("reputation".into());
        }
        let results = apply_rules(
            ScanProfile::Exit,
            &overrides,
            vec![CheckResult::new("reputation", verdict)],
        );
        assert_eq!(should_short_circuit(&results, true), expected_stop);
        let report = Report { results };
        assert_eq!(report.exit_code() == 1, expected_stop);
    }
}
