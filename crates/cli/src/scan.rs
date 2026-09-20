use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use chip_core::model::{
    CaptchaObservation, PingSweepFacts, PortalOutcome, RiskScore,
    ServiceCountryVote, ServiceState,
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
use chip_core::verdict::reputation::judge_reputation;
use chip_core::verdict::service_geo::{
    judge_cdn_edge, judge_search_captcha, judge_service_country,
};
use chip_core::verdict::services::{judge_services_fail, judge_services_warn};
use chip_core::verdict::steal::{judge_steal, steal_pct};
use chip_core::verdict::tampering::judge_tampering;
use chip_core::{CheckResult, CountryCode, Report, Severity, Verdict};
use chip_io::atlas::{
    Anchor, AnchorClient, select_for_city, select_for_country,
};
use chip_io::blocklists::BlockLists;
use chip_io::geoip::GeoIpClient;
use chip_io::globalping::{
    GlobalpingClient, Locations, MeasurementId, MeasurementKind,
    ping_sweep_facts, reach_facts,
};
use chip_io::neighbors::{SweepConfig, sweep};
use chip_io::proxycheck::ProxycheckClient;
use chip_io::ripestat::RipestatClient;
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

pub fn network_24(ip: Ipv4Addr) -> Ipv4Net {
    Ipv4Net::new(ip, 24)
        .expect("24 is a valid IPv4 prefix length")
        .trunc()
}

pub fn should_short_circuit(results: &[CheckResult], fail_fast: bool) -> bool {
    fail_fast
        && results
            .iter()
            .any(|result| result.severity == Severity::Fail)
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
    let prefix = network_24(ip);

    let (reputation, blocklists, geo, provenance) = tokio::join!(
        reputation_client.lookup(ip),
        BlockLists::fetch(http),
        geo_client.consensus(ip),
        ripestat_client.routing_status(prefix)
    );

    vec![
        CheckResult::new(
            "reputation",
            reputation.map_or_else(
                |error| Verdict::error(error.to_string()),
                |facts| {
                    judge_reputation(
                        &facts,
                        RiskScore::new(50).expect("50 is a valid risk score"),
                    )
                },
            ),
        ),
        CheckResult::new("blocklists", judge_blocklists(&blocklists.check(ip))),
        CheckResult::new("geo", judge_geo(&geo, command.country())),
        CheckResult::new(
            "provenance",
            provenance.map_or_else(
                |error| Verdict::error(error.to_string()),
                |facts| judge_routing(&facts),
            ),
        ),
    ]
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
) -> Vec<(String, chip_io::globalping::RawMeasurement)> {
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
        if let Ok(Some(measurement)) = result {
            measurements.push(measurement);
        }
    }
    measurements.sort_by(|left, right| left.0.cmp(&right.0));
    measurements
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

async fn run_globalping_measurements(
    client: &GlobalpingClient,
    command: &ScanCommand,
    city_anchors: &[Anchor],
    listener: Option<u16>,
    control_anchor: Option<&Anchor>,
) -> Vec<CheckResult> {
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
    let anchors =
        anchor_measurements(client, &candidate_id, city_anchors).await;
    let latency = ping_sweep_facts(&candidate, &anchors).map_or_else(
        |error| Verdict::error(error.to_string()),
        |facts: PingSweepFacts| {
            judge_latency(&facts, command.latency_thresholds())
        },
    );
    let mut results = vec![CheckResult::new("latency", latency)];
    if let Some(port) = listener {
        results.push(
            reach_measurement(
                client,
                &candidate_id,
                command.ip(),
                port,
                control_anchor,
            )
            .await,
        );
    }
    results
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

fn tunnel_results(verdict: &Verdict) -> Vec<CheckResult> {
    [
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
    ]
    .into_iter()
    .map(|gate| CheckResult::new(gate, verdict.clone()))
    .collect()
}

type NamedServiceState = (&'static str, ServiceState);
type CdnEdgeObservation = (&'static str, Option<CountryCode>);

struct TunnelObservations {
    fail_services: [NamedServiceState; 4],
    warn_services: [NamedServiceState; 4],
    portal: (Vec<PortalOutcome>, Vec<PortalOutcome>),
    votes: Vec<ServiceCountryVote>,
    captcha: (CaptchaObservation, CaptchaObservation),
    edges: Vec<CdnEdgeObservation>,
    ai: Vec<NamedServiceState>,
}

impl TunnelObservations {
    async fn probe(client: &TunnelClient) -> Self {
        let (
            chatgpt_web,
            chatgpt_app,
            gemini,
            youtube_premium,
            netflix,
            claude,
            tiktok,
            notebooklm,
            portal,
            votes,
            captcha,
            edges,
            ai,
        ) = tokio::join!(
            probe_chatgpt_web(client),
            probe_chatgpt_app(client),
            probe_gemini(client),
            probe_youtube_premium(client),
            probe_netflix(client),
            probe_claude(client),
            probe_tiktok(client),
            probe_notebooklm(client),
            probe_portal_endpoints(client),
            probe_country_votes(client),
            probe_search_captcha(client),
            probe_cdn_edges(client),
            probe_ai_endpoints(client),
        );
        Self {
            fail_services: [
                ("chatgpt_web", chatgpt_web),
                ("chatgpt_app", chatgpt_app),
                ("gemini", gemini),
                ("youtube_premium", youtube_premium),
            ],
            warn_services: [
                ("netflix", netflix),
                ("claude", claude),
                ("tiktok", tiktok),
                ("notebooklm", notebooklm),
            ],
            portal,
            votes,
            captcha,
            edges,
            ai,
        }
    }

    fn into_results(self, expected_country: CountryCode) -> Vec<CheckResult> {
        let mut results =
            service_results(self.fail_services, judge_services_fail);
        results
            .extend(service_results(self.warn_services, judge_services_warn));
        results.push(CheckResult::new(
            "tampering",
            judge_tampering(&self.portal.0, &self.portal.1),
        ));
        results.push(CheckResult::new(
            "service-geo",
            judge_service_country(
                &self.votes,
                &expected_country,
                SERVICE_COUNTRY_FAIL_ON,
            ),
        ));
        results.push(CheckResult::new(
            "service-geo:captcha",
            judge_search_captcha(&self.captcha.0, &self.captcha.1),
        ));
        results.push(CheckResult::new(
            "service-geo:cdn",
            judge_cdn_edge(&self.edges),
        ));
        results.extend(self.ai.into_iter().map(|(name, state)| {
            CheckResult::new(
                format!("ai:{name}"),
                judge_ai_endpoints(&[(name, state)]),
            )
        }));
        results
    }
}

fn service_results<const N: usize>(
    states: [NamedServiceState; N],
    judge: fn(&[(&str, ServiceState)]) -> Verdict,
) -> Vec<CheckResult> {
    states
        .into_iter()
        .map(|(name, state)| {
            CheckResult::new(format!("service:{name}"), judge(&[(name, state)]))
        })
        .collect()
}

async fn run_tunnel_checks(
    client: &TunnelClient,
    expected_country: &CountryCode,
) -> Vec<CheckResult> {
    Box::pin(TunnelObservations::probe(client))
        .await
        .into_results(*expected_country)
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
                results.push(CheckResult::new(
                    "reach",
                    Verdict::error(error.to_string()),
                ));
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
        let port = self.listener_port?;
        let session = self.session.as_ref()?;
        match session.stop_listener(port).await {
            Ok(()) => {
                tracing::debug!(port, "temporary listener stopped");
                None
            }
            Err(error) => {
                tracing::warn!(port, error = %error, "temporary listener cleanup failed");
                Some(CheckResult::new(
                    "listener-cleanup",
                    Verdict::error(error.to_string()),
                ))
            }
        }
    }
}

fn skipped_ssh_results() -> Vec<CheckResult> {
    let mut results = vec![CheckResult::new(
        "reach",
        Verdict::ok("skipped by --no-ssh"),
    )];
    results.extend(tunnel_results(&Verdict::ok("skipped by --no-ssh")));
    results.push(CheckResult::new("steal", Verdict::ok("skipped by --no-ssh")));
    results
}

fn unavailable_ssh_results(error: &impl std::fmt::Display) -> Vec<CheckResult> {
    let detail = format!("SSH unavailable: {error}");
    let mut results =
        vec![CheckResult::new("ssh", Verdict::error(detail.clone()))];
    results.push(CheckResult::new("reach", Verdict::error(detail.clone())));
    results.extend(tunnel_results(&Verdict::error(detail)));
    results.push(CheckResult::new("steal", Verdict::error("SSH unavailable")));
    results
}

async fn run_until_deadline_then_cleanup<T, CleanupOutput>(
    deadline: tokio::time::Instant,
    work: impl std::future::Future<Output = T>,
    cleanup: impl std::future::Future<Output = CleanupOutput>,
) -> (Result<T, tokio::time::error::Elapsed>, CleanupOutput) {
    let outcome = tokio::time::timeout_at(deadline, work).await;
    let cleanup_output = cleanup.await;
    (outcome, cleanup_output)
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
async fn prepare_ssh(command: &ScanCommand) -> (SshSetup, Vec<CheckResult>) {
    let config = ssh_config(command);
    let ip = command.ip();
    if !command.ssh_enabled() {
        return (SshSetup::disconnected(config), skipped_ssh_results());
    }

    let session = match SshSession::connect(ip, &config).await {
        Ok(session) => session,
        Err(error) => {
            let results = unavailable_ssh_results(&error);
            return (SshSetup::disconnected(config), results);
        }
    };
    let (listener_port, results) = start_listener(&session, ip).await;
    (
        SshSetup {
            session: Some(session),
            config,
            listener_port,
        },
        results,
    )
}

async fn run_globalping_branch(
    sources: Result<GlobalpingSources, GlobalpingSetupError>,
    command: &ScanCommand,
    listener_port: Option<u16>,
) -> Vec<CheckResult> {
    match sources {
        Ok(sources) => {
            run_globalping_measurements(
                &sources.client,
                command,
                &sources.city_anchors,
                listener_port,
                sources.reference_anchors.first(),
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
                return tunnel_results(&Verdict::error(format!(
                    "SOCKS tunnel failed: {error}"
                )));
            }
        };
    let results = match TunnelClient::new(tunnel.local_addr(), REQUEST_TIMEOUT)
    {
        Ok(client) => {
            Box::pin(run_tunnel_checks(&client, command.country())).await
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
            session.steal_snapshot().await.map_or_else(
                |error| Verdict::error(error.to_string()),
                |after| judge_steal(steal_pct(&before, &after)),
            )
        }
        Err(error) => Verdict::error(error.to_string()),
    };
    CheckResult::new("steal", verdict)
}

async fn run_ssh_checks(
    command: &ScanCommand,
    setup: &SshSetup,
) -> Vec<CheckResult> {
    let Some(session) = &setup.session else {
        return Vec::new();
    };
    let (mut results, steal) = tokio::join!(
        run_socks_checks(command, setup),
        run_steal_check(session)
    );
    results.push(steal);
    results
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
    let probes = sweep(network_24(ip), &SweepConfig::default()).await;
    let candidate_ptr = probes.iter().find(|probe| probe.ip == ip).map_or_else(
        || {
            chip_core::model::PtrLookup::Unavailable(
                "candidate was not surveyed".to_string(),
            )
        },
        |probe| probe.ptr.clone(),
    );
    vec![
        CheckResult::new("neighbors-ptr", judge_candidate_ptr(&candidate_ptr)),
        CheckResult::new("neighbors", judge_neighbor_extremes(&probes)),
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
    // Preparation is individually bounded by the HTTP and SSH adapters. Keep
    // it outside the cancelling timeout so a listener cannot be created in a
    // future that is then dropped before its owner gets a chance to clean up.
    let (sources, (ssh, mut results)) =
        tokio::join!(prepare_globalping(command, http), prepare_ssh(command));
    let listener_port = ssh.listener_port;
    let checks = Box::pin(async {
        let (globalping, ssh_checks, neighbors) = tokio::join!(
            run_globalping_branch(sources, command, listener_port),
            run_ssh_checks(command, &ssh),
            run_neighbor_checks(command),
        );
        let mut checks = globalping;
        checks.extend(ssh_checks);
        checks.extend(neighbors);
        checks
    });
    let (outcome, cleanup_error) =
        run_until_deadline_then_cleanup(deadline, checks, ssh.stop_listener())
            .await;
    if let Ok(checks) = outcome {
        results.extend(checks);
    } else {
        tracing::warn!("phase B deadline exceeded");
        results.push(CheckResult::new(
            "scan-deadline",
            Verdict::error(format!(
                "phase B exceeded the {}s overall deadline",
                command.deadline().as_secs()
            )),
        ));
    }
    if let Some(cleanup_error) = cleanup_error {
        results.push(cleanup_error);
    }
    results
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
    let mut results = run_phase_a(command, &http).await;
    if !should_short_circuit(&results, command.fail_fast()) {
        results.extend(run_phase_b(command, &http).await);
    }
    let overrides = command.gate_overrides();
    let report = Report {
        results: results
            .into_iter()
            .map(|result| overrides.apply(result))
            .collect(),
    };
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
    fn globalping_budget_matches_the_documented_full_scan() {
        assert_eq!(globalping_budget(8, 4), 84);
    }

    #[tokio::test]
    async fn deadline_cancellation_still_runs_resource_cleanup() {
        let cleaned = std::cell::Cell::new(false);
        let work = std::future::pending::<()>();
        let cleanup = async { cleaned.set(true) };

        let (outcome, ()) = run_until_deadline_then_cleanup(
            tokio::time::Instant::now(),
            work,
            cleanup,
        )
        .await;

        assert!(outcome.is_err());
        assert!(cleaned.get());
    }
}
