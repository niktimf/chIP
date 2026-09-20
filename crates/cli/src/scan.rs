use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use chip_core::model::PingSweepFacts;
use chip_core::model::RiskScore;
use chip_core::verdict::ai::judge_ai_endpoints;
use chip_core::verdict::blocklists::judge_blocklists;
use chip_core::verdict::geo::judge_geo;
use chip_core::verdict::latency::{LatencyThresholds, judge_latency};
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

use crate::config::ScanArgs;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const GLOBALPING_DEADLINE: Duration = Duration::from_secs(90);
const SERVICE_COUNTRY_FAIL_ON: &[&str] = &["google", "youtube"];

pub fn network_24(ip: Ipv4Addr) -> Ipv4Net {
    Ipv4Net::new(ip, 24)
        .expect("24 is a valid IPv4 prefix length")
        .trunc()
}

pub fn should_short_circuit(
    results: &[CheckResult],
    no_fail_fast: bool,
) -> bool {
    !no_fail_fast
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

pub async fn run_phase_a(
    args: &ScanArgs,
    http: &reqwest::Client,
) -> Vec<CheckResult> {
    let ip = args.ip.as_ipv4();
    let reputation_client =
        ProxycheckClient::new(http.clone(), args.proxycheck_api_key.clone());
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
        CheckResult::new("geo", judge_geo(&geo, &args.country)),
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
    args: &ScanArgs,
    city_anchors: &[Anchor],
    listener: Option<u16>,
    control_anchor: Option<&Anchor>,
) -> Vec<CheckResult> {
    fn unavailable(
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

    let locations = match Locations::ru(args.eyeball_probes, args.dc_probes) {
        Ok(locations) => locations,
        Err(error) => return unavailable(&error, listener),
    };
    let candidate_id = match client
        .create(&MeasurementKind::ping(args.ip.as_ipv4()), &locations)
        .await
    {
        Ok(id) => id,
        Err(error) => return unavailable(&error, listener),
    };
    let candidate = match client
        .poll_until_finished(&candidate_id, GLOBALPING_DEADLINE)
        .await
    {
        Ok(measurement) => measurement,
        Err(error) => return unavailable(&error, listener),
    };
    let anchors =
        anchor_measurements(client, &candidate_id, city_anchors).await;
    let latency = LatencyThresholds::new(args.max_excess_ms, args.max_loss_pct)
        .map_or_else(
            |error| Verdict::error(error.to_string()),
            |thresholds| {
                ping_sweep_facts(&candidate, &anchors).map_or_else(
                    |error| Verdict::error(error.to_string()),
                    |facts: PingSweepFacts| judge_latency(&facts, &thresholds),
                )
            },
        );
    let mut results = vec![CheckResult::new("latency", latency)];
    if let Some(port) = listener {
        results.push(
            reach_measurement(
                client,
                &candidate_id,
                args.ip.as_ipv4(),
                port,
                control_anchor,
            )
            .await,
        );
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

async fn run_tunnel_checks(
    client: &TunnelClient,
    expected_country: &CountryCode,
) -> Vec<CheckResult> {
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

    let mut results = Vec::new();
    for (name, state) in [
        ("chatgpt_web", chatgpt_web),
        ("chatgpt_app", chatgpt_app),
        ("gemini", gemini),
        ("youtube_premium", youtube_premium),
    ] {
        results.push(CheckResult::new(
            format!("service:{name}"),
            judge_services_fail(&[(name, state)]),
        ));
    }
    for (name, state) in [
        ("netflix", netflix),
        ("claude", claude),
        ("tiktok", tiktok),
        ("notebooklm", notebooklm),
    ] {
        results.push(CheckResult::new(
            format!("service:{name}"),
            judge_services_warn(&[(name, state)]),
        ));
    }
    results.push(CheckResult::new(
        "tampering",
        judge_tampering(&portal.0, &portal.1),
    ));
    results.push(CheckResult::new(
        "service-geo",
        judge_service_country(
            &votes,
            expected_country,
            SERVICE_COUNTRY_FAIL_ON,
        ),
    ));
    results.push(CheckResult::new(
        "service-geo:captcha",
        judge_search_captcha(&captcha.0, &captcha.1),
    ));
    results.push(CheckResult::new("service-geo:cdn", judge_cdn_edge(&edges)));
    for (name, state) in ai {
        results.push(CheckResult::new(
            format!("ai:{name}"),
            judge_ai_endpoints(&[(name, state)]),
        ));
    }
    results
}

fn select_anchors(
    args: &ScanArgs,
    anchors: &[Anchor],
) -> (Vec<Anchor>, Vec<Anchor>) {
    let city = args
        .city
        .as_ref()
        .map_or_else(Vec::new, |city| select_for_city(anchors, city, 3));
    let city = if city.is_empty() {
        select_for_country(anchors, &args.country, 3)
    } else {
        city
    };
    let city = args
        .anchor
        .map_or(city, |ip| vec![manual_anchor(ip, args.country)]);
    let reference = select_for_city(anchors, &args.reference_city, 2);
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

async fn prepare_globalping(
    args: &ScanArgs,
    http: &reqwest::Client,
) -> Result<GlobalpingSources, GlobalpingSetupError> {
    let globalping =
        GlobalpingClient::new(http.clone(), args.globalping_token.clone());
    match globalping.limits().await {
        Ok(limits)
            if limits.remaining
                < globalping_budget(args.eyeball_probes, args.dc_probes) =>
        {
            return Err(GlobalpingSetupError {
                gate: "globalping-quota",
                detail: format!(
                    "only {} Globalping tests remain; need approximately {}",
                    limits.remaining,
                    globalping_budget(args.eyeball_probes, args.dc_probes)
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
    let (city_anchors, reference_anchors) = select_anchors(args, &anchors);
    Ok(GlobalpingSources {
        client: globalping,
        city_anchors,
        reference_anchors,
    })
}

fn ssh_config(args: &ScanArgs) -> SshConfig {
    SshConfig {
        user: Some(args.ssh_user.clone()),
        port: args.ssh_port,
        private_key: args.ssh_private_key.clone(),
        known_hosts: args.ssh_known_hosts.clone(),
        connect_timeout: Duration::from_secs(15),
        command_timeout: Duration::from_secs(20),
    }
}

async fn prepare_ssh(args: &ScanArgs) -> (SshSetup, Vec<CheckResult>) {
    let config = ssh_config(args);
    let ip = args.ip.as_ipv4();
    let mut results = Vec::new();
    if args.no_ssh {
        results.push(CheckResult::new(
            "reach",
            Verdict::ok("skipped by --no-ssh"),
        ));
        results.extend(tunnel_results(&Verdict::ok("skipped by --no-ssh")));
        results.push(CheckResult::new(
            "steal",
            Verdict::ok("skipped by --no-ssh"),
        ));
        return (
            SshSetup {
                session: None,
                config,
                listener_port: None,
            },
            results,
        );
    }

    let session = match SshSession::connect(ip, &config).await {
        Ok(session) => session,
        Err(error) => {
            let detail = format!("SSH unavailable: {error}");
            results
                .push(CheckResult::new("ssh", Verdict::error(detail.clone())));
            results.push(CheckResult::new(
                "reach",
                Verdict::error(detail.clone()),
            ));
            results.extend(tunnel_results(&Verdict::error(detail)));
            results.push(CheckResult::new(
                "steal",
                Verdict::error("SSH unavailable"),
            ));
            return (
                SshSetup {
                    session: None,
                    config,
                    listener_port: None,
                },
                results,
            );
        }
    };
    let (listener_port, listener_results) = start_listener(&session, ip).await;
    results.extend(listener_results);
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
    args: &ScanArgs,
    listener_port: Option<u16>,
) -> Vec<CheckResult> {
    match sources {
        Ok(sources) => {
            run_globalping_measurements(
                &sources.client,
                args,
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
    args: &ScanArgs,
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
    let tunnel = match SocksTunnel::start(
        args.ip.as_ipv4(),
        &setup.config,
        port,
    )
    .await
    {
        Ok(tunnel) => tunnel,
        Err(error) => {
            return tunnel_results(&Verdict::error(format!(
                "SOCKS tunnel failed: {error}"
            )));
        }
    };
    let results = match TunnelClient::new(tunnel.local_addr(), REQUEST_TIMEOUT)
    {
        Ok(client) => Box::pin(run_tunnel_checks(&client, &args.country)).await,
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

async fn run_ssh_checks(args: &ScanArgs, setup: &SshSetup) -> Vec<CheckResult> {
    let Some(session) = &setup.session else {
        return Vec::new();
    };
    let (mut results, steal) =
        tokio::join!(run_socks_checks(args, setup), run_steal_check(session));
    results.push(steal);
    if let Some(port) = setup.listener_port {
        if let Err(error) = session.stop_listener(port).await {
            results.push(CheckResult::new(
                "listener-cleanup",
                Verdict::error(error.to_string()),
            ));
        }
    }
    results
}

async fn run_neighbor_checks(args: &ScanArgs) -> Vec<CheckResult> {
    if args.no_neighbors {
        return Vec::new();
    }
    let ip = args.ip.as_ipv4();
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

async fn run_phase_b_inner(
    args: &ScanArgs,
    http: &reqwest::Client,
) -> Vec<CheckResult> {
    let (sources, (ssh, mut results)) =
        tokio::join!(prepare_globalping(args, http), prepare_ssh(args));
    let (globalping, ssh_checks, neighbors) = tokio::join!(
        run_globalping_branch(sources, args, ssh.listener_port),
        run_ssh_checks(args, &ssh),
        run_neighbor_checks(args),
    );
    results.extend(globalping);
    results.extend(ssh_checks);
    results.extend(neighbors);
    results
}

pub async fn run_phase_b(
    args: &ScanArgs,
    http: &reqwest::Client,
) -> Vec<CheckResult> {
    Box::pin(tokio::time::timeout(
        Duration::from_secs(args.deadline_secs.get()),
        run_phase_b_inner(args, http),
    ))
    .await
    .unwrap_or_else(|_| {
        vec![CheckResult::new(
            "scan-deadline",
            Verdict::error(format!(
                "phase B exceeded the {}s overall deadline",
                args.deadline_secs
            )),
        )]
    })
}

pub async fn run_scan(args: &ScanArgs) -> Report {
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
    let mut results = run_phase_a(args, &http).await;
    if !should_short_circuit(&results, args.no_fail_fast) {
        results.extend(run_phase_b(args, &http).await);
    }
    let overrides = args.gate_overrides();
    Report {
        results: results
            .into_iter()
            .map(|result| overrides.apply(result))
            .collect(),
    }
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
    #[case::fail_fast_on_fail(Verdict::fail("wrong country"), false, true)]
    #[case::error_is_not_fail(Verdict::error("unavailable"), false, false)]
    #[case::fail_fast_disabled(Verdict::fail("wrong country"), true, false)]
    fn fail_fast_obeys_the_verdict_and_opt_out(
        #[case] verdict: Verdict,
        #[case] no_fail_fast: bool,
        #[case] expected: bool,
    ) {
        let results = [CheckResult::new("geo", verdict)];

        let actual = should_short_circuit(&results, no_fail_fast);

        assert_eq!(actual, expected);
    }

    #[test]
    fn globalping_budget_matches_the_documented_full_scan() {
        assert_eq!(globalping_budget(8, 4), 84);
    }
}
