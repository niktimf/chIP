//! The closed set of gate identities and the `--gate`/`--skip-gate`
//! overrides that key on them.
//!
//! Every gate a scan can report is one row of [`GATES`]. The row carries the
//! two facts the rest of the app keys on: through which channel the gate is
//! measured (which bulk SKIP/ERROR lists cover it) and whether a Russian
//! bridge judges it. Derived sets such as [`tunnel_gates`] are filters over
//! the table, so a new gate is added in exactly one place.

use crate::model::CheckResult;
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

/// A gate identifier (`"latency"`, `"service:gemini"`, `"ai:openai"`).
///
/// The set of gates is closed: the only ways to obtain a `GateId` are the
/// constants of this module and [`FromStr`], which rejects anything
/// [`GATES`] does not name. A typo in `--gate` is therefore a startup error
/// instead of an override that silently never matches, and a misspelled
/// gate in code does not compile because the constant does not exist.
/// `Ord` delegates to the inner `str` so `Report` can sort same-severity
/// rows by gate id for a stable table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GateId(&'static str);

impl GateId {
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// The registry row behind this id. Total: every `GateId` is a copy of
    /// an id in [`GATES`], so the lookup always finds its row.
    fn spec(self) -> &'static GateSpec {
        GATES
            .iter()
            .find(|spec| spec.id == self)
            .expect("every GateId is constructed from the GATES table")
    }

    pub fn channel(self) -> Channel {
        self.spec().channel
    }

    pub fn bridge(self) -> BridgePolicy {
        self.spec().bridge
    }
}

impl fmt::Display for GateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl PartialEq<str> for GateId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for GateId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{0}' is not a known gate id")]
pub struct UnknownGateId(String);

impl FromStr for GateId {
    type Err = UnknownGateId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        GATES
            .iter()
            .map(|spec| spec.id)
            .find(|id| id.as_str() == value)
            .ok_or_else(|| UnknownGateId(value.to_string()))
    }
}

/// Through what a gate is measured. Decides which bulk lists cover it:
/// `--no-ssh` skips everything that needs the candidate, the phase-B
/// deadline marks every unfinished measurement, and so on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Public sources queried from the runner in phase A.
    Direct,
    /// The Globalping ping sweep.
    Globalping,
    /// Globalping HTTPS probes against the temporary listener.
    Listener,
    /// Commands run on the candidate over SSH.
    Ssh,
    /// HTTP through the SOCKS tunnel into the candidate.
    Tunnel,
    /// The `/24` sweep from the runner.
    Neighbors,
    /// Rows about the scan itself; a full scan owes no such row.
    Meta,
}

/// Whether a Russian bridge (`--country RU`) judges the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgePolicy {
    Judged,
    /// Judged only for a foreign exit; reported as SKIP for a bridge.
    ForeignExitOnly,
}

/// One row of the gate registry.
#[derive(Debug)]
pub struct GateSpec {
    pub id: GateId,
    pub channel: Channel,
    pub bridge: BridgePolicy,
}

macro_rules! gates {
    ($($konst:ident = $id:literal, $channel:ident, $bridge:ident;)+) => {
        $(pub const $konst: GateId = GateId($id);)+

        /// Every gate a scan can report, one row per id.
        pub const GATES: &[GateSpec] = &[$(GateSpec {
            id: $konst,
            channel: Channel::$channel,
            bridge: BridgePolicy::$bridge,
        },)+];
    };
}

gates! {
    REPUTATION = "reputation", Direct, Judged;
    REPUTATION_OPERATOR = "reputation:operator", Direct, Judged;
    BLOCKLISTS = "blocklists", Direct, Judged;
    RKN_REGISTRY = "rkn-registry", Direct, Judged;
    PROVENANCE = "provenance", Direct, Judged;
    GEO = "geo", Direct, ForeignExitOnly;
    LATENCY = "latency", Globalping, ForeignExitOnly;
    REACH = "reach", Listener, Judged;
    STEAL = "steal", Ssh, Judged;
    TAMPERING = "tampering", Tunnel, Judged;
    SERVICE_CHATGPT_WEB = "service:chatgpt_web", Tunnel, ForeignExitOnly;
    SERVICE_CHATGPT_APP = "service:chatgpt_app", Tunnel, ForeignExitOnly;
    SERVICE_GEMINI = "service:gemini", Tunnel, ForeignExitOnly;
    SERVICE_YOUTUBE_PREMIUM = "service:youtube_premium", Tunnel,
        ForeignExitOnly;
    SERVICE_NETFLIX = "service:netflix", Tunnel, ForeignExitOnly;
    SERVICE_CLAUDE = "service:claude", Tunnel, ForeignExitOnly;
    SERVICE_TIKTOK = "service:tiktok", Tunnel, ForeignExitOnly;
    SERVICE_NOTEBOOKLM = "service:notebooklm", Tunnel, ForeignExitOnly;
    SERVICE_GEO = "service-geo", Tunnel, ForeignExitOnly;
    SERVICE_GEO_CAPTCHA = "service-geo:captcha", Tunnel, ForeignExitOnly;
    SERVICE_GEO_CDN = "service-geo:cdn", Tunnel, ForeignExitOnly;
    AI_OPENAI = "ai:openai", Tunnel, ForeignExitOnly;
    AI_ANTHROPIC = "ai:anthropic", Tunnel, ForeignExitOnly;
    AI_GEMINI = "ai:gemini", Tunnel, ForeignExitOnly;
    AI_DEEPSEEK = "ai:deepseek", Tunnel, ForeignExitOnly;
    NEIGHBORS_PTR = "neighbors-ptr", Neighbors, Judged;
    NEIGHBORS = "neighbors", Neighbors, Judged;
    SSH = "ssh", Meta, Judged;
    SCAN_DEADLINE = "scan-deadline", Meta, Judged;
    GLOBALPING_QUOTA = "globalping-quota", Meta, Judged;
    LISTENER_CLEANUP = "listener-cleanup", Meta, Judged;
    HTTP_CLIENT = "http-client", Meta, Judged;
}

fn by_channel(wanted: &'static [Channel]) -> impl Iterator<Item = GateId> {
    GATES
        .iter()
        .filter(move |spec| wanted.contains(&spec.channel))
        .map(|spec| spec.id)
}

/// Gates judged through the SOCKS tunnel.
pub fn tunnel_gates() -> impl Iterator<Item = GateId> {
    by_channel(&[Channel::Tunnel])
}

/// Gates of the `/24` sweep.
pub fn neighbor_gates() -> impl Iterator<Item = GateId> {
    by_channel(&[Channel::Neighbors])
}

/// Gates that need any SSH access to the candidate: the temporary listener,
/// remote commands, or the tunnel.
pub fn ssh_gates() -> impl Iterator<Item = GateId> {
    by_channel(&[Channel::Listener, Channel::Ssh, Channel::Tunnel])
}

/// Every measurement gate of phase B — what the deadline reports as
/// unfinished when it fires.
pub fn phase_b_gates() -> impl Iterator<Item = GateId> {
    by_channel(&[
        Channel::Globalping,
        Channel::Listener,
        Channel::Ssh,
        Channel::Tunnel,
        Channel::Neighbors,
    ])
}

/// Every gate a full scan owes a row for (everything except `Meta` rows,
/// which only appear when the scan itself misbehaves).
pub fn scan_gates() -> impl Iterator<Item = GateId> {
    GATES
        .iter()
        .filter(|spec| spec.channel != Channel::Meta)
        .map(|spec| spec.id)
}

/// `--gate`/`--skip-gate` as parsed: which gate ids to force to FAIL when
/// they land on WARN, and which to neutralize entirely. Skip wins when a
///
/// gate id appears in both — an operator who disabled a check did not also
/// mean to make it stricter.
#[derive(Debug, Default, Clone)]
pub struct GateOverrides {
    pub escalate: HashSet<GateId>,
    pub skip: HashSet<GateId>,
}

impl GateOverrides {
    pub fn apply(&self, result: CheckResult) -> CheckResult {
        if self.skip.contains(&result.gate) {
            return CheckResult::skipped(result.gate, result.detail);
        }
        if self.escalate.contains(&result.gate) {
            return result.escalate_warning();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CheckResult, Severity, Verdict};

    fn gate(id: &str) -> GateId {
        id.parse().unwrap()
    }

    fn overrides(escalate: &[&str], skip: &[&str]) -> GateOverrides {
        GateOverrides {
            escalate: escalate.iter().map(|&s| gate(s)).collect(),
            skip: skip.iter().map(|&s| gate(s)).collect(),
        }
    }

    #[test]
    fn every_registered_id_parses_back_to_itself() {
        for spec in GATES {
            let parsed: GateId = spec.id.as_str().parse().unwrap();

            assert_eq!(parsed, spec.id);
        }
    }

    #[test]
    fn an_unknown_gate_id_is_rejected_with_the_id_in_the_error() {
        let error = "service:clade".parse::<GateId>().unwrap_err();

        assert_eq!(error.to_string(), "'service:clade' is not a known gate id");
    }

    #[test]
    fn registered_ids_are_unique() {
        let ids: HashSet<&str> =
            GATES.iter().map(|spec| spec.id.as_str()).collect();

        assert_eq!(ids.len(), GATES.len());
    }

    #[test]
    fn the_tunnel_set_is_every_service_ai_and_service_geo_gate_plus_tampering()
    {
        let tunnel: Vec<&str> = tunnel_gates().map(GateId::as_str).collect();

        assert_eq!(tunnel.len(), 16, "{tunnel:?}");
        assert!(
            tunnel.iter().all(|id| {
                *id == "tampering"
                    || id.starts_with("service:")
                    || id.starts_with("service-geo")
                    || id.starts_with("ai:")
            }),
            "{tunnel:?}"
        );
    }

    #[test]
    fn the_ssh_set_is_reach_steal_and_the_tunnel_gates() {
        let ssh: HashSet<GateId> = ssh_gates().collect();
        let mut expected: HashSet<GateId> = tunnel_gates().collect();
        expected.insert(REACH);
        expected.insert(STEAL);

        assert_eq!(ssh, expected);
    }

    #[test]
    fn phase_b_covers_every_measurement_that_is_not_phase_a() {
        let phase_b: HashSet<GateId> = phase_b_gates().collect();
        let expected: HashSet<GateId> = scan_gates()
            .filter(|gate| gate.channel() != Channel::Direct)
            .collect();

        assert_eq!(phase_b, expected);
    }

    #[test]
    fn a_full_scan_owes_a_row_for_every_non_meta_gate() {
        let scan: Vec<GateId> = scan_gates().collect();

        assert!(scan.contains(&REPUTATION));
        assert!(scan.contains(&SERVICE_CLAUDE));
        assert!(!scan.contains(&SCAN_DEADLINE));
        assert!(!scan.contains(&SSH));
    }

    #[test]
    fn a_gate_not_named_anywhere_passes_through_unchanged() {
        let result = CheckResult::new(GEO, Verdict::warn("50/50 split"));
        let sut = overrides(&[], &[]);

        let out = sut.apply(result.clone());

        assert_eq!(out, result);
    }

    #[rstest::rstest]
    #[case::warn_becomes_fail(Verdict::warn("blocked"), Severity::Fail)]
    #[case::ok_stays_ok(Verdict::ok("available"), Severity::Ok)]
    #[case::fail_stays_fail(Verdict::fail("x"), Severity::Fail)]
    fn escalate_turns_warn_into_fail_but_leaves_ok_and_fail_alone(
        #[case] verdict: Verdict,
        #[case] expected: Severity,
    ) {
        let sut = overrides(&["service:claude"], &[]);

        let out = sut.apply(CheckResult::new(SERVICE_CLAUDE, verdict));

        assert_eq!(out.severity(), expected);
    }

    #[test]
    fn skip_neutralizes_the_result_and_marks_it_skipped_keeping_the_reason() {
        let sut = overrides(&[], &["reputation:operator"]);

        let out = sut.apply(CheckResult::new(
            REPUTATION_OPERATOR,
            Verdict::fail("named Snowd"),
        ));

        assert_eq!(out.severity(), Severity::Ok);
        assert_eq!(out.label(), "SKIP");
        assert_eq!(out.detail, "named Snowd");
    }

    #[test]
    fn skip_wins_over_escalate_for_the_same_gate() {
        let sut = overrides(&["latency"], &["latency"]);

        let out = sut.apply(CheckResult::new(
            LATENCY,
            Verdict::warn("p75 over threshold"),
        ));

        assert_eq!(out.severity(), Severity::Ok);
    }

    #[test]
    fn escalation_cannot_turn_a_skipped_check_into_a_failure() {
        let sut = overrides(&["latency"], &[]);
        let result = sut.apply(CheckResult::skipped(LATENCY, "disabled"));
        assert!(result.is_skipped());
        assert_eq!(result.severity(), Severity::Ok);
    }
}
