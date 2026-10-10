//! The closed set of gates and the `--gate`/`--skip-gate` overrides that key
//! on them.
//!
//! Every gate a scan can report is one variant of [`Gate`]. Two facts the
//! rest of the app keys on are methods of the gate: through which channel it
//! is measured ([`Gate::channel`], which bulk SKIP/ERROR lists cover it) and
//! whether a Russian bridge judges it ([`Gate::bridge`]). Both are exhaustive
//! `match`es, so a new variant does not compile until both are decided.
//! Derived sets such as [`tunnel_gates`] are filters over [`Gate::iter`].

use crate::report::CheckResult;
use std::collections::HashSet;
use strum::IntoEnumIterator;

/// A gate a scan reports a row for.
///
/// The string id (`"latency"`, `"service:gemini"`, `"ai:openai"`) is what
/// `--gate`, `--skip-gate` and the report show; `FromStr` rejects any id that
/// is not a variant, so a typo in `--gate` is a startup error instead of an
/// override that silently never matches.
///
/// `Ord` follows the declaration order, which groups the gates by channel;
/// `Report` uses it to order rows of the same severity.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::Display,
    strum::EnumIter,
)]
#[strum(serialize_all = "kebab-case")]
pub enum Gate {
    Reputation,
    #[strum(serialize = "reputation:operator")]
    ReputationOperator,
    Blocklists,
    RknRegistry,
    Provenance,
    Geo,
    Latency,
    Reach,
    Steal,
    Tampering,
    #[strum(serialize = "service:chatgpt_web")]
    ServiceChatgptWeb,
    #[strum(serialize = "service:chatgpt_app")]
    ServiceChatgptApp,
    #[strum(serialize = "service:gemini")]
    ServiceGemini,
    #[strum(serialize = "service:youtube_premium")]
    ServiceYoutubePremium,
    #[strum(serialize = "service:netflix")]
    ServiceNetflix,
    #[strum(serialize = "service:claude")]
    ServiceClaude,
    #[strum(serialize = "service:tiktok")]
    ServiceTiktok,
    #[strum(serialize = "service:notebooklm")]
    ServiceNotebooklm,
    ServiceGeo,
    #[strum(serialize = "service-geo:captcha")]
    ServiceGeoCaptcha,
    #[strum(serialize = "service-geo:cdn")]
    ServiceGeoCdn,
    #[strum(serialize = "ai:openai")]
    AiOpenai,
    #[strum(serialize = "ai:anthropic")]
    AiAnthropic,
    #[strum(serialize = "ai:gemini")]
    AiGemini,
    #[strum(serialize = "ai:deepseek")]
    AiDeepseek,
    NeighborsPtr,
    Neighbors,
    Ssh,
    ScanDeadline,
    GlobalpingQuota,
    ListenerCleanup,
    HttpClient,
}

impl Gate {
    /// The id shown in the report and accepted by `--gate`.
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    pub const fn channel(self) -> Channel {
        match self {
            Self::Reputation
            | Self::ReputationOperator
            | Self::Blocklists
            | Self::RknRegistry
            | Self::Provenance
            | Self::Geo => Channel::Direct,
            Self::Latency => Channel::Globalping,
            Self::Reach => Channel::Listener,
            Self::Steal => Channel::Ssh,
            Self::Tampering
            | Self::ServiceChatgptWeb
            | Self::ServiceChatgptApp
            | Self::ServiceGemini
            | Self::ServiceYoutubePremium
            | Self::ServiceNetflix
            | Self::ServiceClaude
            | Self::ServiceTiktok
            | Self::ServiceNotebooklm
            | Self::ServiceGeo
            | Self::ServiceGeoCaptcha
            | Self::ServiceGeoCdn
            | Self::AiOpenai
            | Self::AiAnthropic
            | Self::AiGemini
            | Self::AiDeepseek => Channel::Tunnel,
            Self::NeighborsPtr | Self::Neighbors => Channel::Neighbors,
            Self::Ssh
            | Self::ScanDeadline
            | Self::GlobalpingQuota
            | Self::ListenerCleanup
            | Self::HttpClient => Channel::Meta,
        }
    }

    pub const fn bridge(self) -> BridgePolicy {
        match self {
            Self::Geo
            | Self::Latency
            | Self::ServiceChatgptWeb
            | Self::ServiceChatgptApp
            | Self::ServiceGemini
            | Self::ServiceYoutubePremium
            | Self::ServiceNetflix
            | Self::ServiceClaude
            | Self::ServiceTiktok
            | Self::ServiceNotebooklm
            | Self::ServiceGeo
            | Self::ServiceGeoCaptcha
            | Self::ServiceGeoCdn
            | Self::AiOpenai
            | Self::AiAnthropic
            | Self::AiGemini
            | Self::AiDeepseek => BridgePolicy::ForeignExitOnly,
            Self::Reputation
            | Self::ReputationOperator
            | Self::Blocklists
            | Self::RknRegistry
            | Self::Provenance
            | Self::Reach
            | Self::Steal
            | Self::Tampering
            | Self::NeighborsPtr
            | Self::Neighbors
            | Self::Ssh
            | Self::ScanDeadline
            | Self::GlobalpingQuota
            | Self::ListenerCleanup
            | Self::HttpClient => BridgePolicy::Judged,
        }
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

fn by_channel(wanted: &'static [Channel]) -> impl Iterator<Item = Gate> {
    Gate::iter().filter(move |gate| wanted.contains(&gate.channel()))
}

/// Gates judged through the SOCKS tunnel.
pub fn tunnel_gates() -> impl Iterator<Item = Gate> {
    by_channel(&[Channel::Tunnel])
}

/// Gates of the `/24` sweep.
pub fn neighbor_gates() -> impl Iterator<Item = Gate> {
    by_channel(&[Channel::Neighbors])
}

/// Gates that need any SSH access to the candidate: the temporary listener,
/// remote commands, or the tunnel.
pub fn ssh_gates() -> impl Iterator<Item = Gate> {
    by_channel(&[Channel::Listener, Channel::Ssh, Channel::Tunnel])
}

/// Every measurement gate of phase B — what the deadline reports as
/// unfinished when it fires.
pub fn phase_b_gates() -> impl Iterator<Item = Gate> {
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
pub fn scan_gates() -> impl Iterator<Item = Gate> {
    Gate::iter().filter(|gate| gate.channel() != Channel::Meta)
}

/// `--gate`/`--skip-gate` as parsed.
///
/// `escalate` holds the gates to force to FAIL when they land on WARN,
/// `skip` the ones to neutralize entirely. Skip wins when a gate appears
/// in both — an operator who disabled a check did not also
/// mean to make it stricter.
#[derive(Debug, Default, Clone)]
pub struct GateOverrides {
    pub escalate: HashSet<Gate>,
    pub skip: HashSet<Gate>,
}

impl GateOverrides {
    pub fn apply(&self, result: CheckResult) -> CheckResult {
        if self.skip.contains(&result.gate()) {
            return CheckResult::skipped(result.gate(), result.into_detail());
        }
        if self.escalate.contains(&result.gate()) {
            return result.escalate_warning();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{CheckResult, Severity, Verdict};

    fn overrides(escalate: &[Gate], skip: &[Gate]) -> GateOverrides {
        GateOverrides {
            escalate: escalate.iter().copied().collect(),
            skip: skip.iter().copied().collect(),
        }
    }

    /// The ids `--gate`, `--skip-gate` and the report have always used,
    /// listed by hand: renaming a variant must not change any of them.
    const IDS: [&str; 32] = [
        "reputation",
        "reputation:operator",
        "blocklists",
        "rkn-registry",
        "provenance",
        "geo",
        "latency",
        "reach",
        "steal",
        "tampering",
        "service:chatgpt_web",
        "service:chatgpt_app",
        "service:gemini",
        "service:youtube_premium",
        "service:netflix",
        "service:claude",
        "service:tiktok",
        "service:notebooklm",
        "service-geo",
        "service-geo:captcha",
        "service-geo:cdn",
        "ai:openai",
        "ai:anthropic",
        "ai:gemini",
        "ai:deepseek",
        "neighbors-ptr",
        "neighbors",
        "ssh",
        "scan-deadline",
        "globalping-quota",
        "listener-cleanup",
        "http-client",
    ];

    #[test]
    fn every_gate_keeps_its_published_id() {
        let ids: Vec<&str> = Gate::iter().map(Gate::as_str).collect();

        assert_eq!(ids, IDS);
    }

    #[test]
    fn every_id_parses_back_to_its_gate() {
        let parsed: Vec<Gate> = Gate::iter()
            .map(|gate| gate.to_string().parse().unwrap())
            .collect();

        assert_eq!(parsed, Gate::iter().collect::<Vec<_>>());
    }

    #[test]
    fn an_unknown_gate_id_is_rejected() {
        let error = "service:clade".parse::<Gate>().unwrap_err();

        assert_eq!(error, strum::ParseError::VariantNotFound);
    }

    /// Every gate measured through the SOCKS tunnel, listed by hand so the
    /// tests compare the registry against an independent expectation.
    const TUNNEL: [Gate; 16] = [
        Gate::Tampering,
        Gate::ServiceChatgptWeb,
        Gate::ServiceChatgptApp,
        Gate::ServiceGemini,
        Gate::ServiceYoutubePremium,
        Gate::ServiceNetflix,
        Gate::ServiceClaude,
        Gate::ServiceTiktok,
        Gate::ServiceNotebooklm,
        Gate::ServiceGeo,
        Gate::ServiceGeoCaptcha,
        Gate::ServiceGeoCdn,
        Gate::AiOpenai,
        Gate::AiAnthropic,
        Gate::AiGemini,
        Gate::AiDeepseek,
    ];

    #[test]
    fn the_tunnel_set_is_every_service_ai_and_service_geo_gate_plus_tampering()
    {
        let tunnel: HashSet<Gate> = tunnel_gates().collect();

        assert_eq!(tunnel, HashSet::from(TUNNEL));
    }

    #[test]
    fn the_ssh_set_is_reach_steal_and_the_tunnel_gates() {
        let ssh: HashSet<Gate> = ssh_gates().collect();

        let expected: HashSet<Gate> = [Gate::Reach, Gate::Steal]
            .into_iter()
            .chain(TUNNEL)
            .collect();
        assert_eq!(ssh, expected);
    }

    #[test]
    fn phase_b_covers_every_measurement_that_is_not_phase_a() {
        let phase_b: HashSet<Gate> = phase_b_gates().collect();

        let expected: HashSet<Gate> = [
            Gate::Latency,
            Gate::Reach,
            Gate::Steal,
            Gate::NeighborsPtr,
            Gate::Neighbors,
        ]
        .into_iter()
        .chain(TUNNEL)
        .collect();
        assert_eq!(phase_b, expected);
    }

    /// Rows about the scan itself, listed by hand.
    const META: [Gate; 5] = [
        Gate::Ssh,
        Gate::ScanDeadline,
        Gate::GlobalpingQuota,
        Gate::ListenerCleanup,
        Gate::HttpClient,
    ];

    #[test]
    fn a_full_scan_owes_a_row_for_every_non_meta_gate() {
        let scan: HashSet<Gate> = scan_gates().collect();

        let meta = HashSet::from(META);
        let expected: HashSet<Gate> =
            Gate::iter().filter(|gate| !meta.contains(gate)).collect();
        assert_eq!(scan, expected);
    }

    #[test]
    fn the_meta_rows_are_exactly_the_rows_about_the_scan_itself() {
        let meta: HashSet<Gate> = Gate::iter()
            .filter(|gate| gate.channel() == Channel::Meta)
            .collect();

        assert_eq!(meta, HashSet::from(META));
    }

    #[test]
    fn a_gate_not_named_anywhere_passes_through_unchanged() {
        let result = CheckResult::new(Gate::Geo, Verdict::warn("50/50 split"));
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
        let sut = overrides(&[Gate::ServiceClaude], &[]);

        let out = sut.apply(CheckResult::new(Gate::ServiceClaude, verdict));

        assert_eq!(out.severity(), expected);
    }

    #[test]
    fn skip_neutralizes_the_result_and_marks_it_skipped_keeping_the_reason() {
        let sut = overrides(&[], &[Gate::ReputationOperator]);

        let out = sut.apply(CheckResult::new(
            Gate::ReputationOperator,
            Verdict::fail("named Snowd"),
        ));

        assert_eq!(out.severity(), Severity::Ok);
        assert_eq!(out.label(), "SKIP");
        assert_eq!(out.detail(), "named Snowd");
    }

    #[test]
    fn skip_wins_over_escalate_for_the_same_gate() {
        let sut = overrides(&[Gate::Latency], &[Gate::Latency]);

        let out = sut.apply(CheckResult::new(
            Gate::Latency,
            Verdict::warn("p75 over threshold"),
        ));

        assert_eq!(out.severity(), Severity::Ok);
    }

    #[test]
    fn escalation_cannot_turn_a_skipped_check_into_a_failure() {
        let sut = overrides(&[Gate::Latency], &[]);

        let result = sut.apply(CheckResult::skipped(Gate::Latency, "disabled"));

        assert!(result.is_skipped());
        assert_eq!(result.severity(), Severity::Ok);
    }
}
