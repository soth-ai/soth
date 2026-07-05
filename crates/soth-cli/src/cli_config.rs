//! Shared CLI config resolution/helpers for `soth`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const DEFAULT_CONFIG_FILE: &str = "soth.yaml";
pub const DEFAULT_DEVICE_ID_FILE: &str = "device_id";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct SothConfig {
    pub forward_proxy: ForwardProxyConfig,
    pub cloud: CloudConfig,
    pub exchange: ExchangeConfig,
    pub bundle: BundleConfig,
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub pipeline: PipelineOverrides,
    /// Per-extension on/off and per-extension knobs. Today only governs
    /// the historian extension (AI-tool-history backfill + watch). The
    /// `extensions:` block is optional in soth.yaml — missing or empty
    /// keeps the historical default of "everything enabled".
    #[serde(default)]
    pub extensions: ExtensionsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ForwardProxyConfig {
    pub enabled: bool,
    pub address: String,
    pub port: u16,
    pub autostart_on_boot: bool,
    pub ca: CaConfig,
    pub unix_socket_path: Option<String>,
    pub destinations: Vec<String>,
    pub passthrough_unlisted: bool,
    pub pool: ForwardProxyPoolConfig,
    pub process_attribution: ForwardProxyProcessAttributionConfig,
    pub tls: ForwardProxyTlsConfig,
    pub flow_runtime: ForwardProxyFlowRuntimeConfig,
    #[serde(alias = "request_timeout")]
    pub upstream_timeout: DurationSetting,
    pub upstream_retry_on_failure: bool,
    pub upstream_retry_delay: DurationSetting,
    pub capture_max_body_bytes: usize,
    pub buffer_request_bodies: bool,
    pub handler_request_timeout: DurationSetting,
    pub handler_response_timeout: DurationSetting,
    pub handler_recover_from_panics: bool,
    pub max_http_head_bytes: usize,
    pub accept_retry_backoff: DurationSetting,
    pub max_flow_event_backlog: usize,
    pub max_in_flight_bytes: usize,
    pub max_concurrent_flows: usize,

    // ── EXPERIMENTAL: soth-code per-agent gating (forward-looking) ──
    //
    // These two knobs are reserved for future per-agent MITM bypass
    // and cost-skim routing. They are NOT wired into the proxy listener
    // loop today — setting them has no runtime effect beyond appearing
    // in `soth code audit-status`. Hidden from rustdoc and skipped from
    // serialization when empty so they don't show up in default config
    // dumps. Will become real configuration when the bypass-eligibility
    // gate lands at runtime.
    #[doc(hidden)]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bypass_agents: Vec<String>,
    #[doc(hidden)]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cost_skim_agents: Vec<String>,
}

impl Default for ForwardProxyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            address: "127.0.0.1".to_string(),
            port: 8080,
            autostart_on_boot: true,
            ca: CaConfig::default(),
            unix_socket_path: None,
            destinations: vec!["*".to_string()],
            passthrough_unlisted: true,
            pool: ForwardProxyPoolConfig::default(),
            process_attribution: ForwardProxyProcessAttributionConfig::default(),
            tls: ForwardProxyTlsConfig::default(),
            flow_runtime: ForwardProxyFlowRuntimeConfig::default(),
            // Total upstream operation deadline. 30s used to be the default
            // but it bisected long Claude / GPT tool-calling streams that
            // routinely run 30-90s end-to-end, so the user-visible symptom
            // was "API Error: socket connection closed unexpectedly" mid-
            // response. 120s gives streaming LLM responses the headroom
            // they need without hiding genuinely-stuck upstreams.
            upstream_timeout: DurationSetting::millis(120_000),
            // On by default: a single retry (after upstream_retry_delay, bounded
            // by the connect deadline) for transient connect failures — refused
            // / unreachable / reset — which are routine during hotspot handoffs
            // and gateway blips. Without it a single blip surfaces to the user
            // as a 502. The retry only fires on transient errors, never on
            // timeouts, so it can't mask a genuinely-stuck upstream.
            upstream_retry_on_failure: true,
            upstream_retry_delay: DurationSetting::millis(200),
            capture_max_body_bytes: 64 * 1024 * 1024,
            buffer_request_bodies: true,
            // Handler stage timeout (per request/response chunk). 5s was
            // way too tight for HTTP/2 streaming: Claude's first byte on
            // big inference jobs takes 5-10s, which would trip the
            // handler timeout and cause soth-mitm to reap the flow with
            // "reaping stale flow state without explicit stream_end".
            // 15s matches the underlying soth-proxy default in
            // crates/soth-proxy/src/config.rs and aligns with what
            // upstream LLM APIs actually need.
            handler_request_timeout: DurationSetting::millis(15_000),
            handler_response_timeout: DurationSetting::millis(15_000),
            handler_recover_from_panics: true,
            max_http_head_bytes: 64 * 1024,
            accept_retry_backoff: DurationSetting::millis(100),
            max_flow_event_backlog: 8 * 1024,
            max_in_flight_bytes: 64 * 1024 * 1024,
            max_concurrent_flows: 2_048,
            bypass_agents: Vec::new(),
            cost_skim_agents: Vec::new(),
        }
    }
}

impl ForwardProxyConfig {
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }

    /// Filter `bypass_agents` to the subset whose historian usage-
    /// coverage audit has passed.  Returns `(allowed, dropped)`.
    /// Callers should log each dropped agent at WARN level so the
    /// operator notices their config knob silently degraded —
    /// silent ignore would let an operator believe they're saving
    /// proxy CPU when in fact bypass never engaged.
    ///
    /// The plan §10.11 trajectory gate is per-agent: bypass is
    /// only safe once we know historian's session-layer playbook
    /// will recover authoritative `usage` data the network layer
    /// is no longer seeing.  This filter is the runtime
    /// enforcement of that gate.
    pub fn audited_bypass_agents(
        &self,
        historian: &HistorianExtensionConfig,
    ) -> (Vec<String>, Vec<String>) {
        let mut allowed = Vec::new();
        let mut dropped = Vec::new();
        for agent in &self.bypass_agents {
            let adapter = bypass_ua_to_adapter(agent);
            if historian.is_usage_coverage_audited(&adapter) {
                allowed.push(agent.clone());
            } else {
                dropped.push(agent.clone());
            }
        }
        (allowed, dropped)
    }
}

/// Resolve a `bypass_agents` UA-glob pattern to the adapter name
/// the historian audit map keys on.  Bypass list holds outgoing
/// User-Agent prefixes (e.g. "claude-cli/*", "cursor/*") because
/// that's how the proxy matches incoming traffic, but the audit
/// is per-adapter.  Conservative: unmapped patterns return their
/// own (lower-cased, dash→underscore) form, which falls through
/// to "not audited" in the historian map and the bypass entry is
/// dropped.  Add to the table when a new agent's UA prefix is
/// confirmed.
fn bypass_ua_to_adapter(ua_glob: &str) -> String {
    let stripped = ua_glob
        .trim_end_matches('*')
        .trim_end_matches('/')
        .to_ascii_lowercase();
    match stripped.as_str() {
        // Claude Code's CLI sends `claude-cli/<version>`.
        "claude-cli" | "claude-code" | "claude_code" => "claude_code".to_string(),
        "cursor" | "cursor-agent" => "cursor".to_string(),
        "codex" | "openai-codex" | "openai_codex" => "openai_codex".to_string(),
        "gemini-cli" | "gemini_cli" => "gemini_cli".to_string(),
        "pi-agent" | "pi_agent" => "pi_agent".to_string(),
        "windsurf" | "windsurf-extension" => "windsurf".to_string(),
        "opencode" => "opencode".to_string(),
        other => other.replace('-', "_"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DurationSetting {
    Millis(u64),
    Text(String),
}

impl DurationSetting {
    pub fn millis(value: u64) -> Self {
        Self::Millis(value)
    }

    pub fn to_millis_or(&self, default_ms: u64) -> u64 {
        match self {
            Self::Millis(value) => *value,
            Self::Text(value) => parse_duration_text_to_millis(value).unwrap_or(default_ms),
        }
    }
}

impl Default for DurationSetting {
    fn default() -> Self {
        Self::Millis(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ForwardProxyPoolConfig {
    pub max_connections_per_host: u32,
    pub idle_timeout: DurationSetting,
    pub connect_timeout: DurationSetting,
    pub max_idle_per_host: u32,
}

impl Default for ForwardProxyPoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: 64,
            // Pool-side idle timeout: how long an idle upstream connection
            // sits in the pool before being closed. 60s used to be the
            // default but it caused the pool to drop conns right when an
            // LLM client paused between turns, forcing a fresh handshake
            // on the next request. 90s matches the underlying soth-proxy
            // default and improves connection reuse.
            idle_timeout: DurationSetting::millis(90_000),
            connect_timeout: DurationSetting::millis(10_000),
            max_idle_per_host: 16,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ForwardProxyProcessAttributionConfig {
    pub enabled: bool,
    pub lookup_timeout: DurationSetting,
    pub cache_capacity: usize,
    pub cache_ttl: Option<DurationSetting>,
}

impl Default for ForwardProxyProcessAttributionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            lookup_timeout: DurationSetting::millis(5_000),
            cache_capacity: 4_096,
            cache_ttl: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ForwardProxyTlsConfig {
    pub capture_fingerprint: bool,
    pub verify_upstream_tls: bool,
    pub http2_enabled: bool,
    pub http2_max_header_list_size: u32,
    pub http3_passthrough: bool,
}

impl Default for ForwardProxyTlsConfig {
    fn default() -> Self {
        Self {
            capture_fingerprint: true,
            verify_upstream_tls: true,
            http2_enabled: true,
            http2_max_header_list_size: 64 * 1024,
            http3_passthrough: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ForwardProxyFlowRuntimeConfig {
    pub dispatch_queue_capacity: Option<usize>,
    pub closed_flow_lru_capacity: Option<usize>,
    pub stale_flow_ttl: Option<DurationSetting>,
    pub stale_reap_max_batch: Option<usize>,
    pub dispatch_queue_send_timeout: Option<DurationSetting>,
    pub dispatch_close_join_timeout: Option<DurationSetting>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CaConfig {
    pub cert_path: String,
    pub key_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_cert_path: Option<String>,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            cert_path: "~/.soth/certs/soth-mitm-ca.pem".to_string(),
            key_path: "~/.soth/certs/soth-mitm-ca-key.pem".to_string(),
            trust_cert_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CloudConfig {
    pub enabled: bool,
    pub api_key: Option<String>,
    /// Management / dashboard endpoint. Serves `/v1/keys`, `/v1/teams`,
    /// `/v1/dashboard/*`, `/v1/org/*` on `soth-api`.
    pub endpoint: String,
    /// Edge-plane endpoint. Serves `/v1/edge/*` (enroll, heartbeat, bundle,
    /// telemetry, registry) on `soth-ingestion`. When unset, the CLI derives
    /// it by rewriting `api.<domain>` → `ingest.<domain>` in `endpoint`.
    /// Only set this explicitly for custom deployments where derivation
    /// does not apply (single-host dev, on-prem, alternative naming).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingest_endpoint: Option<String>,
    pub sync_interval_secs: u64,
    pub tags: BTreeMap<String, String>,
}

impl Default for CloudConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: None,
            endpoint: "https://api.soth.ai".to_string(),
            ingest_endpoint: None,
            sync_interval_secs: 30,
            tags: BTreeMap::new(),
        }
    }
}

impl CloudConfig {
    /// Return the edge-plane endpoint for enroll / bundle / heartbeat /
    /// telemetry. Honors `ingest_endpoint` when present; otherwise derives
    /// from `endpoint` by rewriting an `api.` hostname prefix to `ingest.`.
    ///
    /// Leaves hosts without an `api.` prefix unchanged, so single-host dev
    /// and custom deployments keep working without extra config.
    pub fn resolved_ingest_endpoint(&self) -> String {
        if let Some(explicit) = self.ingest_endpoint.as_deref() {
            let trimmed = explicit.trim();
            if !trimmed.is_empty() {
                return trimmed.trim_end_matches('/').to_string();
            }
        }
        derive_ingest_endpoint(self.endpoint.as_str())
    }
}

/// Rewrites `https://api.<rest>` → `https://ingest.<rest>` while preserving
/// scheme, port, and any path. Returns the input unchanged when the host
/// does not start with `api.`, when the URL is malformed, or when empty.
pub fn derive_ingest_endpoint(management: &str) -> String {
    let trimmed = management.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return trimmed.to_string();
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (hostname, port) = authority
        .split_once(':')
        .map_or((authority, ""), |(h, p)| (h, p));
    let Some(tail) = hostname.strip_prefix("api.") else {
        return trimmed.trim_end_matches('/').to_string();
    };
    let mut rewritten = format!("{scheme}://ingest.{tail}");
    if !port.is_empty() {
        rewritten.push(':');
        rewritten.push_str(port);
    }
    if !path.is_empty() {
        rewritten.push('/');
        rewritten.push_str(path);
    }
    rewritten.trim_end_matches('/').to_string()
}

#[cfg(test)]
mod cloud_endpoint_tests {
    use super::{derive_ingest_endpoint, CloudConfig};

    #[test]
    fn derives_ingest_from_prod_api_host() {
        assert_eq!(
            derive_ingest_endpoint("https://api.soth.ai"),
            "https://ingest.soth.ai"
        );
    }

    #[test]
    fn derives_ingest_from_staging_api_host() {
        assert_eq!(
            derive_ingest_endpoint("https://api.staging.soth.xyz"),
            "https://ingest.staging.soth.xyz"
        );
    }

    #[test]
    fn preserves_port_and_path() {
        assert_eq!(
            derive_ingest_endpoint("https://api.soth.ai:8443/v1"),
            "https://ingest.soth.ai:8443/v1"
        );
    }

    #[test]
    fn strips_trailing_slash() {
        assert_eq!(
            derive_ingest_endpoint("https://api.soth.ai/"),
            "https://ingest.soth.ai"
        );
    }

    #[test]
    fn leaves_non_api_host_unchanged() {
        assert_eq!(
            derive_ingest_endpoint("https://cloud.example.com"),
            "https://cloud.example.com"
        );
        assert_eq!(
            derive_ingest_endpoint("http://localhost:4201"),
            "http://localhost:4201"
        );
    }

    #[test]
    fn leaves_empty_unchanged() {
        assert_eq!(derive_ingest_endpoint(""), "");
        assert_eq!(derive_ingest_endpoint("   "), "");
    }

    #[test]
    fn explicit_ingest_endpoint_wins_over_derivation() {
        let cfg = CloudConfig {
            endpoint: "https://api.soth.ai".to_string(),
            ingest_endpoint: Some("https://alt-ingest.internal/".to_string()),
            ..CloudConfig::default()
        };
        assert_eq!(
            cfg.resolved_ingest_endpoint(),
            "https://alt-ingest.internal"
        );
    }

    #[test]
    fn empty_explicit_ingest_endpoint_falls_back_to_derivation() {
        let cfg = CloudConfig {
            endpoint: "https://api.soth.ai".to_string(),
            ingest_endpoint: Some("   ".to_string()),
            ..CloudConfig::default()
        };
        assert_eq!(cfg.resolved_ingest_endpoint(), "https://ingest.soth.ai");
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct ExchangeConfig {
    pub enabled: bool,
    pub legacy_upload_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BundleConfig {
    pub bundle_dir: String,
    pub vendor_pubkey_hex: String,
    pub verify_vendor_signature: bool,
    pub require_verified_bundle: bool,
    pub org_approval_pubkey_hex: Option<String>,
}

impl Default for BundleConfig {
    fn default() -> Self {
        Self {
            bundle_dir: "~/.soth/bundle".to_string(),
            vendor_pubkey_hex: "00".repeat(32),
            verify_vendor_signature: true,
            require_verified_bundle: false,
            org_approval_pubkey_hex: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub db_path: String,
    pub classify_max_in_flight: usize,
    pub classify_slot_acquire_timeout_ms: u64,
    pub db_write_queue_capacity: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            db_path: "~/.soth/logs/events.db".to_string(),
            classify_max_in_flight: 8,
            classify_slot_acquire_timeout_ms: 250,
            db_write_queue_capacity: 4_096,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PipelineOverrides {
    pub unknown_app_action: Option<String>,
    pub non_cataloged_host_action: Option<String>,
}

/// Per-extension toggles. Each field is its own struct so individual
/// extensions can grow knobs without affecting the others.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct ExtensionsConfig {
    pub historian: HistorianExtensionConfig,
    pub code: CodeExtensionConfig,
}

/// Historian extension config. Backfills + watches local AI-tool history
/// (Cursor, Claude Code, Gemini CLI, ...) and enriches it with classify.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HistorianExtensionConfig {
    /// Master switch. Off → no backfill, no watch, no periodic SQLite
    /// scans of Cursor's `state.vscdb`. Set to false when debugging
    /// network issues that may correlate with historian CPU bursts.
    pub enabled: bool,

    /// How historian runs in relation to the proxy worker.
    ///
    /// `Subprocess` (default): historian runs in its own process at
    /// nice +5 / BELOW_NORMAL_PRIORITY_CLASS. The proxy worker's
    /// tokio runtime never sees historian's classify CPU bursts, so
    /// long-lived TLS tunnels (video, websockets) don't get reaped
    /// by upstream CDNs because of momentary mitm-runtime starvation.
    ///
    /// `InProcess`: historian registers as an ExtensionRegistry hook
    /// inside the proxy worker. Lower memory floor (~30-50 MiB), but
    /// classify bursts compete with mitm flow handling. Kept as an
    /// opt-in for resource-constrained installs (containers,
    /// CI runners) where the extra process is more expensive than
    /// the occasional flow hiccup.
    pub run_mode: HistorianRunMode,

    /// Per-adapter audit verdicts that gate the proxy A→C
    /// trajectory (plan §10.11). For each AI-coding-agent X,
    /// `usage_coverage_audited == true` means an engineer has
    /// verified that historian's playbook reliably extracts
    /// per-turn `usage` blocks from X's session log — i.e.
    /// authoritative cost telemetry will survive the proxy
    /// going into bypass mode for that agent.
    ///
    /// Until this flag is true for an agent, the runtime will
    /// **refuse** to honor membership of that agent in
    /// `proxy.bypass_agents`: bypassing without audited usage
    /// coverage means losing billing-grade cost data the cloud
    /// can no longer recover. The check filters the bypass
    /// list at proxy boot and emits a warning per excluded
    /// agent.
    ///
    /// Defaults: `claude_code = true` (plan §9 confirmation;
    /// historian's `claude_code` playbook ships with verified
    /// `usage` extraction). All other agents default `false`
    /// pending the per-agent audit (~1 engineer-day each).
    ///
    /// Uses an explicit field-default fn rather than
    /// `#[serde(default)]` so that a YAML file containing
    /// `historian: {}` (no `adapters` key) still gets the
    /// canonical seven-agent table — `BTreeMap::default()` is
    /// `{}` and would silently erase the per-agent verdicts.
    #[serde(default = "default_historian_adapters")]
    pub adapters: BTreeMap<String, HistorianAdapterAudit>,
}

fn default_historian_adapters() -> BTreeMap<String, HistorianAdapterAudit> {
    // Sample-run audit performed 2026-05-08 against real session
    // logs on a developer host (Claude Code + Cursor + Codex
    // available locally; Gemini CLI / OpenClaw / Pi Agent /
    // Windsurf / OpenCode unavailable).  Findings:
    //
    //   claude_code  source has rich `message.usage` (input,
    //                output, cache_creation_input,
    //                cache_read_input) — billing-grade — but
    //                the historian playbook has `tokens: None`,
    //                so the data is NOT extracted.  Plan §9's
    //                "claude_code is audited" was based on
    //                content extraction, not usage extraction.
    //                Playbook update required before this
    //                verdict can flip true.
    //
    //   cursor       sample of 123 chat rows had 0 `input_tokens`
    //                in composerData and 1 in bubbleId — Cursor
    //                does not record per-turn usage in its
    //                chat storage at all.  No playbook fix can
    //                recover what isn't there.
    //
    //   openai_codex source has token info at
    //                `payload.info.total_token_usage.{input,output,
    //                total}_tokens` BUT only on `type:event_msg`
    //                lines.  The current playbook filters
    //                `type:response_item` only, so event_msg
    //                token data is dropped.  Fix: include
    //                event_msg in the filter + structured token
    //                extraction (TokenConfig today supports a
    //                single scalar field — needs extension to
    //                multi-field for billing-grade data).
    //
    //   gemini_cli   no local data on this audit host. Playbook
    //                declares `tokens.total` (scalar). Even when
    //                it works, this is single-total only — not
    //                billing-grade per Anthropic-style usage.
    //                Verdict deferred pending real session log.
    //
    //   openclaw     no local data. tokens=None in playbook.
    //
    //   pi_agent / windsurf / opencode  NO historian playbook
    //                exists at all.  Cannot be audited until a
    //                playbook lands.
    //
    // Net: NO agent currently passes the audit.  The defaults
    // below reflect that.  Operators who need bypass mode
    // before the engineering work is done can hand-flip a
    // verdict in soth.yaml — `audited_at` carries who-and-when
    // attribution if they do.

    let mut adapters = BTreeMap::new();
    adapters.insert(
        "claude_code".to_string(),
        HistorianAdapterAudit {
            usage_coverage_audited: true,
            audited_at: Some("2026-05-08 sample audit + playbook fix".to_string()),
            caveats: Some(
                "playbook now extracts message.usage.{input,output,cache_creation_input,\
                 cache_read_input}_tokens per assistant turn — billing-grade.  Verified \
                 against real session logs and pinned by jsonl::tests::\
                 claude_code_playbook_extracts_billing_grade_usage."
                    .to_string(),
            ),
        },
    );
    adapters.insert(
        "cursor".to_string(),
        HistorianAdapterAudit {
            usage_coverage_audited: false,
            audited_at: Some("2026-05-08 sample audit".to_string()),
            caveats: Some(
                "Cursor does not record per-turn usage in chat storage \
                 (state.vscdb composerData/bubbleId) — nothing to extract"
                    .to_string(),
            ),
        },
    );
    adapters.insert(
        "openai_codex".to_string(),
        HistorianAdapterAudit {
            usage_coverage_audited: false,
            audited_at: Some("2026-05-08 sample audit".to_string()),
            caveats: Some(
                "source has payload.info.{total,last}_token_usage but ONLY on \
                 type:event_msg lines (not type:response_item which the playbook \
                 reads as messages).  Engine refactor required: extract session-\
                 level tokens from non-message lines, not just per-message — \
                 different shape than TokenConfig per-record extraction supports.  \
                 Tracked as engineering work distinct from the claude_code-style \
                 playbook tweak."
                    .to_string(),
            ),
        },
    );
    adapters.insert(
        "gemini_cli".to_string(),
        HistorianAdapterAudit {
            usage_coverage_audited: false,
            audited_at: Some("2026-05-08 desk audit (no local data)".to_string()),
            caveats: Some(
                "playbook declares tokens.total (scalar) — not billing-grade \
                 per-turn structured usage"
                    .to_string(),
            ),
        },
    );
    for agent in ["pi_agent", "windsurf", "opencode"] {
        adapters.insert(
            agent.to_string(),
            HistorianAdapterAudit {
                usage_coverage_audited: false,
                audited_at: Some("2026-05-08 desk audit".to_string()),
                caveats: Some("no historian playbook exists for this agent yet".to_string()),
            },
        );
    }
    adapters
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistorianAdapterAudit {
    /// True once an engineer has run a real session through the
    /// adapter's historian playbook and confirmed that `usage`
    /// blocks extract reliably per assistant turn. False until
    /// then. Source of truth for the proxy's bypass-eligibility
    /// check.
    #[serde(default)]
    pub usage_coverage_audited: bool,

    /// Optional human note (audit date, who ran it, sample
    /// session ID). Carries on the wire so an operator
    /// inspecting the config can see when each verdict was
    /// recorded without digging through commit history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audited_at: Option<String>,

    /// Optional free-form caveat — e.g. "extracts input but not
    /// cache_creation tokens", "only audited for tool_use turns,
    /// not assistant text". Helps later operators decide whether
    /// the audit's quality is enough for their billing needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caveats: Option<String>,
}

impl Default for HistorianExtensionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            run_mode: HistorianRunMode::default(),
            adapters: default_historian_adapters(),
        }
    }
}

impl HistorianExtensionConfig {
    /// True when the named agent has had its historian usage-coverage
    /// audit completed.  Used by the proxy to gate bypass eligibility.
    /// Unknown agents (not in the map) are treated as "not audited".
    pub fn is_usage_coverage_audited(&self, agent: &str) -> bool {
        self.adapters
            .get(agent)
            .map(|a| a.usage_coverage_audited)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistorianRunMode {
    /// Historian runs as a sibling process supervised by `soth start`.
    /// Default — isolates classify CPU from the mitm runtime.
    Subprocess,
    /// Historian runs as an ExtensionRegistry hook inside the proxy
    /// worker. Backwards-compatible behavior; explicit opt-in.
    InProcess,
}

impl Default for HistorianRunMode {
    fn default() -> Self {
        Self::Subprocess
    }
}

/// `soth-code` extension config. Per-action policy gate at the AI coding
/// agent's hook boundary (Claude Code, Cursor, Codex, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CodeExtensionConfig {
    /// Master switch. Off → `soth code hook` invocations no-op (allow
    /// all, no enqueue, no classify). On → hook handler runs the full
    /// parse → redact → classify → policy → enqueue pipeline.
    pub enabled: bool,

    /// Behavior when policy evaluation fails (OPA bundle missing,
    /// timeout exceeded, etc.).
    ///
    /// `Block` (default — security tool stance): a failure halts the
    /// agent action with an error message. Surfaces problems loudly.
    ///
    /// `Allow`: failures are logged and the action proceeds. Operator
    /// must accept the visibility risk; surfaces a `WARN` log line on
    /// every fall-through. (Silent fail-open is how earlier policy-
    /// enforcement implementations shipped enforcement that secretly
    /// did not enforce — do not opt into Allow lightly.)
    pub on_policy_error: PolicyErrorMode,

    /// Hard ceiling for the synchronous hook path. The agent waits this
    /// long before assuming the hook has hung. Default 30s — anything
    /// longer freezes the agent UX.
    pub timeout_ms: u32,

    /// Per-agent enablement. Agents with no entry default to disabled
    /// — adapters opt in explicitly so a misconfigured `code` block
    /// doesn't accidentally route through every adapter shipped.
    ///
    /// Example yaml:
    /// ```yaml
    /// code:
    ///   enabled: true
    ///   agents:
    ///     claude_code: { enabled: true }
    /// ```
    pub agents: std::collections::HashMap<String, CodeAgentConfig>,

    /// Raw payload capture knob. Default is `Metadata` — only derived
    /// signals (classify outputs, hashes, artifact metadata) get
    /// persisted to the queue and shipped to the cloud. Operators
    /// opting into `Audit` (raw payload on Block decisions only) or
    /// `Full` (raw payload on every event) accept compliance and
    /// retention responsibility for the captured content. Cloud-side
    /// gating per-org provides defense-in-depth.
    pub capture: CodeCaptureConfig,

    /// How the per-action classify path runs.  Hooks are short-lived
    /// subprocesses, so loading the 23 MB ONNX bundle per invocation
    /// blows the latency target.  When `Subprocess` (default), `soth
    /// start` supervises a long-running classify daemon alongside
    /// historian and hooks talk to it over localhost TCP.
    pub classify: CodeClassifyConfig,
}

/// `code.classify` block.  Controls how the per-hook classify call
/// is dispatched — daemon, in-process, or off entirely.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct CodeClassifyConfig {
    pub run_mode: ClassifyRunMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassifyRunMode {
    /// Default.  `soth start` supervises a long-running classify
    /// daemon (sibling to historian).  Hook subprocesses talk to it
    /// over localhost TCP NDJSON, amortizing the ONNX
    /// `Session::new` cost (≈50–150 ms cold) across every action
    /// for the daemon's lifetime.  Falls back to `InProcess` per-
    /// invocation when the daemon is unreachable.
    Subprocess,
    /// Each hook subprocess loads `~/.soth/bundle/` itself.
    /// Adds ~50–150 ms cold latency per action — fine for low-
    /// traffic dev hosts but blows the gate-latency budget on
    /// active sessions.  Useful when the supervisor isn't running
    /// (e.g.  CI runners that invoke `soth code hook` directly).
    InProcess,
    /// Skip classify entirely.  Sidecar fields render as
    /// `unknown`/0 on the dashboard.  Operators choose this when
    /// the agent's traffic is purely structural (no NL prompts) or
    /// when they want to take classify off the hot path during
    /// debugging.
    Disabled,
}

impl Default for ClassifyRunMode {
    fn default() -> Self {
        Self::Subprocess
    }
}

/// `code.capture` block. See [`CodeCaptureMode`] for semantics; the
/// `max_payload_bytes` cap protects against megabyte-sized MCP tool
/// responses blowing up queue-row size when raw capture is enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CodeCaptureConfig {
    pub mode: CodeCaptureMode,
    pub max_payload_bytes: usize,
}

impl Default for CodeCaptureConfig {
    fn default() -> Self {
        Self {
            mode: CodeCaptureMode::Metadata,
            max_payload_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeCaptureMode {
    /// Default: derived signals only; raw payload dropped before enqueue.
    Metadata,
    /// Raw payload preserved only for Block decisions (forensics).
    Audit,
    /// Raw payload preserved on every event (debugging / compliance).
    Full,
}

impl Default for CodeCaptureMode {
    fn default() -> Self {
        Self::Metadata
    }
}

impl Default for CodeExtensionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            on_policy_error: PolicyErrorMode::Block,
            timeout_ms: 30_000,
            agents: std::collections::HashMap::new(),
            capture: CodeCaptureConfig::default(),
            classify: CodeClassifyConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyErrorMode {
    Block,
    Allow,
}

impl Default for PolicyErrorMode {
    fn default() -> Self {
        Self::Block
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct CodeAgentConfig {
    /// Whether the adapter is active. Off-by-default per agent so a
    /// misconfigured `code` block doesn't route through unintended
    /// adapters.
    pub enabled: bool,
}

/// Resolve the user's home directory for `~` expansion and default soth
/// paths. `$HOME` wins when set: Unix always sets it, and on Windows —
/// where it is normally absent — honoring it matches every other soth
/// path helper (which honor `SOTH_HOME_DIR`) and keeps test sandboxes
/// working. `dirs::home_dir()` alone won't do: on Windows it resolves via
/// the known-folder OS API and ignores the environment entirely.
fn home_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return Some(PathBuf::from(home));
        }
    }
    dirs::home_dir()
}

pub fn default_config_path() -> PathBuf {
    home_dir()
        .map(|home| home.join(".soth").join(DEFAULT_CONFIG_FILE))
        .unwrap_or_else(|| PathBuf::from(".soth").join(DEFAULT_CONFIG_FILE))
}

pub fn default_device_id_path() -> PathBuf {
    home_dir()
        .map(|home| home.join(".soth").join(DEFAULT_DEVICE_ID_FILE))
        .unwrap_or_else(|| PathBuf::from(".soth").join(DEFAULT_DEVICE_ID_FILE))
}

pub fn discover_default_config_path() -> Option<PathBuf> {
    let path = default_config_path();
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

pub fn expand_tilde(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix("~/") {
        return home_dir()
            .map(|home| home.join(rest))
            .unwrap_or_else(|| PathBuf::from(raw.as_ref()));
    }
    path.to_path_buf()
}

pub fn resolve_config_path(
    explicit: Option<&PathBuf>,
    global: Option<&PathBuf>,
) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(expand_tilde(path));
    }
    if let Some(path) = global {
        return Some(expand_tilde(path));
    }
    discover_default_config_path()
}

pub fn load_config(path: PathBuf) -> Result<SothConfig> {
    let content =
        fs::read_to_string(&path).with_context(|| format!("failed reading {}", path.display()))?;
    let cfg = serde_yaml::from_str::<SothConfig>(&content)
        .with_context(|| format!("failed parsing {}", path.display()))?;
    Ok(cfg)
}

pub fn load_effective_config(
    explicit: Option<&PathBuf>,
    global: Option<&PathBuf>,
) -> Result<SothConfig> {
    if let Some(path) = resolve_config_path(explicit, global) {
        return load_config(path);
    }
    Ok(SothConfig::default())
}

pub fn write_config(path: &Path, config: &SothConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    let body = serde_yaml::to_string(config).context("failed serializing config YAML")?;
    fs::write(path, body).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

fn parse_duration_text_to_millis(raw: &str) -> Option<u64> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        return trimmed.parse::<u64>().ok();
    }

    let mut total: u64 = 0;
    for token in trimmed.split_whitespace() {
        let (num, unit) = split_number_and_unit(token)?;
        let value = num.parse::<u64>().ok()?;
        let factor = match unit {
            "" | "ms" | "msec" | "millisecond" | "milliseconds" => 1,
            "s" | "sec" | "secs" | "second" | "seconds" => 1_000,
            "m" | "min" | "mins" | "minute" | "minutes" => 60_000,
            "h" | "hr" | "hrs" | "hour" | "hours" => 3_600_000,
            "d" | "day" | "days" => 86_400_000,
            _ => return None,
        };
        total = total.checked_add(value.checked_mul(factor)?)?;
    }
    Some(total)
}

fn split_number_and_unit(token: &str) -> Option<(&str, &str)> {
    if token.is_empty() {
        return None;
    }
    let split = token
        .char_indices()
        .find(|(_, ch)| !ch.is_ascii_digit())
        .map(|(idx, _)| idx)
        .unwrap_or(token.len());
    if split == 0 {
        return None;
    }
    Some((&token[..split], token[split..].trim()))
}

pub fn read_client_device_id() -> Option<String> {
    let path = default_device_id_path();
    let value = fs::read_to_string(path).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn write_client_device_id(device_id: &str) -> Result<()> {
    let path = default_device_id_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    fs::write(&path, format!("{device_id}\n"))
        .with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

pub fn sync_client_device_id(
    config: &mut SothConfig,
    preferred_device_id: Option<&str>,
) -> Result<String> {
    let device_id = preferred_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            config
                .cloud
                .tags
                .get("device_id")
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .or_else(read_client_device_id)
        .unwrap_or_else(|| format!("device-{}", Uuid::new_v4()));

    config
        .cloud
        .tags
        .insert("device_id".to_string(), device_id.clone());
    let _ = write_client_device_id(&device_id);
    Ok(device_id)
}

/// Force-generate a fresh client device id, overwriting any persisted one
/// in both the config tags and the on-disk `device_id` file. Used by
/// `soth enroll --new-device-id` as the escape hatch when the cloud has
/// rejected the stale device_id (e.g. after an org migration): reusing the
/// old id would just reproduce the same 403.
pub fn regenerate_client_device_id(config: &mut SothConfig) -> Result<String> {
    let device_id = format!("device-{}", Uuid::new_v4());
    config
        .cloud
        .tags
        .insert("device_id".to_string(), device_id.clone());
    write_client_device_id(&device_id)?;
    Ok(device_id)
}

pub fn resolved_db_path(config: &SothConfig) -> PathBuf {
    expand_tilde(Path::new(config.proxy.db_path.as_str()))
}

#[cfg(test)]
mod device_id_tests {
    use super::{regenerate_client_device_id, SothConfig};
    use std::env;

    /// Run `f` with HOME (and the Windows/soth-specific home vars) pointed at
    /// a throwaway tempdir so device_id file writes stay sandboxed.
    fn with_temp_home<T>(f: impl FnOnce() -> T) -> T {
        let _guard = crate::commands::proxy::lock_test_env();
        let temp = tempfile::tempdir().expect("tempdir");
        let old_home = env::var_os("HOME");
        let old_userprofile = env::var_os("USERPROFILE");
        let old_soth_home = env::var_os("SOTH_HOME_DIR");
        unsafe {
            env::set_var("HOME", temp.path());
            env::set_var("USERPROFILE", temp.path());
            env::set_var("SOTH_HOME_DIR", temp.path().join(".soth"));
        }
        let result = f();
        match old_home {
            Some(v) => unsafe { env::set_var("HOME", v) },
            None => unsafe { env::remove_var("HOME") },
        }
        match old_userprofile {
            Some(v) => unsafe { env::set_var("USERPROFILE", v) },
            None => unsafe { env::remove_var("USERPROFILE") },
        }
        match old_soth_home {
            Some(v) => unsafe { env::set_var("SOTH_HOME_DIR", v) },
            None => unsafe { env::remove_var("SOTH_HOME_DIR") },
        }
        result
    }

    #[test]
    fn regenerate_replaces_stale_device_id_tag() {
        with_temp_home(|| {
            let mut config = SothConfig::default();
            config
                .cloud
                .tags
                .insert("device_id".to_string(), "device-stale".to_string());

            let fresh = regenerate_client_device_id(&mut config).expect("regenerate");

            assert!(fresh.starts_with("device-"), "id has device- prefix");
            assert_ne!(fresh, "device-stale", "stale id was replaced");
            assert_eq!(
                config.cloud.tags.get("device_id").map(String::as_str),
                Some(fresh.as_str()),
                "config tag reflects the fresh id"
            );
        });
    }

    #[test]
    fn regenerate_yields_distinct_ids() {
        with_temp_home(|| {
            let mut config = SothConfig::default();
            let first = regenerate_client_device_id(&mut config).expect("first");
            let second = regenerate_client_device_id(&mut config).expect("second");
            assert_ne!(first, second, "each regenerate produces a fresh id");
        });
    }
}

#[cfg(test)]
mod code_extension_config_tests {
    use super::{
        CodeAgentConfig, CodeExtensionConfig, ExtensionsConfig, ForwardProxyConfig,
        HistorianAdapterAudit, HistorianExtensionConfig, PolicyErrorMode, SothConfig,
    };

    #[test]
    fn code_config_default_matches_documented() {
        // README example default must match code default — a prior bug
        // shipped because docs claimed `minimal` log level was default while
        // code default was `standard`. Pin the contract here.
        let c = CodeExtensionConfig::default();
        assert!(c.enabled, "extension default is on");
        assert_eq!(c.on_policy_error, PolicyErrorMode::Block);
        assert_eq!(c.timeout_ms, 30_000);
        assert!(
            c.agents.is_empty(),
            "no agents default to enabled — adapters opt in explicitly"
        );
        assert_eq!(
            c.classify.run_mode,
            super::ClassifyRunMode::Subprocess,
            "default classify run mode is supervised daemon — pinning so the \
             upgrade path doesn't silently regress to per-hook ONNX loads"
        );
    }

    #[test]
    fn agent_default_is_disabled() {
        // Per-agent default off so a misconfigured `code` block doesn't
        // route through unintended adapters.
        let a = CodeAgentConfig::default();
        assert!(!a.enabled);
    }

    #[test]
    fn yaml_round_trip_with_claude_code_only() {
        let yaml = r#"
extensions:
  code:
    enabled: true
    on_policy_error: block
    timeout_ms: 30000
    agents:
      claude_code:
        enabled: true
"#;
        let cfg: SothConfig = serde_yaml::from_str(yaml).expect("parse soth config");
        let code = &cfg.extensions.code;
        assert!(code.enabled);
        assert_eq!(code.timeout_ms, 30_000);
        assert_eq!(code.on_policy_error, PolicyErrorMode::Block);
        let claude = code
            .agents
            .get("claude_code")
            .expect("claude_code adapter entry present");
        assert!(claude.enabled);
    }

    #[test]
    fn missing_code_block_uses_defaults() {
        // Backwards-compat: existing soth.yaml files with no `code:` block
        // must keep working. `extensions:` is `serde(default)`, and
        // `code:` inherits CodeExtensionConfig::default().
        let yaml = "forward_proxy:\n  enabled: true\n";
        let cfg: SothConfig = serde_yaml::from_str(yaml).expect("parse minimal config");
        let code = &cfg.extensions.code;
        assert!(code.enabled, "missing block should default-enable");
        assert!(code.agents.is_empty());
    }

    #[test]
    fn proxy_bypass_and_cost_skim_default_empty() {
        let cfg = ForwardProxyConfig::default();
        assert!(
            cfg.bypass_agents.is_empty(),
            "no bypass until explicit per-agent flip"
        );
        assert!(
            cfg.cost_skim_agents.is_empty(),
            "no cost-skim until usage-coverage audit gates flip"
        );
    }

    #[test]
    fn yaml_round_trip_with_proxy_bypass_lists() {
        let yaml = r#"
forward_proxy:
  bypass_agents:
    - "claude-cli/*"
  cost_skim_agents:
    - "cursor/*"
"#;
        let cfg: SothConfig = serde_yaml::from_str(yaml).expect("parse with bypass lists");
        assert_eq!(cfg.forward_proxy.bypass_agents, vec!["claude-cli/*"]);
        assert_eq!(cfg.forward_proxy.cost_skim_agents, vec!["cursor/*"]);
    }

    #[test]
    fn extensions_config_default_includes_code() {
        let ext = ExtensionsConfig::default();
        assert!(ext.code.enabled);
        // historian still defaulting (regression guard)
        assert!(ext.historian.enabled);
    }

    #[test]
    fn historian_audit_defaults_post_2026_05_audit() {
        // Per the 2026-05-08 audit + playbook fix:
        // - claude_code: TRUE (playbook now extracts
        //   message.usage.{input,output,cache_creation_input,
        //   cache_read_input}_tokens per assistant turn,
        //   billing-grade — pinned by
        //   `jsonl::tests::claude_code_playbook_extracts_billing_grade_usage`).
        // - All others: FALSE (Codex blocked on engine
        //   refactor; gemini_cli ships scalar-only;
        //   cursor source has nothing to extract;
        //   pi_agent / windsurf / opencode have no
        //   playbook).
        let h = HistorianExtensionConfig::default();
        assert!(
            h.is_usage_coverage_audited("claude_code"),
            "claude_code must be audited true post-playbook-fix"
        );
        for agent in [
            "cursor",
            "openai_codex",
            "gemini_cli",
            "pi_agent",
            "windsurf",
            "opencode",
        ] {
            assert!(
                !h.is_usage_coverage_audited(agent),
                "{agent} default verdict stays false until its blocker is cleared"
            );
        }
        // Unknown agents — also "not audited".  Default-deny.
        assert!(!h.is_usage_coverage_audited("unknown_future_agent"));
    }

    #[test]
    fn audited_bypass_lets_only_claude_through() {
        // claude_code passes audit post-fix; the others stay
        // dropped.  Operator who wires up bypass for the full
        // set sees only `claude-cli/*` engage.
        let proxy = ForwardProxyConfig {
            bypass_agents: vec![
                "claude-cli/*".to_string(),
                "cursor/*".to_string(),
                "windsurf-extension/*".to_string(),
            ],
            ..ForwardProxyConfig::default()
        };
        let historian = HistorianExtensionConfig::default();
        let (allowed, dropped) = proxy.audited_bypass_agents(&historian);
        assert_eq!(allowed, vec!["claude-cli/*"]);
        assert_eq!(dropped.len(), 2);
        assert!(dropped.contains(&"cursor/*".to_string()));
        assert!(dropped.contains(&"windsurf-extension/*".to_string()));
    }

    #[test]
    fn audited_bypass_passes_when_operator_flips_verdict() {
        // Operators whose engineering work has earned a flip
        // can manually set the verdict in soth.yaml. Pin that
        // flow: a hand-flipped claude_code verdict makes
        // claude-cli/* pass the filter even though the default
        // is false.  This is the "I did the audit, here's the
        // evidence" path.
        let proxy = ForwardProxyConfig {
            bypass_agents: vec!["claude-cli/*".to_string()],
            ..ForwardProxyConfig::default()
        };
        let mut historian = HistorianExtensionConfig::default();
        historian.adapters.insert(
            "claude_code".to_string(),
            HistorianAdapterAudit {
                usage_coverage_audited: true,
                audited_at: Some("2026-06-01 manual after playbook fix".to_string()),
                caveats: None,
            },
        );
        let (allowed, dropped) = proxy.audited_bypass_agents(&historian);
        assert_eq!(allowed, vec!["claude-cli/*"]);
        assert!(dropped.is_empty());
    }
}
