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

    // ── soth-code per-agent gating (→ docs/gryph/plan.md §10.11/.12) ──
    /// User-Agent glob patterns for AI coding agents whose traffic is
    /// **fully bypassed** at the proxy: TLS pass-through, no telemetry,
    /// no classify. The `soth-code` extension is the canonical source
    /// for these agents (action layer + historian session layer cover
    /// the visibility need). Default empty — no bypass until explicitly
    /// flipped per-agent following the A→C trajectory gate
    /// (plan §10.11).
    #[serde(default)]
    pub bypass_agents: Vec<String>,
    /// User-Agent glob patterns for agents in **cost-skim** mode: proxy
    /// emits a narrow event with provider/model/tokens/cost only, no
    /// classify, no tool-use parsing. Used as a transitional fallback
    /// for agents whose historian playbook does not yet capture
    /// authoritative `usage` blocks (plan §10.12). Migrates to
    /// `bypass_agents` once historian usage coverage is audited.
    /// Default empty.
    #[serde(default)]
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
            upstream_retry_on_failure: false,
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
pub struct ExtensionsConfig {
    pub historian: HistorianExtensionConfig,
    pub code: CodeExtensionConfig,
}

impl Default for ExtensionsConfig {
    fn default() -> Self {
        Self {
            historian: HistorianExtensionConfig::default(),
            code: CodeExtensionConfig::default(),
        }
    }
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
}

impl Default for HistorianExtensionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            run_mode: HistorianRunMode::default(),
        }
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
/// agent's hook boundary (Claude Code, Cursor, Codex, …). See
/// `docs/gryph/plan.md` §10 for the layer model and §10.11 for the
/// per-agent A→C trajectory.
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
    /// every fall-through (gryph Issue #20: silent fail-open is how
    /// Pi Agent shipped policy enforcement that secretly didn't enforce).
    pub on_policy_error: PolicyErrorMode,

    /// Hard ceiling for the synchronous hook path. The agent waits this
    /// long before assuming the hook has hung. Default 30s, matching
    /// gryph PR #22's chosen value (anything longer freezes the agent).
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
}

impl Default for CodeExtensionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            on_policy_error: PolicyErrorMode::Block,
            timeout_ms: 30_000,
            agents: std::collections::HashMap::new(),
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
pub struct CodeAgentConfig {
    /// Whether the adapter is active. Off-by-default per agent so a
    /// misconfigured `code` block doesn't route through unintended
    /// adapters.
    pub enabled: bool,
}

impl Default for CodeAgentConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

pub fn default_config_path() -> PathBuf {
    dirs::home_dir()
        .map(|home| home.join(".soth").join(DEFAULT_CONFIG_FILE))
        .unwrap_or_else(|| PathBuf::from(".soth").join(DEFAULT_CONFIG_FILE))
}

pub fn default_device_id_path() -> PathBuf {
    dirs::home_dir()
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
        return dirs::home_dir()
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

pub fn resolved_db_path(config: &SothConfig) -> PathBuf {
    expand_tilde(Path::new(config.proxy.db_path.as_str()))
}

#[cfg(test)]
mod code_extension_config_tests {
    use super::{
        CodeAgentConfig, CodeExtensionConfig, ExtensionsConfig, ForwardProxyConfig,
        PolicyErrorMode, SothConfig,
    };

    #[test]
    fn code_config_default_matches_documented() {
        // README example default must match code default — gryph Issue #41
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
        assert!(cfg.bypass_agents.is_empty(), "no bypass until explicit per-agent flip");
        assert!(cfg.cost_skim_agents.is_empty(), "no cost-skim until usage-coverage audit gates flip");
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
}
