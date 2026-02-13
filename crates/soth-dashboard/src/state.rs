//! Dashboard state - thread-safe metrics sink

use chrono::{Duration as ChronoDuration, Utc};
use parking_lot::RwLock;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tracing::debug;

/// Maximum number of recent entries to keep
const MAX_RECENT_ENTRIES: usize = 10;

/// Maximum number of recent proxy requests to keep
const MAX_RECENT_PROXY_REQUESTS: usize = 50;

/// Maximum number of daily trend points to keep
const MAX_DAILY_TREND_POINTS: usize = 30;
const ROLLUP_WARM_START_WINDOW_HOURS: i64 = 24;
const SQLITE_BUSY_TIMEOUT_MS: u64 = 2_000;

/// Thread-safe dashboard state that layers push updates to
#[derive(Clone)]
pub struct DashboardState {
    inner: Arc<RwLock<Inner>>,
    /// Dedicated shard for high-frequency proxy metrics to reduce lock contention
    proxy: Arc<RwLock<ProxyMetrics>>,
}

struct Inner {
    started_at: Instant,
    identity: IdentityMetrics,
    policy: PolicyMetrics,
    observe: ObserveMetrics,
    budget: BudgetMetrics,
    advanced_budget: AdvancedBudgetMetrics,
    /// Set of unique DIDs seen
    unique_dids: HashSet<String>,
    /// Current date for daily trend tracking
    current_date: String,
}

/// Warm-start summary for rollup bootstrap.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RollupWarmStartSummary {
    pub rows_scanned: usize,
    pub providers_loaded: usize,
    pub requests: u64,
    pub responses: u64,
    pub pii_events: u64,
    pub total_tokens: u64,
    pub total_cost_usd: f64,
}

// --- Identity Panel ---
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IdentityMetrics {
    pub total_verifications: u64,
    pub successful: u64,
    pub failed: u64,
    pub unique_dids: usize,
    pub recent_dids: VecDeque<DidEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidEntry {
    pub did: String,
    pub verified: bool,
    pub last_seen: String,
}

// --- Policy Panel ---
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PolicyMetrics {
    pub evaluations: u64,
    pub allowed: u64,
    pub denied: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub active_version: Option<String>,
    pub recent_denials: VecDeque<DenialEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenialEntry {
    pub timestamp: String,
    pub method: String,
    pub tool: Option<String>,
    pub reason: String,
}

// --- Observe Panel ---
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ObserveMetrics {
    pub requests: u64,
    pub responses: u64,
    pub pii_detections: u64,
    pub pii_by_type: HashMap<String, u64>,
}

// --- Budget Panel ---
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BudgetMetrics {
    pub total_tokens: u64,
    pub total_cost_usd: f64,
    pub daily_limit_usd: Option<f64>,
    pub cost_by_model: HashMap<String, f64>,
    pub alerts: Vec<BudgetAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetAlert {
    pub level: String,
    pub message: String,
}

// --- Proxy Panel ---
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProxyMetrics {
    /// Total requests intercepted
    pub total_requests: u64,
    /// Total responses processed
    pub total_responses: u64,
    /// Active connections
    pub active_connections: u64,
    /// Requests by provider
    pub requests_by_provider: HashMap<String, u64>,
    /// Token usage by provider (input, output)
    pub tokens_by_provider: HashMap<String, ProviderTokens>,
    /// Cost by provider
    pub cost_by_provider: HashMap<String, f64>,
    /// Total tokens (all providers)
    pub total_tokens: u64,
    /// Total cost (all providers)
    pub total_cost_usd: f64,
    /// Recent proxy requests
    pub recent_requests: VecDeque<ProxyRequestEntry>,
    /// Proxy status
    pub status: ProxyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderTokens {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRequestEntry {
    pub request_id: Option<String>,
    pub timestamp: String,
    pub provider: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub status_code: Option<u16>,
    pub latency_ms: Option<u64>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyStatus {
    pub enabled: bool,
    pub listen_address: Option<String>,
    pub ca_installed: bool,
}

/// Canonical budget primitives derived from proxy + budget state.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BudgetPrimitives {
    pub total_requests: u64,
    pub total_responses: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
    pub total_cost_usd: f64,
    pub daily_limit_usd: Option<f64>,
    pub utilization_pct: Option<f64>,
    pub alerts: Vec<BudgetAlert>,
    pub provider_breakdown: Vec<ProviderBudgetPrimitive>,
    pub recent_requests: Vec<BudgetRequestPrimitive>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProviderBudgetPrimitive {
    pub provider: String,
    pub request_count: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub total_cost_usd: f64,
    pub avg_cost_per_request: f64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BudgetRequestPrimitive {
    pub request_id: Option<String>,
    pub timestamp: String,
    pub provider: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub model: Option<String>,
    pub status_code: Option<u16>,
    pub latency_ms: Option<u64>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cost_usd: f64,
}

// --- Advanced Budget Analytics ---

/// Advanced budget metrics for Developer and CFO views
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AdvancedBudgetMetrics {
    // Basic metrics (existing)
    pub total_tokens: u64,
    pub total_cost_usd: f64,
    pub daily_limit_usd: Option<f64>,
    pub cost_by_model: HashMap<String, f64>,
    pub alerts: Vec<BudgetAlert>,

    // Provider breakdown
    pub cost_by_provider: HashMap<String, ProviderCostBreakdown>,

    // MCP tool costs
    pub cost_by_tool: Vec<ToolCostEntry>,

    // Team/project allocation (from tags)
    pub cost_by_tag: HashMap<String, HashMap<String, f64>>,

    // Daily trend (last 30 days)
    pub daily_trend: VecDeque<DailyTrendPoint>,

    // Cost anomalies
    pub anomalies: Vec<CostAnomalyEntry>,

    // Optimization recommendations
    pub recommendations: Vec<RecommendationEntry>,

    // Request type breakdown
    pub cost_by_request_type: HashMap<String, f64>,
}

/// Provider cost breakdown with model details
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProviderCostBreakdown {
    pub total_cost: f64,
    pub total_tokens: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub request_count: u64,
    pub model_breakdown: HashMap<String, ModelCostEntry>,
}

/// Model cost entry
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ModelCostEntry {
    pub model_name: String,
    pub cost: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub request_count: u64,
    pub avg_cost_per_request: f64,
}

/// MCP tool cost entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCostEntry {
    pub tool_name: String,
    pub server_name: String,
    pub total_cost: f64,
    pub call_count: u64,
    pub avg_cost_per_call: f64,
}

/// Daily trend data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyTrendPoint {
    pub date: String,
    pub cost: f64,
    pub tokens: u64,
    pub requests: u64,
    pub by_provider: HashMap<String, f64>,
}

/// Cost anomaly entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostAnomalyEntry {
    pub id: String,
    pub anomaly_type: String,
    pub severity: String,
    pub description: String,
    pub detected_at: String,
    pub current_value: f64,
    pub expected_value: f64,
}

/// Cost optimization recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendationEntry {
    pub id: String,
    pub recommendation_type: String,
    pub title: String,
    pub description: String,
    pub estimated_savings: f64,
    pub effort: String,
}

impl DashboardState {
    /// Create a new dashboard state
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                started_at: Instant::now(),
                identity: IdentityMetrics::default(),
                policy: PolicyMetrics::default(),
                observe: ObserveMetrics::default(),
                budget: BudgetMetrics::default(),
                advanced_budget: AdvancedBudgetMetrics::default(),
                unique_dids: HashSet::new(),
                current_date: Utc::now().format("%Y-%m-%d").to_string(),
            })),
            proxy: Arc::new(RwLock::new(ProxyMetrics::default())),
        }
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        self.inner.read().started_at.elapsed().as_secs()
    }

    /// Create a new dashboard state and best-effort warm-start from rollups.
    pub fn new_with_rollup_warm_start(db_path: &Path) -> Self {
        let state = Self::new();
        if let Err(error) = state.warm_start_from_rollups(db_path) {
            debug!(
                db_path = %db_path.display(),
                "Warm-start from rollups failed during state init: {}",
                error
            );
        }
        state
    }

    /// Warm-start dashboard metrics from materialized `rollups_1m`.
    ///
    /// This restores recent aggregate state on boot so proxy/budget cards are
    /// immediately meaningful before new live events arrive.
    pub fn warm_start_from_rollups(
        &self,
        db_path: &Path,
    ) -> std::io::Result<RollupWarmStartSummary> {
        if !db_path.exists() {
            return Ok(RollupWarmStartSummary::default());
        }

        let cutoff = (Utc::now() - ChronoDuration::hours(ROLLUP_WARM_START_WINDOW_HOURS))
            .format("%Y-%m-%dT%H:%M:00Z")
            .to_string();

        let conn = Connection::open(db_path).map_err(to_io_error)?;
        conn.busy_timeout(std::time::Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
            .map_err(to_io_error)?;

        let has_rollups: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='rollups_1m'",
                [],
                |row| row.get(0),
            )
            .map_err(to_io_error)?;
        if has_rollups == 0 {
            return Ok(RollupWarmStartSummary::default());
        }

        let (rows_scanned, requests, responses, pii_events, total_tokens, total_cost_usd): (
            i64,
            i64,
            i64,
            i64,
            i64,
            f64,
        ) = conn
            .query_row(
                r#"
                SELECT
                    COUNT(*),
                    COALESCE(SUM(requests), 0),
                    COALESCE(SUM(responses), 0),
                    COALESCE(SUM(pii_events), 0),
                    COALESCE(SUM(total_tokens), 0),
                    COALESCE(SUM(total_cost_usd), 0.0)
                FROM rollups_1m
                WHERE bucket_start >= ?1
                "#,
                params![cutoff],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .map_err(to_io_error)?;

        let mut provider_rows: Vec<(String, u64, u64, f64)> = Vec::new();
        let mut provider_stmt = conn
            .prepare(
                r#"
                SELECT
                    provider,
                    COALESCE(SUM(requests), 0) as requests,
                    COALESCE(SUM(total_tokens), 0) as total_tokens,
                    COALESCE(SUM(total_cost_usd), 0.0) as total_cost_usd
                FROM rollups_1m
                WHERE bucket_start >= ?1
                GROUP BY provider
                ORDER BY total_cost_usd DESC, requests DESC
                "#,
            )
            .map_err(to_io_error)?;
        let rows = provider_stmt
            .query_map(params![cutoff], |row| {
                let provider: String = row.get(0)?;
                Ok((
                    if provider.is_empty() {
                        "unknown".to_string()
                    } else {
                        provider
                    },
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, f64>(3)?,
                ))
            })
            .map_err(to_io_error)?;
        for row in rows {
            provider_rows.push(row.map_err(to_io_error)?);
        }

        let requests = requests.max(0) as u64;
        let responses = responses.max(0) as u64;
        let pii_events = pii_events.max(0) as u64;
        let total_tokens = total_tokens.max(0) as u64;

        {
            let mut inner = self.inner.write();
            inner.observe.requests = requests;
            inner.observe.responses = responses;
            inner.observe.pii_detections = pii_events;
            inner.budget.total_tokens = total_tokens;
            inner.budget.total_cost_usd = total_cost_usd;

            inner.advanced_budget.total_tokens = total_tokens;
            inner.advanced_budget.total_cost_usd = total_cost_usd;
            inner.advanced_budget.cost_by_provider.clear();
            for (provider, request_count, provider_tokens, provider_cost) in provider_rows.iter() {
                inner.advanced_budget.cost_by_provider.insert(
                    provider.clone(),
                    ProviderCostBreakdown {
                        total_cost: *provider_cost,
                        total_tokens: *provider_tokens,
                        input_tokens: 0,
                        output_tokens: *provider_tokens,
                        request_count: *request_count,
                        model_breakdown: HashMap::new(),
                    },
                );
            }
        }

        {
            let mut proxy = self.proxy.write();
            proxy.total_requests = requests;
            proxy.total_responses = responses;
            proxy.total_tokens = total_tokens;
            proxy.total_cost_usd = total_cost_usd;
            proxy.requests_by_provider.clear();
            proxy.tokens_by_provider.clear();
            proxy.cost_by_provider.clear();
            for (provider, request_count, provider_tokens, provider_cost) in provider_rows.iter() {
                proxy
                    .requests_by_provider
                    .insert(provider.clone(), *request_count);
                proxy.tokens_by_provider.insert(
                    provider.clone(),
                    ProviderTokens {
                        input_tokens: 0,
                        output_tokens: *provider_tokens,
                    },
                );
                proxy
                    .cost_by_provider
                    .insert(provider.clone(), *provider_cost);
            }
        }

        Ok(RollupWarmStartSummary {
            rows_scanned: rows_scanned.max(0) as usize,
            providers_loaded: provider_rows.len(),
            requests,
            responses,
            pii_events,
            total_tokens,
            total_cost_usd,
        })
    }

    // --- Update methods (called by layers) ---

    /// Record an identity verification attempt
    pub fn record_identity_verification(&self, did: &str, success: bool) {
        let mut inner = self.inner.write();
        inner.identity.total_verifications += 1;

        if success {
            inner.identity.successful += 1;
        } else {
            inner.identity.failed += 1;
        }

        // Track unique DIDs
        inner.unique_dids.insert(did.to_string());
        inner.identity.unique_dids = inner.unique_dids.len();

        // Add to recent DIDs
        let entry = DidEntry {
            did: did.to_string(),
            verified: success,
            last_seen: Utc::now().to_rfc3339(),
        };

        // Remove existing entry for same DID if present
        inner.identity.recent_dids.retain(|e| e.did != did);

        // Add to front
        inner.identity.recent_dids.push_front(entry);

        // Trim to max size
        while inner.identity.recent_dids.len() > MAX_RECENT_ENTRIES {
            inner.identity.recent_dids.pop_back();
        }
    }

    /// Record a policy evaluation
    pub fn record_policy_evaluation(&self, allowed: bool, denial: Option<DenialEntry>) {
        let mut inner = self.inner.write();
        inner.policy.evaluations += 1;

        if allowed {
            inner.policy.allowed += 1;
        } else {
            inner.policy.denied += 1;

            // Add denial to recent list
            if let Some(entry) = denial {
                inner.policy.recent_denials.push_front(entry);
                while inner.policy.recent_denials.len() > MAX_RECENT_ENTRIES {
                    inner.policy.recent_denials.pop_back();
                }
            }
        }
    }

    /// Record a cache access
    pub fn record_cache_access(&self, hit: bool) {
        let mut inner = self.inner.write();
        if hit {
            inner.policy.cache_hits += 1;
        } else {
            inner.policy.cache_misses += 1;
        }
    }

    /// Set the active policy version reported by runtime evaluation paths.
    pub fn set_policy_active_version(&self, version: impl Into<String>) {
        let mut inner = self.inner.write();
        inner.policy.active_version = Some(version.into());
    }

    /// Record a request
    pub fn record_request(&self) {
        let mut inner = self.inner.write();
        inner.observe.requests += 1;
    }

    /// Record a response
    pub fn record_response(&self) {
        let mut inner = self.inner.write();
        inner.observe.responses += 1;
    }

    /// Record PII detection
    pub fn record_pii_detection(&self, pii_type: &str) {
        let mut inner = self.inner.write();
        inner.observe.pii_detections += 1;
        *inner
            .observe
            .pii_by_type
            .entry(pii_type.to_string())
            .or_insert(0) += 1;
    }

    /// Record token usage
    pub fn record_token_usage(&self, model: &str, tokens: u64, cost: f64) {
        let mut inner = self.inner.write();
        inner.budget.total_tokens += tokens;
        inner.budget.total_cost_usd += cost;
        *inner
            .budget
            .cost_by_model
            .entry(model.to_string())
            .or_insert(0.0) += cost;
    }

    /// Set the daily budget limit (for display)
    pub fn set_daily_limit(&self, limit: Option<f64>) {
        let mut inner = self.inner.write();
        inner.budget.daily_limit_usd = limit;
    }

    /// Set a budget alert
    pub fn set_budget_alert(&self, alert: BudgetAlert) {
        let mut inner = self.inner.write();
        // Only keep the most recent alerts (up to 5)
        inner.budget.alerts.push(alert);
        if inner.budget.alerts.len() > 5 {
            inner.budget.alerts.remove(0);
        }
    }

    /// Clear budget alerts
    pub fn clear_budget_alerts(&self) {
        let mut inner = self.inner.write();
        inner.budget.alerts.clear();
    }

    // --- Proxy methods (called by proxy transport runtime) ---

    /// Record a proxy request starting
    pub fn record_proxy_request(
        &self,
        request_id: Option<&str>,
        provider: &str,
        host: &str,
        method: &str,
        path: &str,
    ) {
        let mut proxy = self.proxy.write();
        proxy.total_requests += 1;
        proxy.active_connections += 1;

        *proxy
            .requests_by_provider
            .entry(provider.to_string())
            .or_insert(0) += 1;

        // Add to recent requests
        let entry = ProxyRequestEntry {
            request_id: request_id.map(|id| id.to_string()),
            timestamp: Utc::now().to_rfc3339(),
            provider: provider.to_string(),
            host: host.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            status_code: None,
            latency_ms: None,
            input_tokens: None,
            output_tokens: None,
            cost_usd: None,
            model: None,
        };

        proxy.recent_requests.push_front(entry);
        while proxy.recent_requests.len() > MAX_RECENT_PROXY_REQUESTS {
            proxy.recent_requests.pop_back();
        }
    }

    /// Record a proxy response
    pub fn record_proxy_response(
        &self,
        request_id: Option<&str>,
        provider: &str,
        status_code: u16,
        latency_ms: u64,
        model: Option<&str>,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        cost_usd: Option<f64>,
    ) {
        let mut proxy = self.proxy.write();
        proxy.total_responses += 1;

        if proxy.active_connections > 0 {
            proxy.active_connections -= 1;
        }

        // Update tokens by provider (accept partial usage if one side is missing).
        let input = input_tokens.unwrap_or(0);
        let output = output_tokens.unwrap_or(0);
        if input > 0 || output > 0 {
            let tokens = proxy
                .tokens_by_provider
                .entry(provider.to_string())
                .or_default();
            tokens.input_tokens += input;
            tokens.output_tokens += output;
            proxy.total_tokens += input + output;
        }

        // Update cost by provider
        if let Some(cost) = cost_usd {
            *proxy
                .cost_by_provider
                .entry(provider.to_string())
                .or_insert(0.0) += cost;
            proxy.total_cost_usd += cost;
        }

        // Update matching pending request by request_id first, then provider fallback.
        let match_index = request_id
            .and_then(|request_id| {
                proxy.recent_requests.iter().position(|entry| {
                    entry.request_id.as_deref() == Some(request_id) && entry.status_code.is_none()
                })
            })
            .or_else(|| {
                proxy
                    .recent_requests
                    .iter()
                    .position(|entry| entry.provider == provider && entry.status_code.is_none())
            });

        if let Some(index) = match_index {
            let entry = proxy
                .recent_requests
                .get_mut(index)
                .expect("index returned by position must exist");
            entry.status_code = Some(status_code);
            entry.latency_ms = Some(latency_ms);
            entry.input_tokens = input_tokens;
            entry.output_tokens = output_tokens;
            entry.cost_usd = cost_usd;
            entry.model = model.map(|s| s.to_string());
        }
    }

    /// Update proxy status
    pub fn set_proxy_status(
        &self,
        enabled: bool,
        listen_address: Option<&str>,
        ca_installed: bool,
    ) {
        let mut proxy = self.proxy.write();
        proxy.status.enabled = enabled;
        proxy.status.listen_address = listen_address.map(|s| s.to_string());
        proxy.status.ca_installed = ca_installed;
    }

    /// Decrement active connections (for error cases)
    pub fn decrement_proxy_connections(&self) {
        let mut proxy = self.proxy.write();
        if proxy.active_connections > 0 {
            proxy.active_connections -= 1;
        }
    }

    // --- Read methods (called by API) ---

    /// Get identity metrics
    pub fn identity(&self) -> IdentityMetrics {
        self.inner.read().identity.clone()
    }

    /// Get policy metrics
    pub fn policy(&self) -> PolicyMetrics {
        self.inner.read().policy.clone()
    }

    /// Get observe metrics
    pub fn observe(&self) -> ObserveMetrics {
        self.inner.read().observe.clone()
    }

    /// Get budget metrics
    pub fn budget(&self) -> BudgetMetrics {
        self.inner.read().budget.clone()
    }

    /// Get proxy metrics
    pub fn proxy(&self) -> ProxyMetrics {
        self.proxy.read().clone()
    }

    /// Get canonical budget primitives shared by Budget and Observability.
    pub fn budget_primitives(&self) -> BudgetPrimitives {
        let proxy = self.proxy();
        let budget = self.budget();

        let total_input_tokens: u64 = proxy
            .tokens_by_provider
            .values()
            .map(|tokens| tokens.input_tokens)
            .sum();
        let total_output_tokens: u64 = proxy
            .tokens_by_provider
            .values()
            .map(|tokens| tokens.output_tokens)
            .sum();

        let provider_set: HashSet<String> = proxy
            .requests_by_provider
            .keys()
            .chain(proxy.tokens_by_provider.keys())
            .chain(proxy.cost_by_provider.keys())
            .cloned()
            .collect();

        let mut provider_breakdown: Vec<ProviderBudgetPrimitive> = provider_set
            .into_iter()
            .map(|provider| {
                let request_count = proxy
                    .requests_by_provider
                    .get(&provider)
                    .copied()
                    .unwrap_or_default();
                let token_usage = proxy
                    .tokens_by_provider
                    .get(&provider)
                    .cloned()
                    .unwrap_or_default();
                let total_cost = proxy
                    .cost_by_provider
                    .get(&provider)
                    .copied()
                    .unwrap_or_default();
                let total_tokens = token_usage.input_tokens + token_usage.output_tokens;
                let avg_cost_per_request = if request_count > 0 {
                    total_cost / request_count as f64
                } else {
                    0.0
                };

                ProviderBudgetPrimitive {
                    provider,
                    request_count,
                    input_tokens: token_usage.input_tokens,
                    output_tokens: token_usage.output_tokens,
                    total_tokens,
                    total_cost_usd: total_cost,
                    avg_cost_per_request,
                }
            })
            .collect();

        provider_breakdown.sort_by(|a, b| {
            b.total_cost_usd
                .partial_cmp(&a.total_cost_usd)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.request_count.cmp(&a.request_count))
                .then_with(|| a.provider.cmp(&b.provider))
        });

        let recent_requests: Vec<BudgetRequestPrimitive> = proxy
            .recent_requests
            .iter()
            .map(|entry| {
                let input_tokens = entry.input_tokens.unwrap_or(0);
                let output_tokens = entry.output_tokens.unwrap_or(0);
                BudgetRequestPrimitive {
                    request_id: entry.request_id.clone(),
                    timestamp: entry.timestamp.clone(),
                    provider: entry.provider.clone(),
                    host: entry.host.clone(),
                    method: entry.method.clone(),
                    path: entry.path.clone(),
                    model: entry.model.clone(),
                    status_code: entry.status_code,
                    latency_ms: entry.latency_ms,
                    input_tokens,
                    output_tokens,
                    total_tokens: input_tokens + output_tokens,
                    cost_usd: entry.cost_usd.unwrap_or(0.0),
                }
            })
            .collect();

        let utilization_pct = budget.daily_limit_usd.and_then(|limit| {
            if limit > 0.0 {
                Some((proxy.total_cost_usd / limit) * 100.0)
            } else {
                None
            }
        });

        BudgetPrimitives {
            total_requests: proxy.total_requests,
            total_responses: proxy.total_responses,
            total_input_tokens,
            total_output_tokens,
            total_tokens: proxy.total_tokens,
            total_cost_usd: proxy.total_cost_usd,
            daily_limit_usd: budget.daily_limit_usd,
            utilization_pct,
            alerts: budget.alerts,
            provider_breakdown,
            recent_requests,
        }
    }

    /// Get advanced budget metrics
    pub fn advanced_budget(&self) -> AdvancedBudgetMetrics {
        self.inner.read().advanced_budget.clone()
    }

    // --- Advanced Budget Methods ---

    /// Record advanced token usage with provider and model breakdown
    pub fn record_advanced_token_usage(
        &self,
        provider: &str,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
        cost: f64,
        request_type: &str,
    ) {
        let mut inner = self.inner.write();

        // Update basic metrics
        inner.budget.total_tokens += input_tokens + output_tokens;
        inner.budget.total_cost_usd += cost;
        *inner
            .budget
            .cost_by_model
            .entry(model.to_string())
            .or_insert(0.0) += cost;

        // Update advanced metrics
        inner.advanced_budget.total_tokens += input_tokens + output_tokens;
        inner.advanced_budget.total_cost_usd += cost;
        *inner
            .advanced_budget
            .cost_by_model
            .entry(model.to_string())
            .or_insert(0.0) += cost;

        // Update provider breakdown
        let provider_breakdown = inner
            .advanced_budget
            .cost_by_provider
            .entry(provider.to_string())
            .or_default();
        provider_breakdown.total_cost += cost;
        provider_breakdown.total_tokens += input_tokens + output_tokens;
        provider_breakdown.input_tokens += input_tokens;
        provider_breakdown.output_tokens += output_tokens;
        provider_breakdown.request_count += 1;

        // Update model breakdown within provider
        let model_entry = provider_breakdown
            .model_breakdown
            .entry(model.to_string())
            .or_default();
        model_entry.model_name = model.to_string();
        model_entry.cost += cost;
        model_entry.input_tokens += input_tokens;
        model_entry.output_tokens += output_tokens;
        model_entry.request_count += 1;
        model_entry.avg_cost_per_request = model_entry.cost / model_entry.request_count as f64;

        // Update request type breakdown
        *inner
            .advanced_budget
            .cost_by_request_type
            .entry(request_type.to_string())
            .or_insert(0.0) += cost;

        // Update daily trend
        let today = Utc::now().format("%Y-%m-%d").to_string();
        if inner.current_date != today {
            inner.current_date = today.clone();
        }

        // Find or create today's trend point
        if let Some(today_point) = inner.advanced_budget.daily_trend.front_mut() {
            if today_point.date == today {
                today_point.cost += cost;
                today_point.tokens += input_tokens + output_tokens;
                today_point.requests += 1;
                *today_point
                    .by_provider
                    .entry(provider.to_string())
                    .or_insert(0.0) += cost;
            } else {
                // New day, create new point
                let mut by_provider = HashMap::new();
                by_provider.insert(provider.to_string(), cost);
                inner
                    .advanced_budget
                    .daily_trend
                    .push_front(DailyTrendPoint {
                        date: today,
                        cost,
                        tokens: input_tokens + output_tokens,
                        requests: 1,
                        by_provider,
                    });

                // Trim to max size
                while inner.advanced_budget.daily_trend.len() > MAX_DAILY_TREND_POINTS {
                    inner.advanced_budget.daily_trend.pop_back();
                }
            }
        } else {
            // First data point
            let mut by_provider = HashMap::new();
            by_provider.insert(provider.to_string(), cost);
            inner
                .advanced_budget
                .daily_trend
                .push_front(DailyTrendPoint {
                    date: today,
                    cost,
                    tokens: input_tokens + output_tokens,
                    requests: 1,
                    by_provider,
                });
        }
    }

    /// Record MCP tool cost attribution
    pub fn record_mcp_tool_cost(&self, tool_name: &str, server_name: &str, cost: f64) {
        let mut inner = self.inner.write();

        // Find existing tool entry or create new one
        if let Some(entry) = inner
            .advanced_budget
            .cost_by_tool
            .iter_mut()
            .find(|e| e.tool_name == tool_name && e.server_name == server_name)
        {
            entry.total_cost += cost;
            entry.call_count += 1;
            entry.avg_cost_per_call = entry.total_cost / entry.call_count as f64;
        } else {
            inner.advanced_budget.cost_by_tool.push(ToolCostEntry {
                tool_name: tool_name.to_string(),
                server_name: server_name.to_string(),
                total_cost: cost,
                call_count: 1,
                avg_cost_per_call: cost,
            });
        }

        // Sort by total cost descending
        inner.advanced_budget.cost_by_tool.sort_by(|a, b| {
            b.total_cost
                .partial_cmp(&a.total_cost)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Keep top 50 tools
        inner.advanced_budget.cost_by_tool.truncate(50);
    }

    /// Record a cost tag
    pub fn record_cost_tag(&self, tag_key: &str, tag_value: &str, cost: f64) {
        let mut inner = self.inner.write();
        let tag_map = inner
            .advanced_budget
            .cost_by_tag
            .entry(tag_key.to_string())
            .or_default();
        *tag_map.entry(tag_value.to_string()).or_insert(0.0) += cost;
    }

    /// Add a cost anomaly
    pub fn add_anomaly(&self, anomaly: CostAnomalyEntry) {
        let mut inner = self.inner.write();
        inner.advanced_budget.anomalies.push(anomaly);

        // Keep only recent anomalies (last 20)
        if inner.advanced_budget.anomalies.len() > 20 {
            inner.advanced_budget.anomalies.remove(0);
        }
    }

    /// Clear anomalies
    pub fn clear_anomalies(&self) {
        let mut inner = self.inner.write();
        inner.advanced_budget.anomalies.clear();
    }

    /// Set recommendations
    pub fn set_recommendations(&self, recommendations: Vec<RecommendationEntry>) {
        let mut inner = self.inner.write();
        inner.advanced_budget.recommendations = recommendations;
    }

    /// Update daily limit for advanced metrics
    pub fn set_advanced_daily_limit(&self, limit: Option<f64>) {
        let mut inner = self.inner.write();
        inner.advanced_budget.daily_limit_usd = limit;
    }

    /// Set advanced budget alerts
    pub fn set_advanced_alerts(&self, alerts: Vec<BudgetAlert>) {
        let mut inner = self.inner.write();
        inner.advanced_budget.alerts = alerts;
    }
}

impl Default for DashboardState {
    fn default() -> Self {
        Self::new()
    }
}

fn to_io_error(error: rusqlite::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};
    use tempfile::tempdir;

    #[test]
    fn test_identity_metrics() {
        let state = DashboardState::new();

        state.record_identity_verification("did:key:z123", true);
        state.record_identity_verification("did:key:z456", false);
        state.record_identity_verification("did:key:z123", true);

        let metrics = state.identity();
        assert_eq!(metrics.total_verifications, 3);
        assert_eq!(metrics.successful, 2);
        assert_eq!(metrics.failed, 1);
        assert_eq!(metrics.unique_dids, 2);
        assert_eq!(metrics.recent_dids.len(), 2);
    }

    #[test]
    fn test_policy_metrics() {
        let state = DashboardState::new();

        state.record_policy_evaluation(true, None);
        state.record_policy_evaluation(
            false,
            Some(DenialEntry {
                timestamp: Utc::now().to_rfc3339(),
                method: "tools/call".to_string(),
                tool: Some("dangerous_tool".to_string()),
                reason: "Access denied".to_string(),
            }),
        );

        let metrics = state.policy();
        assert_eq!(metrics.evaluations, 2);
        assert_eq!(metrics.allowed, 1);
        assert_eq!(metrics.denied, 1);
        assert_eq!(metrics.recent_denials.len(), 1);
    }

    #[test]
    fn test_cache_metrics() {
        let state = DashboardState::new();

        state.record_cache_access(true);
        state.record_cache_access(true);
        state.record_cache_access(false);

        let metrics = state.policy();
        assert_eq!(metrics.cache_hits, 2);
        assert_eq!(metrics.cache_misses, 1);
    }

    #[test]
    fn test_policy_active_version() {
        let state = DashboardState::new();
        state.set_policy_active_version("v9");
        let metrics = state.policy();
        assert_eq!(metrics.active_version.as_deref(), Some("v9"));
    }

    #[test]
    fn test_observe_metrics() {
        let state = DashboardState::new();

        state.record_request();
        state.record_request();
        state.record_response();
        state.record_pii_detection("email");
        state.record_pii_detection("ssn");
        state.record_pii_detection("email");

        let metrics = state.observe();
        assert_eq!(metrics.requests, 2);
        assert_eq!(metrics.responses, 1);
        assert_eq!(metrics.pii_detections, 3);
        assert_eq!(metrics.pii_by_type.get("email"), Some(&2));
        assert_eq!(metrics.pii_by_type.get("ssn"), Some(&1));
    }

    #[test]
    fn test_budget_metrics() {
        let state = DashboardState::new();

        state.record_token_usage("gpt-4o", 1000, 0.05);
        state.record_token_usage("gpt-4o", 500, 0.025);
        state.record_token_usage("claude-3", 2000, 0.08);

        let metrics = state.budget();
        assert_eq!(metrics.total_tokens, 3500);
        assert!((metrics.total_cost_usd - 0.155).abs() < 0.001);
        assert!((metrics.cost_by_model.get("gpt-4o").unwrap() - 0.075).abs() < 0.001);
    }

    #[test]
    fn test_budget_alerts() {
        let state = DashboardState::new();

        state.set_budget_alert(BudgetAlert {
            level: "warning".to_string(),
            message: "80% budget used".to_string(),
        });

        let metrics = state.budget();
        assert_eq!(metrics.alerts.len(), 1);
        assert_eq!(metrics.alerts[0].level, "warning");
    }

    #[test]
    fn test_warm_start_from_rollups_populates_proxy_and_budget_metrics() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE rollups_1m (
                bucket_start TEXT NOT NULL,
                source TEXT NOT NULL,
                provider TEXT NOT NULL,
                agent TEXT NOT NULL,
                total_events INTEGER NOT NULL DEFAULT 0,
                requests INTEGER NOT NULL DEFAULT 0,
                responses INTEGER NOT NULL DEFAULT 0,
                error_events INTEGER NOT NULL DEFAULT 0,
                pii_events INTEGER NOT NULL DEFAULT 0,
                total_tokens INTEGER NOT NULL DEFAULT 0,
                total_cost_usd REAL NOT NULL DEFAULT 0.0,
                PRIMARY KEY (bucket_start, source, provider, agent)
            );
            "#,
        )
        .unwrap();

        let now = Utc::now();
        let recent_bucket = (now - chrono::Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:00Z")
            .to_string();
        let old_bucket = (now - chrono::Duration::hours(40))
            .format("%Y-%m-%dT%H:%M:00Z")
            .to_string();

        conn.execute(
            r#"
            INSERT INTO rollups_1m (
                bucket_start, source, provider, agent,
                total_events, requests, responses, error_events, pii_events,
                total_tokens, total_cost_usd
            )
            VALUES (?1, 'ai_proxy', 'openai', 'codex', 5, 5, 4, 0, 1, 1000, 1.25)
            "#,
            params![recent_bucket],
        )
        .unwrap();
        conn.execute(
            r#"
            INSERT INTO rollups_1m (
                bucket_start, source, provider, agent,
                total_events, requests, responses, error_events, pii_events,
                total_tokens, total_cost_usd
            )
            VALUES (?1, 'ai_proxy', 'anthropic', 'claude', 3, 3, 3, 0, 0, 700, 0.95)
            "#,
            params![recent_bucket],
        )
        .unwrap();
        conn.execute(
            r#"
            INSERT INTO rollups_1m (
                bucket_start, source, provider, agent,
                total_events, requests, responses, error_events, pii_events,
                total_tokens, total_cost_usd
            )
            VALUES (?1, 'ai_proxy', 'openai', 'codex', 10, 10, 9, 0, 2, 2000, 3.50)
            "#,
            params![old_bucket],
        )
        .unwrap();

        let state = DashboardState::new();
        let summary = state.warm_start_from_rollups(&db_path).unwrap();
        assert_eq!(summary.rows_scanned, 2);
        assert_eq!(summary.providers_loaded, 2);
        assert_eq!(summary.requests, 8);
        assert_eq!(summary.responses, 7);
        assert_eq!(summary.pii_events, 1);
        assert_eq!(summary.total_tokens, 1700);
        assert!((summary.total_cost_usd - 2.20).abs() < 0.0001);

        let observe = state.observe();
        assert_eq!(observe.requests, 8);
        assert_eq!(observe.responses, 7);
        assert_eq!(observe.pii_detections, 1);

        let budget = state.budget();
        assert_eq!(budget.total_tokens, 1700);
        assert!((budget.total_cost_usd - 2.20).abs() < 0.0001);

        let proxy = state.proxy();
        assert_eq!(proxy.total_requests, 8);
        assert_eq!(proxy.total_responses, 7);
        assert_eq!(proxy.total_tokens, 1700);
        assert!((proxy.total_cost_usd - 2.20).abs() < 0.0001);
        assert_eq!(proxy.requests_by_provider.get("openai"), Some(&5));
        assert_eq!(proxy.requests_by_provider.get("anthropic"), Some(&3));

        let tokens_openai = proxy.tokens_by_provider.get("openai").unwrap();
        assert_eq!(tokens_openai.input_tokens, 0);
        assert_eq!(tokens_openai.output_tokens, 1000);
    }

    #[test]
    fn test_warm_start_from_rollups_without_table_is_noop() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");
        Connection::open(&db_path).unwrap();

        let state = DashboardState::new();
        let summary = state.warm_start_from_rollups(&db_path).unwrap();

        assert_eq!(summary.rows_scanned, 0);
        assert_eq!(state.proxy().total_requests, 0);
        assert_eq!(state.budget().total_tokens, 0);
    }

    #[test]
    fn test_proxy_metrics() {
        let state = DashboardState::new();

        // Record a request
        state.record_proxy_request(
            Some("req-openai-1"),
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
        );

        let metrics = state.proxy();
        assert_eq!(metrics.total_requests, 1);
        assert_eq!(metrics.active_connections, 1);
        assert_eq!(metrics.requests_by_provider.get("openai"), Some(&1));
        assert_eq!(metrics.recent_requests.len(), 1);

        // Record response with usage
        state.record_proxy_response(
            Some("req-openai-1"),
            "openai",
            200,
            150,
            Some("gpt-4o"),
            Some(100),
            Some(50),
            Some(0.015),
        );

        let metrics = state.proxy();
        assert_eq!(metrics.total_responses, 1);
        assert_eq!(metrics.active_connections, 0);
        assert_eq!(metrics.total_tokens, 150);
        assert!((metrics.total_cost_usd - 0.015).abs() < 0.001);

        let tokens = metrics.tokens_by_provider.get("openai").unwrap();
        assert_eq!(tokens.input_tokens, 100);
        assert_eq!(tokens.output_tokens, 50);
    }

    #[test]
    fn test_proxy_status() {
        let state = DashboardState::new();

        state.set_proxy_status(true, Some("127.0.0.1:8080"), true);

        let metrics = state.proxy();
        assert!(metrics.status.enabled);
        assert_eq!(
            metrics.status.listen_address,
            Some("127.0.0.1:8080".to_string())
        );
        assert!(metrics.status.ca_installed);
    }

    #[test]
    fn test_proxy_response_updates_matching_pending_provider() {
        let state = DashboardState::new();

        state.record_proxy_request(
            Some("req-openai-2"),
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
        );
        state.record_proxy_request(
            Some("req-anthropic-1"),
            "anthropic",
            "api.anthropic.com",
            "POST",
            "/v1/messages",
        );

        // Response arrives for an older request (openai), not the front entry.
        state.record_proxy_response(
            Some("req-openai-2"),
            "openai",
            200,
            123,
            Some("gpt-4o"),
            Some(10),
            Some(20),
            Some(0.01),
        );

        let metrics = state.proxy();
        let openai_entry = metrics
            .recent_requests
            .iter()
            .find(|entry| entry.provider == "openai")
            .expect("openai request entry should exist");
        let anthropic_entry = metrics
            .recent_requests
            .iter()
            .find(|entry| entry.provider == "anthropic")
            .expect("anthropic request entry should exist");

        assert_eq!(openai_entry.status_code, Some(200));
        assert_eq!(anthropic_entry.status_code, None);
    }

    #[test]
    fn test_budget_primitives_from_proxy_metrics() {
        let state = DashboardState::new();
        state.set_daily_limit(Some(10.0));
        state.set_budget_alert(BudgetAlert {
            level: "warning".to_string(),
            message: "usage above 80%".to_string(),
        });

        state.record_proxy_request(
            Some("req-budget-1"),
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
        );
        state.record_proxy_response(
            Some("req-budget-1"),
            "openai",
            200,
            100,
            Some("gpt-4o"),
            Some(120),
            Some(80),
            Some(0.02),
        );

        let primitives = state.budget_primitives();
        assert_eq!(primitives.total_requests, 1);
        assert_eq!(primitives.total_responses, 1);
        assert_eq!(primitives.total_input_tokens, 120);
        assert_eq!(primitives.total_output_tokens, 80);
        assert_eq!(primitives.total_tokens, 200);
        assert!((primitives.total_cost_usd - 0.02).abs() < 0.0001);
        assert_eq!(primitives.daily_limit_usd, Some(10.0));
        assert_eq!(primitives.alerts.len(), 1);
        assert_eq!(primitives.provider_breakdown.len(), 1);
        assert_eq!(primitives.provider_breakdown[0].provider, "openai");
        assert_eq!(primitives.provider_breakdown[0].input_tokens, 120);
        assert_eq!(primitives.provider_breakdown[0].output_tokens, 80);
        assert_eq!(primitives.recent_requests.len(), 1);
        assert_eq!(primitives.recent_requests[0].cost_usd, 0.02);
    }
}
