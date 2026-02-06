//! Dashboard state - thread-safe metrics sink

use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

/// Maximum number of recent entries to keep
const MAX_RECENT_ENTRIES: usize = 10;

/// Maximum number of recent proxy requests to keep
const MAX_RECENT_PROXY_REQUESTS: usize = 50;

/// Maximum number of daily trend points to keep
const MAX_DAILY_TREND_POINTS: usize = 30;

/// Thread-safe dashboard state that layers push updates to
#[derive(Clone)]
pub struct DashboardState {
    inner: Arc<RwLock<Inner>>,
}

struct Inner {
    started_at: Instant,
    identity: IdentityMetrics,
    policy: PolicyMetrics,
    observe: ObserveMetrics,
    budget: BudgetMetrics,
    proxy: ProxyMetrics,
    advanced_budget: AdvancedBudgetMetrics,
    /// Set of unique DIDs seen
    unique_dids: HashSet<String>,
    /// Current date for daily trend tracking
    current_date: String,
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
                proxy: ProxyMetrics::default(),
                advanced_budget: AdvancedBudgetMetrics::default(),
                unique_dids: HashSet::new(),
                current_date: Utc::now().format("%Y-%m-%d").to_string(),
            })),
        }
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        self.inner.read().started_at.elapsed().as_secs()
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

    // --- Proxy methods (called by ForwardProxyTransport) ---

    /// Record a proxy request starting
    pub fn record_proxy_request(&self, provider: &str, host: &str, method: &str, path: &str) {
        let mut inner = self.inner.write();
        inner.proxy.total_requests += 1;
        inner.proxy.active_connections += 1;

        *inner
            .proxy
            .requests_by_provider
            .entry(provider.to_string())
            .or_insert(0) += 1;

        // Add to recent requests
        let entry = ProxyRequestEntry {
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

        inner.proxy.recent_requests.push_front(entry);
        while inner.proxy.recent_requests.len() > MAX_RECENT_PROXY_REQUESTS {
            inner.proxy.recent_requests.pop_back();
        }
    }

    /// Record a proxy response
    pub fn record_proxy_response(
        &self,
        provider: &str,
        status_code: u16,
        latency_ms: u64,
        model: Option<&str>,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        cost_usd: Option<f64>,
    ) {
        let mut inner = self.inner.write();
        inner.proxy.total_responses += 1;

        if inner.proxy.active_connections > 0 {
            inner.proxy.active_connections -= 1;
        }

        // Update tokens by provider
        if let (Some(input), Some(output)) = (input_tokens, output_tokens) {
            let tokens = inner
                .proxy
                .tokens_by_provider
                .entry(provider.to_string())
                .or_default();
            tokens.input_tokens += input;
            tokens.output_tokens += output;
            inner.proxy.total_tokens += input + output;
        }

        // Update cost by provider
        if let Some(cost) = cost_usd {
            *inner
                .proxy
                .cost_by_provider
                .entry(provider.to_string())
                .or_insert(0.0) += cost;
            inner.proxy.total_cost_usd += cost;
        }

        // Update most recent request with response data
        if let Some(entry) = inner.proxy.recent_requests.front_mut() {
            if entry.provider == provider && entry.status_code.is_none() {
                entry.status_code = Some(status_code);
                entry.latency_ms = Some(latency_ms);
                entry.input_tokens = input_tokens;
                entry.output_tokens = output_tokens;
                entry.cost_usd = cost_usd;
                entry.model = model.map(|s| s.to_string());
            }
        }
    }

    /// Update proxy status
    pub fn set_proxy_status(&self, enabled: bool, listen_address: Option<&str>, ca_installed: bool) {
        let mut inner = self.inner.write();
        inner.proxy.status.enabled = enabled;
        inner.proxy.status.listen_address = listen_address.map(|s| s.to_string());
        inner.proxy.status.ca_installed = ca_installed;
    }

    /// Decrement active connections (for error cases)
    pub fn decrement_proxy_connections(&self) {
        let mut inner = self.inner.write();
        if inner.proxy.active_connections > 0 {
            inner.proxy.active_connections -= 1;
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
        self.inner.read().proxy.clone()
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
        *inner.budget.cost_by_model.entry(model.to_string()).or_insert(0.0) += cost;

        // Update advanced metrics
        inner.advanced_budget.total_tokens += input_tokens + output_tokens;
        inner.advanced_budget.total_cost_usd += cost;
        *inner.advanced_budget.cost_by_model.entry(model.to_string()).or_insert(0.0) += cost;

        // Update provider breakdown
        let provider_breakdown = inner.advanced_budget.cost_by_provider
            .entry(provider.to_string())
            .or_default();
        provider_breakdown.total_cost += cost;
        provider_breakdown.total_tokens += input_tokens + output_tokens;
        provider_breakdown.input_tokens += input_tokens;
        provider_breakdown.output_tokens += output_tokens;
        provider_breakdown.request_count += 1;

        // Update model breakdown within provider
        let model_entry = provider_breakdown.model_breakdown
            .entry(model.to_string())
            .or_default();
        model_entry.model_name = model.to_string();
        model_entry.cost += cost;
        model_entry.input_tokens += input_tokens;
        model_entry.output_tokens += output_tokens;
        model_entry.request_count += 1;
        model_entry.avg_cost_per_request = model_entry.cost / model_entry.request_count as f64;

        // Update request type breakdown
        *inner.advanced_budget.cost_by_request_type
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
                *today_point.by_provider.entry(provider.to_string()).or_insert(0.0) += cost;
            } else {
                // New day, create new point
                let mut by_provider = HashMap::new();
                by_provider.insert(provider.to_string(), cost);
                inner.advanced_budget.daily_trend.push_front(DailyTrendPoint {
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
            inner.advanced_budget.daily_trend.push_front(DailyTrendPoint {
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
        if let Some(entry) = inner.advanced_budget.cost_by_tool
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
            b.total_cost.partial_cmp(&a.total_cost).unwrap_or(std::cmp::Ordering::Equal)
        });

        // Keep top 50 tools
        inner.advanced_budget.cost_by_tool.truncate(50);
    }

    /// Record a cost tag
    pub fn record_cost_tag(&self, tag_key: &str, tag_value: &str, cost: f64) {
        let mut inner = self.inner.write();
        let tag_map = inner.advanced_budget.cost_by_tag
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_proxy_metrics() {
        let state = DashboardState::new();

        // Record a request
        state.record_proxy_request("openai", "api.openai.com", "POST", "/v1/chat/completions");

        let metrics = state.proxy();
        assert_eq!(metrics.total_requests, 1);
        assert_eq!(metrics.active_connections, 1);
        assert_eq!(metrics.requests_by_provider.get("openai"), Some(&1));
        assert_eq!(metrics.recent_requests.len(), 1);

        // Record response with usage
        state.record_proxy_response("openai", 200, 150, Some("gpt-4o"), Some(100), Some(50), Some(0.015));

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
        assert_eq!(metrics.status.listen_address, Some("127.0.0.1:8080".to_string()));
        assert!(metrics.status.ca_installed);
    }
}
