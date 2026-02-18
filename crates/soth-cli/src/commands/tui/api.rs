//! API client for fetching dashboard data

use anyhow::Result;
use serde::Deserialize;
use soth_core::types::WrapEvent;
use soth_dashboard::event_store::AgentStats;
use soth_dashboard::state::{
    BudgetPrimitives, IdentityMetrics, ObserveMetrics, PolicyMetrics, ProxyMetrics,
};

/// API response wrapper
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ApiResponse<T> {
    pub timestamp: String,
    pub uptime_secs: u64,
    pub data: T,
}

/// Events summary from the API
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct EventsSummary {
    pub total_events: usize,
    pub events: Vec<WrapEvent>,
}

/// Agents summary from the API
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AgentsSummary {
    pub total_agents: usize,
    pub agents: Vec<AgentStats>,
}

/// Snapshot payload from /api/snapshot.
#[derive(Debug, Deserialize)]
pub struct DashboardSnapshot {
    pub identity: IdentityMetrics,
    pub policy: PolicyMetrics,
    pub observe: ObserveMetrics,
    pub proxy: ProxyMetrics,
}

/// Materialized request/response cluster row.
#[derive(Debug, Clone, Deserialize)]
pub struct ClusterRow {
    pub request_seq: i64,
    #[serde(default)]
    pub request_event_id: Option<String>,
    pub provider: Option<String>,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    pub method: Option<String>,
    pub response_event_id: Option<String>,
    pub latency_ms: Option<u64>,
    pub status_code: Option<u16>,
}

/// Clusters summary from /api/clusters.
#[derive(Debug, Deserialize)]
pub struct ClustersSummary {
    pub clusters: Vec<ClusterRow>,
}

/// Materialized minute rollup row.
#[derive(Debug, Clone, Deserialize)]
pub struct RollupRow {
    pub total_events: u64,
    #[serde(default)]
    pub error_events: u64,
    #[serde(default)]
    pub requests: u64,
    #[serde(default)]
    pub responses: u64,
}

/// Rollups summary from /api/rollups.
#[derive(Debug, Deserialize)]
pub struct RollupsSummary {
    pub rows: Vec<RollupRow>,
}

/// Event stream telemetry from /api/events/stream/stats.
#[derive(Debug, Clone, Deserialize)]
pub struct StreamStats {
    pub lagged_receivers: u64,
    pub lagged_events: u64,
    #[serde(default)]
    pub backfill_batches: u64,
    #[serde(default)]
    pub backfilled_events: u64,
    #[serde(default)]
    pub broadcast_send_failures: u64,
    #[serde(default)]
    pub latest_seq: i64,
}

/// Hot lane data for frequent refreshes.
pub struct HotData {
    pub events: Vec<WrapEvent>,
    pub clusters: Vec<ClusterRow>,
    pub stream_stats: StreamStats,
}

/// Cold lane data for slower refreshes.
pub struct ColdData {
    pub identity: IdentityMetrics,
    pub policy: PolicyMetrics,
    pub observe: ObserveMetrics,
    pub budget_primitives: BudgetPrimitives,
    pub proxy: ProxyMetrics,
    pub rollups: Vec<RollupRow>,
    pub agents: Vec<AgentStats>,
    pub uptime_secs: u64,
}

/// Event payload response row.
#[derive(Debug, Deserialize)]
pub struct EventPayloadData {
    pub content: String,
}

/// Fetch hot-lane metrics with optional incremental cursors.
pub async fn fetch_hot(
    api_url: &str,
    since_event_seq: Option<i64>,
    since_cluster_seq: Option<i64>,
) -> Result<HotData> {
    // Don't use proxy for localhost - the dashboard is local
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .no_proxy()
        .build()?;

    let events_path = match since_event_seq {
        Some(seq) => format!("/api/events?limit=400&since_seq={seq}"),
        None => "/api/events?limit=180".to_string(),
    };
    let clusters_path = match since_cluster_seq {
        Some(seq) => format!("/api/clusters?limit=400&since_seq={seq}"),
        None => "/api/clusters?limit=180".to_string(),
    };

    let base = normalized_api_base(api_url);
    let (events_res, clusters_res, stream_stats_res) = tokio::join!(
        fetch_endpoint::<EventsSummary>(&client, &base, &events_path),
        fetch_endpoint::<ClustersSummary>(&client, &base, &clusters_path),
        fetch_endpoint::<StreamStats>(&client, &base, "/api/events/stream/stats"),
    );

    let mut fallback_error: Option<anyhow::Error> = None;

    let events = match events_res {
        Ok(res) => res.data.events,
        Err(error) => {
            fallback_error = Some(error);
            Vec::new()
        }
    };

    let clusters = match clusters_res {
        Ok(res) => res.data.clusters,
        Err(error) => {
            if fallback_error.is_none() {
                fallback_error = Some(error);
            }
            Vec::new()
        }
    };

    // Non-critical telemetry; default to zero stats if endpoint is temporarily unavailable.
    let stream_stats = match stream_stats_res {
        Ok(res) => res.data,
        Err(_) => StreamStats {
            lagged_receivers: 0,
            lagged_events: 0,
            backfill_batches: 0,
            backfilled_events: 0,
            broadcast_send_failures: 0,
            latest_seq: 0,
        },
    };

    if events.is_empty() && clusters.is_empty() {
        if let Some(error) = fallback_error {
            return Err(error);
        }
    }

    Ok(HotData {
        events,
        clusters,
        stream_stats,
    })
}

/// Fetch cold-lane metrics.
pub async fn fetch_cold(api_url: &str) -> Result<ColdData> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .no_proxy()
        .build()?;

    let base = normalized_api_base(api_url);
    let (snapshot_res, budget_primitives_res, rollups_res, agents_res) = tokio::try_join!(
        fetch_endpoint::<DashboardSnapshot>(&client, &base, "/api/snapshot"),
        fetch_endpoint::<BudgetPrimitives>(&client, &base, "/api/budget/primitives"),
        fetch_endpoint::<RollupsSummary>(&client, &base, "/api/rollups?limit=180"),
        fetch_endpoint::<AgentsSummary>(&client, &base, "/api/agents"),
    )?;
    let snapshot = snapshot_res.data;

    Ok(ColdData {
        identity: snapshot.identity,
        policy: snapshot.policy,
        observe: snapshot.observe,
        budget_primitives: budget_primitives_res.data,
        proxy: snapshot.proxy,
        rollups: rollups_res.data.rows,
        agents: agents_res.data.agents,
        uptime_secs: snapshot_res.uptime_secs,
    })
}

/// Fetch full payload text for a single event part (request|response|content).
pub async fn fetch_event_payload(api_url: &str, event_id: &str, part: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .no_proxy()
        .build()?;

    let base = normalized_api_base(api_url);
    let path = format!("/api/events/{event_id}/payload?part={part}");
    let res = fetch_endpoint::<EventPayloadData>(&client, &base, &path).await?;
    Ok(res.data.content)
}

async fn fetch_endpoint<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    base_url: &str,
    path: &str,
) -> Result<ApiResponse<T>> {
    let url = format!("{base_url}{path}");
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("API error: {} {}", response.status(), path);
    }

    let data = response.json::<ApiResponse<T>>().await?;
    Ok(data)
}

fn normalized_api_base(api_url: &str) -> String {
    let trimmed = api_url.trim().trim_end_matches('/');
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else if trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        format!("http://127.0.0.1:{trimmed}")
    } else {
        format!("http://{trimmed}")
    };

    if let Ok(mut url) = reqwest::Url::parse(&with_scheme) {
        let host = url.host_str().unwrap_or_default();
        if host.eq_ignore_ascii_case("localhost") || host == "::1" {
            let _ = url.set_host(Some("127.0.0.1"));
        }
        if url.port().is_none() {
            let _ = url.set_port(Some(3001));
        }
        return url.as_str().trim_end_matches('/').to_string();
    }

    "http://127.0.0.1:3001".to_string()
}
