//! API client for fetching dashboard data

use anyhow::Result;
use serde::Deserialize;
use soth_core::types::WrapEvent;
use soth_dashboard::event_store::AgentStats;
use soth_dashboard::state::{
    BudgetMetrics, IdentityMetrics, ObserveMetrics, PolicyMetrics, ProxyMetrics,
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

/// All dashboard data combined
pub struct DashboardData {
    pub identity: IdentityMetrics,
    pub policy: PolicyMetrics,
    pub observe: ObserveMetrics,
    pub budget: BudgetMetrics,
    pub proxy: ProxyMetrics,
    pub events: Vec<WrapEvent>,
    pub agents: Vec<AgentStats>,
    pub uptime_secs: u64,
}

/// Fetch all dashboard data
pub async fn fetch_all(api_url: &str) -> Result<DashboardData> {
    // Don't use proxy for localhost - the dashboard is local
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .no_proxy()
        .build()?;

    // Fetch all endpoints in parallel
    let (identity_res, policy_res, observe_res, budget_res, proxy_res, events_res, agents_res) = tokio::try_join!(
        fetch_endpoint::<IdentityMetrics>(&client, api_url, "/api/identity"),
        fetch_endpoint::<PolicyMetrics>(&client, api_url, "/api/policy"),
        fetch_endpoint::<ObserveMetrics>(&client, api_url, "/api/observe"),
        fetch_endpoint::<BudgetMetrics>(&client, api_url, "/api/budget"),
        fetch_endpoint::<ProxyMetrics>(&client, api_url, "/api/proxy"),
        fetch_endpoint::<EventsSummary>(&client, api_url, "/api/events?limit=100"),
        fetch_endpoint::<AgentsSummary>(&client, api_url, "/api/agents"),
    )?;

    Ok(DashboardData {
        identity: identity_res.data,
        policy: policy_res.data,
        observe: observe_res.data,
        budget: budget_res.data,
        proxy: proxy_res.data,
        events: events_res.data.events,
        agents: agents_res.data.agents,
        uptime_secs: identity_res.uptime_secs,
    })
}

async fn fetch_endpoint<T: for<'de> Deserialize<'de>>(
    client: &reqwest::Client,
    base_url: &str,
    path: &str,
) -> Result<ApiResponse<T>> {
    let url = format!("{}{}", base_url, path);
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("API error: {} {}", response.status(), path);
    }

    let data = response.json::<ApiResponse<T>>().await?;
    Ok(data)
}
