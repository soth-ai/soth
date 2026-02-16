//! Host routing/interception decision helpers for proxy transport.

use soth_core::config::{HostAction, HostFilterConfig, HostFilterMode};
use soth_oisp::{InterceptDecision, OispEngine};
use std::time::SystemTime;
use tracing::info;

use crate::metrics;
use crate::transport::proxy_support::{
    CatalogDiscoveryLimiter, DiscoveryKind, DiscoveryReserveResult,
};

pub(crate) fn is_force_intercept_all_active(enabled: bool, expires_at: Option<SystemTime>) -> bool {
    if !enabled {
        return false;
    }
    match expires_at {
        Some(deadline) => SystemTime::now() <= deadline,
        None => true,
    }
}

pub(crate) fn force_intercept_all_action(
    hosts: &HostFilterConfig,
    enabled: bool,
    expires_at: Option<SystemTime>,
    host: &str,
    phase: &str,
) -> Option<HostAction> {
    if !is_force_intercept_all_active(enabled, expires_at) {
        return None;
    }
    let mut debug_hosts = hosts.clone();
    debug_hosts.mode = HostFilterMode::Discovery;
    let action = debug_hosts.action_for_host(host);
    let metric = match action {
        HostAction::Intercept => "debug_intercept_all",
        HostAction::Tunnel => "debug_intercept_all_tunnel",
        HostAction::Block => "block",
    };
    metrics::record_filter_decision(phase, metric);
    Some(action)
}

pub(crate) fn try_catalog_discovery_intercept(
    host_mode: HostFilterMode,
    engine: &OispEngine,
    limiter: &CatalogDiscoveryLimiter,
    host: &str,
    phase: &str,
) -> bool {
    if host_mode != HostFilterMode::Discovery {
        return false;
    }
    if engine.classify(host).is_some() || !engine.is_catalog_domain(host) {
        return false;
    }

    match limiter.reserve_once_per_day(DiscoveryKind::Catalog, host) {
        DiscoveryReserveResult::Reserved => {
            metrics::record_filter_decision(phase, "catalog_discovery_intercept");
            info!(
                host = %host,
                "Catalog discovery interception enabled for first capture of the day"
            );
            true
        }
        DiscoveryReserveResult::AlreadySeen => {
            metrics::record_filter_decision(phase, "catalog_discovery_seen_skip");
            false
        }
        DiscoveryReserveResult::DailyCapReached => {
            metrics::record_filter_decision(phase, "catalog_discovery_cap_skip");
            false
        }
    }
}

pub(crate) fn get_action(
    hosts: &HostFilterConfig,
    engine: &OispEngine,
    limiter: &CatalogDiscoveryLimiter,
    force_enabled: bool,
    force_until: Option<SystemTime>,
    host: &str,
    path: &str,
) -> HostAction {
    if matches!(hosts.action_for_host(host), HostAction::Block) {
        metrics::record_filter_decision("http", "block");
        return HostAction::Block;
    }
    if let Some(action) =
        force_intercept_all_action(hosts, force_enabled, force_until, host, "http")
    {
        return action;
    }

    match engine.should_intercept(host, path) {
        InterceptDecision::Intercept { .. } => {
            metrics::record_filter_decision("http", "intercept");
            HostAction::Intercept
        }
        InterceptDecision::Passthrough => {
            if try_catalog_discovery_intercept(hosts.mode, engine, limiter, host, "http") {
                HostAction::Intercept
            } else {
                metrics::record_filter_decision("http", "passthrough");
                HostAction::Tunnel
            }
        }
        InterceptDecision::Noise => {
            if try_catalog_discovery_intercept(hosts.mode, engine, limiter, host, "http") {
                HostAction::Intercept
            } else {
                metrics::record_filter_decision("http", "noise");
                HostAction::Tunnel
            }
        }
        InterceptDecision::Tunnel => {
            if try_catalog_discovery_intercept(hosts.mode, engine, limiter, host, "http") {
                HostAction::Intercept
            } else {
                metrics::record_filter_decision("http", "tunnel");
                HostAction::Tunnel
            }
        }
    }
}

pub(crate) fn get_connect_action(
    hosts: &HostFilterConfig,
    engine: &OispEngine,
    limiter: &CatalogDiscoveryLimiter,
    force_enabled: bool,
    force_until: Option<SystemTime>,
    host: &str,
) -> HostAction {
    if matches!(hosts.action_for_host(host), HostAction::Block) {
        metrics::record_filter_decision("connect", "block");
        return HostAction::Block;
    }
    if let Some(action) =
        force_intercept_all_action(hosts, force_enabled, force_until, host, "connect")
    {
        return action;
    }

    if engine.should_intercept_host(host) {
        metrics::record_filter_decision("connect", "intercept");
        HostAction::Intercept
    } else if try_catalog_discovery_intercept(hosts.mode, engine, limiter, host, "connect") {
        HostAction::Intercept
    } else {
        metrics::record_filter_decision("connect", "tunnel");
        HostAction::Tunnel
    }
}
