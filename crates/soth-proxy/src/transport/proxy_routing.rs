//! Host routing/interception decision helpers for proxy transport.

use soth_core::config::{HostAction, HostFilterConfig, HostFilterMode};
use soth_oisp::{ConnectDecisionAction, InterceptDecision, OispEngine};
use std::time::SystemTime;
use tracing::debug;

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
            debug!(
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
    method: &str,
) -> HostAction {
    let static_action = hosts.action_for_host(host);
    if matches!(static_action, HostAction::Block) {
        metrics::record_filter_decision("http", "block");
        debug!(
            host = %host,
            path = %path,
            method = %method,
            host_mode = ?hosts.mode,
            static_action = "block",
            "Decision trace: host filter blocked HTTP request"
        );
        return HostAction::Block;
    }
    if let Some(action) =
        force_intercept_all_action(hosts, force_enabled, force_until, host, "http")
    {
        debug!(
            host = %host,
            path = %path,
            method = %method,
            host_mode = ?hosts.mode,
            static_action = ?static_action,
            forced_action = ?action,
            "Decision trace: debug force-intercept host action applied"
        );
        return action;
    }

    let request_decision = engine.evaluate_request_decision(host, path, Some(method), None);
    let intercept_decision = engine.should_intercept_with_context(host, path, Some(method), None);

    match intercept_decision {
        InterceptDecision::Intercept { .. } => {
            metrics::record_filter_decision("http", "intercept");
            debug!(
                host = %host,
                path = %path,
                method = %method,
                host_mode = ?hosts.mode,
                static_action = ?static_action,
                request_outcome = ?request_decision.outcome,
                request_rule_id = ?request_decision.rule_id.as_deref(),
                request_reason = ?request_decision.reason.as_deref(),
                final_action = "intercept",
                "Decision trace: HTTP request routed to MITM"
            );
            HostAction::Intercept
        }
        InterceptDecision::Passthrough => {
            if try_catalog_discovery_intercept(hosts.mode, engine, limiter, host, "http") {
                debug!(
                    host = %host,
                    path = %path,
                    method = %method,
                    host_mode = ?hosts.mode,
                    static_action = ?static_action,
                    request_outcome = ?request_decision.outcome,
                    request_rule_id = ?request_decision.rule_id.as_deref(),
                    request_reason = ?request_decision.reason.as_deref(),
                    final_action = "intercept",
                    override_reason = "catalog_discovery_intercept",
                    "Decision trace: HTTP passthrough overridden by catalog discovery"
                );
                HostAction::Intercept
            } else {
                metrics::record_filter_decision("http", "passthrough");
                debug!(
                    host = %host,
                    path = %path,
                    method = %method,
                    host_mode = ?hosts.mode,
                    static_action = ?static_action,
                    request_outcome = ?request_decision.outcome,
                    request_rule_id = ?request_decision.rule_id.as_deref(),
                    request_reason = ?request_decision.reason.as_deref(),
                    final_action = "tunnel",
                    "Decision trace: HTTP request routed to passthrough tunnel"
                );
                HostAction::Tunnel
            }
        }
        InterceptDecision::Noise => {
            if try_catalog_discovery_intercept(hosts.mode, engine, limiter, host, "http") {
                debug!(
                    host = %host,
                    path = %path,
                    method = %method,
                    host_mode = ?hosts.mode,
                    request_outcome = ?request_decision.outcome,
                    request_rule_id = ?request_decision.rule_id.as_deref(),
                    request_reason = ?request_decision.reason.as_deref(),
                    final_action = "intercept",
                    override_reason = "catalog_discovery_intercept",
                    "Decision trace: noise request captured due to catalog discovery override"
                );
                HostAction::Intercept
            } else {
                metrics::record_filter_decision("http", "noise");
                debug!(
                    host = %host,
                    path = %path,
                    method = %method,
                    host_mode = ?hosts.mode,
                    static_action = ?static_action,
                    request_outcome = ?request_decision.outcome,
                    request_rule_id = ?request_decision.rule_id.as_deref(),
                    request_reason = ?request_decision.reason.as_deref(),
                    final_action = "tunnel",
                    "Decision trace: noise request tunneled"
                );
                HostAction::Tunnel
            }
        }
        InterceptDecision::Tunnel => {
            if try_catalog_discovery_intercept(hosts.mode, engine, limiter, host, "http") {
                debug!(
                    host = %host,
                    path = %path,
                    method = %method,
                    host_mode = ?hosts.mode,
                    static_action = ?static_action,
                    request_outcome = ?request_decision.outcome,
                    request_rule_id = ?request_decision.rule_id.as_deref(),
                    request_reason = ?request_decision.reason.as_deref(),
                    final_action = "intercept",
                    override_reason = "catalog_discovery_intercept",
                    "Decision trace: tunnel request overridden by catalog discovery"
                );
                HostAction::Intercept
            } else {
                metrics::record_filter_decision("http", "tunnel");
                debug!(
                    host = %host,
                    path = %path,
                    method = %method,
                    host_mode = ?hosts.mode,
                    static_action = ?static_action,
                    request_outcome = ?request_decision.outcome,
                    request_rule_id = ?request_decision.rule_id.as_deref(),
                    request_reason = ?request_decision.reason.as_deref(),
                    final_action = "tunnel",
                    "Decision trace: HTTP request routed to tunnel"
                );
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
    let static_action = hosts.action_for_host(host);
    if matches!(static_action, HostAction::Block) {
        metrics::record_filter_decision("connect", "block");
        debug!(
            host = %host,
            host_mode = ?hosts.mode,
            static_action = "block",
            final_action = "block",
            "Decision trace: CONNECT blocked by host filter"
        );
        return HostAction::Block;
    }
    if let Some(action) =
        force_intercept_all_action(hosts, force_enabled, force_until, host, "connect")
    {
        debug!(
            host = %host,
            host_mode = ?hosts.mode,
            static_action = ?static_action,
            forced_action = ?action,
            "Decision trace: CONNECT debug force-intercept action applied"
        );
        return action;
    }

    let connect_decision = engine.evaluate_connect_decision(host, None, Some("unknown"));
    let connect_action = connect_decision.action.clone();
    if matches!(connect_action, ConnectDecisionAction::Intercept) {
        metrics::record_filter_decision("connect", "intercept");
        debug!(
            host = %host,
            host_mode = ?hosts.mode,
            static_action = ?static_action,
            connect_action = "intercept",
            connect_rule_id = ?connect_decision.rule_id.as_deref(),
            connect_reason = ?connect_decision.reason.as_deref(),
            final_action = "intercept",
            "Decision trace: CONNECT routed to MITM"
        );
        HostAction::Intercept
    } else if try_catalog_discovery_intercept(hosts.mode, engine, limiter, host, "connect") {
        debug!(
            host = %host,
            host_mode = ?hosts.mode,
            static_action = ?static_action,
            connect_action = ?connect_action,
            connect_rule_id = ?connect_decision.rule_id.as_deref(),
            connect_reason = ?connect_decision.reason.as_deref(),
            final_action = "intercept",
            override_reason = "catalog_discovery_intercept",
            "Decision trace: CONNECT overridden to intercept for catalog discovery"
        );
        HostAction::Intercept
    } else {
        metrics::record_filter_decision("connect", "tunnel");
        debug!(
            host = %host,
            host_mode = ?hosts.mode,
            static_action = ?static_action,
            connect_action = ?connect_action,
            connect_rule_id = ?connect_decision.rule_id.as_deref(),
            connect_reason = ?connect_decision.reason.as_deref(),
            final_action = "tunnel",
            "Decision trace: CONNECT routed to tunnel"
        );
        HostAction::Tunnel
    }
}
