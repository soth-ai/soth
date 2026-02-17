//! Request/agent detection helpers for proxy transport.

use hudsucker::hyper::Request;
use soth_oisp::types::provider::EntryType;
use soth_oisp::{DetectionContext, OispEngine};

#[derive(Debug, Clone, Default)]
pub(crate) struct BundleDetectionResult {
    pub(crate) agent: Option<String>,
    pub(crate) detection_reason: Option<String>,
    pub(crate) parse_confidence: Option<f64>,
    pub(crate) detection_source: Option<String>,
    pub(crate) target_entity_id: Option<String>,
}

/// Extract host from URI or headers.
/// Handles both regular requests and CONNECT requests (authority form).
pub(crate) fn extract_host<T>(req: &Request<T>) -> String {
    // Try uri.host() first (works for absolute URLs).
    req.uri()
        .host()
        .map(|h| h.to_string())
        // Try authority (works for CONNECT requests like "host:port").
        .or_else(|| req.uri().authority().map(|a| a.host().to_string()))
        // Fallback to Host header.
        .or_else(|| {
            req.headers()
                .get("host")
                .and_then(|h| h.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_string())
        })
        .unwrap_or_default()
}

/// Detect agent/client from User-Agent header.
pub(crate) fn detect_agent_from_user_agent<T>(req: &Request<T>) -> Option<&'static str> {
    let ua = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let ua_lower = ua.to_lowercase();

    if ua_lower.contains("openai-codex") || ua_lower.contains("codex/") {
        Some("codex")
    } else if ua_lower.contains("warp") {
        Some("warp")
    } else if ua_lower.contains("claude-code")
        || ua_lower.contains("claude_code")
        || ua_lower.contains("claude code")
    {
        Some("claude-code")
    } else if ua_lower.contains("cursor") {
        Some("cursor")
    } else if ua_lower.contains("continue") {
        Some("continue")
    } else if ua_lower.contains("copilot") {
        Some("github-copilot")
    } else if ua_lower.contains("vscode") || ua_lower.contains("visual studio code") {
        Some("vscode")
    } else if ua_lower.contains("intellij") || ua_lower.contains("jetbrains") {
        Some("jetbrains")
    } else if ua_lower.contains("neovim") || ua_lower.contains("nvim") {
        Some("neovim")
    } else if ua_lower.contains("emacs") {
        Some("emacs")
    } else if ua_lower.contains("zed") {
        Some("zed")
    } else if ua_lower.contains("windsurf") {
        Some("windsurf")
    } else if ua_lower.contains("anthropic") || ua_lower.contains("claude") {
        Some("claude")
    } else if ua_lower.contains("openai") || ua_lower.contains("chatgpt") {
        Some("chatgpt")
    } else {
        // Unrecognized/non-empty User-Agent currently has no stable agent mapping.
        None
    }
}

pub(crate) fn is_anthropic_api_host(host: &str) -> bool {
    let normalized = host.trim().to_ascii_lowercase();
    normalized == "api.anthropic.com"
        || normalized.ends_with(".api.anthropic.com")
        || normalized == "api.claude.ai"
        || normalized.ends_with(".api.claude.ai")
}

pub(crate) fn has_anthropic_api_key_header<T>(req: &Request<T>) -> bool {
    if req.headers().contains_key("x-api-key") {
        return true;
    }

    req.headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase().contains("sk-ant-"))
        .unwrap_or(false)
}

/// Anthropic API hosts can represent either direct inference traffic
/// (API key present) or agent-orchestrated traffic (no API key).
pub(crate) fn should_treat_anthropic_api_as_agent<T>(host: &str, req: &Request<T>) -> bool {
    is_anthropic_api_host(host) && !has_anthropic_api_key_header(req)
}

/// Best-effort local process-name heuristic for discovery-mode agent labeling.
pub(crate) fn detect_agent_from_process_name(process_name: &str) -> Option<&'static str> {
    let lower = process_name.to_ascii_lowercase();
    if lower.is_empty() {
        return None;
    }
    if lower.contains("warp") {
        Some("warp")
    } else if lower.contains("openai-codex") || lower.contains("codex") {
        Some("codex")
    } else if lower.contains("claude-code") || lower.contains("claude code") {
        Some("claude-code")
    } else if lower.contains("claude") {
        Some("claude")
    } else if lower.contains("cursor") {
        Some("cursor")
    } else if lower.contains("windsurf") || lower.contains("codeium") {
        Some("windsurf")
    } else if lower.contains("copilot") {
        Some("github-copilot")
    } else if lower.contains("chatgpt") || lower.contains("openai") {
        Some("chatgpt")
    } else {
        None
    }
}

/// Check if a request should be logged for observability.
/// Uses blacklist approach: include everything EXCEPT obvious non-inference content.
pub(crate) fn should_log_request(path: &str, method: &str) -> bool {
    // CONNECT is transport setup, not an application request.
    if method.eq_ignore_ascii_case("CONNECT") {
        return false;
    }

    let path_lower = path.to_lowercase();

    // POST requests to AI providers are almost always inference - include them.
    if method == "POST" {
        // Only skip obvious tracking POSTs.
        if path_lower.contains("/v1/t")
            || path_lower.contains("/event_logging")
            || path_lower.contains("/analytics")
            || path_lower.contains("/tracking")
            || path_lower.contains("/segment")
            || path_lower.contains("/log")
            || path_lower.contains("/beacon")
        {
            return false;
        }
        return true;
    }

    // For GET/other methods, filter out static assets and noise.

    // Skip static assets and images.
    if path_lower.ends_with(".png")
        || path_lower.ends_with(".jpg")
        || path_lower.ends_with(".jpeg")
        || path_lower.ends_with(".gif")
        || path_lower.ends_with(".svg")
        || path_lower.ends_with(".ico")
        || path_lower.ends_with(".webp")
        || path_lower.ends_with(".css")
        || path_lower.ends_with(".js")
        || path_lower.ends_with(".map")
        || path_lower.ends_with(".woff")
        || path_lower.ends_with(".woff2")
        || path_lower.ends_with(".ttf")
        || path_lower.ends_with(".eot")
    {
        return false;
    }

    // Skip build/static paths.
    if path_lower.contains("/_next/")
        || path_lower.contains("/static/")
        || path_lower.contains("/assets/")
        || path_lower.contains("/chunks/")
        || path_lower.contains("/webpack/")
    {
        return false;
    }

    // Skip tracking/analytics.
    if path_lower.contains("/v1/t")
        || path_lower.contains("/event_logging")
        || path_lower.contains("/analytics")
        || path_lower.contains("/tracking")
        || path_lower.contains("/segment")
        || path_lower.contains("/beacon")
        || path_lower.contains("/metrics")
        || path_lower.contains("/healthz")
        || path_lower.contains("/ping")
    {
        return false;
    }

    // Include everything else (might be inference-related).
    true
}

pub(crate) fn resolve_bundle_detection(
    oisp_engine: &OispEngine,
    provider: Option<&str>,
    host: &str,
    path: &str,
    user_agent: Option<&str>,
    model: Option<&str>,
    process_name: Option<&str>,
    process_bundle_id: Option<&str>,
    process_agent: Option<&str>,
) -> BundleDetectionResult {
    let detection_context = DetectionContext {
        host: Some(host.to_string()),
        path: Some(path.to_string()),
        user_agent: user_agent.map(ToString::to_string),
        model: model.map(ToString::to_string),
        process_name: process_name.map(ToString::to_string),
        bundle_id: process_bundle_id.map(ToString::to_string),
        client_name: process_agent.map(ToString::to_string),
        client_version: None,
        env_keys: Vec::new(),
    };

    let provider_scoped_detection = provider
        .and_then(|provider_id| oisp_engine.evaluate_detection(provider_id, &detection_context))
        .or_else(|| oisp_engine.evaluate_detection_for_host(host, &detection_context));
    let provider_scoped_is_generic = provider_scoped_detection
        .as_ref()
        .map(|value| is_generic_detection_reason(value.detection_reason.as_str()))
        .unwrap_or(true);
    let cross_entry_detection = if provider_scoped_detection.is_none() || provider_scoped_is_generic
    {
        oisp_engine
            .evaluate_detection_across_entry_types(&detection_context, &[EntryType::AgentApp])
    } else {
        None
    };
    let bundle_detection = provider_scoped_detection.clone().or_else(|| {
        cross_entry_detection
            .as_ref()
            .map(|value| value.outcome.clone())
    });
    let bundle_agent = bundle_detection
        .as_ref()
        .and_then(|value| value.agent.clone())
        .or_else(|| {
            cross_entry_detection.as_ref().and_then(|value| {
                value
                    .outcome
                    .agent
                    .clone()
                    .or_else(|| Some(value.provider_id.clone()))
            })
        });

    let (detection_reason, parse_confidence, detection_source) =
        if let Some(value) = bundle_detection.as_ref() {
            let reason = normalize_detection_reason(value.detection_reason.as_str());
            let confidence = if is_generic_detection_reason(reason.as_str()) {
                0.0
            } else {
                value.parse_confidence
            };
            (Some(reason), Some(confidence), Some("bundle".to_string()))
        } else {
            (
                Some("bundle_unclassified".to_string()),
                Some(0.0),
                Some("bundle".to_string()),
            )
        };

    BundleDetectionResult {
        agent: bundle_agent,
        detection_reason,
        parse_confidence,
        detection_source,
        target_entity_id: bundle_detection
            .as_ref()
            .and_then(|value| value.target_entity_id.clone()),
    }
}

fn is_generic_detection_reason(reason: &str) -> bool {
    matches!(
        reason.trim().to_ascii_lowercase().as_str(),
        "bundle_unclassified" | "fallback_unknown" | "unknown" | "unclassified"
    )
}

fn normalize_detection_reason(reason: &str) -> String {
    if is_generic_detection_reason(reason) {
        "bundle_unclassified".to_string()
    } else {
        reason.trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{is_generic_detection_reason, normalize_detection_reason};

    #[test]
    fn generic_reasons_are_normalized() {
        assert_eq!(
            normalize_detection_reason("fallback_unknown"),
            "bundle_unclassified"
        );
        assert_eq!(normalize_detection_reason("unknown"), "bundle_unclassified");
        assert_eq!(
            normalize_detection_reason("bundle_unclassified"),
            "bundle_unclassified"
        );
    }

    #[test]
    fn non_generic_reason_is_preserved() {
        assert_eq!(normalize_detection_reason("ua_match"), "ua_match");
        assert!(!is_generic_detection_reason("host_classification"));
    }
}
