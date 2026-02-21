//! Request/agent detection helpers for proxy transport.

use hudsucker::hyper::Request;
use soth_oisp::{DetectionContext, InterceptDecision, OispEngine};

#[derive(Debug, Clone, Default)]
pub(crate) struct BundleDetectionResult {
    pub(crate) agent: Option<String>,
    pub(crate) detection_reason: Option<String>,
    pub(crate) parse_confidence: Option<f64>,
    pub(crate) detection_source: Option<String>,
    pub(crate) detection_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapturePolicy {
    Full,
    SelectiveBody,
    MetadataOnly,
}

const CAPTURE_CONFIDENCE_FULL_MIN: f64 = 0.85;
const CAPTURE_CONFIDENCE_SELECTIVE_MIN: f64 = 0.45;

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

pub(crate) fn is_noise_intercept_decision(decision: InterceptDecision) -> bool {
    matches!(decision, InterceptDecision::Noise)
}

/// Check if a request should be logged for observability.
/// Uses blacklist approach: include everything EXCEPT obvious non-inference content.
#[cfg(test)]
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

    let bundle_detection = provider
        .and_then(|provider_id| oisp_engine.evaluate_detection(provider_id, &detection_context));
    let bundle_agent = bundle_detection
        .as_ref()
        .and_then(|value| value.agent.clone());
    let detection_id = bundle_detection
        .as_ref()
        .and_then(|value| value.detection_id.clone());

    let (detection_reason, parse_confidence, detection_source) =
        if let Some(value) = bundle_detection.as_ref() {
            let reason = normalize_detection_reason(value.detection_reason.as_str());
            let confidence = if reason.eq_ignore_ascii_case("bundle_unclassified") {
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
        detection_id,
    }
}

fn is_generic_detection_reason(reason: &str) -> bool {
    matches!(
        reason.trim().to_ascii_lowercase().as_str(),
        "bundle_unclassified"
    )
}

fn normalize_detection_reason(reason: &str) -> String {
    let normalized = reason.trim();
    if normalized.is_empty() || is_generic_detection_reason(normalized) {
        "bundle_unclassified".to_string()
    } else {
        normalized.to_string()
    }
}

pub(crate) fn classify_capture_policy(
    parse_confidence: Option<f64>,
    detection_reason: Option<&str>,
) -> CapturePolicy {
    if detection_reason.is_none() {
        return CapturePolicy::MetadataOnly;
    }
    let confidence = parse_confidence.unwrap_or(0.0);
    if confidence >= CAPTURE_CONFIDENCE_FULL_MIN {
        CapturePolicy::Full
    } else if confidence >= CAPTURE_CONFIDENCE_SELECTIVE_MIN {
        CapturePolicy::SelectiveBody
    } else {
        CapturePolicy::MetadataOnly
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_capture_policy, is_generic_detection_reason, normalize_detection_reason,
        resolve_bundle_detection, CapturePolicy,
    };
    use serde_json::json;
    use soth_oisp::types::bundle::parse_compiled_bundle;
    use soth_oisp::OispEngine;

    #[test]
    fn bundle_unclassified_reason_is_normalized() {
        assert_eq!(
            normalize_detection_reason("bundle_unclassified"),
            "bundle_unclassified"
        );
        assert_eq!(
            normalize_detection_reason("host_classification"),
            "host_classification"
        );
    }

    #[test]
    fn non_generic_reason_is_preserved() {
        assert_eq!(normalize_detection_reason("ua_match"), "ua_match");
        assert!(!is_generic_detection_reason("path_match"));
    }

    #[test]
    fn capture_policy_uses_reason_and_confidence() {
        assert_eq!(
            classify_capture_policy(Some(0.99), Some("ua_match")),
            CapturePolicy::Full
        );
        assert_eq!(
            classify_capture_policy(Some(0.60), Some("path_match")),
            CapturePolicy::SelectiveBody
        );
        assert_eq!(
            classify_capture_policy(Some(0.20), Some("model_match")),
            CapturePolicy::MetadataOnly
        );
        assert_eq!(
            classify_capture_policy(Some(0.99), Some("bundle_unclassified")),
            CapturePolicy::Full
        );
        assert_eq!(
            classify_capture_policy(None, None),
            CapturePolicy::MetadataOnly
        );
    }

    #[test]
    fn resolve_bundle_detection_does_not_fallback_across_entry_types() {
        let engine = OispEngine::new(
            parse_compiled_bundle(&json!({
                "schema_version": 3,
                "version": "v3",
                "compiled_at": "2026-02-21T00:00:00Z",
                "bundle_type": "local",
                "core": {
                    "providers": {
                        "chatgpt": {
                            "id": "chatgpt",
                            "name": "ChatGPT",
                            "type": "agent-app",
                            "detection_id": "agent.chatgpt.app",
                            "detection": {
                                "process_rules": [
                                    {
                                        "agent": "codex",
                                        "reason": "process_match",
                                        "bundle_id": "@openai/codex"
                                    }
                                ]
                            }
                        }
                    },
                    "domain_index": [
                        {
                            "host": "chatgpt.com",
                            "provider_id": "chatgpt",
                            "entry_type": "agent-app"
                        }
                    ]
                },
                "filters": {},
                "gating": {
                    "allowed_app_origins": {
                        "non_hosts": ["@openai/codex"]
                    },
                    "allowed_host_origins": []
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let result = resolve_bundle_detection(
            &engine,
            None,
            "unknown.example.com",
            "/backend-api/codex/responses",
            None,
            None,
            Some("codex"),
            Some("@openai/codex"),
            None,
        );

        assert_eq!(result.detection_id, None);
        assert_eq!(result.agent, None);
        assert_eq!(
            result.detection_reason.as_deref(),
            Some("bundle_unclassified")
        );
    }

    #[test]
    fn resolve_bundle_detection_requires_provider_context() {
        let engine = OispEngine::new(
            parse_compiled_bundle(&json!({
                "schema_version": 3,
                "version": "v3",
                "compiled_at": "2026-02-21T00:00:00Z",
                "bundle_type": "local",
                "core": {
                    "providers": {
                        "chatgpt": {
                            "id": "chatgpt",
                            "name": "ChatGPT",
                            "type": "agent-app",
                            "detection_id": "agent.chatgpt.app",
                            "detection": {
                                "path_rules": [
                                    {
                                        "agent": "chatgpt",
                                        "reason": "path_match",
                                        "path": "**/backend-api/conversation"
                                    }
                                ]
                            }
                        }
                    },
                    "domain_index": [
                        {
                            "host": "chatgpt.com",
                            "provider_id": "chatgpt",
                            "entry_type": "agent-app"
                        }
                    ]
                },
                "filters": {},
                "gating": {}
            }))
            .unwrap(),
        )
        .unwrap();

        let result = resolve_bundle_detection(
            &engine,
            None,
            "chatgpt.com",
            "/backend-api/conversation",
            None,
            None,
            None,
            None,
            None,
        );

        assert_eq!(result.detection_id, None);
        assert_eq!(result.agent, None);
        assert_eq!(
            result.detection_reason.as_deref(),
            Some("bundle_unclassified")
        );
    }

    #[test]
    fn resolve_bundle_detection_keeps_host_classification_identity() {
        let engine = OispEngine::new(
            parse_compiled_bundle(&json!({
                "schema_version": 3,
                "version": "v3",
                "compiled_at": "2026-02-21T00:00:00Z",
                "bundle_type": "local",
                "core": {
                    "providers": {
                        "chatgpt": {
                            "id": "chatgpt",
                            "name": "ChatGPT",
                            "type": "agent-app",
                            "detection_id": "agent.chatgpt.app",
                            "detection": {
                                "path_rules": [
                                    {
                                        "agent": "chatgpt",
                                        "reason": "host_classification",
                                        "path": "/backend-api/**"
                                    }
                                ]
                            }
                        }
                    },
                    "domain_index": [
                        {
                            "host": "chatgpt.com",
                            "provider_id": "chatgpt",
                            "entry_type": "agent-app"
                        }
                    ]
                },
                "filters": {},
                "gating": {}
            }))
            .unwrap(),
        )
        .unwrap();

        let result = resolve_bundle_detection(
            &engine,
            Some("chatgpt"),
            "chatgpt.com",
            "/backend-api/conversation",
            None,
            None,
            None,
            None,
            None,
        );

        assert_eq!(result.detection_id.as_deref(), Some("agent.chatgpt.app"));
        assert_eq!(result.agent.as_deref(), Some("chatgpt"));
        assert_eq!(
            result.detection_reason.as_deref(),
            Some("host_classification")
        );
        assert_eq!(result.parse_confidence, Some(0.95));
    }
}
