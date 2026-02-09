//! Shared PII enrichment for transport-emitted wrap events.

use std::collections::BTreeSet;
use std::sync::Arc;

use soth_core::config::ObserveConfig;
use soth_core::types::observation::PiiType;
use soth_core::types::{EventSource, WrapDirection, WrapEvent};
use soth_observe::PiiDetector;

#[derive(Clone)]
pub struct PiiEventEnricher {
    detector: Option<Arc<PiiDetector>>,
    ai_inference_enabled: bool,
    mcp_enabled: bool,
    agent_apps_enabled: bool,
}

impl PiiEventEnricher {
    pub fn from_observe_config(config: &ObserveConfig) -> Self {
        let detector = if config.enabled && config.pii_detection {
            Some(Arc::new(PiiDetector::new()))
        } else {
            None
        };
        Self {
            detector,
            ai_inference_enabled: config.pii_scopes.ai_inference,
            mcp_enabled: config.pii_scopes.mcp,
            agent_apps_enabled: config.pii_scopes.agent_apps,
        }
    }

    pub fn enrich(&self, event: &mut WrapEvent) {
        let Some(detector) = self.detector.as_ref() else {
            return;
        };
        if !self.enabled_for_source(event.source) {
            return;
        }

        let mut pii_types = BTreeSet::new();
        for payload in input_payloads(event) {
            detect_types(detector, Some(payload), &mut pii_types);
        }

        if !pii_types.is_empty() {
            event.pii_detected = true;
            event.pii_types = pii_types.into_iter().collect();
        }
    }

    fn enabled_for_source(&self, source: EventSource) -> bool {
        match source {
            EventSource::AiProxy => self.ai_inference_enabled,
            EventSource::Mcp => self.mcp_enabled,
            EventSource::AgentApp => self.agent_apps_enabled,
        }
    }
}

fn detect_types(detector: &PiiDetector, content: Option<&str>, output: &mut BTreeSet<String>) {
    let Some(content) = content else {
        return;
    };
    if content.trim().is_empty() {
        return;
    }

    for pii_type in detector.detect_types(content) {
        output.insert(pii_type_key(pii_type).to_string());
    }
}

fn pii_type_key(pii_type: PiiType) -> &'static str {
    match pii_type {
        PiiType::Ssn => "ssn",
        PiiType::Email => "email",
        PiiType::CreditCard => "credit_card",
        PiiType::Phone => "phone",
        PiiType::IpAddress => "ip_address",
        PiiType::ApiKey => "api_key",
        PiiType::Other => "other",
    }
}

fn input_payloads(event: &WrapEvent) -> Vec<&str> {
    let mut payloads = Vec::new();

    // Prefer explicit request payload when available (paired request/response rows).
    if let Some(request) = event.request_content.as_deref() {
        if !request.trim().is_empty() {
            payloads.push(request);
            return payloads;
        }
    }

    // For one-way events, only inspect inbound content.
    if matches!(event.direction, WrapDirection::In) {
        if let Some(content) = event.content.as_deref() {
            if !content.trim().is_empty() {
                payloads.push(content);
            }
        }
    }

    payloads
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::types::{AgentInfo, DetectionSource, WrapDirection};

    fn mk_event(source: EventSource, content: &str) -> WrapEvent {
        WrapEvent::new(
            "session",
            "server",
            WrapDirection::In,
            AgentInfo::new("agent", DetectionSource::Environment),
        )
        .with_source(source)
        .with_content(content.to_string())
    }

    #[test]
    fn detects_pii_for_enabled_scope() {
        let mut config = ObserveConfig::default();
        config.pii_scopes.ai_inference = false;
        config.pii_scopes.mcp = true;
        config.pii_scopes.agent_apps = false;
        let enricher = PiiEventEnricher::from_observe_config(&config);

        let mut mcp_event = mk_event(EventSource::Mcp, "email me at test@example.com");
        enricher.enrich(&mut mcp_event);
        assert!(mcp_event.pii_detected);
        assert!(mcp_event.pii_types.iter().any(|t| t == "email"));

        let mut ai_event = mk_event(EventSource::AiProxy, "email me at test@example.com");
        enricher.enrich(&mut ai_event);
        assert!(!ai_event.pii_detected);
    }

    #[test]
    fn disabled_detection_is_noop() {
        let mut config = ObserveConfig::default();
        config.pii_detection = false;
        let enricher = PiiEventEnricher::from_observe_config(&config);

        let mut event = mk_event(EventSource::AgentApp, "test@example.com");
        enricher.enrich(&mut event);
        assert!(!event.pii_detected);
        assert!(event.pii_types.is_empty());
    }

    #[test]
    fn ignores_response_only_payloads() {
        let config = ObserveConfig::default();
        let enricher = PiiEventEnricher::from_observe_config(&config);

        let mut response_event = WrapEvent::new(
            "session",
            "server",
            WrapDirection::Out,
            AgentInfo::new("agent", DetectionSource::Environment),
        )
        .with_source(EventSource::AiProxy)
        .with_content("customer email test@example.com".to_string());

        enricher.enrich(&mut response_event);
        assert!(!response_event.pii_detected);
        assert!(response_event.pii_types.is_empty());
    }

    #[test]
    fn detects_from_request_side_in_paired_response_rows() {
        let config = ObserveConfig::default();
        let enricher = PiiEventEnricher::from_observe_config(&config);

        let mut event = WrapEvent::new(
            "session",
            "server",
            WrapDirection::Out,
            AgentInfo::new("agent", DetectionSource::Environment),
        )
        .with_source(EventSource::AiProxy)
        .with_request(
            "{\"email\":\"test@example.com\"}".to_string(),
            "".to_string(),
        )
        .with_response("{\"ok\":true}".to_string(), "".to_string());

        enricher.enrich(&mut event);
        assert!(event.pii_detected);
        assert!(event.pii_types.iter().any(|t| t == "email"));
    }
}
