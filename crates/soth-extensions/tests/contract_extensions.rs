use std::sync::Arc;

use async_trait::async_trait;
use soth_extensions::{
    Extension, ExtensionCapabilities, ExtensionError, ExtensionHandle, ExtensionHealth,
    ExtensionManagerBuilder, ExtensionType, GovernableEvent,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// No-op test extension
// ---------------------------------------------------------------------------

struct NoopExtension {
    started: bool,
    handle: Option<ExtensionHandle>,
}

impl NoopExtension {
    fn new() -> Self {
        Self {
            started: false,
            handle: None,
        }
    }
}

#[async_trait]
impl Extension for NoopExtension {
    fn extension_type(&self) -> ExtensionType {
        ExtensionType::Custom("noop-test".to_string())
    }

    fn name(&self) -> &str {
        "noop-test"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    fn capabilities(&self) -> ExtensionCapabilities {
        ExtensionCapabilities {
            needs_detect: false,
            needs_classify: false,
            can_block: false,
            emits_telemetry: true,
        }
    }

    async fn start(&mut self) -> Result<(), ExtensionError> {
        self.started = true;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ExtensionError> {
        self.started = false;
        Ok(())
    }

    async fn health(&self) -> ExtensionHealth {
        if self.started {
            ExtensionHealth::Healthy
        } else {
            ExtensionHealth::Unhealthy {
                reason: "not started".to_string(),
            }
        }
    }

    fn set_handle(&mut self, handle: ExtensionHandle) {
        self.handle = Some(handle);
    }
}

fn make_test_event() -> GovernableEvent {
    GovernableEvent {
        event_id: Uuid::new_v4(),
        timestamp_epoch_ms: chrono::Utc::now().timestamp_millis(),
        source: soth_core::EventSource::Extension {
            ext_type: ExtensionType::Custom("noop-test".to_string()),
        },
        provider: soth_core::DetectedProvider::Unknown,
        model: None,
        endpoint_type: soth_core::EndpointType::Unknown,
        normalized: None,
        artifacts: Vec::new(),
        capture_mode: soth_core::CaptureMode::MetadataOnly,
        embed_content: None,
        context: soth_core::ExtensionContext {
            extension_name: "noop-test".to_string(),
            extension_version: "0.1.0".to_string(),
            metadata: Default::default(),
        },
    }
}

fn empty_policy_bundle() -> Arc<soth_policy::PolicyBundle> {
    Arc::new(soth_policy::PolicyBundle {
        metadata: soth_policy::sync_policy::PolicyBundleMetadata {
            bundle_version: "test".to_string(),
            schema_version: "1".to_string(),
            org_id: "test".to_string(),
            signed_at: 0,
        },
        system_rules: Arc::new(soth_policy::sync_policy::CompiledRuleSet::default()),
        org_rules: Arc::new(soth_policy::sync_policy::CompiledRuleSet::default()),
        org_patterns: Arc::new(soth_policy::sync_policy::OrgPatterns {
            patterns: Vec::new(),
        }),
        budget_limits: soth_policy::sync_policy::BudgetLimits::default(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn builder_requires_policy_bundle() {
    let result = ExtensionManagerBuilder::new()
        .register(NoopExtension::new())
        .build();
    assert!(result.is_err());
}

#[test]
fn builder_succeeds_with_policy_bundle() {
    let result = ExtensionManagerBuilder::new()
        .register(NoopExtension::new())
        .with_policy_bundle(empty_policy_bundle())
        .build();
    assert!(result.is_ok());
    assert_eq!(result.unwrap().extension_count(), 1);
}

#[test]
fn builder_registers_multiple_extensions() {
    let manager = ExtensionManagerBuilder::new()
        .register(NoopExtension::new())
        .register(NoopExtension::new())
        .with_policy_bundle(empty_policy_bundle())
        .build()
        .unwrap();
    assert_eq!(manager.extension_count(), 2);
}

#[tokio::test]
async fn manager_starts_and_shuts_down_cleanly() {
    let mut manager = ExtensionManagerBuilder::new()
        .register(NoopExtension::new())
        .with_policy_bundle(empty_policy_bundle())
        .build()
        .unwrap();

    let handle = tokio::spawn(async move {
        manager.run().await;
    });

    // Let the manager start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Abort triggers shutdown
    handle.abort();
    let _ = handle.await;
}

#[test]
fn governable_event_embed_content_is_skip_serialized() {
    let mut event = make_test_event();
    event.embed_content = Some("secret local content".to_string());

    let json = serde_json::to_string(&event).unwrap();
    assert!(!json.contains("secret local content"));
    assert!(!json.contains("embed_content"));
}

#[test]
fn extension_capabilities_default_is_safe() {
    let caps = ExtensionCapabilities::default();
    assert!(!caps.needs_detect);
    assert!(!caps.needs_classify);
    assert!(!caps.can_block);
    assert!(caps.emits_telemetry);
}

#[test]
fn telemetry_event_default_roundtrips() {
    let event = soth_core::TelemetryEvent::default();
    let json = serde_json::to_string(&event).unwrap();
    let roundtripped: soth_core::TelemetryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtripped.event_id, event.event_id);
    assert_eq!(roundtripped.data_source, soth_core::DataSource::LiveProxy);
}

#[test]
fn extension_health_variants() {
    let healthy = ExtensionHealth::Healthy;
    assert_eq!(healthy, ExtensionHealth::Healthy);

    let degraded = ExtensionHealth::Degraded {
        reason: "slow".to_string(),
    };
    assert!(matches!(degraded, ExtensionHealth::Degraded { .. }));
}
