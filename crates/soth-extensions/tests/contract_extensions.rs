use std::sync::Arc;

use async_trait::async_trait;
use soth_extensions::{
    Extension, ExtensionArchetype, ExtensionManifest, ExtensionRegistry, ExtensionRuntimeContext,
    ExtensionSource, ExtensionStatus, GovernableEvent, TelemetryQueueWriter,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// No-op governance extension for testing
// ---------------------------------------------------------------------------

struct NoopGovernance;

#[async_trait]
impl Extension for NoopGovernance {
    fn manifest(&self) -> &ExtensionManifest {
        static MANIFEST: ExtensionManifest = ExtensionManifest {
            name: "noop_test",
            version: "0.1.0",
            source: ExtensionSource::Custom(String::new()),
            capabilities: &[],
            archetype: ExtensionArchetype::Governance,
            requires_daemon: false,
            tracing_target: "noop_test",
        };
        &MANIFEST
    }

    fn status(&self, _ctx: &ExtensionRuntimeContext) -> ExtensionStatus {
        ExtensionStatus {
            name: "noop_test".to_string(),
            version: "0.1.0".to_string(),
            archetype: ExtensionArchetype::Governance,
            installed: true,
            enabled: true,
            healthy: true,
            ..ExtensionStatus::default()
        }
    }
}

// ---------------------------------------------------------------------------
// No-op passive observer extension for testing
// ---------------------------------------------------------------------------

struct NoopObserver;

#[async_trait]
impl Extension for NoopObserver {
    fn manifest(&self) -> &ExtensionManifest {
        static MANIFEST: ExtensionManifest = ExtensionManifest {
            name: "noop_observer",
            version: "0.1.0",
            source: ExtensionSource::Custom(String::new()),
            capabilities: &[],
            archetype: ExtensionArchetype::PassiveObserver,
            requires_daemon: false,
            tracing_target: "noop_observer",
        };
        &MANIFEST
    }

    fn observation_interval(&self) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_secs(300))
    }

    fn status(&self, _ctx: &ExtensionRuntimeContext) -> ExtensionStatus {
        ExtensionStatus {
            name: "noop_observer".to_string(),
            version: "0.1.0".to_string(),
            archetype: ExtensionArchetype::PassiveObserver,
            installed: true,
            enabled: true,
            healthy: true,
            ..ExtensionStatus::default()
        }
    }
}

fn test_ctx() -> ExtensionRuntimeContext {
    ExtensionRuntimeContext::from_defaults()
}

fn make_test_event() -> GovernableEvent {
    GovernableEvent {
        event_id: Uuid::new_v4(),
        timestamp_epoch_ms: 1700000000000,
        source: soth_core::EventSource::Extension {
            source: ExtensionSource::Custom("noop_test".to_string()),
        },
        provider: soth_core::DetectedProvider::Unknown,
        model: None,
        endpoint_type: soth_core::EndpointType::Unknown,
        normalized: None,
        artifacts: Vec::new(),
        capture_mode: soth_core::CaptureMode::MetadataOnly,
        embed_content: None,
        context: soth_core::ExtensionContext {
            extension_name: "noop_test".to_string(),
            extension_version: "0.1.0".to_string(),
            metadata: Default::default(),
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn registry_registers_and_counts() {
    let mut reg = ExtensionRegistry::empty();
    assert_eq!(reg.extension_count(), 0);
    reg.register(Arc::new(NoopGovernance));
    assert_eq!(reg.extension_count(), 1);
    reg.register(Arc::new(NoopObserver));
    assert_eq!(reg.extension_count(), 2);
}

#[test]
fn registry_all_status_reports_all_extensions() {
    let mut reg = ExtensionRegistry::empty();
    reg.register(Arc::new(NoopGovernance));
    reg.register(Arc::new(NoopObserver));
    let statuses = reg.all_status(&test_ctx());
    assert_eq!(statuses.len(), 2);
    assert_eq!(statuses[0].name, "noop_test");
    assert_eq!(statuses[1].name, "noop_observer");
}

#[test]
fn registry_passive_observers_filters_correctly() {
    let mut reg = ExtensionRegistry::empty();
    reg.register(Arc::new(NoopGovernance));
    reg.register(Arc::new(NoopObserver));
    let passive = reg.passive_observers();
    assert_eq!(passive.len(), 1);
    assert_eq!(passive[0].manifest().name, "noop_observer");
}

#[test]
fn registry_build_observer_broadcast_returns_none_when_no_observers() {
    let mut reg = ExtensionRegistry::empty();
    reg.register(Arc::new(NoopGovernance));
    let broadcast = reg.build_observer_broadcast(Arc::new(test_ctx()));
    assert!(broadcast.is_none());
}

#[test]
fn registry_build_observer_broadcast_returns_some_with_observers() {
    let mut reg = ExtensionRegistry::empty();
    reg.register(Arc::new(NoopObserver));
    let broadcast = reg.build_observer_broadcast(Arc::new(test_ctx()));
    assert!(broadcast.is_some());

    // Should be callable without panicking
    let event = soth_core::PreEmitEvent::default();
    (broadcast.unwrap())(&event);
}

#[test]
fn registry_all_migrations_collects_from_all_extensions() {
    let mut reg = ExtensionRegistry::empty();
    reg.register(Arc::new(NoopGovernance));
    reg.register(Arc::new(NoopObserver));
    let migrations = reg.all_migrations();
    assert_eq!(migrations.len(), 2);
    // Both noop extensions return empty migrations
    assert!(migrations[0].1.is_empty());
    assert!(migrations[1].1.is_empty());
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
fn telemetry_queue_writer_roundtrips_through_file() {
    let dir = tempfile::tempdir().unwrap();
    let queue_path = dir.path().join("test.queue");
    let writer = TelemetryQueueWriter::from_path(queue_path.clone());

    let event = make_test_event();
    let decision = soth_core::PolicyDecision {
        kind: soth_core::PolicyDecisionKind::Allow,
        matched_rule: None,
        warnings: Vec::new(),
        eval_latency_us: 0,
    };

    writer.enqueue(&event, &decision).unwrap();

    let contents = std::fs::read_to_string(&queue_path).unwrap();
    let record: soth_extensions::OwnedGovernableQueueRecord =
        serde_json::from_str(contents.trim()).unwrap();
    assert_eq!(record.schema_version, 1);
    assert_eq!(record.extension, "noop_test");
    assert_eq!(record.event.event_id, event.event_id);
}

#[test]
fn extension_status_default_is_safe() {
    let status = ExtensionStatus::default();
    assert!(!status.installed);
    assert!(!status.enabled);
    assert!(!status.healthy);
    assert_eq!(status.event_count, 0);
    assert_eq!(status.observation_count, 0);
}

#[test]
fn extension_manifest_has_stable_name() {
    let ext = NoopGovernance;
    assert_eq!(ext.manifest().name, "noop_test");
    assert_eq!(ext.manifest().archetype, ExtensionArchetype::Governance);
}
