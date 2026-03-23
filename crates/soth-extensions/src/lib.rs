#![allow(clippy::type_complexity)]
#![forbid(unsafe_code)]

pub mod context;
pub mod error;
pub mod extension;
pub mod install;
pub mod migrations;
pub mod observation_queue;
pub mod registry;
pub mod status;
pub mod telemetry_queue;

pub use context::ExtensionRuntimeContext;
pub use error::ExtensionError;
pub use extension::{Capability, Extension, ExtensionArchetype, ExtensionManifest};
pub use install::{install_with_backup, InstallSummary, InstallTarget};
pub use migrations::MigrationRunner;
pub use observation_queue::{
    ObservationQueueRecord, ObservationQueueWriter, OwnedObservationQueueRecord,
};
pub use registry::ExtensionRegistry;
pub use status::{BackfillProgressSnapshot, ExtensionStatus, LifecycleState, ToolBackfillProgress};
pub use telemetry_queue::{
    GovernableQueueRecord, OwnedGovernableQueueRecord, TelemetryQueueWriter,
};

// Re-export core extension types for convenience
pub use soth_core::{
    EventSource, ExtensionContext, ExtensionSource, ExtensionType, GovernableEvent,
    ObservationEvent, PreEmitEvent,
};
