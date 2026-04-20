#![forbid(unsafe_code)]

pub mod artifacts;
pub mod bundle;
pub mod classify;
pub mod crypto;
pub mod detect;
pub mod error;
pub mod extensions;
pub mod identity;
pub mod native_bundle;
pub mod normalized;
pub mod observation;
pub mod policy;
pub mod pre_emit;
pub mod providers;
pub mod request;
pub mod session;
pub mod telemetry;

// ── error (already explicit) ──────────────────────────────────────────────────
pub use error::{Result, SothError};

// ── crypto ────────────────────────────────────────────────────────────────────
pub use crypto::{
    cache_key_from_normalized, commitment_hash, derive_proxy_signing_seed, sha256_hex,
};

// ── providers ─────────────────────────────────────────────────────────────────
pub use providers::DetectedProvider;

// ── artifacts ─────────────────────────────────────────────────────────────────
pub use artifacts::{
    ArtifactKind, ArtifactLocation, ArtifactSeverity, CaptureMode, ParseConfidence, ParseSource,
    ParseWarning, SensitiveArtifact,
};

// ── normalized ────────────────────────────────────────────────────────────────
pub use normalized::{EndpointType, FormatMetadata, GraphQlOperationType, NormalizedRequest};

// ── request ───────────────────────────────────────────────────────────────────
pub use request::{
    FrameDirection, FrameKind, RawRequest, RawResponse, RequestHeaders, StreamChunk,
};

// ── identity ──────────────────────────────────────────────────────────────────
pub use identity::{AppIdentity, AppKind, ConnectionMeta, ProcessInfo, SocketFamily, TlsInfo};

// ── detect ────────────────────────────────────────────────────────────────────
pub use detect::DetectResult;

// ── classify ──────────────────────────────────────────────────────────────────
pub use classify::{
    AnomalyFlag, AppType, ClassificationSource, DeploymentContext, ProcessMatchKind,
    ProcessResolution, ProxyContext, SessionSnapshot, SurfaceType, TrafficClassification,
};

// ── extensions ────────────────────────────────────────────────────────────────
pub use extensions::{
    EventSource, ExtensionContext, ExtensionSource, ExtensionType, GovernableEvent,
};

// ── observation ───────────────────────────────────────────────────────────────
pub use observation::{
    EvidenceSignal, EvidenceSignalType, ObservationEvent, ObservationKind, ObservationSubject,
};

// ── policy ────────────────────────────────────────────────────────────────────
pub use policy::{
    DeploymentModel, MatchedRule, PolicyContext, PolicyDecision, PolicyDecisionKind, PolicyWarning,
    RedactTarget, RerouteTarget, RuleKind, SemanticPolicyContext,
};

// ── pre_emit ──────────────────────────────────────────────────────────────────
pub use pre_emit::{ObserverBroadcast, PreEmitEvent};

// ── session ───────────────────────────────────────────────────────────────────
pub use session::{
    AnomalyBaseline, AnomalyDelta, CodeBlob, ConversationFingerprint, MessageFingerprint,
    SeenPrefixRecord, Session, SessionAppIdentity, SessionKey, SessionMutations, SessionStats,
};

// ── telemetry ─────────────────────────────────────────────────────────────────
pub use telemetry::{
    BundleTrustLevel, CacheLevel, ClassificationFlag, DataSource, ImportCategory,
    InteractionMode, ProgrammingLanguage, RequestMethod, RoutingReason, SensitiveCodeFlags,
    TelemetryEvent, TelemetryPolicyKind, UseCaseLabel, VolatilityClass,
};

// ── native_bundle ─────────────────────────────────────────────────────────────
pub use native_bundle::{
    NativeBundle, NativeBundleCapture, NativeBundleCatalogEntry, NativeBundleDomainIndexEntry,
    NativeBundleEntity, NativeBundleFilter, NativeBundleFormat, NativeBundleMetadata,
    NativeBundleProviderLink, NativeBundleRule, NativeBundleSetting, NativeBundleSignal,
    NativeBundleVendor, NATIVE_BUNDLE_SCHEMA_VERSION,
};

// ── bundle ────────────────────────────────────────────────────────────────────
// Kept as glob: the bundle module re-exports 50+ public items from six
// sub-modules (detect, entity_index, env_index, gating, matching, classify).
// Enumerating them all would add significant churn with little readability
// benefit; callers that need precise paths already import via
// `soth_core::bundle::submodule::Type`.
pub use bundle::*;
