//! Conformance harness for cross-lane parity between proxy and SDK code paths.
//!
//! For every fixture in the `fixtures/` corpus, the harness runs:
//!   - **Proxy lane**: `RawRequest` → `process_with_registry` → `classify`
//!   - **SDK lane**:   `TypedLlmCall` → `process_normalized` → `classify`
//!
//! The two `ClassifiedResult`s must agree on the set of fields that comprise
//! the SDK-to-cloud contract. Per-call ephemeral fields (event_id, nonces,
//! timings, transport metadata) and intentionally divergent fields
//! (`parse_source`, parser_id, schema_version) are excluded by design.
//!
//! When a fixture diverges, the harness reports each mismatched field by
//! name so the failure is debuggable without re-running locally with prints.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use serde::Deserialize;

use soth_core::{
    AppType, ArtifactKind, AttributionContext, CaptureMode, ClassificationSource, ConnectionMeta,
    DetectResult, EndpointType, IdentityContext, OwnedDetectBundle, ProcessMatchKind,
    ProcessResolution, ProviderEntry, ProxyContext, RawRequest, RestFormatDescriptor,
    RestRequestPaths, SessionSnapshot, SocketFamily, SurfaceType, TrafficClassification,
    TransportContext, TypedLlmCall, TypedMessage, TypedTool,
};
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddrV4};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixture file format
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Fixture {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub axes: FixtureAxes,
    pub typed_call: TypedCallSpec,
    pub raw_request: RawRequestSpec,
}

#[derive(Debug, Default, Deserialize)]
pub struct FixtureAxes {
    pub provider: Option<String>,
    pub streaming: Option<bool>,
    pub tools: Option<bool>,
    pub content_class: Option<String>,
    pub parse_confidence: Option<String>,
    pub capture_mode: Option<String>,
    pub use_case_label: Option<String>,
    pub anomaly_flag: Option<String>,
    pub policy_decision: Option<String>,
    pub format: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TypedCallSpec {
    pub provider: String,
    pub model: String,
    pub messages: Vec<TypedMessageSpec>,
    #[serde(default)]
    pub system: Option<String>,
    #[serde(default)]
    pub tools: Vec<TypedToolSpec>,
    #[serde(default)]
    pub stream: bool,
    #[serde(default)]
    pub temperature: Option<f32>,
    #[serde(default)]
    pub top_p: Option<f32>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub stop_sequences: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TypedMessageSpec {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
pub struct TypedToolSpec {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub parameters_json: String,
}

#[derive(Debug, Deserialize)]
pub struct RawRequestSpec {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    /// Body as a serde_json::Value — the harness re-serializes it to bytes
    /// so the fixture stays human-editable.
    pub body: serde_json::Value,
    /// Optional matched_provider hint for the proxy lane (mirrors the
    /// proxy's gating step). Defaults to the typed_call.provider when
    /// omitted.
    #[serde(default)]
    pub matched_provider: Option<String>,
}

impl TypedCallSpec {
    fn into_call(self) -> TypedLlmCall {
        TypedLlmCall {
            provider: self.provider,
            model: self.model,
            messages: self
                .messages
                .into_iter()
                .map(|m| TypedMessage {
                    role: m.role,
                    content: m.content,
                })
                .collect(),
            system: self.system,
            tools: self
                .tools
                .into_iter()
                .map(|t| TypedTool {
                    name: t.name,
                    description: t.description,
                    parameters_json: t.parameters_json,
                })
                .collect(),
            stream: self.stream,
            temperature: self.temperature,
            top_p: self.top_p,
            max_tokens: self.max_tokens,
            stop_sequences: self.stop_sequences,
            endpoint_type: EndpointType::ChatCompletion,
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture discovery + loading
// ---------------------------------------------------------------------------

pub fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

pub fn load_fixtures() -> Vec<(PathBuf, Fixture)> {
    let dir = fixture_dir();
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) => panic!("failed to read fixtures dir {dir:?}: {error}"),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => panic!("read fixture {path:?}: {error}"),
        };
        let fixture: Fixture = match serde_json::from_slice(&bytes) {
            Ok(fixture) => fixture,
            Err(error) => panic!("parse fixture {path:?}: {error}"),
        };
        out.push((path, fixture));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

// ---------------------------------------------------------------------------
// Bundle / context construction shared across both lanes
// ---------------------------------------------------------------------------

/// Build a synthetic detect bundle that recognizes the conventional provider
/// slugs used by the fixture corpus. Mirrors `soth-detect`'s test fixture.
pub fn build_detect_bundle() -> OwnedDetectBundle {
    let mut rest_formats = HashMap::new();
    rest_formats.insert(
        "openai".to_string(),
        RestFormatDescriptor {
            request: RestRequestPaths {
                model: Some("$.model".to_string()),
                messages: Some("$.messages".to_string()),
                tools: Some("$.tools".to_string()),
                temperature: Some("$.temperature".to_string()),
                max_tokens: Some("$.max_tokens".to_string()),
                stream: Some("$.stream".to_string()),
                stop: Some("$.stop".to_string()),
                ..RestRequestPaths::default()
            },
            system_in_messages: true,
            ..RestFormatDescriptor::default()
        },
    );
    rest_formats.insert(
        "anthropic".to_string(),
        RestFormatDescriptor {
            request: RestRequestPaths {
                model: Some("$.model".to_string()),
                messages: Some("$.messages".to_string()),
                system: Some("$.system".to_string()),
                ..RestRequestPaths::default()
            },
            system_in_messages: false,
            ..RestFormatDescriptor::default()
        },
    );
    rest_formats.insert(
        "cohere".to_string(),
        RestFormatDescriptor {
            request: RestRequestPaths {
                model: Some("$.model".to_string()),
                messages: Some("$.messages".to_string()),
                ..RestRequestPaths::default()
            },
            system_in_messages: true,
            ..RestFormatDescriptor::default()
        },
    );
    rest_formats.insert(
        "mistral".to_string(),
        RestFormatDescriptor {
            request: RestRequestPaths {
                model: Some("$.model".to_string()),
                messages: Some("$.messages".to_string()),
                ..RestRequestPaths::default()
            },
            system_in_messages: true,
            ..RestFormatDescriptor::default()
        },
    );

    let mut domain_index = HashMap::new();
    domain_index.insert("api.openai.com".to_string(), "openai".to_string());
    domain_index.insert("api.anthropic.com".to_string(), "anthropic".to_string());
    domain_index.insert("api.cohere.com".to_string(), "cohere".to_string());
    domain_index.insert("api.mistral.ai".to_string(), "mistral".to_string());

    let mut providers = HashMap::new();
    for slug in ["openai", "anthropic", "cohere", "mistral"] {
        providers.insert(
            slug.to_string(),
            ProviderEntry {
                provider_id: Some(slug.to_string()),
                name: Some(slug.to_string()),
                api_format: Some(slug.to_string()),
                ..ProviderEntry::default()
            },
        );
    }

    OwnedDetectBundle {
        rest_formats,
        domain_index,
        llm_providers: providers,
        ..OwnedDetectBundle::default()
    }
}

pub fn build_proxy_context(declared_provider: Option<String>) -> ProxyContext {
    ProxyContext {
        identity: IdentityContext {
            org_id: "org-conformance".to_string(),
            user_id_hmac: "user-hmac".to_string(),
            team_id: "team".to_string(),
            device_id_hash: "device".to_string(),
            endpoint_hash: "endpoint".to_string(),
            capture_mode: CaptureMode::MetadataOnly,
            traffic_classification: TrafficClassification::ToolUsage,
            classification_source: ClassificationSource::Sdk,
            session_snapshot: Some(SessionSnapshot::default()),
            declared_provider,
            declared_application: None,
            session_id: None,
            deployment_context: None,
            bundle_trust_level: None,
            precomputed_commitment_nonce: None,
            precomputed_commitment_hash: None,
        },
        transport: TransportContext::default(),
        attribution: AttributionContext {
            process_resolution: ProcessResolution {
                match_kind: ProcessMatchKind::Unknown,
                app_type: AppType::Unknown,
                capture_mode: Some(CaptureMode::MetadataOnly),
                process_name: None,
                bundle_id: None,
                matched_app_id: None,
                ..Default::default()
            },
            product_id: None,
            surface_type: SurfaceType::Unknown,
            is_shadow_it: false,
        },
    }
}

// ---------------------------------------------------------------------------
// Lane runners
// ---------------------------------------------------------------------------

pub struct LaneOutput {
    pub detect: DetectResult,
    pub classified: soth_classify::ClassifiedResult,
}

pub fn run_proxy_lane(
    fixture: &Fixture,
    detect_bundle: &OwnedDetectBundle,
    classify_bundle: &soth_classify::ClassifyBundle,
    config: &soth_classify::ClassifyConfig,
) -> LaneOutput {
    let registry = soth_detect::ParserRegistry::default();
    let body_bytes = serde_json::to_vec(&fixture.raw_request.body).expect("serialize body");

    let mut connection_meta = ConnectionMeta {
        connection_id: Uuid::new_v4(),
        socket_family: SocketFamily::TcpV4 {
            local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080),
            remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
        },
        process_info: None,
        tls_info: None,
        app_identity: None,
        capture_mode: Some(CaptureMode::MetadataOnly),
        matched_provider: fixture
            .raw_request
            .matched_provider
            .clone()
            .or_else(|| Some(fixture.typed_call.provider.clone())),
        matched_application: None,
        h2_connection_id: None,
        h2_stream_id: None,
    };
    // Drop the explicit clone to avoid `unused_mut` if the field initializer
    // changes; keep the variable mutable for any pre-call header tweaks.
    connection_meta.app_identity = None;

    let request = RawRequest {
        method: fixture.raw_request.method.clone(),
        path: fixture.raw_request.path.clone(),
        headers: fixture.raw_request.headers.clone(),
        body: Bytes::from(body_bytes),
        connection_meta,
    };

    let detect = soth_detect::process_with_registry(
        &registry,
        &request,
        &detect_bundle.as_slice(),
        &SessionSnapshot::default(),
    );

    let proxy_ctx = build_proxy_context(Some(fixture.typed_call.provider.clone()));
    let user_content = fixture
        .typed_call
        .messages
        .iter()
        .filter(|m| m.role == "user")
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let classified = soth_classify::classify(
        &detect,
        if user_content.is_empty() {
            None
        } else {
            Some(user_content.as_str())
        },
        &proxy_ctx,
        classify_bundle,
        config,
    );

    LaneOutput { detect, classified }
}

pub fn run_sdk_lane(
    fixture: &Fixture,
    detect_bundle: &OwnedDetectBundle,
    classify_bundle: &soth_classify::ClassifyBundle,
    config: &soth_classify::ClassifyConfig,
) -> LaneOutput {
    let registry = soth_detect::ParserRegistry::default();
    let call = TypedCallSpec {
        provider: fixture.typed_call.provider.clone(),
        model: fixture.typed_call.model.clone(),
        messages: fixture
            .typed_call
            .messages
            .iter()
            .map(|m| TypedMessageSpec {
                role: m.role.clone(),
                content: m.content.clone(),
            })
            .collect(),
        system: fixture.typed_call.system.clone(),
        tools: fixture
            .typed_call
            .tools
            .iter()
            .map(|t| TypedToolSpec {
                name: t.name.clone(),
                description: t.description.clone(),
                parameters_json: t.parameters_json.clone(),
            })
            .collect(),
        stream: fixture.typed_call.stream,
        temperature: fixture.typed_call.temperature,
        top_p: fixture.typed_call.top_p,
        max_tokens: fixture.typed_call.max_tokens,
        stop_sequences: fixture.typed_call.stop_sequences.clone(),
    }
    .into_call();

    let detect = soth_detect::process_normalized(
        &registry,
        &call,
        &detect_bundle.as_slice(),
        &SessionSnapshot::default(),
        CaptureMode::MetadataOnly,
    );

    let proxy_ctx = build_proxy_context(Some(call.provider.clone()));
    let user_content = call.user_content();
    let classified = soth_classify::classify(
        &detect,
        if user_content.is_empty() {
            None
        } else {
            Some(user_content.as_str())
        },
        &proxy_ctx,
        classify_bundle,
        config,
    );

    LaneOutput { detect, classified }
}

// ---------------------------------------------------------------------------
// Facade lane — runs the same fixture through `SothSdk::pre_call` /
// `post_call`. Asserts the public-API facade does not introduce drift
// vs. calling `process_normalized` + `classify` directly (run_sdk_lane).
// ---------------------------------------------------------------------------

pub struct FacadeOutput {
    pub decision: soth_sdk_core::Decision,
    /// Telemetry event emitted by `post_call`. Always present — even
    /// `Decision::Block` paths still call `post_call` to consume the
    /// token, and the SDK emits an event regardless.
    pub telemetry: Option<soth_core::TelemetryEvent>,
}

pub fn run_facade_lane(
    fixture: &Fixture,
    detect_bundle: &OwnedDetectBundle,
    classify_bundle: &std::sync::Arc<soth_classify::ClassifyBundle>,
) -> FacadeOutput {
    use zeroize::Zeroizing;

    let config = soth_sdk_core::SdkConfigBuilder::new()
        .api_key("conformance-test")
        .org_id("org-conformance")
        .hmac_key(soth_sdk_core::HmacKey::Static(Zeroizing::new(vec![0u8; 32])))
        .build()
        .expect("build sdk config");

    let sdk = soth_sdk_core::SothSdk::for_test(
        config,
        detect_bundle.clone(),
        std::sync::Arc::clone(classify_bundle),
    )
    .expect("init sdk for_test");

    // Build the typed call from the fixture (same conversion the SDK
    // direct lane uses).
    let call = TypedCallSpec {
        provider: fixture.typed_call.provider.clone(),
        model: fixture.typed_call.model.clone(),
        messages: fixture
            .typed_call
            .messages
            .iter()
            .map(|m| TypedMessageSpec {
                role: m.role.clone(),
                content: m.content.clone(),
            })
            .collect(),
        system: fixture.typed_call.system.clone(),
        tools: fixture
            .typed_call
            .tools
            .iter()
            .map(|t| TypedToolSpec {
                name: t.name.clone(),
                description: t.description.clone(),
                parameters_json: t.parameters_json.clone(),
            })
            .collect(),
        stream: fixture.typed_call.stream,
        temperature: fixture.typed_call.temperature,
        top_p: fixture.typed_call.top_p,
        max_tokens: fixture.typed_call.max_tokens,
        stop_sequences: fixture.typed_call.stop_sequences.clone(),
    }
    .into_call();

    let decision = sdk.pre_call(&call);
    let token = decision.token();

    let response = soth_sdk_core::LlmResponse::new(EndpointType::ChatCompletion);
    sdk.post_call(token, &response);

    let telemetry = sdk.drain_telemetry_for_test().into_iter().next();

    FacadeOutput { decision, telemetry }
}

// ---------------------------------------------------------------------------
// Diff: compare proxy and SDK outputs on the SDK-to-cloud contract surface.
//
// The fields below comprise the *contract*. Anything not in this list is
// either intentionally divergent (parse_source: Rest{} vs Sdk) or
// per-call ephemeral (event_id, nonces, timings) and lives in the
// allowlist by virtue of not appearing here. If a field SHOULD be in
// the contract and was forgotten, add it here.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Diff {
    pub field: String,
    pub proxy: String,
    pub sdk: String,
}

/// Strict cross-lane comparison.
///
/// Asserts the fields that are at parity *today* between the proxy REST
/// parser and the SDK's `process_normalized` path. Provider-specific
/// content-extraction fields (`user_content_hash`, `system_prompt_hash`,
/// `tool_definition_hash`, `conversation_hash`) and ML-pipeline outputs
/// derived from them (`use_case_label`, `volatility_class`, `anomaly_flags`)
/// are surfaced via [`compare_advisory`] but excluded from this strict
/// check — they have known content-shape divergences tracked in the
/// README's "Follow-up parity work" section.
pub fn compare(proxy: &LaneOutput, sdk: &LaneOutput) -> Vec<Diff> {
    let mut diffs = Vec::new();

    push_eq(
        &mut diffs,
        "normalized.provider",
        &proxy.detect.normalized.provider,
        &sdk.detect.normalized.provider,
    );
    push_eq(
        &mut diffs,
        "normalized.model",
        &format!("{:?}", proxy.detect.normalized.model),
        &format!("{:?}", sdk.detect.normalized.model),
    );
    push_eq(
        &mut diffs,
        "normalized.endpoint_type",
        &format!("{:?}", proxy.detect.normalized.endpoint_type),
        &format!("{:?}", sdk.detect.normalized.endpoint_type),
    );
    push_eq(
        &mut diffs,
        "normalized.is_ai_call",
        &proxy.detect.normalized.is_ai_call.to_string(),
        &sdk.detect.normalized.is_ai_call.to_string(),
    );
    push_eq(
        &mut diffs,
        "normalized.has_tool_definitions",
        &proxy.detect.normalized.has_tool_definitions.to_string(),
        &sdk.detect.normalized.has_tool_definitions.to_string(),
    );
    push_eq(
        &mut diffs,
        "normalized.stream",
        &proxy.detect.normalized.stream.to_string(),
        &sdk.detect.normalized.stream.to_string(),
    );

    // ── DetectResult.artifacts (set comparison by ArtifactKind label) ───
    let proxy_kinds = artifact_kind_set(&proxy.detect.artifacts);
    let sdk_kinds = artifact_kind_set(&sdk.detect.artifacts);
    if proxy_kinds != sdk_kinds {
        diffs.push(Diff {
            field: "detect.artifacts".to_string(),
            proxy: format!("{proxy_kinds:?}"),
            sdk: format!("{sdk_kinds:?}"),
        });
    }

    push_eq(
        &mut diffs,
        "detect.capture_mode",
        &format!("{:?}", proxy.detect.capture_mode),
        &format!("{:?}", sdk.detect.capture_mode),
    );
    push_eq(
        &mut diffs,
        "classified.policy_decision.kind",
        &policy_decision_label(&proxy.classified.policy_decision.kind),
        &policy_decision_label(&sdk.classified.policy_decision.kind),
    );

    // TelemetryEvent shape contract (the cloud ingestion surface)
    push_eq(
        &mut diffs,
        "telemetry.provider",
        &proxy.classified.telemetry_event.provider,
        &sdk.classified.telemetry_event.provider,
    );
    push_eq(
        &mut diffs,
        "telemetry.model",
        &format!("{:?}", proxy.classified.telemetry_event.model),
        &format!("{:?}", sdk.classified.telemetry_event.model),
    );
    push_eq(
        &mut diffs,
        "telemetry.endpoint_type",
        &format!("{:?}", proxy.classified.telemetry_event.endpoint_type),
        &format!("{:?}", sdk.classified.telemetry_event.endpoint_type),
    );
    push_eq(
        &mut diffs,
        "telemetry.capture_mode",
        &format!("{:?}", proxy.classified.telemetry_event.capture_mode),
        &format!("{:?}", sdk.classified.telemetry_event.capture_mode),
    );

    diffs
}

/// Advisory cross-lane comparison.
///
/// Reports content-extraction fields that have known divergences between
/// proxy and SDK lanes. The harness prints these without failing — they
/// represent the next workstream's parity goal. As [`process_normalized`]
/// is brought into byte-level alignment with the proxy REST parser, fields
/// graduate from this advisory list into the strict `compare` set.
pub fn compare_advisory(proxy: &LaneOutput, sdk: &LaneOutput) -> Vec<Diff> {
    let mut diffs = Vec::new();
    push_eq(
        &mut diffs,
        "normalized.user_content_hash",
        &proxy.detect.normalized.user_content_hash,
        &sdk.detect.normalized.user_content_hash,
    );
    push_eq(
        &mut diffs,
        "normalized.system_prompt_hash",
        &format!("{:?}", proxy.detect.normalized.system_prompt_hash),
        &format!("{:?}", sdk.detect.normalized.system_prompt_hash),
    );
    push_eq(
        &mut diffs,
        "normalized.tool_definition_hash",
        &format!("{:?}", proxy.detect.normalized.tool_definition_hash),
        &format!("{:?}", sdk.detect.normalized.tool_definition_hash),
    );
    push_eq(
        &mut diffs,
        "normalized.conversation_hash",
        &proxy.detect.normalized.conversation_hash,
        &sdk.detect.normalized.conversation_hash,
    );
    push_eq(
        &mut diffs,
        "classified.use_case_label",
        &format!("{:?}", proxy.classified.use_case_label),
        &format!("{:?}", sdk.classified.use_case_label),
    );
    push_eq(
        &mut diffs,
        "classified.volatility_class",
        &format!("{:?}", proxy.classified.volatility_class),
        &format!("{:?}", sdk.classified.volatility_class),
    );
    let proxy_anomaly = anomaly_flag_set(&proxy.classified.anomaly_flags);
    let sdk_anomaly = anomaly_flag_set(&sdk.classified.anomaly_flags);
    if proxy_anomaly != sdk_anomaly {
        diffs.push(Diff {
            field: "classified.anomaly_flags".to_string(),
            proxy: format!("{proxy_anomaly:?}"),
            sdk: format!("{sdk_anomaly:?}"),
        });
    }
    diffs
}

/// Compare the SDK direct lane to the facade lane. The facade should
/// emit a `TelemetryEvent` byte-identical to the SDK lane's
/// `classified.telemetry_event` (excluding per-call ephemeral fields:
/// `event_id`, `timestamp_epoch_ms`, `commitment_nonce`,
/// `commitment_hash`). Any divergence is a facade bug.
pub fn compare_sdk_vs_facade(sdk: &LaneOutput, facade: &FacadeOutput) -> Vec<Diff> {
    let mut diffs = Vec::new();

    let Some(facade_event) = facade.telemetry.as_ref() else {
        diffs.push(Diff {
            field: "facade.telemetry".to_string(),
            proxy: format!("{:?}", sdk.classified.telemetry_event.provider),
            sdk: "<no event emitted>".to_string(),
        });
        return diffs;
    };

    let sdk_event = &sdk.classified.telemetry_event;

    // Cloud ingestion contract — these fields are what the cloud reads.
    push_eq(
        &mut diffs,
        "telemetry.provider",
        &sdk_event.provider,
        &facade_event.provider,
    );
    push_eq(
        &mut diffs,
        "telemetry.model",
        &format!("{:?}", sdk_event.model),
        &format!("{:?}", facade_event.model),
    );
    push_eq(
        &mut diffs,
        "telemetry.endpoint_type",
        &format!("{:?}", sdk_event.endpoint_type),
        &format!("{:?}", facade_event.endpoint_type),
    );
    push_eq(
        &mut diffs,
        "telemetry.capture_mode",
        &format!("{:?}", sdk_event.capture_mode),
        &format!("{:?}", facade_event.capture_mode),
    );
    push_eq(
        &mut diffs,
        "telemetry.parse_source",
        &format!("{:?}", sdk_event.parse_source),
        &format!("{:?}", facade_event.parse_source),
    );
    push_eq(
        &mut diffs,
        "telemetry.parse_confidence",
        &format!("{:?}", sdk_event.parse_confidence),
        &format!("{:?}", facade_event.parse_confidence),
    );
    push_eq(
        &mut diffs,
        "telemetry.use_case",
        &format!("{:?}", sdk_event.use_case),
        &format!("{:?}", facade_event.use_case),
    );
    push_eq(
        &mut diffs,
        "telemetry.volatility_class",
        &format!("{:?}", sdk_event.volatility_class),
        &format!("{:?}", facade_event.volatility_class),
    );
    push_eq(
        &mut diffs,
        "telemetry.policy_kind",
        &format!("{:?}", sdk_event.policy_kind),
        &format!("{:?}", facade_event.policy_kind),
    );
    push_eq(
        &mut diffs,
        "telemetry.estimated_input_tokens",
        &format!("{:?}", sdk_event.estimated_input_tokens),
        &format!("{:?}", facade_event.estimated_input_tokens),
    );

    let sdk_anomaly = anomaly_flag_set(&sdk_event.anomaly_flags);
    let facade_anomaly = anomaly_flag_set(&facade_event.anomaly_flags);
    if sdk_anomaly != facade_anomaly {
        diffs.push(Diff {
            field: "telemetry.anomaly_flags".to_string(),
            proxy: format!("{sdk_anomaly:?}"),
            sdk: format!("{facade_anomaly:?}"),
        });
    }

    diffs
}

fn push_eq(diffs: &mut Vec<Diff>, field: &str, left: &str, right: &str) {
    if left != right {
        diffs.push(Diff {
            field: field.to_string(),
            proxy: left.to_string(),
            sdk: right.to_string(),
        });
    }
}

fn artifact_kind_set(arts: &[soth_core::SensitiveArtifact]) -> BTreeSet<String> {
    arts.iter().map(|a| artifact_kind_label(&a.kind)).collect()
}

fn artifact_kind_label(kind: &ArtifactKind) -> String {
    match kind {
        ArtifactKind::ApiKey { provider } => format!("api_key:{provider:?}"),
        ArtifactKind::PrivateKey => "private_key".to_string(),
        ArtifactKind::CodeBlock { language } => format!("code_block:{language}"),
        other => format!("{other:?}"),
    }
}

fn anomaly_flag_set(flags: &[soth_core::AnomalyFlag]) -> BTreeSet<String> {
    flags.iter().map(|f| format!("{f:?}")).collect()
}

fn policy_decision_label(kind: &soth_core::PolicyDecisionKind) -> String {
    match kind {
        soth_core::PolicyDecisionKind::Allow => "Allow".to_string(),
        soth_core::PolicyDecisionKind::Block { .. } => "Block".to_string(),
        soth_core::PolicyDecisionKind::Redact { .. } => "Redact".to_string(),
        soth_core::PolicyDecisionKind::Reroute { .. } => "Reroute".to_string(),
        soth_core::PolicyDecisionKind::Flag { .. } => "Flag".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Coverage tracker — surfaces which taxonomy axes the corpus exercises.
//
// `parity.rs` prints the coverage matrix at the end so growing the corpus
// can be a guided activity rather than spelunking through fixture JSON.
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct CoverageReport {
    pub providers: BTreeSet<String>,
    pub streaming: BTreeSet<bool>,
    pub tools: BTreeSet<bool>,
    pub content_classes: BTreeSet<String>,
    pub capture_modes: BTreeSet<String>,
    pub use_case_labels: BTreeSet<String>,
    pub anomaly_flags: BTreeSet<String>,
    pub policy_decisions: BTreeSet<String>,
}

impl CoverageReport {
    pub fn record(&mut self, fixture: &Fixture) {
        if let Some(p) = &fixture.axes.provider {
            self.providers.insert(p.clone());
        } else {
            self.providers.insert(fixture.typed_call.provider.clone());
        }
        if let Some(s) = fixture.axes.streaming {
            self.streaming.insert(s);
        } else {
            self.streaming.insert(fixture.typed_call.stream);
        }
        if let Some(t) = fixture.axes.tools {
            self.tools.insert(t);
        } else {
            self.tools.insert(!fixture.typed_call.tools.is_empty());
        }
        if let Some(c) = &fixture.axes.content_class {
            self.content_classes.insert(c.clone());
        }
        if let Some(c) = &fixture.axes.capture_mode {
            self.capture_modes.insert(c.clone());
        }
        if let Some(l) = &fixture.axes.use_case_label {
            self.use_case_labels.insert(l.clone());
        }
        if let Some(f) = &fixture.axes.anomaly_flag {
            self.anomaly_flags.insert(f.clone());
        }
        if let Some(d) = &fixture.axes.policy_decision {
            self.policy_decisions.insert(d.clone());
        }
    }

    pub fn render(&self, total_fixtures: usize) -> String {
        format!(
            "fixtures: {total}\n  providers ({}): {:?}\n  streaming: {:?}\n  tools: {:?}\n  content_classes: {:?}\n  capture_modes: {:?}\n  use_case_labels: {:?}\n  anomaly_flags: {:?}\n  policy_decisions: {:?}\n",
            self.providers.len(),
            self.providers,
            self.streaming,
            self.tools,
            self.content_classes,
            self.capture_modes,
            self.use_case_labels,
            self.anomaly_flags,
            self.policy_decisions,
            total = total_fixtures,
        )
    }
}

// ---------------------------------------------------------------------------
// Entry point used by the parity test
// ---------------------------------------------------------------------------

pub struct ParityRunner {
    pub detect_bundle: OwnedDetectBundle,
    pub classify_bundle: std::sync::Arc<soth_classify::ClassifyBundle>,
    pub config: soth_classify::ClassifyConfig,
}

impl ParityRunner {
    pub fn new() -> Self {
        Self {
            detect_bundle: build_detect_bundle(),
            classify_bundle: soth_classify::fallback_bundle(),
            config: soth_classify::ClassifyConfig::default(),
        }
    }

    pub fn run(&self, fixture: &Fixture) -> Vec<Diff> {
        let proxy =
            run_proxy_lane(fixture, &self.detect_bundle, &self.classify_bundle, &self.config);
        let sdk = run_sdk_lane(fixture, &self.detect_bundle, &self.classify_bundle, &self.config);
        compare(&proxy, &sdk)
    }
}

impl Default for ParityRunner {
    fn default() -> Self {
        Self::new()
    }
}

// Path helper for tests.
pub fn fixtures_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}
