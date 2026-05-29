use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::artifacts::{CaptureMode, ParseConfidence, ParseSource};
use crate::classify::{
    AnomalyFlag, AppType, ProcessMatchKind, ProcessResolution, SurfaceType, TrafficClassification,
};
use crate::normalized::EndpointType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UseCaseLabel {
    CodeGeneration,
    CodeReview,
    CodeDebugging,
    CodeRefactor,
    TextSummarization,
    TextGeneration,
    Translation,
    DataAnalysis,
    DataExtraction,
    QuestionAnswering,
    DocumentSearch,
    AgentTask,
    ToolOrchestration,
    ImageAnalysis,
    AudioTranscription,
    SystemPromptOnly,
    // ── Variants below were introduced when the use-case MLP was retrained
    // on the 400k corpus. The model now distinguishes these as separate
    // categories instead of bucketing them; the proxy preserves that
    // granularity so the dashboard can surface them as first-class buckets
    // rather than collapsing into TextGeneration / ToolOrchestration /
    // CodeReview / DataAnalysis. Order matters for `LABEL_SPACE` in
    // soth-classify::model: appended *after* the legacy 16 variants and
    // *before* `Unknown` so the legacy index range (0–15) for the raw-
    // weights fallback parser is preserved.
    /// Infra / DevOps work — k8s manifests, terraform, CI/CD config,
    /// shell scripts targeted at platform operations. Used to map to
    /// `ToolOrchestration` which is now reserved for actual agent
    /// tool-call orchestration.
    InfraDevops,
    /// Legal / contract drafting and review — agreements, policies,
    /// compliance text. Used to map to `TextGeneration` which masked
    /// the higher sensitivity of this category.
    LegalContract,
    /// Long-form research synthesis — multi-source reading, literature
    /// review, briefings. Used to map to `DataAnalysis`.
    ResearchSynthesis,
    /// Security analysis — vulnerability triage, threat modelling,
    /// pen-test scoping. Used to map to `CodeReview` which conflated
    /// it with general code quality review.
    SecurityAnalysis,
    /// Editing existing content — copyedits, style passes, grammar
    /// fixes. Used to map to `TextGeneration` which conflated it
    /// with drafting net-new content.
    ContentEditing,
    Unknown,
}

/// Discriminator that explains *why* a `UseCaseLabel` was chosen, especially
/// when the chosen label is `Unknown`. Lets the cloud/dashboard distinguish a
/// genuinely-unknown classification from a configuration skip, an upstream
/// error, or an unenriched historian event — all of which previously emitted
/// `Unknown` indistinguishably.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UseCaseLabelReason {
    /// Model classified above the confidence threshold.
    #[default]
    Confident,
    /// Model ran but top-1 confidence is below threshold; label still emitted.
    LowConfidence,
    /// `ClassifyConfig::embedding_enabled = false`.
    EmbeddingDisabled,
    /// Detect pipeline marked the call as not-AI; classifier short-circuited.
    NotAiCall,
    /// Heuristic parse with no resolved model — model context required to classify.
    HeuristicNoModel,
    /// CodeContextRepeat lane optimization — embedding intentionally skipped.
    CodeContextRepeat,
    /// No content available to embed (e.g. response-only event).
    NoContent,
    /// ONNX or legacy embedder panicked or returned a degenerate vector.
    EmbeddingFailed,
    /// Bundle has no real ONNX models — `KeywordClassifier` fallback in use.
    FallbackBundle,
    /// Bundle declared a label string not in the canonical `UseCaseLabel` enum.
    UnmappedBundleLabel,
    /// Model weights/biases/labels shape mismatch (defensive check).
    ModelShapeError,
    /// Extension event was queued without running `ClassifyEnricher`.
    /// Applies to any extension that produces `GovernableEvent`s
    /// (historian, soth-code, future extensions). Original variant
    /// name was `HistorianNotEnriched` from when historian was the
    /// only extension; serde alias preserves backwards compat for
    /// any in-flight events with the old wire form.
    #[serde(alias = "historian_not_enriched")]
    ExtensionNotEnriched,
    /// soth-code synthesized this row for a `pre_tool_use` hook.
    /// Classify pipeline did not run — the dashboard's `use_case`
    /// is the tool name itself (`Bash`, `Read`, …).  Lets rollups
    /// distinguish synthesized tool rows from real ONNX
    /// classifications.
    PreToolCall,
    /// Same as `PreToolCall` but for `post_tool_use` events.
    /// Phase split lets dashboards count "tool calls issued" vs
    /// "tool calls completed" without a JOIN on action_seq.
    PostToolCall,
    /// Struct default — never populated by a real classify run.
    UninitializedDefault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolatilityClass {
    Static,
    LowVolatile,
    Dynamic,
    HighlyDynamic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheLevel {
    Exact,
    Semantic,
    Prefix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingReason {
    CostOptimization,
    ComplexityBased,
    PolicyReroute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgrammingLanguage {
    Python,
    JavaScript,
    TypeScript,
    Rust,
    Go,
    Java,
    Cpp,
    C,
    CSharp,
    Ruby,
    Php,
    Swift,
    Kotlin,
    Sql,
    Shell,
    Terraform,
    Solidity,
    Yaml,
    Json,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportCategory {
    Crypto,
    Auth,
    Network,
    Database,
    Filesystem,
    Serialization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationFlag {
    CodeDetected,
    CredentialDetected,
    HighAnomaly,
    PolicyTriggered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryPolicyKind {
    Allow,
    Block,
    Redact,
    Reroute,
    Flag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SensitiveCodeFlags {
    pub credential_pattern_detected: bool,
    pub auth_logic_detected: bool,
    pub crypto_operations_detected: bool,
    pub network_calls_detected: bool,
    pub file_io_detected: bool,
    pub org_pattern_matches: Vec<String>,
    pub private_key_detected: bool,
    pub hardcoded_secret_detected: bool,
    /// Exact credential types detected, such as `openai_api_key`,
    /// `rsa_private_key`, `github_pat`, or `postgres_connection_string`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detected_secret_types: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleTrustLevel {
    Verified,
    Unverified,
    SignatureDisabled,
}

/// Auxiliary classification head — interaction mode (how the user is engaging with AI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionMode {
    /// AI is augmenting the user's work (code completion, suggestions).
    Augmentative,
    /// User is directing AI to execute a task ("write X", "fix Y").
    Directive,
    /// User is exploring/creating freely (brainstorming, creative writing).
    Expressive,
    /// Not classified.
    Unknown,
}

impl Default for InteractionMode {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSource {
    LiveProxy,
    HistorianClaudeCode,
    HistorianGemini,
    HistorianCodex,
    HistorianCursor,
    HistorianGithubCopilot,
    HistorianContinue,
    HistorianOpenClaw,
    HistorianUnknown,
    // ── soth-code extension: per-action live capture from agent hooks.
    //    Distinct from Historian* variants which are post-hoc session
    //    backfill.
    CodeClaudeCode,
    CodeCursor,
    CodeCodex,
    CodeGeminiCli,
    CodeWindsurf,
    CodeOpenCode,
    CodePiAgent,
    /// Code-extension event from an agent that doesn't match any of the
    /// seven shipped adapter names. Mirrors `HistorianUnknown`: keeps
    /// the event on the action layer instead of mis-attributing it to
    /// Claude Code (the prior smoke-friendly default). Surfaces as the
    /// "unknown" agent on the dashboard so operators can audit the
    /// source rather than silently bucket it into someone else's tile.
    CodeUnknown,
}

impl Default for DataSource {
    fn default() -> Self {
        Self::LiveProxy
    }
}

/// Event-stream observation layer.
///
/// SOTH observes AI agent activity at three orthogonal layers:
///
/// - **Network** — proxy MITM observation, one event per HTTP request/response.
/// - **Action** — `soth-code` hook capture, one event per agent tool call.
/// - **Session** — historian file-watch reconstruction, one event per
///   conversation session.
///
/// The dashboard renders these as distinct streams; counts are reported
/// per-layer and never summed across layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventLayer {
    Network,
    Action,
    Session,
}

impl EventLayer {
    /// Derive the canonical layer from a `DataSource`.
    ///
    /// Used when an event predates the explicit `event_layer` field, or
    /// when a writer leaves it unset and the layer can be inferred
    /// unambiguously from data source. See [`TelemetryEvent::effective_event_layer`].
    pub fn from_data_source(ds: DataSource) -> Self {
        match ds {
            DataSource::LiveProxy => Self::Network,
            DataSource::HistorianClaudeCode
            | DataSource::HistorianGemini
            | DataSource::HistorianCodex
            | DataSource::HistorianCursor
            | DataSource::HistorianGithubCopilot
            | DataSource::HistorianContinue
            | DataSource::HistorianOpenClaw
            | DataSource::HistorianUnknown => Self::Session,
            DataSource::CodeClaudeCode
            | DataSource::CodeCursor
            | DataSource::CodeCodex
            | DataSource::CodeGeminiCli
            | DataSource::CodeWindsurf
            | DataSource::CodeOpenCode
            | DataSource::CodePiAgent
            | DataSource::CodeUnknown => Self::Action,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event_id: Uuid,
    pub timestamp_epoch_ms: i64,
    pub connection_id: Option<Uuid>,
    pub provider: String,
    pub model: Option<String>,
    pub endpoint_type: EndpointType,
    pub parse_confidence: ParseConfidence,
    pub parse_source: ParseSource,
    pub capture_mode: CaptureMode,
    pub use_case: UseCaseLabel,
    /// Raw label string when the edge wrote a value that doesn't
    /// match a `UseCaseLabel` enum variant — typically the
    /// soth-code per-tool synthesized labels (`"bash"`, `"read"`,
    /// `"edit"`, MCP tool names, …).  When `Some(_)`, the wire
    /// converter (`soth-api-types/src/convert.rs`) prefers it
    /// over the enum's snake-case name so the dashboard sees
    /// the literal tool name instead of `"unknown"`.  `None` for
    /// proxy / historian rows where the typed enum is
    /// authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_case_label_override: Option<String>,
    pub volatility_class: VolatilityClass,
    pub cache_level: Option<CacheLevel>,
    pub routing_reason: Option<RoutingReason>,
    pub request_method: RequestMethod,
    pub estimated_input_tokens: Option<u32>,
    pub estimated_output_tokens: Option<u32>,
    pub estimated_cost_usd: Option<f32>,
    pub process_resolution: Option<ProcessResolution>,
    pub traffic_classification: Option<TrafficClassification>,
    pub languages: Vec<ProgrammingLanguage>,
    pub import_categories: Vec<ImportCategory>,
    pub classification_flags: Vec<ClassificationFlag>,
    pub anomaly_flags: Vec<AnomalyFlag>,
    pub anomaly_score: Option<f32>,
    pub policy_kind: Option<TelemetryPolicyKind>,
    #[serde(default)]
    pub bundle_trust_level: Option<BundleTrustLevel>,
    pub sensitive_code_flags: SensitiveCodeFlags,
    #[serde(default)]
    pub session_key_hash: String,
    #[serde(default)]
    pub is_prefix_repeat: bool,
    #[serde(default)]
    pub is_code_context_repeat: bool,
    #[serde(default)]
    pub novel_token_count: u32,
    #[serde(default)]
    pub repeated_token_count: u32,
    #[serde(default)]
    pub first_step_event_id: Option<String>,
    #[serde(default)]
    pub original_event_id: Option<String>,
    #[serde(default)]
    pub prefix_hash: Option<String>,
    #[serde(default)]
    pub agent_step_number: Option<u32>,
    #[serde(default)]
    pub is_historical: bool,
    #[serde(default)]
    pub data_source: DataSource,
    #[serde(default)]
    pub original_timestamp: Option<i64>,
    #[serde(default)]
    pub topic_cluster_id: u32,
    #[serde(default)]
    pub semantic_hash: String,
    #[serde(default)]
    pub is_semantic_collision: bool,
    #[serde(default)]
    pub endpoint_hash: String,
    #[serde(default)]
    pub policy_rule_id: Option<String>,

    #[serde(default)]
    pub use_case_confidence: f32,
    #[serde(default)]
    pub secondary_label: Option<UseCaseLabel>,
    #[serde(default)]
    pub complexity_score: u8,
    /// Why `use_case` has its current value — see [`UseCaseLabelReason`].
    /// Defaults to `UninitializedDefault` for backward compatibility with
    /// existing wire payloads that omit the field.
    #[serde(default)]
    pub use_case_label_reason: UseCaseLabelReason,
    #[serde(default)]
    pub interaction_mode: InteractionMode,
    #[serde(default)]
    pub embedding_norm: f32,
    #[serde(default)]
    pub system_prompt_hash: Option<String>,
    #[serde(default)]
    pub system_prompt_token_length: Option<u32>,
    #[serde(default)]
    pub dynamic_fraction: f32,
    #[serde(default)]
    pub prefix_repeat_signature: Option<String>,
    #[serde(default)]
    pub tool_definition_hash: Option<String>,
    #[serde(default)]
    pub collision_response_stability: Option<f32>,
    #[serde(default)]
    pub commitment_hash: String,
    #[serde(default)]
    pub code_fraction: f32,

    // Response-side fields (populated after response arrives via PendingEmitStore)
    #[serde(default)]
    pub actual_output_tokens: Option<u64>,
    #[serde(default)]
    pub finish_reason: Option<String>,
    #[serde(default)]
    pub response_latency_ms: Option<u64>,
    #[serde(default)]
    pub ttfb_ms: Option<u64>,

    // Session metadata (captured at request time)
    #[serde(default)]
    pub session_request_count: Option<u32>,
    #[serde(default)]
    pub session_total_tokens: Option<u64>,
    #[serde(default)]
    pub session_credential_alerts: Option<u32>,
    #[serde(default)]
    pub conversation_turn: Option<u32>,

    // WebSocket turn number
    #[serde(default)]
    pub ws_turn_number: Option<u64>,

    // Connection intelligence (JA4 fingerprint, TLS metadata, H2 multiplexing)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja4_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_stream_id: Option<u32>,

    // Product/Surface taxonomy (populated by catalog lookup)
    #[serde(default)]
    pub session_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_id: Option<String>,
    #[serde(default)]
    pub surface_type: SurfaceType,
    #[serde(default)]
    pub is_shadow_it: bool,

    /// Event-stream observation layer tag.
    /// `None` for legacy events; resolve via [`TelemetryEvent::effective_event_layer`]
    /// which falls back to deriving from `data_source`. New writers
    /// (`soth-code`, future explicit-layer producers) populate this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_layer: Option<EventLayer>,

    /// Raw hook-payload JSON, captured by `soth-code` only when an
    /// operator opts into Audit or Full capture modes. `None` is the
    /// default, the wire-format invariant, and what every other
    /// extension (historian, the proxy LiveProxy path) emits.
    /// Truncated at the edge to a configurable cap; the truncation
    /// marker `…[truncated]` is preserved on the suffix.
    /// Cloud-side ingestion stores this verbatim into the
    /// `intercept_events.raw_payload` column when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_payload: Option<String>,

    /// Which capture mode produced `raw_payload` — `"audit"` or
    /// `"full"`. `None` when no raw capture happened. Useful in the
    /// cloud both for the dashboard banner ("raw capture is on for
    /// this org") and for audit-log entries when an operator views
    /// raw content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_capture_mode: Option<String>,
}

impl Default for TelemetryEvent {
    fn default() -> Self {
        Self {
            event_id: Uuid::nil(),
            timestamp_epoch_ms: 0,
            connection_id: None,
            provider: "unknown".to_string(),
            model: None,
            endpoint_type: EndpointType::Unknown,
            parse_confidence: ParseConfidence::Heuristic,
            parse_source: ParseSource::Heuristic,
            capture_mode: CaptureMode::MetadataOnly,
            use_case: UseCaseLabel::Unknown,
            use_case_label_override: None,
            volatility_class: VolatilityClass::Static,
            cache_level: None,
            routing_reason: None,
            request_method: RequestMethod::Unknown,
            estimated_input_tokens: None,
            estimated_output_tokens: None,
            estimated_cost_usd: None,
            process_resolution: None,
            traffic_classification: None,
            languages: Vec::new(),
            import_categories: Vec::new(),
            classification_flags: Vec::new(),
            anomaly_flags: Vec::new(),
            anomaly_score: None,
            policy_kind: None,
            bundle_trust_level: None,
            sensitive_code_flags: SensitiveCodeFlags::default(),
            session_key_hash: String::new(),
            is_prefix_repeat: false,
            is_code_context_repeat: false,
            novel_token_count: 0,
            repeated_token_count: 0,
            first_step_event_id: None,
            original_event_id: None,
            prefix_hash: None,
            agent_step_number: None,
            is_historical: false,
            data_source: DataSource::LiveProxy,
            original_timestamp: None,
            topic_cluster_id: 0,
            semantic_hash: String::new(),
            is_semantic_collision: false,
            endpoint_hash: String::new(),
            policy_rule_id: None,
            use_case_confidence: 0.0,
            secondary_label: None,
            complexity_score: 0,
            use_case_label_reason: UseCaseLabelReason::UninitializedDefault,
            embedding_norm: 0.0,
            system_prompt_hash: None,
            system_prompt_token_length: None,
            dynamic_fraction: 0.0,
            prefix_repeat_signature: None,
            tool_definition_hash: None,
            collision_response_stability: None,
            commitment_hash: String::new(),
            code_fraction: 0.0,
            actual_output_tokens: None,
            finish_reason: None,
            response_latency_ms: None,
            ttfb_ms: None,
            session_request_count: None,
            session_total_tokens: None,
            session_credential_alerts: None,
            conversation_turn: None,
            ws_turn_number: None,
            ja4_hash: None,
            tls_version: None,
            alpn_protocol: None,
            h2_connection_id: None,
            h2_stream_id: None,
            session_id: None,
            product_id: None,
            surface_type: SurfaceType::Unknown,
            is_shadow_it: false,
            interaction_mode: InteractionMode::Unknown,
            event_layer: None,
            raw_payload: None,
            raw_capture_mode: None,
        }
    }
}

impl TelemetryEvent {
    /// Effective event layer.
    ///
    /// Returns the explicit `event_layer` field when set (new writers),
    /// otherwise derives from `data_source` for backwards compat with
    /// legacy events that predate this field.
    pub fn effective_event_layer(&self) -> EventLayer {
        self.event_layer
            .unwrap_or_else(|| EventLayer::from_data_source(self.data_source))
    }

    /// Convert a GovernableEvent (from extensions like historian) into a
    /// TelemetryEvent suitable for the telemetry pipeline.
    ///
    /// Maps metadata fields set by the historian (is_historical, data_source,
    /// original_timestamp) onto first-class TelemetryEvent fields.
    ///
    /// Also performs artifact-based enrichment: languages, classification flags,
    /// sensitive code flags, and code fraction are derived from the event's
    /// `artifacts` and `normalized` fields. This ensures historian events carry
    /// the same code/secrets/language signals as live proxy events (minus
    /// embedding-dependent stages like clustering and anomaly scoring).
    pub fn from_governable(
        gov: &crate::extensions::GovernableEvent,
        policy_kind: Option<TelemetryPolicyKind>,
    ) -> Self {
        let meta = &gov.context.metadata;

        let data_source = meta
            .get("data_source")
            .and_then(|s| serde_json::from_value(serde_json::Value::String(s.clone())).ok())
            .unwrap_or(DataSource::LiveProxy);

        let is_historical = meta
            .get("is_historical")
            .map(|s| s == "true")
            .unwrap_or(false);

        let original_timestamp = meta
            .get("original_timestamp")
            .and_then(|s| s.parse::<i64>().ok());

        let semantic_hash = meta.get("semantic_hash").cloned().unwrap_or_default();

        let system_prompt_hash = meta.get("system_prompt_hash").cloned();

        let (
            estimated_input_tokens,
            estimated_output_tokens,
            estimated_cost_usd,
            system_prompt_token_length,
            tool_definition_hash,
            mut import_categories,
        ) = if let Some(ref norm) = gov.normalized {
            (
                Some(norm.estimated_input_tokens),
                norm.estimated_output_tokens,
                Some(norm.estimated_cost_usd as f32),
                norm.system_prompt_token_estimate,
                norm.tool_definition_hash.clone(),
                Vec::new(), // import_categories not on NormalizedRequest
            )
        } else {
            (None, None, None, None, None, Vec::new())
        };

        // Extensions (soth-code, future ones) attach import
        // categories from their own tree-sitter detect run as a
        // JSON-array metadata key.  Fold them into the
        // canonical list so the proxy / extension paths drive
        // the same `network_calls_detected` /
        // `file_io_detected` / `crypto_operations_detected` /
        // `auth_logic_detected` flags downstream.
        if import_categories.is_empty() {
            if let Some(raw) = meta.get("import_categories") {
                if let Ok(parsed) = serde_json::from_str::<Vec<ImportCategory>>(raw) {
                    import_categories = parsed;
                }
            }
        }

        // Artifact-based enrichment — mirrors the logic in soth-classify stage7
        let languages = extract_languages_from_artifacts(&gov.artifacts);
        let classification_flags =
            build_classification_flags_from_artifacts(&gov.artifacts, &policy_kind);
        let sensitive_code_flags =
            build_sensitive_code_flags_from_artifacts(&gov.artifacts, &import_categories);
        let code_fraction = compute_code_fraction_from_artifacts(
            &gov.artifacts,
            gov.normalized
                .as_ref()
                .map(|n| n.estimated_input_tokens)
                .unwrap_or(0),
        );

        // Pre-computed classify enrichment (written by an extension's
        // write-time enricher — historian's `ClassifyEnricher`,
        // soth-code's hook handler, etc. — before queue serialization,
        // since embed_content is #[serde(skip)]). Detect "extension
        // queued an event without running enrichment" by checking for
        // the presence of any classify.* metadata. Callers (sync
        // sender) emit a WARN when they see the `ExtensionNotEnriched`
        // reason — soth-core stays log-free for the SDK/WASM build.
        let raw_use_case = meta
            .get("classify.use_case")
            .and_then(|s| serde_json::from_str::<UseCaseLabel>(s).ok());
        let raw_reason = meta
            .get("classify.use_case_label_reason")
            .and_then(|s| serde_json::from_str::<UseCaseLabelReason>(s).ok());
        let use_case_label_reason = match (raw_use_case.is_some(), raw_reason) {
            // Real classify ran AND emitted a reason → trust it.
            (true, Some(r)) => r,
            // Real classify ran but reason missing → assume Confident.
            (true, None) => UseCaseLabelReason::Confident,
            // No `classify.use_case` enum match BUT we have a reason
            // — that's the soth-code per-tool synthesized path
            // (label is a literal tool name like "Bash" that doesn't
            // map to UseCaseLabel).  Trust the explicit reason
            // instead of erasing it as ExtensionNotEnriched.
            (false, Some(r)) => r,
            // Neither label nor reason — extension didn't enrich.
            (false, None) => UseCaseLabelReason::ExtensionNotEnriched,
        };
        let use_case = raw_use_case.unwrap_or(UseCaseLabel::Unknown);
        // When the metadata key carries a value that doesn't match
        // a `UseCaseLabel` enum variant — soth-code's per-tool
        // synthesized labels (`"bash"`, `"read"`, `"edit"`, MCP
        // tool names, …) — preserve the literal string so the
        // wire converter can pass it through to the dashboard.
        // Otherwise the enum collapses to Unknown and the
        // `use_case_label` column shows "unknown" for every tool
        // call row.
        let use_case_label_override = if raw_use_case.is_none() {
            meta.get("classify.use_case")
                .and_then(|raw| serde_json::from_str::<String>(raw).ok())
                .filter(|s| !s.is_empty())
        } else {
            None
        };
        let use_case_confidence = meta
            .get("classify.use_case_confidence")
            .and_then(|s| s.parse::<f32>().ok())
            .unwrap_or(0.0);
        let volatility_class = meta
            .get("classify.volatility_class")
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(VolatilityClass::Static);
        let dynamic_fraction = meta
            .get("classify.dynamic_fraction")
            .and_then(|s| s.parse::<f32>().ok())
            .unwrap_or(0.0);
        let anomaly_score = meta
            .get("classify.anomaly_score")
            .and_then(|s| s.parse::<f32>().ok())
            .filter(|&v| v > 0.0);
        // `classify.anomaly_flags` is a JSON-array-of-strings
        // (snake_case enum forms — `["topic_drift",
        // "token_burst"]`).  Without this read the
        // `anomaly_flags` field stays `Vec::new()` even when the
        // edge daemon detected drift, and the dashboard's
        // anomaly column shows empty for every row.
        let extension_anomaly_flags = meta
            .get("classify.anomaly_flags")
            .and_then(|s| serde_json::from_str::<Vec<crate::AnomalyFlag>>(s).ok())
            .unwrap_or_default();
        let complexity_score = meta
            .get("classify.complexity_score")
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0);
        let topic_cluster_id = meta
            .get("classify.topic_cluster_id")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        // Raw-payload capture: only present when `soth-code` is in
        // Audit or Full mode (operator-opt-in). Default Metadata mode
        // doesn't write these keys, so they round-trip as None for
        // the proxy LiveProxy path and historian. See
        // extensions/code/src/event.rs::CodeCaptureMode.
        let raw_payload = meta.get("raw_payload").cloned();
        let raw_capture_mode = meta.get("raw_capture").cloned();

        // Synthesize a ProcessResolution from identity metadata so the sync
        // sender emits tool_identity_key/source_class/tool_name/tool_kind/
        // tool_category/provider_id tags for historian events — matching the
        // tagging live-proxy events receive from process detection.
        let process_resolution = meta.get("tool_identity_key").map(|key| ProcessResolution {
            match_kind: ProcessMatchKind::Exact,
            app_type: AppType::NonHost,
            capture_mode: Some(gov.capture_mode),
            process_name: None,
            bundle_id: None,
            matched_app_id: Some(key.clone()),
            tool_name: meta.get("tool_name").cloned(),
            tool_kind: meta.get("tool_kind").cloned(),
            tool_category: meta.get("tool_category").cloned(),
            provider_id: meta.get("provider_id").cloned(),
        });

        Self {
            event_id: gov.event_id,
            timestamp_epoch_ms: gov.timestamp_epoch_ms,
            connection_id: None,
            provider: gov.provider.clone(),
            model: gov.model.clone(),
            endpoint_type: gov.endpoint_type,
            parse_confidence: gov
                .normalized
                .as_ref()
                .map(|n| n.parse_confidence)
                .unwrap_or(ParseConfidence::Heuristic),
            parse_source: gov
                .normalized
                .as_ref()
                .map(|n| n.parse_source)
                .unwrap_or(ParseSource::Heuristic),
            capture_mode: gov.capture_mode,
            request_method: RequestMethod::Post,
            estimated_input_tokens,
            estimated_output_tokens,
            estimated_cost_usd,
            is_historical,
            data_source,
            original_timestamp,
            semantic_hash,
            system_prompt_hash,
            system_prompt_token_length,
            tool_definition_hash,
            policy_kind,
            languages,
            import_categories,
            classification_flags,
            sensitive_code_flags,
            code_fraction,
            use_case,
            use_case_label_override,
            use_case_confidence,
            use_case_label_reason,
            volatility_class,
            dynamic_fraction,
            anomaly_score,
            anomaly_flags: extension_anomaly_flags,
            complexity_score,
            topic_cluster_id,
            process_resolution,
            raw_payload,
            raw_capture_mode,
            interaction_mode: meta
                .get("interaction_mode")
                .and_then(|s| serde_json::from_value(serde_json::Value::String(s.clone())).ok())
                .unwrap_or(InteractionMode::Unknown),
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Artifact-based enrichment helpers for from_governable()
// ---------------------------------------------------------------------------
// These mirror the logic in soth-classify's stage7_telemetry but live in
// soth-core so that governance queue events can be enriched without pulling
// in the full classify pipeline and its ONNX/bundle dependencies.

fn extract_languages_from_artifacts(
    artifacts: &[crate::SensitiveArtifact],
) -> Vec<ProgrammingLanguage> {
    use crate::ArtifactKind;

    let mut out = Vec::new();
    for artifact in artifacts {
        if let ArtifactKind::CodeBlock { language } = &artifact.kind {
            let mapped = match language.to_ascii_lowercase().as_str() {
                "python" => ProgrammingLanguage::Python,
                "javascript" => ProgrammingLanguage::JavaScript,
                "typescript" => ProgrammingLanguage::TypeScript,
                "rust" => ProgrammingLanguage::Rust,
                "go" => ProgrammingLanguage::Go,
                "java" => ProgrammingLanguage::Java,
                "cpp" | "c++" => ProgrammingLanguage::Cpp,
                "c" => ProgrammingLanguage::C,
                "csharp" | "c#" => ProgrammingLanguage::CSharp,
                "ruby" => ProgrammingLanguage::Ruby,
                "php" => ProgrammingLanguage::Php,
                "swift" => ProgrammingLanguage::Swift,
                "kotlin" => ProgrammingLanguage::Kotlin,
                "sql" => ProgrammingLanguage::Sql,
                "shell" | "bash" | "zsh" => ProgrammingLanguage::Shell,
                "terraform" => ProgrammingLanguage::Terraform,
                "solidity" => ProgrammingLanguage::Solidity,
                "yaml" | "yml" => ProgrammingLanguage::Yaml,
                "json" => ProgrammingLanguage::Json,
                _ => ProgrammingLanguage::Unknown,
            };
            if !out.contains(&mapped) {
                out.push(mapped);
            }
        }
    }
    out
}

fn build_classification_flags_from_artifacts(
    artifacts: &[crate::SensitiveArtifact],
    policy_kind: &Option<TelemetryPolicyKind>,
) -> Vec<ClassificationFlag> {
    use crate::ArtifactKind;

    let mut flags = Vec::new();

    let has_code = artifacts
        .iter()
        .any(|a| matches!(a.kind, ArtifactKind::CodeBlock { .. }));
    if has_code {
        flags.push(ClassificationFlag::CodeDetected);
    }

    let has_credentials = artifacts.iter().any(|a| a.is_credential());
    if has_credentials {
        flags.push(ClassificationFlag::CredentialDetected);
    }

    if matches!(
        policy_kind,
        Some(TelemetryPolicyKind::Block)
            | Some(TelemetryPolicyKind::Redact)
            | Some(TelemetryPolicyKind::Flag)
    ) {
        flags.push(ClassificationFlag::PolicyTriggered);
    }

    flags
}

fn build_sensitive_code_flags_from_artifacts(
    artifacts: &[crate::SensitiveArtifact],
    import_categories: &[ImportCategory],
) -> SensitiveCodeFlags {
    use crate::ArtifactKind;

    let mut flags = SensitiveCodeFlags::default();

    for artifact in artifacts {
        match &artifact.kind {
            ArtifactKind::PrivateKey => {
                flags.private_key_detected = true;
                mark_credential_artifact(&mut flags, artifact);
            }
            ArtifactKind::CodeBlock { .. } => {
                flags.auth_logic_detected = true;
            }
            ArtifactKind::ApiKey { .. }
            | ArtifactKind::Jwt
            | ArtifactKind::HexKey
            | ArtifactKind::ConnectionString
            | ArtifactKind::UnknownCredential => {
                mark_credential_artifact(&mut flags, artifact);
            }
            ArtifactKind::OrgPattern { pattern_id } => {
                flags.org_pattern_matches.push(pattern_id.to_string());
            }
            ArtifactKind::AuthLogic => {
                flags.auth_logic_detected = true;
            }
            ArtifactKind::CryptoOperation => {
                flags.crypto_operations_detected = true;
            }
            ArtifactKind::AwsAccessKey
            | ArtifactKind::GitHubPat
            | ArtifactKind::GitLabToken
            | ArtifactKind::SlackToken
            | ArtifactKind::StripeSecretKey => {
                mark_credential_artifact(&mut flags, artifact);
            }
        }
    }

    flags.detected_secret_types.sort();
    flags.detected_secret_types.dedup();

    for category in import_categories {
        match category {
            ImportCategory::Network => flags.network_calls_detected = true,
            ImportCategory::Filesystem => flags.file_io_detected = true,
            ImportCategory::Crypto => flags.crypto_operations_detected = true,
            ImportCategory::Auth => flags.auth_logic_detected = true,
            _ => {}
        }
    }

    flags
}

fn mark_credential_artifact(flags: &mut SensitiveCodeFlags, artifact: &crate::SensitiveArtifact) {
    flags.credential_pattern_detected = true;
    flags.hardcoded_secret_detected = true;
    if let Some(credential_kind) = artifact.credential_kind_label() {
        flags.detected_secret_types.push(credential_kind);
    }
}

fn compute_code_fraction_from_artifacts(
    artifacts: &[crate::SensitiveArtifact],
    estimated_input_tokens: u32,
) -> f32 {
    use crate::ArtifactKind;

    let code_block_count = artifacts
        .iter()
        .filter(|a| matches!(a.kind, ArtifactKind::CodeBlock { .. }))
        .count();

    if code_block_count == 0 {
        return 0.0;
    }

    let total_tokens = estimated_input_tokens.max(1) as f32;
    let estimated_code_tokens = (code_block_count as f32) * 200.0;
    (estimated_code_tokens / total_tokens).clamp(0.0, 1.0)
}

#[cfg(test)]
mod data_source_serde_tests {
    use super::{DataSource, EventLayer, TelemetryEvent};

    #[test]
    fn code_variants_serialize_to_snake_case() {
        let cases = [
            (DataSource::CodeClaudeCode, "\"code_claude_code\""),
            (DataSource::CodeCursor, "\"code_cursor\""),
            (DataSource::CodeCodex, "\"code_codex\""),
            (DataSource::CodeGeminiCli, "\"code_gemini_cli\""),
            (DataSource::CodeWindsurf, "\"code_windsurf\""),
            (DataSource::CodeOpenCode, "\"code_open_code\""),
            (DataSource::CodePiAgent, "\"code_pi_agent\""),
            (DataSource::CodeUnknown, "\"code_unknown\""),
        ];
        for (variant, expected) in cases {
            assert_eq!(
                serde_json::to_string(&variant).unwrap(),
                expected,
                "serialization for {variant:?}"
            );
        }
    }

    #[test]
    fn code_variants_round_trip() {
        let variants = [
            DataSource::CodeClaudeCode,
            DataSource::CodeCursor,
            DataSource::CodeCodex,
            DataSource::CodeGeminiCli,
            DataSource::CodeWindsurf,
            DataSource::CodeOpenCode,
            DataSource::CodePiAgent,
            DataSource::CodeUnknown,
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let back: DataSource = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant, "round-trip for {variant:?}");
        }
    }

    #[test]
    fn historian_variants_unchanged() {
        // Regression guard: existing Historian variants must keep their
        // wire form so cloud rollups don't silently re-bucket them.
        assert_eq!(
            serde_json::to_string(&DataSource::HistorianClaudeCode).unwrap(),
            "\"historian_claude_code\""
        );
        assert_eq!(
            serde_json::to_string(&DataSource::LiveProxy).unwrap(),
            "\"live_proxy\""
        );
    }

    #[test]
    fn event_layer_from_data_source_buckets() {
        assert_eq!(
            EventLayer::from_data_source(DataSource::LiveProxy),
            EventLayer::Network
        );
        for ds in [
            DataSource::HistorianClaudeCode,
            DataSource::HistorianGemini,
            DataSource::HistorianCodex,
            DataSource::HistorianCursor,
            DataSource::HistorianGithubCopilot,
            DataSource::HistorianContinue,
            DataSource::HistorianOpenClaw,
            DataSource::HistorianUnknown,
        ] {
            assert_eq!(
                EventLayer::from_data_source(ds),
                EventLayer::Session,
                "{ds:?} should be Session layer"
            );
        }
        for ds in [
            DataSource::CodeClaudeCode,
            DataSource::CodeCursor,
            DataSource::CodeCodex,
            DataSource::CodeGeminiCli,
            DataSource::CodeWindsurf,
            DataSource::CodeOpenCode,
            DataSource::CodePiAgent,
        ] {
            assert_eq!(
                EventLayer::from_data_source(ds),
                EventLayer::Action,
                "{ds:?} should be Action layer"
            );
        }
    }

    #[test]
    fn effective_event_layer_falls_back_to_data_source() {
        // Legacy event: explicit field None, data_source dictates layer.
        let mut ev = TelemetryEvent {
            data_source: DataSource::HistorianClaudeCode,
            ..TelemetryEvent::default()
        };
        assert_eq!(ev.event_layer, None);
        assert_eq!(ev.effective_event_layer(), EventLayer::Session);

        // New writer: explicit field set, takes precedence.
        ev.event_layer = Some(EventLayer::Action);
        assert_eq!(ev.effective_event_layer(), EventLayer::Action);
    }

    #[test]
    fn event_layer_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&EventLayer::Network).unwrap(),
            "\"network\""
        );
        assert_eq!(
            serde_json::to_string(&EventLayer::Action).unwrap(),
            "\"action\""
        );
        assert_eq!(
            serde_json::to_string(&EventLayer::Session).unwrap(),
            "\"session\""
        );
    }

    #[test]
    fn from_governable_extracts_raw_payload_when_present() {
        // Pin the contract: when an extension (soth-code in Audit /
        // Full mode) writes `raw_payload` and `raw_capture` into
        // GovernableEvent metadata, `from_governable` surfaces them
        // as TelemetryEvent fields so the cloud's ingestion can
        // store them in `intercept_events.raw_payload` /
        // `raw_capture_mode` columns. Default Metadata mode keeps
        // both `None`.
        use crate::extensions::{ExtensionContext, ExtensionSource, GovernableEvent};
        use crate::EventSource;
        use std::collections::HashMap;
        use uuid::Uuid;

        // Case 1: capture happened — fields present.
        let mut meta = HashMap::new();
        meta.insert("raw_payload".to_string(), r#"{"command":"ls"}"#.to_string());
        meta.insert("raw_capture".to_string(), "audit".to_string());
        let gov = GovernableEvent {
            event_id: Uuid::nil(),
            timestamp_epoch_ms: 0,
            source: EventSource::Extension {
                source: ExtensionSource::Code,
            },
            provider: "code".to_string(),
            model: None,
            endpoint_type: super::EndpointType::Unknown,
            normalized: None,
            artifacts: vec![],
            capture_mode: super::CaptureMode::MetadataOnly,
            embed_content: None,
            context: ExtensionContext {
                extension_name: "code".to_string(),
                extension_version: "0.1.0".to_string(),
                metadata: meta,
            },
        };
        let te = TelemetryEvent::from_governable(&gov, None);
        assert_eq!(te.raw_payload.as_deref(), Some(r#"{"command":"ls"}"#));
        assert_eq!(te.raw_capture_mode.as_deref(), Some("audit"));

        // Case 2: no capture metadata — fields stay None (default
        // Metadata mode behavior, which is what every event
        // historically looked like).
        let mut gov = gov;
        gov.context.metadata.clear();
        let te = TelemetryEvent::from_governable(&gov, None);
        assert!(te.raw_payload.is_none());
        assert!(te.raw_capture_mode.is_none());
    }

    #[test]
    fn from_governable_preserves_synthesized_tool_label_via_override() {
        use crate::{UseCaseLabel, UseCaseLabelReason};
        // soth-code's per-tool synthesized rows write
        // `classify.use_case = "\"bash\""` (a literal tool name
        // that doesn't deserialize as the typed `UseCaseLabel`
        // enum).  Without the override field these rows would
        // wire-encode `use_case_label = "unknown"` and the
        // dashboard's `/code` endpoint would show "unknown" for
        // every tool call — exactly the bug we shipped a fix
        // for.  Pin both legs:
        //   * `use_case` collapses to `Unknown` (typed enum
        //     can't hold "bash") — accepted, the wire converter
        //     handles it.
        //   * `use_case_label_override` carries the literal
        //     "bash" so `convert.rs` can prefer it and the
        //     cloud sees the real tool name.
        //   * Reason is the explicit `pre_tool_call` from
        //     metadata, NOT `ExtensionNotEnriched`.
        use crate::extensions::{ExtensionContext, ExtensionSource, GovernableEvent};
        use crate::EventSource;
        use std::collections::HashMap;
        use uuid::Uuid;

        let mut meta = HashMap::new();
        meta.insert("classify.use_case".to_string(), "\"bash\"".to_string());
        meta.insert(
            "classify.use_case_label_reason".to_string(),
            "\"pre_tool_call\"".to_string(),
        );
        let gov = GovernableEvent {
            event_id: Uuid::nil(),
            timestamp_epoch_ms: 0,
            source: EventSource::Extension {
                source: ExtensionSource::Code,
            },
            provider: "code".to_string(),
            model: Some("claude-opus-4-7".to_string()),
            endpoint_type: super::EndpointType::Unknown,
            normalized: None,
            artifacts: vec![],
            capture_mode: super::CaptureMode::MetadataOnly,
            embed_content: None,
            context: ExtensionContext {
                extension_name: "code".to_string(),
                extension_version: "0.1.0".to_string(),
                metadata: meta,
            },
        };
        let te = TelemetryEvent::from_governable(&gov, None);
        assert_eq!(te.use_case, UseCaseLabel::Unknown);
        assert_eq!(te.use_case_label_override.as_deref(), Some("bash"));
        assert_eq!(te.use_case_label_reason, UseCaseLabelReason::PreToolCall);
        assert_eq!(te.model.as_deref(), Some("claude-opus-4-7"));
    }

    #[test]
    fn from_governable_reads_anomaly_flags_from_extension_metadata() {
        use crate::AnomalyFlag;
        // The classify daemon emits real anomaly flags
        // (`topic_drift`, `token_burst`, `tool_call_depth_spike`,
        // …) in session-tracked mode.  Hook handler writes
        // `classify.anomaly_flags` as a JSON array of snake_case
        // enum names.  Pin the read path so a future change
        // can't silently drop them — every flag the daemon
        // detected must round-trip through `from_governable` and
        // surface in the dashboard's anomaly column.
        use crate::extensions::{ExtensionContext, ExtensionSource, GovernableEvent};
        use crate::EventSource;
        use std::collections::HashMap;
        use uuid::Uuid;

        let mut meta = HashMap::new();
        meta.insert(
            "classify.use_case".to_string(),
            "\"code_generation\"".to_string(),
        );
        meta.insert(
            "classify.anomaly_flags".to_string(),
            r#"["topic_drift","token_burst"]"#.to_string(),
        );
        let gov = GovernableEvent {
            event_id: Uuid::nil(),
            timestamp_epoch_ms: 0,
            source: EventSource::Extension {
                source: ExtensionSource::Code,
            },
            provider: "code".to_string(),
            model: None,
            endpoint_type: super::EndpointType::Unknown,
            normalized: None,
            artifacts: vec![],
            capture_mode: super::CaptureMode::MetadataOnly,
            embed_content: None,
            context: ExtensionContext {
                extension_name: "code".to_string(),
                extension_version: "0.1.0".to_string(),
                metadata: meta,
            },
        };
        let te = TelemetryEvent::from_governable(&gov, None);
        assert!(te.anomaly_flags.contains(&AnomalyFlag::TopicDrift));
        assert!(te.anomaly_flags.contains(&AnomalyFlag::TokenBurst));
        assert_eq!(te.anomaly_flags.len(), 2);
    }

    #[test]
    fn telemetry_event_legacy_json_deserializes_with_no_event_layer() {
        // Regression guard: an event serialized before this field existed
        // must still deserialize, with `event_layer: None`.
        let ev = TelemetryEvent {
            data_source: DataSource::LiveProxy,
            ..TelemetryEvent::default()
        };
        let json = serde_json::to_value(&ev).unwrap();
        // Strip event_layer to simulate older wire form.
        let mut obj = json.as_object().unwrap().clone();
        obj.remove("event_layer");
        let stripped = serde_json::Value::Object(obj);
        let back: TelemetryEvent = serde_json::from_value(stripped).unwrap();
        assert_eq!(back.event_layer, None);
        assert_eq!(back.effective_event_layer(), EventLayer::Network);
    }
}
