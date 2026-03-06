use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::artifacts::{CaptureMode, ParseConfidence, ParseSource};
use crate::classify::{AnomalyFlag, ProcessResolution, TrafficClassification};
use crate::normalized::EndpointType;
use crate::providers::DetectedProvider;

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
    Unknown,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveCodeFlags {
    pub credential_pattern_detected: bool,
    pub auth_logic_detected: bool,
    pub crypto_operations_detected: bool,
    pub network_calls_detected: bool,
    pub file_io_detected: bool,
    pub org_pattern_matches: Vec<String>,
    pub private_key_detected: bool,
    pub hardcoded_secret_detected: bool,
}

impl Default for SensitiveCodeFlags {
    fn default() -> Self {
        Self {
            credential_pattern_detected: false,
            auth_logic_detected: false,
            crypto_operations_detected: false,
            network_calls_detected: false,
            file_io_detected: false,
            org_pattern_matches: Vec::new(),
            private_key_detected: false,
            hardcoded_secret_detected: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleTrustLevel {
    Verified,
    Unverified,
    SignatureDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSource {
    LiveProxy,
    HistorianClaudeCode,
    HistorianGemini,
    HistorianCodex,
}

impl Default for DataSource {
    fn default() -> Self {
        Self::LiveProxy
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event_id: Uuid,
    pub timestamp_epoch_ms: i64,
    pub connection_id: Option<Uuid>,
    pub provider: DetectedProvider,
    pub model: Option<String>,
    pub endpoint_type: EndpointType,
    pub parse_confidence: ParseConfidence,
    pub parse_source: ParseSource,
    pub capture_mode: CaptureMode,
    pub use_case: UseCaseLabel,
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
}

impl Default for TelemetryEvent {
    fn default() -> Self {
        Self {
            event_id: Uuid::nil(),
            timestamp_epoch_ms: 0,
            connection_id: None,
            provider: DetectedProvider::Unknown,
            model: None,
            endpoint_type: EndpointType::Unknown,
            parse_confidence: ParseConfidence::Heuristic,
            parse_source: ParseSource::Heuristic,
            capture_mode: CaptureMode::MetadataOnly,
            use_case: UseCaseLabel::Unknown,
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
            embedding_norm: 0.0,
            system_prompt_hash: None,
            system_prompt_token_length: None,
            dynamic_fraction: 0.0,
            prefix_repeat_signature: None,
            tool_definition_hash: None,
            collision_response_stability: None,
            commitment_hash: String::new(),
            code_fraction: 0.0,
        }
    }
}
