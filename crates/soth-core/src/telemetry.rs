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
    pub sensitive_code_flags: SensitiveCodeFlags,
}
