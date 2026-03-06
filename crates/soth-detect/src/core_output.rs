use crate::types::{
    ArtifactLocation as DetectArtifactLocation, ArtifactType, DetectResult, EndpointType,
    FormatMeta, GqlOpType, ParseSource as DetectParseSource, ParseWarning as DetectParseWarning,
    Severity,
};
use soth_core::{
    ArtifactKind, ArtifactLocation, ArtifactSeverity, DetectedProvider,
    EndpointType as CoreEndpointType, FormatMetadata, GraphQlOperationType, NormalizedRequest,
    ParseSource, ParseWarning, SensitiveArtifact,
};

impl From<&DetectResult> for soth_core::DetectResult {
    fn from(value: &DetectResult) -> Self {
        Self {
            normalized: to_core_normalized(value),
            artifacts: value.artifacts.iter().map(map_artifact).collect(),
            capture_mode: value.capture_mode,
            parse_source: map_parse_source(&value.parse_source),
            confidence: value.confidence,
            detect_latency_us: value.detect_latency_us,
            warnings: value.warnings.iter().map(map_detect_warning).collect(),
            session_mutations: value.session_mutations.clone(),
            is_prefix_repeat: value.is_prefix_repeat,
            novel_token_count: value.novel_token_count,
            repeated_token_count: value.repeated_token_count,
            novel_tail_start_idx: value.novel_tail_start_idx,
            prefix_hash: value.prefix_hash.clone(),
            is_repeated_code_context: value.is_repeated_code_context,
            ast_normalized_hash: value.ast_normalized_hash.clone(),
            first_blob_event_id: value.first_blob_event_id,
            import_categories: value
                .import_categories
                .iter()
                .map(map_import_category)
                .collect(),
        }
    }
}

pub fn to_core_detect_result(value: &DetectResult) -> soth_core::DetectResult {
    soth_core::DetectResult::from(value)
}

fn to_core_normalized(value: &DetectResult) -> NormalizedRequest {
    let normalized = &value.normalized;
    NormalizedRequest {
        parse_confidence: normalized.parse_confidence,
        parser_id: normalized.parser_id.to_string(),
        schema_version: normalized.schema_version.to_string(),
        parse_warnings: normalized
            .parse_warnings
            .iter()
            .map(map_parse_warning)
            .collect(),
        is_ai_call: normalized.is_ai_call,
        provider: map_provider(normalized.provider.canonical_name()),
        model: normalized.model.clone(),
        endpoint_type: map_endpoint_type(&normalized.endpoint_type),
        api_version: normalized.api_version.clone(),
        system_prompt_hash: normalized.system_prompt_hash.clone(),
        system_prompt_token_estimate: normalized.system_prompt_token_estimate,
        user_content_hash: normalized.user_content_hash.clone(),
        user_content_token_estimate: normalized.user_content_token_estimate,
        conversation_hash: normalized.conversation_hash.clone(),
        conversation_turn: normalized.conversation_turn,
        has_tool_definitions: normalized.has_tool_definitions,
        tool_definition_hash: normalized.tool_definition_hash.clone(),
        temperature: normalized.temperature,
        max_tokens: normalized.max_tokens,
        stream: normalized.stream,
        top_p: normalized.top_p,
        stop_sequences: normalized.stop_sequences.clone(),
        estimated_input_tokens: normalized.estimated_input_tokens,
        estimated_cost_usd: normalized.estimated_cost_usd as f64,
        parse_source: map_parse_source(&value.parse_source),
        canonical_cache_key: normalized.canonical_hash.clone(),
        format_metadata: map_format_metadata(&normalized.format_meta),
        has_structured_output: false,
        has_tool_results: false,
        estimated_output_tokens: None,
    }
}

fn map_provider(value: &str) -> DetectedProvider {
    match value.to_ascii_lowercase().as_str() {
        "anthropic" => DetectedProvider::Anthropic,
        "openai" => DetectedProvider::OpenAi,
        "azure_openai" => DetectedProvider::AzureOpenAi,
        "gemini" | "google" | "google_vertex" => DetectedProvider::Gemini,
        "cohere" => DetectedProvider::Cohere,
        "bedrock" => DetectedProvider::Bedrock,
        "mistral" => DetectedProvider::Mistral,
        "groq" => DetectedProvider::Groq,
        "together" => DetectedProvider::Together,
        "fireworks" => DetectedProvider::Fireworks,
        "ollama" => DetectedProvider::Ollama,
        "vllm" => DetectedProvider::VLlm,
        "lmstudio" => DetectedProvider::LmStudio,
        "vertex_ai" => DetectedProvider::VertexAi,
        _ => DetectedProvider::Unknown,
    }
}

fn map_endpoint_type(value: &EndpointType) -> CoreEndpointType {
    match value {
        EndpointType::Chat => CoreEndpointType::ChatCompletion,
        EndpointType::Completion => CoreEndpointType::TextCompletion,
        EndpointType::Embedding => CoreEndpointType::Embedding,
        EndpointType::Unknown => CoreEndpointType::Unknown,
    }
}

fn map_parse_source(value: &DetectParseSource) -> ParseSource {
    match value {
        DetectParseSource::OpenAI => ParseSource::Rest {
            provider: DetectedProvider::OpenAi,
        },
        DetectParseSource::Anthropic => ParseSource::Rest {
            provider: DetectedProvider::Anthropic,
        },
        DetectParseSource::Cohere => ParseSource::Rest {
            provider: DetectedProvider::Cohere,
        },
        DetectParseSource::Google => ParseSource::Rest {
            provider: DetectedProvider::Gemini,
        },
        DetectParseSource::Bedrock => ParseSource::Rest {
            provider: DetectedProvider::Bedrock,
        },
        DetectParseSource::GraphQL { .. } => ParseSource::GraphQl,
        DetectParseSource::Grpc { .. } => ParseSource::Grpc,
        DetectParseSource::JsonRpc { .. } => ParseSource::JsonRpc,
        DetectParseSource::AgentApp { .. } => ParseSource::AgentApp,
        DetectParseSource::Heuristic => ParseSource::Heuristic,
        DetectParseSource::Filtered => ParseSource::Filtered,
    }
}

fn map_format_metadata(value: &FormatMeta) -> FormatMetadata {
    match value {
        FormatMeta::Rest { path } => FormatMetadata::Rest {
            content_type: path.clone(),
        },
        FormatMeta::GraphQL {
            operation_name,
            operation_type,
            ..
        } => FormatMetadata::GraphQl {
            operation_name: operation_name.clone(),
            operation_type: match operation_type {
                GqlOpType::Query => GraphQlOperationType::Query,
                GqlOpType::Mutation => GraphQlOperationType::Mutation,
                GqlOpType::Subscription => GraphQlOperationType::Subscription,
                GqlOpType::Unknown => GraphQlOperationType::Unknown,
            },
        },
        FormatMeta::Grpc {
            service, method, ..
        } => FormatMetadata::Grpc {
            service: service.clone(),
            method: method.clone(),
        },
        FormatMeta::JsonRpc { method, .. } => FormatMetadata::JsonRpc {
            method: method.clone().unwrap_or_default(),
        },
        FormatMeta::WebSocket { .. } | FormatMeta::Unknown { .. } => FormatMetadata::Unknown,
    }
}

fn map_parse_warning(value: &DetectParseWarning) -> ParseWarning {
    match value {
        DetectParseWarning::GraphQLUnknownOperation(operation_name) => {
            ParseWarning::GraphQlUnknownOperation {
                operation_name: operation_name.clone(),
            }
        }
        DetectParseWarning::GrpcDescriptorMissing(_) => ParseWarning::GrpcNoDescriptor,
        DetectParseWarning::ParserError(reason) => ParseWarning::PartialBodyParse {
            reason: reason.clone(),
        },
        _ => ParseWarning::PartialBodyParse {
            reason: format!("{value:?}"),
        },
    }
}

fn map_detect_warning(value: &crate::types::DetectWarning) -> ParseWarning {
    ParseWarning::PartialBodyParse {
        reason: format!("{}: {}", value.code, value.detail),
    }
}

fn map_artifact(value: &crate::types::SensitiveArtifact) -> SensitiveArtifact {
    SensitiveArtifact {
        kind: map_artifact_kind(&value.artifact_type),
        severity: map_artifact_severity(&value.severity),
        location: map_artifact_location(&value.location),
    }
}

fn map_artifact_kind(value: &ArtifactType) -> ArtifactKind {
    match value {
        ArtifactType::PrivateKey => ArtifactKind::PrivateKey,
        ArtifactType::JwtToken => ArtifactKind::Jwt,
        ArtifactType::ConnectionString => ArtifactKind::ConnectionString,
        ArtifactType::CodeBlock { language } => ArtifactKind::CodeBlock {
            language: language.clone(),
        },
        ArtifactType::OpenAIKey => ArtifactKind::ApiKey {
            provider: Some(DetectedProvider::OpenAi),
        },
        ArtifactType::AnthropicKey => ArtifactKind::ApiKey {
            provider: Some(DetectedProvider::Anthropic),
        },
        ArtifactType::AwsAccessKey
        | ArtifactType::GitHubPat
        | ArtifactType::GitLabToken
        | ArtifactType::SlackToken
        | ArtifactType::StripeSecretKey => ArtifactKind::ApiKey { provider: None },
        ArtifactType::UnknownCredential => ArtifactKind::UnknownCredential,
        ArtifactType::AuthLogicFlag => ArtifactKind::AuthLogic,
        ArtifactType::CryptoFlag => ArtifactKind::CryptoOperation,
        ArtifactType::OrgPatternMatch { pattern_id } => ArtifactKind::OrgPattern {
            pattern_id: *pattern_id,
        },
    }
}

fn map_artifact_severity(value: &Severity) -> ArtifactSeverity {
    match value {
        Severity::Critical => ArtifactSeverity::Critical,
        Severity::High => ArtifactSeverity::High,
        Severity::Medium => ArtifactSeverity::Medium,
        Severity::Low => ArtifactSeverity::Low,
    }
}

fn map_artifact_location(value: &DetectArtifactLocation) -> ArtifactLocation {
    match value {
        DetectArtifactLocation::SystemPrompt => ArtifactLocation::SystemPrompt { char_offset: 0 },
        DetectArtifactLocation::UserMessage { turn_index } => ArtifactLocation::UserContent {
            turn: *turn_index,
            char_offset: 0,
        },
        DetectArtifactLocation::ToolDefinition { tool_name } => ArtifactLocation::ToolResult {
            tool_name: Some(tool_name.clone()),
        },
        _ => ArtifactLocation::Unknown,
    }
}

fn map_import_category(
    value: &crate::code::DetectedImportCategory,
) -> soth_core::ImportCategory {
    match value {
        crate::code::DetectedImportCategory::Crypto => soth_core::ImportCategory::Crypto,
        crate::code::DetectedImportCategory::Auth => soth_core::ImportCategory::Auth,
        crate::code::DetectedImportCategory::Network => soth_core::ImportCategory::Network,
        crate::code::DetectedImportCategory::Database => soth_core::ImportCategory::Database,
        crate::code::DetectedImportCategory::FileSystem => soth_core::ImportCategory::Filesystem,
        crate::code::DetectedImportCategory::Serialization => {
            soth_core::ImportCategory::Serialization
        }
    }
}
