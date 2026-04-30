use crate::providers::DetectedProvider;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveArtifact {
    pub kind: ArtifactKind,
    /// Exact credential taxonomy detected by the scanner, such as
    /// `openai_api_key`, `rsa_private_key`, or `postgres_connection_string`.
    /// This must never contain the raw credential value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_kind: Option<String>,
    pub severity: ArtifactSeverity,
    pub location: ArtifactLocation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactKind {
    PrivateKey,
    ApiKey { provider: Option<DetectedProvider> },
    Jwt,
    HexKey,
    ConnectionString,
    CodeBlock { language: String },
    UnknownCredential,
    OrgPattern { pattern_id: u32 },
    AuthLogic,
    CryptoOperation,
    // Specific key types (from soth-parse ArtifactType)
    AwsAccessKey,
    GitHubPat,
    GitLabToken,
    SlackToken,
    StripeSecretKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactLocation {
    SystemPrompt { char_offset: u32 },
    UserContent { turn: u32, char_offset: u32 },
    AssistantContent { turn: u32, char_offset: u32 },
    ToolResult { tool_name: Option<String> },
    Header { name: String },
    StreamChunk { sequence: u64 },
    Unknown,
}

impl SensitiveArtifact {
    pub fn credential_kind_label(&self) -> Option<String> {
        if let Some(kind) = self
            .credential_kind
            .as_deref()
            .map(str::trim)
            .filter(|kind| !kind.is_empty())
        {
            return Some(kind.to_string());
        }

        match &self.kind {
            ArtifactKind::PrivateKey => Some("generic_private_key".to_string()),
            ArtifactKind::ApiKey {
                provider: Some(provider),
            } => Some(format!("{}_api_key", provider.canonical_name())),
            ArtifactKind::ApiKey { provider: None } => Some("api_key".to_string()),
            ArtifactKind::Jwt => Some("jwt".to_string()),
            ArtifactKind::HexKey => Some("hex_secret".to_string()),
            ArtifactKind::ConnectionString => Some("connection_string".to_string()),
            ArtifactKind::UnknownCredential => Some("unknown_credential".to_string()),
            ArtifactKind::AwsAccessKey => Some("aws_access_key_id".to_string()),
            ArtifactKind::GitHubPat => Some("github_pat".to_string()),
            ArtifactKind::GitLabToken => Some("gitlab_token".to_string()),
            ArtifactKind::SlackToken => Some("slack_token".to_string()),
            ArtifactKind::StripeSecretKey => Some("stripe_secret_key".to_string()),
            ArtifactKind::CodeBlock { .. }
            | ArtifactKind::OrgPattern { .. }
            | ArtifactKind::AuthLogic
            | ArtifactKind::CryptoOperation => None,
        }
    }

    pub fn is_private_key(&self) -> bool {
        matches!(self.kind, ArtifactKind::PrivateKey)
    }

    pub fn is_credential(&self) -> bool {
        matches!(
            self.kind,
            ArtifactKind::PrivateKey
                | ArtifactKind::ApiKey { .. }
                | ArtifactKind::Jwt
                | ArtifactKind::HexKey
                | ArtifactKind::ConnectionString
                | ArtifactKind::UnknownCredential
                | ArtifactKind::AwsAccessKey
                | ArtifactKind::GitHubPat
                | ArtifactKind::GitLabToken
                | ArtifactKind::SlackToken
                | ArtifactKind::StripeSecretKey
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    MetadataOnly,
    Full,
    SensitiveArtifacts,
    FullContent,
}

impl Default for CaptureMode {
    fn default() -> Self {
        Self::MetadataOnly
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseConfidence {
    Full,
    Partial,
    Heuristic,
}

impl Default for ParseConfidence {
    fn default() -> Self {
        Self::Heuristic
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ParseSource {
    Rest {
        provider: DetectedProvider,
    },
    GraphQl,
    Grpc,
    JsonRpc,
    AgentApp,
    Heuristic,
    Filtered,
    /// Pre-parsed input supplied by an SDK consumer via `process_normalized`.
    /// The proxy's HTTP fingerprint/parse phase is skipped — the caller has
    /// already decoded a typed LLM call (provider, model, messages, tools).
    Sdk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ParseWarning {
    InvalidJson,
    MissingField {
        field: String,
    },
    NonJsonBody,
    LongestStringHeuristic,
    ContentNotExtracted,
    GraphQlSyntaxError,
    GraphQlUnknownOperation {
        operation_name: String,
    },
    GrpcDescriptorMissing {
        service: String,
    },
    GrpcNoDescriptor,
    WebSocketBinaryUnparseable,
    TreeSitterPanic,
    TreeSitterTimeout,
    ParserError {
        reason: String,
    },
    NoParserForFormat {
        format: String,
    },
    FilteredByKeyword,
    CodeDetectionSkipped,
    PartialBodyParse {
        reason: String,
    },
    #[serde(alias = "oversize_body")]
    BodyTruncated {
        actual_bytes: u64,
        limit_bytes: u64,
    },
    EncodingError,
}
