use crate::providers::DetectedProvider;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveArtifact {
    pub kind: ArtifactKind,
    pub severity: ArtifactSeverity,
    pub location: ArtifactLocation,
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
    ToolResult { tool_name: Option<String> },
    Unknown,
}

impl SensitiveArtifact {
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
    Rest { provider: DetectedProvider },
    GraphQl,
    Grpc,
    JsonRpc,
    AgentApp,
    Heuristic,
    Filtered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ParseWarning {
    GraphQlUnknownOperation { operation_name: String },
    PartialBodyParse { reason: String },
    OversizeBody { actual_bytes: u64, limit_bytes: u64 },
    EncodingError,
    GrpcNoDescriptor,
}
