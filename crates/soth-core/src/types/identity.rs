//! Identity types for SOTH
//!
//! Defines identity context and trust levels for agent verification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Trust level for an agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// No identity verification
    Anonymous,
    /// Identity claimed but not verified
    Claimed,
    /// Identity cryptographically verified
    Verified,
    /// Identity verified and in trust store
    Trusted,
}

impl Default for TrustLevel {
    fn default() -> Self {
        Self::Anonymous
    }
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Anonymous => write!(f, "anonymous"),
            Self::Claimed => write!(f, "claimed"),
            Self::Verified => write!(f, "verified"),
            Self::Trusted => write!(f, "trusted"),
        }
    }
}

/// Identity context for policy evaluation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityContext {
    /// Whether the identity has been verified
    pub verified: bool,

    /// The DID (Decentralized Identifier) if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,

    /// Signature algorithm used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_alg: Option<String>,

    /// When the credentials were issued
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,

    /// Whether there's a log proof
    #[serde(default)]
    pub has_log_proof: bool,

    /// Trust level
    #[serde(default)]
    pub trust_level: TrustLevel,
}

impl IdentityContext {
    /// Create a new anonymous identity context
    pub fn anonymous() -> Self {
        Self::default()
    }

    /// Create a verified identity context
    pub fn verified(did: String) -> Self {
        Self {
            verified: true,
            did: Some(did),
            signature_alg: Some("Ed25519".to_string()),
            issued_at: Some(Utc::now()),
            trust_level: TrustLevel::Verified,
            ..Default::default()
        }
    }

    /// Create a trusted identity context (verified and in trust store)
    pub fn trusted(did: String) -> Self {
        Self {
            verified: true,
            did: Some(did),
            signature_alg: Some("Ed25519".to_string()),
            issued_at: Some(Utc::now()),
            trust_level: TrustLevel::Trusted,
            ..Default::default()
        }
    }
}

/// Agent information context
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentContext {
    /// Agent identifier
    pub id: String,

    /// Agent display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Agent capabilities
    #[serde(default)]
    pub capabilities: Vec<String>,

    /// Model being used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Publisher/organization
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,

    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,
}

impl AgentContext {
    /// Create a new agent context with just an ID
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Default::default()
        }
    }

    /// Set the agent name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Add capabilities
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Set the model
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_display() {
        assert_eq!(TrustLevel::Anonymous.to_string(), "anonymous");
        assert_eq!(TrustLevel::Verified.to_string(), "verified");
    }

    #[test]
    fn test_identity_context_anonymous() {
        let ctx = IdentityContext::anonymous();
        assert!(!ctx.verified);
        assert!(ctx.did.is_none());
        assert_eq!(ctx.trust_level, TrustLevel::Anonymous);
    }

    #[test]
    fn test_identity_context_verified() {
        let ctx = IdentityContext::verified("did:key:z6Mk...".to_string());
        assert!(ctx.verified);
        assert_eq!(ctx.did, Some("did:key:z6Mk...".to_string()));
        assert_eq!(ctx.trust_level, TrustLevel::Verified);
    }

    #[test]
    fn test_agent_context_builder() {
        let agent = AgentContext::new("agent-1")
            .with_name("Test Agent")
            .with_model("claude-3")
            .with_capabilities(vec!["read".to_string(), "write".to_string()]);

        assert_eq!(agent.id, "agent-1");
        assert_eq!(agent.name, Some("Test Agent".to_string()));
        assert_eq!(agent.model, Some("claude-3".to_string()));
        assert_eq!(agent.capabilities.len(), 2);
    }
}
