//! Identity verification layer

use super::middleware::{error_response, get_request_id, Layer, LayerResult, RequestContext};
use crate::enforcement::core;
use crate::protocol::{JsonRpcError, JsonRpcMessage};
use soth_dashboard::DashboardState;
use soth_identity::TrustStore;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Identity verification mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMode {
    /// Identity verification is disabled
    Disabled,
    /// Identity is optional (verified if present)
    Optional,
    /// Identity is required for all requests
    Required,
}

impl Default for IdentityMode {
    fn default() -> Self {
        Self::Optional
    }
}

/// Identity layer configuration
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// Verification mode
    pub mode: IdentityMode,
    /// Header name for signature
    pub signature_header: String,
    /// Header name for DID
    pub did_header: String,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            mode: IdentityMode::Optional,
            signature_header: "X-Agent-Signature".to_string(),
            did_header: "X-Agent-DID".to_string(),
        }
    }
}

/// Identity verification layer
pub struct IdentityLayer {
    /// Configuration
    config: IdentityConfig,
    /// Trust store for verified DIDs
    trust_store: Arc<RwLock<TrustStore>>,
    /// Dashboard state for metrics (optional)
    dashboard: Option<DashboardState>,
}

impl IdentityLayer {
    /// Create a new identity layer
    pub fn new(config: IdentityConfig) -> Self {
        Self {
            config,
            trust_store: Arc::new(RwLock::new(TrustStore::in_memory())),
            dashboard: None,
        }
    }

    /// Create with a trust store
    pub fn with_trust_store(config: IdentityConfig, trust_store: TrustStore) -> Self {
        Self {
            config,
            trust_store: Arc::new(RwLock::new(trust_store)),
            dashboard: None,
        }
    }

    /// Set dashboard state for metrics reporting
    pub fn with_dashboard(mut self, state: DashboardState) -> Self {
        self.dashboard = Some(state);
        self
    }

    /// Add a trusted DID
    pub async fn add_trusted_did(&self, did: &str) -> soth_identity::Result<()> {
        let mut store = self.trust_store.write().await;
        store.trust(did)
    }

    /// Check if a DID is trusted
    pub async fn is_trusted(&self, did: &str) -> bool {
        let store = self.trust_store.read().await;
        store.is_trusted(did)
    }

    /// Verify identity from message metadata
    async fn verify_identity(
        &self,
        ctx: &mut RequestContext,
        message: &JsonRpcMessage,
    ) -> Result<bool, String> {
        // Extract DID and signature from context metadata
        let did = ctx
            .metadata
            .get(&self.config.did_header)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let signature = ctx.metadata.get(&self.config.signature_header).cloned();

        let store = self.trust_store.read().await;
        let verification = core::verify_mcp_identity(
            |candidate| store.is_trusted(candidate),
            message,
            did.as_deref(),
            signature.as_ref(),
        )?;

        ctx.agent_did = verification.did.clone();
        ctx.identity_verified = verification.verified;

        if verification.verified {
            if let Some(ref did) = verification.did {
                debug!("Identity verified for DID: {}", did);
            }
        }

        Ok(verification.verified)
    }
}

impl Layer for IdentityLayer {
    fn process<'a>(
        &'a self,
        ctx: &'a mut RequestContext,
        message: JsonRpcMessage,
    ) -> Pin<Box<dyn Future<Output = LayerResult> + Send + 'a>> {
        Box::pin(async move {
            // Skip if disabled
            if self.config.mode == IdentityMode::Disabled {
                return LayerResult::Continue(message);
            }

            // Try to verify identity
            match self.verify_identity(ctx, &message).await {
                Ok(verified) => {
                    // Record to dashboard if DID was present
                    if let Some(ref did) = ctx.agent_did {
                        if let Some(ref dash) = self.dashboard {
                            dash.record_identity_verification(did, verified);
                        }
                    }

                    if self.config.mode == IdentityMode::Required && !verified {
                        let id = get_request_id(&message);
                        return error_response(id, JsonRpcError::identity_required());
                    }
                    LayerResult::Continue(message)
                }
                Err(e) => {
                    warn!("Identity verification error: {}", e);

                    // Record failed verification to dashboard
                    if let Some(ref did) = ctx.agent_did {
                        if let Some(ref dash) = self.dashboard {
                            dash.record_identity_verification(did, false);
                        }
                    }

                    if self.config.mode == IdentityMode::Required {
                        let id = get_request_id(&message);
                        return error_response(
                            id,
                            JsonRpcError::new(-32852, format!("Identity error: {e}")),
                        );
                    }

                    // Optional mode - continue without verified identity
                    LayerResult::Continue(message)
                }
            }
        })
    }

    fn name(&self) -> &'static str {
        "identity"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{JsonRpcRequest, RequestId};
    use serde_json::json;
    use soth_identity::{signing::sign_bytes, Did, KeyPair};

    #[tokio::test]
    async fn test_identity_layer_disabled() {
        let layer = IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Disabled,
            ..Default::default()
        });

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new("test", None, RequestId::Number(1)));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));
        assert!(!ctx.identity_verified);
    }

    #[tokio::test]
    async fn test_identity_layer_optional_no_identity() {
        let layer = IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Optional,
            ..Default::default()
        });

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new("test", None, RequestId::Number(1)));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));
    }

    #[tokio::test]
    async fn test_identity_layer_required_no_identity() {
        let layer = IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Required,
            ..Default::default()
        });

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new("test", None, RequestId::Number(1)));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Response(_)));
    }

    #[tokio::test]
    async fn test_identity_layer_required_valid_signature() {
        let layer = IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Required,
            ..Default::default()
        });

        let keypair = KeyPair::generate();
        let did = Did::from_key_pair(&keypair).unwrap().uri();
        layer.add_trusted_did(&did).await.unwrap();

        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "tools/call",
            Some(json!({"name": "test_tool", "arguments": {"x": 1}})),
            RequestId::Number(1),
        ));
        let canonical = core::canonical_jsonrpc_message_bytes(&msg).unwrap();
        let signature = keypair.sign_base64(&canonical).unwrap();

        let mut ctx = RequestContext::new("session-1")
            .with_metadata(layer.config.did_header.clone(), json!(did.clone()))
            .with_metadata(layer.config.signature_header.clone(), json!(signature));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));
        assert!(ctx.identity_verified);
        assert_eq!(ctx.agent_did, Some(did));
    }

    #[tokio::test]
    async fn test_identity_layer_required_invalid_signature() {
        let layer = IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Required,
            ..Default::default()
        });

        let keypair = KeyPair::generate();
        let did = Did::from_key_pair(&keypair).unwrap().uri();
        layer.add_trusted_did(&did).await.unwrap();

        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "tools/call",
            Some(json!({"name": "test_tool"})),
            RequestId::Number(1),
        ));
        let bad_signature = keypair.sign_base64(b"wrong-payload").unwrap();

        let mut ctx = RequestContext::new("session-1")
            .with_metadata(layer.config.did_header.clone(), json!(did.clone()))
            .with_metadata(layer.config.signature_header.clone(), json!(bad_signature));

        let result = layer.process(&mut ctx, msg).await;
        match result {
            LayerResult::Response(resp) => {
                let err = resp.error.expect("required mode should return an error");
                assert_eq!(err.code, -32852);
            }
            _ => panic!("expected identity failure response"),
        }
        assert!(!ctx.identity_verified);
        assert_eq!(ctx.agent_did, Some(did));
    }

    #[tokio::test]
    async fn test_identity_layer_required_signature_signer_mismatch() {
        let layer = IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Required,
            ..Default::default()
        });

        let trusted_keypair = KeyPair::generate();
        let trusted_did = Did::from_key_pair(&trusted_keypair).unwrap().uri();
        layer.add_trusted_did(&trusted_did).await.unwrap();

        let other_keypair = KeyPair::generate();
        let other_did = Did::from_key_pair(&other_keypair).unwrap().uri();

        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "tools/call",
            Some(json!({"name": "test_tool"})),
            RequestId::Number(1),
        ));
        let canonical = core::canonical_jsonrpc_message_bytes(&msg).unwrap();
        let signature_block = sign_bytes(&canonical, &other_keypair, &other_did).unwrap();
        let signature_json = serde_json::to_string(&signature_block).unwrap();

        let mut ctx = RequestContext::new("session-1")
            .with_metadata(layer.config.did_header.clone(), json!(trusted_did.clone()))
            .with_metadata(layer.config.signature_header.clone(), json!(signature_json));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Response(_)));
        assert!(!ctx.identity_verified);
        assert_eq!(ctx.agent_did, Some(trusted_did));
    }
}
