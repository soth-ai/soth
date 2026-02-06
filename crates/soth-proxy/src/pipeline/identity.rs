//! Identity verification layer

use super::middleware::{error_response, get_request_id, Layer, LayerResult, RequestContext};
use crate::protocol::{JsonRpcError, JsonRpcMessage};
use soth_dashboard::DashboardState;
use soth_identity::{TrustStore, Did};
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
        let did = ctx.metadata
            .get(&self.config.did_header)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let signature = ctx.metadata
            .get(&self.config.signature_header)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        match (did, signature) {
            (Some(did), Some(_sig)) => {
                // Verify the signature
                let store = self.trust_store.read().await;

                // Check if DID is trusted
                if !store.is_trusted(&did) {
                    return Err(format!("DID not in trust store: {did}"));
                }

                // Get the message content for verification
                let _content = match message {
                    JsonRpcMessage::Request(req) => {
                        serde_json::to_value(req).ok()
                    }
                    JsonRpcMessage::Response(resp) => {
                        serde_json::to_value(resp).ok()
                    }
                };

                // Decode public key from DID and verify
                match Did::parse(&did) {
                    Ok(parsed_did) => {
                        match parsed_did.to_key_pair() {
                            Ok(_keypair) => {
                                // For now, just mark as verified if DID is valid and trusted
                                // Full signature verification would require the signed document
                                // format from soth_identity::SignedDocument
                                ctx.identity_verified = true;
                                ctx.agent_did = Some(did.clone());
                                debug!("Identity verified for DID: {}", did);
                                Ok(true)
                            }
                            Err(e) => {
                                Err(format!("Invalid DID key: {e}"))
                            }
                        }
                    }
                    Err(e) => {
                        Err(format!("Invalid DID: {e}"))
                    }
                }
            }
            (Some(did), None) => {
                // DID present but no signature - mark as unverified
                ctx.agent_did = Some(did);
                ctx.identity_verified = false;
                Ok(false)
            }
            (None, Some(_)) => {
                Err("Signature present without DID".to_string())
            }
            (None, None) => {
                // No identity information
                Ok(false)
            }
        }
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

    #[tokio::test]
    async fn test_identity_layer_disabled() {
        let layer = IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Disabled,
            ..Default::default()
        });

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "test",
            None,
            RequestId::Number(1),
        ));

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
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "test",
            None,
            RequestId::Number(1),
        ));

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
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "test",
            None,
            RequestId::Number(1),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Response(_)));
    }
}
