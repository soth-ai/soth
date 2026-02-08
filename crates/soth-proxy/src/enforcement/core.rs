//! Shared enforcement helpers used by both MCP and forward proxy runtimes.

use std::collections::HashSet;

use soth_budget::{BudgetTracker, TokenCounter};
use soth_core::types::{
    budget::BudgetScope,
    policy::{PolicyDecision, PolicyInput, PolicyInputBuilder},
    TrafficEnvelope,
};
use soth_identity::{signing::verify_bytes, signing::SignatureBlock, Did};
use soth_policy::PolicyEngine;

use crate::metrics;
use crate::pipeline::middleware::RequestContext;
use crate::protocol::{methods, JsonRpcMessage, JsonRpcRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMode {
    Disabled,
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    Disabled,
    Audit,
    Enforce,
}

#[derive(Debug, Clone, Default)]
pub struct IdentityResult {
    pub verified: bool,
    pub did: Option<String>,
    pub policy_version: Option<String>,
}

pub struct ProxyEnforcementInput<'a> {
    pub envelope: &'a TrafficEnvelope,
}

pub struct ProxyEnforcementConfig<'a> {
    pub identity_mode: IdentityMode,
    pub trusted_dids: &'a HashSet<String>,
    pub policy_mode: PolicyMode,
    pub policy_engine: Option<&'a PolicyEngine>,
    pub budget_tracker: Option<&'a BudgetTracker>,
    pub budget_block_on_exceeded: bool,
    pub default_model: &'a str,
}

pub fn parse_signature_from_str(raw_signature: &str, did: &str) -> Result<SignatureBlock, String> {
    let signature = match serde_json::from_str::<SignatureBlock>(raw_signature) {
        Ok(block) => block,
        Err(_) => SignatureBlock {
            algorithm: "Ed25519".to_string(),
            value: raw_signature.to_string(),
            signer: did.to_string(),
            created: chrono::Utc::now(),
        },
    };

    if signature.algorithm != "Ed25519" {
        return Err(format!(
            "Unsupported signature algorithm: {}",
            signature.algorithm
        ));
    }
    if signature.signer != did {
        return Err(format!(
            "Signature signer mismatch: signer={}, did={}",
            signature.signer, did
        ));
    }

    Ok(signature)
}

pub fn parse_signature_from_value(
    signature_value: serde_json::Value,
    did: &str,
) -> Result<SignatureBlock, String> {
    if signature_value.is_object() {
        let signature = serde_json::from_value::<SignatureBlock>(signature_value)
            .map_err(|e| format!("Invalid signature block: {e}"))?;
        if signature.algorithm != "Ed25519" {
            return Err(format!(
                "Unsupported signature algorithm: {}",
                signature.algorithm
            ));
        }
        if signature.signer != did {
            return Err(format!(
                "Signature signer mismatch: signer={}, did={}",
                signature.signer, did
            ));
        }
        return Ok(signature);
    }

    if let Some(sig_str) = signature_value.as_str() {
        return parse_signature_from_str(sig_str, did);
    }

    Err("Signature metadata must be a string or object".to_string())
}

pub fn canonical_proxy_request_bytes(
    host: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<Vec<u8>, String> {
    let value = serde_json::json!({
        "host": host,
        "method": method,
        "path": path,
        "body": body.unwrap_or(""),
    });
    soth_identity::canonicalize_json(&value)
        .map_err(|e| format!("Failed to canonicalize proxy request for signing: {e}"))
}

pub fn canonical_jsonrpc_message_bytes(message: &JsonRpcMessage) -> Result<Vec<u8>, String> {
    let value = match message {
        JsonRpcMessage::Request(req) => serde_json::to_value(req)
            .map_err(|e| format!("Failed to serialize request for signing: {e}"))?,
        JsonRpcMessage::Response(resp) => serde_json::to_value(resp)
            .map_err(|e| format!("Failed to serialize response for signing: {e}"))?,
    };

    soth_identity::canonicalize_json(&value)
        .map_err(|e| format!("Failed to canonicalize message for signing: {e}"))
}

pub fn verify_signature_for_did(
    canonical: &[u8],
    did: &str,
    signature: &SignatureBlock,
) -> Result<(), String> {
    let parsed_did = Did::parse(did).map_err(|e| format!("Invalid DID: {e}"))?;
    let keypair = parsed_did
        .to_key_pair()
        .map_err(|e| format!("Invalid DID key: {e}"))?;

    let verified = verify_bytes(canonical, signature, &keypair)
        .map_err(|e| format!("Signature verification failed: {e}"))?;
    if !verified {
        return Err(format!("Invalid signature for DID: {did}"));
    }
    Ok(())
}

pub fn verify_proxy_identity(
    mode: IdentityMode,
    trusted_dids: &HashSet<String>,
    host: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    did: Option<&str>,
    signature: Option<&str>,
) -> Result<IdentityResult, String> {
    if mode == IdentityMode::Disabled {
        return Ok(IdentityResult::default());
    }

    match (did, signature) {
        (None, None) => {
            if mode == IdentityMode::Required {
                Err("Identity required: missing DID and signature".to_string())
            } else {
                Ok(IdentityResult::default())
            }
        }
        (Some(did), None) => {
            if mode == IdentityMode::Required {
                Err("Identity required: signature missing".to_string())
            } else {
                Ok(IdentityResult {
                    verified: false,
                    did: Some(did.to_string()),
                    policy_version: None,
                })
            }
        }
        (None, Some(_)) => Err("Signature provided without DID".to_string()),
        (Some(did), Some(signature)) => {
            if !trusted_dids.contains(did) {
                return Err(format!("DID not in trust store: {did}"));
            }

            let signature_block = parse_signature_from_str(signature, did)?;
            let canonical = canonical_proxy_request_bytes(host, method, path, body)?;
            verify_signature_for_did(&canonical, did, &signature_block)?;

            Ok(IdentityResult {
                verified: true,
                did: Some(did.to_string()),
                policy_version: None,
            })
        }
    }
}

pub fn verify_mcp_identity<F>(
    is_trusted_did: F,
    message: &JsonRpcMessage,
    did: Option<&str>,
    signature: Option<&serde_json::Value>,
) -> Result<IdentityResult, String>
where
    F: Fn(&str) -> bool,
{
    match (did, signature) {
        (Some(did), Some(signature_value)) => {
            if !is_trusted_did(did) {
                return Err(format!("DID not in trust store: {did}"));
            }

            let signature_block = parse_signature_from_value(signature_value.clone(), did)?;
            let canonical = canonical_jsonrpc_message_bytes(message)?;
            verify_signature_for_did(&canonical, did, &signature_block)?;

            Ok(IdentityResult {
                verified: true,
                did: Some(did.to_string()),
                policy_version: None,
            })
        }
        (Some(did), None) => Ok(IdentityResult {
            verified: false,
            did: Some(did.to_string()),
            policy_version: None,
        }),
        (None, Some(_)) => Err("Signature present without DID".to_string()),
        (None, None) => Ok(IdentityResult::default()),
    }
}

pub fn build_proxy_policy_input(
    envelope: &TrafficEnvelope,
    identity: &IdentityResult,
) -> PolicyInput {
    let provider = envelope.provider.as_deref().unwrap_or("unknown");
    let host = envelope.host.as_deref().unwrap_or("unknown");
    let http_method = envelope.method.as_str();
    let path = envelope.path.as_deref().unwrap_or("/");
    let model = envelope.model.as_deref();

    let mut builder = PolicyInputBuilder::new()
        .session_id(&envelope.session_id)
        .method(format!("proxy/{}", http_method.to_lowercase()))
        .tool(format!("{provider}:{path}"))
        .arguments_json(serde_json::json!({
            "provider": provider,
            "host": host,
            "method": http_method,
            "path": path,
            "model": model,
        }));

    if let Some(agent_id) = envelope.agent.as_deref() {
        builder = builder.agent_id(agent_id);
    }

    if identity.verified {
        builder = builder.identity_verified(true);
        if let Some(ref did) = identity.did {
            builder = builder.identity_did(did);
        }
    }

    builder.build()
}

pub fn build_mcp_policy_input(ctx: &RequestContext, req: &JsonRpcRequest) -> PolicyInput {
    let mut builder = PolicyInputBuilder::new()
        .session_id(&ctx.session_id)
        .method(&req.method)
        .timestamp(ctx.timestamp);

    if let Some(ref agent_id) = ctx.agent_id {
        builder = builder.agent_id(agent_id);
    }

    if ctx.identity_verified {
        builder = builder.identity_verified(true);
        if let Some(ref did) = ctx.agent_did {
            builder = builder.identity_did(did);
        }
    }

    if let Some(ref params) = req.params {
        if req.method == methods::TOOLS_CALL {
            if let Some(name) = params.get("name").and_then(|v| v.as_str()) {
                builder = builder.tool(name);
            }
            if let Some(args) = params.get("arguments") {
                builder = builder.arguments_json(args.clone());
            }
        }

        if req.method == methods::RESOURCES_READ {
            if let Some(uri) = params.get("uri").and_then(|v| v.as_str()) {
                builder = builder.resource(uri);
            }
        }
    }

    builder.build()
}

pub fn evaluate_policy(
    engine: &PolicyEngine,
    input: &PolicyInput,
) -> Result<(PolicyDecision, String), String> {
    let result = engine
        .evaluate(input)
        .map_err(|e| format!("Policy evaluation failed: {e}"))?;
    Ok((result.decision, result.policy_version))
}

pub fn decision_reason(decision: &PolicyDecision, default_reason: &str) -> String {
    decision
        .reason
        .clone()
        .or_else(|| {
            if decision.violations.is_empty() {
                None
            } else {
                Some(decision.violations.join("; "))
            }
        })
        .unwrap_or_else(|| default_reason.to_string())
}

pub fn estimate_mcp_tokens(value: &serde_json::Value) -> u64 {
    TokenCounter::count_mcp_context_tokens(value)
}

pub fn is_budget_exceeded(tracker: &BudgetTracker, agent_id: Option<&str>) -> bool {
    tracker.is_budget_exceeded(agent_id)
}

pub fn record_budget_spend(
    tracker: &BudgetTracker,
    session_id: &str,
    agent_id: Option<&str>,
    model: &str,
    input_tokens: u64,
    output_tokens: u64,
) {
    tracker.record_spend(session_id, agent_id, model, input_tokens, output_tokens);
}

fn budget_scope_label(scope: BudgetScope) -> &'static str {
    match scope {
        BudgetScope::Global => "global",
        BudgetScope::PerAgent => "per_agent",
        BudgetScope::PerSession => "per_session",
        BudgetScope::PerModel => "per_model",
    }
}

pub fn enforce_proxy_request(
    config: ProxyEnforcementConfig<'_>,
    input: ProxyEnforcementInput<'_>,
) -> Result<IdentityResult, (u16, String, Option<String>)> {
    let envelope = input.envelope;

    let host = envelope.host.as_deref().unwrap_or_default();
    let method = envelope.method.as_str();
    let path = envelope.path.as_deref().unwrap_or("/");
    let did = envelope.did.as_deref();
    let signature = envelope.signature.as_deref();

    let mut identity = match verify_proxy_identity(
        config.identity_mode,
        config.trusted_dids,
        host,
        method,
        path,
        envelope.request_body.as_deref(),
        did,
        signature,
    ) {
        Ok(identity) => identity,
        Err(err) => {
            if config.identity_mode == IdentityMode::Required {
                return Err((401, err, None));
            }
            IdentityResult {
                verified: false,
                did: did.map(ToString::to_string),
                policy_version: None,
            }
        }
    };

    if let Some(tracker) = config.budget_tracker {
        let agent_id = identity
            .did
            .as_deref()
            .or(envelope.agent.as_deref())
            .map(|s| s.to_string());
        metrics::record_budget_check("request");
        if config.budget_block_on_exceeded {
            if let Some(scope) = tracker.first_exceeded_scope(
                &envelope.session_id,
                agent_id.as_deref(),
                envelope.model.as_deref(),
            ) {
                metrics::record_budget_block(budget_scope_label(scope));
                return Err((
                    429,
                    format!("Budget exceeded ({})", budget_scope_label(scope)),
                    None,
                ));
            }
        }
        if let Some(body) = envelope.request_body.as_deref() {
            let input_tokens = TokenCounter::estimate_tokens(body);
            let effective_model = envelope.model.as_deref().unwrap_or(config.default_model);
            tracker.record_spend(
                &envelope.session_id,
                agent_id.as_deref(),
                effective_model,
                input_tokens,
                0,
            );
        }
    }

    let Some(engine) = config.policy_engine else {
        return Ok(identity);
    };

    let policy_input = build_proxy_policy_input(envelope, &identity);
    let eval_start = std::time::Instant::now();
    let (decision, policy_version) = match evaluate_policy(engine, &policy_input) {
        Ok(v) => v,
        Err(err) => {
            let active_version = engine.active_policy_version();
            metrics::record_policy_evaluation("error", eval_start.elapsed());
            metrics::set_policy_active_version(&active_version);
            match config.policy_mode {
                PolicyMode::Enforce => {
                    return Err((
                        403,
                        format!("Policy evaluation failed (enforce mode): {err}"),
                        Some(active_version),
                    ));
                }
                PolicyMode::Audit | PolicyMode::Disabled => {
                    identity.policy_version = Some(active_version);
                    return Ok(identity);
                }
            }
        }
    };
    metrics::record_policy_evaluation("success", eval_start.elapsed());
    metrics::set_policy_active_version(&policy_version);
    let policy_version = Some(policy_version);
    identity.policy_version = policy_version.clone();

    if decision.allow {
        return Ok(identity);
    }

    let reason = decision_reason(&decision, "Policy denied proxy request");
    match config.policy_mode {
        PolicyMode::Enforce => Err((403, reason, policy_version)),
        PolicyMode::Audit | PolicyMode::Disabled => Ok(identity),
    }
}
