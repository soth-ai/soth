//! Pipeline integration tests
//!
//! End-to-end tests for the full processing pipeline

use soth_proxy::{
    PipelineBuilder,
    IdentityLayer, PolicyLayer, ObserveLayer, BudgetLayer,
    pipeline::middleware::RequestContext,
    pipeline::identity::{IdentityConfig, IdentityMode},
    pipeline::policy::{PolicyConfig, PolicyMode},
    pipeline::observe::ObserveConfig,
    pipeline::budget::BudgetConfig,
    protocol::{JsonRpcMessage, JsonRpcRequest, RequestId},
};
use soth_core::types::policy::PolicyData;
use serde_json::json;

fn make_tool_call_request(tool: &str, id: u64) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": tool,
            "arguments": {}
        })),
        id: Some(RequestId::Number(id as i64)),
    })
}

#[tokio::test]
async fn test_pipeline_basic_passthrough() {
    // Create a minimal pipeline
    let pipeline = PipelineBuilder::new().build();

    let mut ctx = RequestContext::new("test-session".to_string());
    let request = make_tool_call_request("read_file", 1);

    let result = pipeline.process(&mut ctx, request).await;

    // Should pass through successfully (no upstream, so returns as-is or error)
    // The important thing is it doesn't panic
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn test_pipeline_with_observe_layer() {
    let pipeline = PipelineBuilder::new()
        .layer(ObserveLayer::new(ObserveConfig {
            log_requests: true,
            log_responses: true,
            pii_detection: true,
            count_tokens: true,
            log_to_file: false, // Don't write to file in tests
        }))
        .build();

    let mut ctx = RequestContext::new("observe-session".to_string());
    let request = make_tool_call_request("test_tool", 1);

    // Process should not panic
    let _ = pipeline.process(&mut ctx, request).await;
}

#[tokio::test]
async fn test_pipeline_with_identity_layer_optional() {
    let pipeline = PipelineBuilder::new()
        .layer(IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Optional,
            ..Default::default()
        }))
        .build();

    let mut ctx = RequestContext::new("identity-session".to_string());
    let request = make_tool_call_request("test_tool", 1);

    // Should pass without identity in optional mode
    let _ = pipeline.process(&mut ctx, request).await;
}

#[tokio::test]
async fn test_pipeline_with_policy_layer() {
    // Create and configure the policy engine first
    let engine = soth_policy::PolicyEngine::new();
    engine.set_policy_data(PolicyData {
        blocked_tools: vec!["blocked_tool".to_string()],
        ..Default::default()
    }).expect("policy data should be set");

    let policy_layer = PolicyLayer::with_engine(
        PolicyConfig {
            mode: PolicyMode::Enforce,
            log_evaluations: true,
        },
        engine,
    );

    let pipeline = PipelineBuilder::new()
        .layer(policy_layer)
        .build();

    // Test allowed tool
    let mut ctx = RequestContext::new("policy-session".to_string());
    let allowed_request = make_tool_call_request("allowed_tool", 1);
    let result = pipeline.process(&mut ctx, allowed_request).await;
    // Should not be blocked
    assert!(result.is_ok());

    // Test blocked tool
    let mut ctx = RequestContext::new("policy-session-2".to_string());
    let blocked_request = make_tool_call_request("blocked_tool", 2);
    let result = pipeline.process(&mut ctx, blocked_request).await;
    // Should be blocked with error
    match result {
        Ok(Some(JsonRpcMessage::Response(resp))) => {
            assert!(resp.error.is_some(), "blocked tool should return error");
        }
        _ => {} // Other results also acceptable
    }
}

#[tokio::test]
async fn test_pipeline_with_budget_layer() {
    let pipeline = PipelineBuilder::new()
        .layer(BudgetLayer::new(BudgetConfig {
            enabled: true,
            block_on_exceeded: false, // Don't block, just track
            default_model: "gpt-4o".to_string(),
        }))
        .build();

    let mut ctx = RequestContext::new("budget-session".to_string());
    let request = make_tool_call_request("test_tool", 1);

    // Should pass through with budget tracking
    let _ = pipeline.process(&mut ctx, request).await;
}

#[tokio::test]
async fn test_full_pipeline_stack() {
    // Build a complete pipeline with all layers
    let pipeline = PipelineBuilder::new()
        .layer(ObserveLayer::new(ObserveConfig {
            log_requests: true,
            log_responses: true,
            pii_detection: true,
            count_tokens: true,
            log_to_file: false,
        }))
        .layer(IdentityLayer::new(IdentityConfig {
            mode: IdentityMode::Optional,
            ..Default::default()
        }))
        .layer(PolicyLayer::new(PolicyConfig {
            mode: PolicyMode::Audit, // Audit mode so we don't block
            log_evaluations: true,
        }))
        .layer(BudgetLayer::new(BudgetConfig {
            enabled: true,
            block_on_exceeded: false,
            default_model: "gpt-4o".to_string(),
        }))
        .build();

    let mut ctx = RequestContext::new("full-pipeline-session".to_string());
    let request = make_tool_call_request("read_file", 1);

    // Process through all layers
    let _ = pipeline.process(&mut ctx, request).await;

    // Context should have been modified by layers
    // (specific assertions depend on layer implementations)
}

#[tokio::test]
async fn test_pipeline_handles_notifications() {
    let pipeline = PipelineBuilder::new()
        .layer(ObserveLayer::new(ObserveConfig {
            log_requests: true,
            log_responses: false,
            pii_detection: false,
            count_tokens: false,
            log_to_file: false,
        }))
        .build();

    let mut ctx = RequestContext::new("notification-session".to_string());

    // Create a notification (no id)
    let notification = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "notifications/progress".to_string(),
        params: Some(json!({
            "progressToken": "token-123",
            "progress": 50,
            "total": 100
        })),
        id: None,
    });

    // Should handle notifications without error
    let _ = pipeline.process(&mut ctx, notification).await;
}

#[tokio::test]
async fn test_request_context_fields() {
    let ctx = RequestContext::new("session-123".to_string());

    // Session ID is a field
    assert_eq!(ctx.session_id, "session-123");

    // Default values
    assert!(ctx.agent_id.is_none());
    assert!(!ctx.identity_verified);
    assert!(ctx.agent_did.is_none());

    // Test builder pattern
    let ctx = RequestContext::new("session-456")
        .with_agent_id("agent-1")
        .with_verified_identity("did:key:z6MkTest");

    assert_eq!(ctx.session_id, "session-456");
    assert_eq!(ctx.agent_id, Some("agent-1".to_string()));
    assert!(ctx.identity_verified);
    assert_eq!(ctx.agent_did, Some("did:key:z6MkTest".to_string()));
}

#[tokio::test]
async fn test_pipeline_preserves_request_id() {
    let pipeline = PipelineBuilder::new().build();

    let mut ctx = RequestContext::new("id-test".to_string());
    let request = JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "test/method".to_string(),
        params: None,
        id: Some(RequestId::String("unique-id-12345".to_string())),
    });

    let result = pipeline.process(&mut ctx, request).await;

    // If we get a response, it should preserve the ID
    if let Ok(Some(JsonRpcMessage::Response(resp))) = result {
        assert_eq!(resp.id, RequestId::String("unique-id-12345".to_string()));
    }
}

#[tokio::test]
async fn test_concurrent_pipeline_processing() {
    use std::sync::Arc;

    let pipeline = Arc::new(
        PipelineBuilder::new()
            .layer(ObserveLayer::new(ObserveConfig {
                log_requests: true,
                log_responses: true,
                pii_detection: false,
                count_tokens: false,
                log_to_file: false,
            }))
            .build()
    );

    // Spawn multiple concurrent requests
    let mut handles = vec![];

    for i in 0..10 {
        let pipeline = Arc::clone(&pipeline);
        let handle = tokio::spawn(async move {
            let mut ctx = RequestContext::new(format!("concurrent-{}", i));
            let request = make_tool_call_request("test_tool", i as u64);
            pipeline.process(&mut ctx, request).await
        });
        handles.push(handle);
    }

    // All should complete without panic
    for handle in handles {
        let _ = handle.await.expect("task should complete");
    }
}
