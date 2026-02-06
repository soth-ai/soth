//! Policy integration tests
//!
//! Tests for policy evaluation, YAML compilation, and enforcement

use soth_core::types::identity::AgentContext;
use soth_core::types::policy::{PolicyData, PolicyInputBuilder};
use soth_policy::{PolicyCompiler, PolicyEngine, PolicyEngineConfig, PolicyLoader};
use std::collections::HashMap;
use tempfile::tempdir;

#[test]
fn test_policy_engine_default_allow() {
    let engine = PolicyEngine::new();

    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("read_file")
        .agent_id("test-agent")
        .build();

    let result = engine.evaluate(&input).expect("evaluation should succeed");

    // Default policy allows everything
    assert!(result.decision.allow);
}

#[test]
fn test_policy_engine_blocked_tool() {
    let engine = PolicyEngine::new();

    // Set up policy data with blocked tools
    let policy_data = PolicyData {
        blocked_tools: vec!["dangerous_tool".to_string(), "shell_exec".to_string()],
        ..Default::default()
    };
    engine
        .set_policy_data(policy_data)
        .expect("set policy data should succeed");

    // Blocked tool should be denied
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("dangerous_tool")
        .build();

    let result = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(!result.decision.allow);
    assert!(result
        .decision
        .violations
        .iter()
        .any(|v| v.contains("blocked")));

    // Non-blocked tool should be allowed
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("safe_tool")
        .build();

    let result = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(result.decision.allow);
}

#[test]
fn test_policy_engine_blocked_agent() {
    let engine = PolicyEngine::new();

    let policy_data = PolicyData {
        blocked_agents: vec!["malicious-agent".to_string()],
        ..Default::default()
    };
    engine
        .set_policy_data(policy_data)
        .expect("set policy data should succeed");

    // Blocked agent should be denied
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .agent_id("malicious-agent")
        .build();

    let result = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(!result.decision.allow);

    // Non-blocked agent should be allowed
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .agent_id("good-agent")
        .build();

    let result = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(result.decision.allow);
}

#[test]
fn test_policy_engine_identity_required_tools_denied() {
    let engine = PolicyEngine::new();

    let policy_data = PolicyData {
        identity_required_tools: vec!["write_file".to_string()],
        ..Default::default()
    };
    engine
        .set_policy_data(policy_data)
        .expect("set policy data should succeed");

    // Without identity verification, should be denied
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("write_file")
        .identity_verified(false)
        .build();

    let result = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(!result.decision.allow);
    assert!(result
        .decision
        .violations
        .iter()
        .any(|v| v.contains("identity")));
}

#[test]
fn test_policy_engine_identity_required_tools_allowed() {
    let engine = PolicyEngine::new();

    let policy_data = PolicyData {
        identity_required_tools: vec!["write_file".to_string()],
        ..Default::default()
    };
    engine
        .set_policy_data(policy_data)
        .expect("set policy data should succeed");

    // With identity verification, should be allowed
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("write_file")
        .identity_verified(true)
        .identity_did("did:key:z6MkTest")
        .build();

    let result = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(
        result.decision.allow,
        "Expected allow but got: {:?}",
        result.decision
    );
}

#[test]
fn test_policy_engine_capability_requirements() {
    let engine = PolicyEngine::new();

    let mut tool_capabilities = HashMap::new();
    tool_capabilities.insert("admin_tool".to_string(), "admin".to_string());
    tool_capabilities.insert("read_tool".to_string(), "read".to_string());

    let policy_data = PolicyData {
        tool_capabilities,
        ..Default::default()
    };
    engine
        .set_policy_data(policy_data)
        .expect("set policy data should succeed");

    // Agent without required capability should be denied
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("admin_tool")
        .agent(AgentContext {
            id: "limited-agent".to_string(),
            capabilities: vec!["read".to_string()],
            ..Default::default()
        })
        .build();

    let result = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(!result.decision.allow);

    // Agent with required capability should be allowed
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("admin_tool")
        .agent(AgentContext {
            id: "admin-agent".to_string(),
            capabilities: vec!["admin".to_string(), "read".to_string()],
            ..Default::default()
        })
        .build();

    let result = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(result.decision.allow);
}

#[test]
fn test_policy_engine_audit_mode() {
    let engine = PolicyEngine::with_config(PolicyEngineConfig {
        mode: "audit".to_string(),
        ..Default::default()
    });

    let policy_data = PolicyData {
        blocked_tools: vec!["blocked_tool".to_string()],
        ..Default::default()
    };
    engine
        .set_policy_data(policy_data)
        .expect("set policy data should succeed");

    // In audit mode, blocked tool should still be "allowed" but flagged
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("blocked_tool")
        .build();

    let (allowed, result) = engine
        .is_allowed(&input)
        .expect("evaluation should succeed");

    // is_allowed returns true in audit mode
    assert!(allowed);
    // But the decision itself shows it would be denied
    assert!(!result.decision.allow);
}

#[test]
fn test_policy_engine_caching() {
    let engine = PolicyEngine::new();

    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("test_tool")
        .build();

    // First call - cache miss
    let result1 = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(!result1.cache_hit);

    // Second call - cache hit
    let result2 = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(result2.cache_hit);

    // Results should be the same
    assert_eq!(result1.decision.allow, result2.decision.allow);
}

#[test]
fn test_policy_engine_disabled() {
    let engine = PolicyEngine::with_config(PolicyEngineConfig {
        enabled: false,
        ..Default::default()
    });

    // Even with blocked tools set, everything should be allowed when disabled
    let policy_data = PolicyData {
        blocked_tools: vec!["everything".to_string()],
        ..Default::default()
    };
    engine
        .set_policy_data(policy_data)
        .expect("set policy data should succeed");

    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("everything")
        .build();

    let result = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(result.decision.allow);
    assert_eq!(
        result.decision.matched_rule,
        Some("policy_disabled".to_string())
    );
}

#[test]
fn test_policy_compiler_yaml_to_rego() {
    // Use correct schema: tool condition needs 'name' field, deny needs 'message'
    let yaml = r#"
name: test_policy
description: A test policy
rules:
  - name: block_dangerous
    condition:
      type: tool
      name: dangerous_tool
    action:
      type: deny
      message: "Dangerous tool blocked"
  - name: allow_all
    condition:
      type: always
    action:
      type: allow
"#;

    let rego = PolicyCompiler::compile_yaml(yaml).expect("YAML compilation should succeed");

    // Should produce valid Rego code
    assert!(rego.contains("package mcp.policy"));
    assert!(rego.contains("block_dangerous"));
    assert!(rego.contains("allow_all"));
}

#[test]
fn test_policy_loader_from_file() {
    let dir = tempdir().expect("temp dir should work");

    // Create a policy data file
    let data_path = dir.path().join("policy_data.yaml");
    let yaml_content = r#"
blocked_tools:
  - dangerous_tool
  - shell_exec
blocked_agents:
  - bad_agent
identity_required_tools:
  - write_file
"#;
    std::fs::write(&data_path, yaml_content).expect("write should succeed");

    // Load the policy data
    let data = PolicyLoader::load_policy_data_yaml(&data_path).expect("loading should succeed");

    assert!(data.blocked_tools.contains(&"dangerous_tool".to_string()));
    assert!(data.blocked_agents.contains(&"bad_agent".to_string()));
    assert!(data
        .identity_required_tools
        .contains(&"write_file".to_string()));
}

#[test]
fn test_policy_allowed_dids_no_did_denied() {
    let engine = PolicyEngine::new();

    let policy_data = PolicyData {
        allowed_dids: vec!["did:key:z6MkAllowed".to_string()],
        ..Default::default()
    };
    engine
        .set_policy_data(policy_data)
        .expect("set policy data should succeed");

    // Request without DID should be denied when allowed_dids is set
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("some_tool")
        .build();

    let result = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(
        !result.decision.allow,
        "Expected deny but got: {:?}",
        result.decision
    );
}

#[test]
fn test_policy_allowed_dids_wrong_did_denied() {
    let engine = PolicyEngine::new();

    let policy_data = PolicyData {
        allowed_dids: vec!["did:key:z6MkAllowed".to_string()],
        ..Default::default()
    };
    engine
        .set_policy_data(policy_data)
        .expect("set policy data should succeed");

    // Request with wrong DID should be denied
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("some_tool")
        .identity_verified(true)
        .identity_did("did:key:z6MkWrongDid")
        .build();

    let result = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(
        !result.decision.allow,
        "Expected deny but got: {:?}",
        result.decision
    );
}

#[test]
fn test_policy_allowed_dids_correct_did_allowed() {
    let engine = PolicyEngine::new();

    let policy_data = PolicyData {
        allowed_dids: vec!["did:key:z6MkAllowed".to_string()],
        ..Default::default()
    };
    engine
        .set_policy_data(policy_data)
        .expect("set policy data should succeed");

    // Request with allowed DID should succeed
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("some_tool")
        .identity_verified(true)
        .identity_did("did:key:z6MkAllowed")
        .build();

    let result = engine.evaluate(&input).expect("evaluation should succeed");
    assert!(
        result.decision.allow,
        "Expected allow but got: {:?}",
        result.decision
    );
}

#[test]
fn test_policy_input_builder() {
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("read_file")
        .resource("/tmp/test.txt")
        .agent(AgentContext {
            id: "my-agent".to_string(),
            name: Some("My Agent".to_string()),
            capabilities: vec!["read".to_string(), "write".to_string()],
            model: Some("gpt-4".to_string()),
            ..Default::default()
        })
        .session_id("session-123")
        .identity_verified(true)
        .identity_did("did:key:z6MkTest")
        .build();

    assert_eq!(input.request.method, "tools/call");
    assert_eq!(input.request.tool, Some("read_file".to_string()));
    assert_eq!(input.agent.id, "my-agent");
    assert_eq!(input.agent.name, Some("My Agent".to_string()));
    assert!(input.agent.capabilities.contains(&"read".to_string()));
    assert!(input.identity.verified);
    assert_eq!(input.identity.did, Some("did:key:z6MkTest".to_string()));
}
