//! Policy management commands

use crate::PolicyCommands;
use anyhow::Result;
use soth_policy::{PolicyCompiler, PolicyEngine, PolicyLoader, EvaluationResult};
use soth_core::types::policy::PolicyInputBuilder;
use std::path::PathBuf;
use tokio::fs;
use tracing::info;

/// Run policy command
pub async fn run(action: PolicyCommands) -> Result<()> {
    match action {
        PolicyCommands::Compile { input, output } => {
            compile_policies(input, output).await?;
        }
        PolicyCommands::Test { dir } => {
            test_policies(dir).await?;
        }
        PolicyCommands::Evaluate { input, policy } => {
            evaluate_policy(input, policy).await?;
        }
        PolicyCommands::List => {
            list_policies().await?;
        }
    }
    Ok(())
}

/// Compile YAML policies to Rego
async fn compile_policies(input: PathBuf, output: Option<PathBuf>) -> Result<()> {
    info!("Compiling policies from {:?}", input);

    if !input.exists() {
        anyhow::bail!("Input directory does not exist: {input:?}");
    }

    let output_dir = output.unwrap_or_else(|| input.join("compiled"));

    fs::create_dir_all(&output_dir).await?;

    let mut compiled_count = 0;
    let mut entries = fs::read_dir(&input).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
            let content = fs::read_to_string(&path).await?;

            match PolicyCompiler::compile_yaml(&content) {
                Ok(rego) => {
                    let output_name = path
                        .file_stem()
                        .unwrap()
                        .to_string_lossy()
                        .to_string()
                        + ".rego";
                    let output_path = output_dir.join(&output_name);

                    fs::write(&output_path, &rego).await?;
                    println!("Compiled: {path:?} -> {output_path:?}");
                    compiled_count += 1;
                }
                Err(e) => {
                    println!("Failed to compile {path:?}: {e}");
                }
            }
        }
    }

    println!("\nCompiled {compiled_count} policies");

    Ok(())
}

/// Test policies
async fn test_policies(dir: PathBuf) -> Result<()> {
    info!("Testing policies in {:?}", dir);

    if !dir.exists() {
        anyhow::bail!("Policy directory does not exist: {dir:?}");
    }

    let engine = PolicyEngine::new();

    // Load policy data from YAML files in the directory
    let mut entries = fs::read_dir(&dir).await?;
    let mut loaded = 0;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
            match PolicyLoader::load_policy_data_yaml(&path) {
                Ok(data) => {
                    engine.set_policy_data(data)?;
                    loaded += 1;
                    println!("Loaded: {path:?}");
                }
                Err(e) => {
                    println!("Failed to load {path:?}: {e}");
                }
            }
        }
    }

    println!("\nLoaded {loaded} policy files");

    // Run test cases
    println!("\nRunning test cases...\n");

    // Test 1: Normal tool call
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("read_file")
        .build();
    let result = engine.evaluate(&input)?;
    print_test_result("Normal tool call", &result);

    // Test 2: Blocked tool
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("shell_exec")
        .build();
    let result = engine.evaluate(&input)?;
    print_test_result("Blocked tool (shell_exec)", &result);

    // Test 3: With verified identity
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("write_file")
        .identity_verified(true)
        .identity_did("did:key:z6MkTest")
        .build();
    let result = engine.evaluate(&input)?;
    print_test_result("Write with verified identity", &result);

    // Test 4: Write without identity
    let input = PolicyInputBuilder::new()
        .method("tools/call")
        .tool("write_file")
        .identity_verified(false)
        .build();
    let result = engine.evaluate(&input)?;
    print_test_result("Write without identity", &result);

    Ok(())
}

/// Print test result
fn print_test_result(name: &str, result: &EvaluationResult) {
    let status = if result.decision.allow {
        "ALLOW"
    } else {
        "DENY"
    };

    println!("  {status} - {name}");
    if !result.decision.violations.is_empty() {
        println!("      Violations: {:?}", result.decision.violations);
    }
    if let Some(ref rule) = result.decision.matched_rule {
        println!("      Matched rule: {rule}");
    }
}

/// Evaluate a policy with input
async fn evaluate_policy(input_path: PathBuf, policy_path: Option<PathBuf>) -> Result<()> {
    // Load input
    let input_content = fs::read_to_string(&input_path).await?;
    let input_json: serde_json::Value = serde_json::from_str(&input_content)?;

    // Build policy input
    let mut builder = PolicyInputBuilder::new();

    if let Some(method) = input_json.get("method").and_then(|v| v.as_str()) {
        builder = builder.method(method);
    }
    if let Some(tool) = input_json.get("tool").and_then(|v| v.as_str()) {
        builder = builder.tool(tool);
    }
    if let Some(resource) = input_json.get("resource").and_then(|v| v.as_str()) {
        builder = builder.resource(resource);
    }
    if let Some(verified) = input_json.get("identity_verified").and_then(|v| v.as_bool()) {
        builder = builder.identity_verified(verified);
    }
    if let Some(did) = input_json.get("identity_did").and_then(|v| v.as_str()) {
        builder = builder.identity_did(did);
    }
    if let Some(agent_id) = input_json.get("agent_id").and_then(|v| v.as_str()) {
        builder = builder.agent_id(agent_id);
    }

    let input = builder.build();

    // Create engine and load policies
    let engine = PolicyEngine::new();

    if let Some(policy) = policy_path {
        let data = PolicyLoader::load_policy_data_yaml(&policy)?;
        engine.set_policy_data(data)?;
    }

    // Evaluate
    let result = engine.evaluate(&input)?;

    println!("Policy Evaluation Result:");
    println!("  Allowed: {}", result.decision.allow);
    if !result.decision.violations.is_empty() {
        println!("  Violations: {:?}", result.decision.violations);
    }
    if let Some(ref rule) = result.decision.matched_rule {
        println!("  Matched rule: {rule}");
    }
    println!("  Cache hit: {}", result.cache_hit);
    println!("  Eval time: {:?}", result.eval_time);
    println!();
    println!("Input:");
    println!("{}", serde_json::to_string_pretty(&input)?);

    Ok(())
}

/// List loaded policies
async fn list_policies() -> Result<()> {
    let policies_dir = PathBuf::from("policies");

    if !policies_dir.exists() {
        println!("No policies directory found");
        return Ok(());
    }

    println!("Policies:");

    let mut entries = fs::read_dir(&policies_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
            let content = fs::read_to_string(&path).await?;

            // Try to parse and show summary
            if let Ok(yaml) = serde_yaml::from_str::<serde_json::Value>(&content) {
                let name = yaml.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed");
                let desc = yaml.get("description").and_then(|v| v.as_str()).unwrap_or("");
                let rules = yaml.get("rules").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);

                println!("  {name} ({rules} rules)");
                if !desc.is_empty() {
                    println!("    {desc}");
                }
            } else {
                println!("  {path:?} (failed to parse)");
            }
        }
    }

    Ok(())
}
