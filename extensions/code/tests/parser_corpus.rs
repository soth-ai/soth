//! Fixture-corpus integration test for the Claude Code adapter.
//!
//! Walks `tests/fixtures/claude_code/<hook_type>/*.json` and runs every
//! file through `ClaudeCodeAdapter::parse_event`. Asserts each parses
//! without error and produces an event whose hook_type matches the
//! directory name.
//!
//! When upstream Claude Code changes a payload shape, the regression
//! shows up here as a per-fixture failure rather than a silent data-
//! loss bug in production. New observed payloads land in this corpus
//! before the parser change ships, so the failure is the change.
//!
//! Captured payloads are realistic but synthetic — file paths are
//! placeholders, content is short, and any "destructive" example is
//! safe to load (e.g. the `rm -rf /` Bash fixture is for the
//! credential-detection / policy-decision Phase-2 work, not real
//! filesystem traffic).

use std::fs;
use std::path::Path;

use soth_code::adapter::{Adapter, ClaudeCodeAdapter};
use soth_code::event::{ActionType, CodeEvent};

const FIXTURE_ROOT: &str = "tests/fixtures/claude_code";

/// All hook-type directories under the fixture root.
fn hook_type_dirs() -> Vec<String> {
    let root = Path::new(FIXTURE_ROOT);
    fs::read_dir(root)
        .unwrap_or_else(|_| panic!("fixture root {FIXTURE_ROOT} must exist"))
        .filter_map(|e| {
            let e = e.ok()?;
            if !e.file_type().ok()?.is_dir() {
                return None;
            }
            Some(e.file_name().to_string_lossy().into_owned())
        })
        .collect()
}

fn fixtures_in(hook_type: &str) -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(FIXTURE_ROOT).join(hook_type);
    fs::read_dir(&dir)
        .unwrap_or_else(|_| panic!("fixture dir {} must exist", dir.display()))
        .filter_map(|e| {
            let e = e.ok()?;
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                return None;
            }
            let bytes = fs::read(&path).ok()?;
            Some((path.file_name()?.to_string_lossy().into_owned(), bytes))
        })
        .collect()
}

/// The fixture corpus exists and has at least the documented minimum
/// (≥20 across hook types, per docs/gryph/implementation.md D-2 and
/// Phase 1 gate).
#[test]
fn corpus_meets_minimum_size() {
    let mut total = 0;
    for hook_type in hook_type_dirs() {
        total += fixtures_in(&hook_type).len();
    }
    assert!(
        total >= 20,
        "fixture corpus has {total} payloads; Phase 1 gate requires ≥20"
    );
}

/// Every fixture parses without error. CI fails as soon as upstream
/// Claude Code changes a payload shape we haven't accounted for.
#[test]
fn every_fixture_parses() {
    let adapter = ClaudeCodeAdapter::new();
    let mut count = 0;
    for hook_type in hook_type_dirs() {
        for (file_name, bytes) in fixtures_in(&hook_type) {
            let result = adapter.parse_event(&hook_type, &bytes);
            assert!(
                result.is_ok(),
                "fixture {hook_type}/{file_name} failed to parse: {:?}",
                result.err()
            );
            count += 1;
        }
    }
    assert!(
        count > 0,
        "no fixtures discovered — guard against empty corpus"
    );
}

/// Per-fixture spot checks. New checks land here when an adapter
/// mapping or field-extraction lesson is worth pinning.
#[test]
fn pre_tool_use_read_maps_to_file_read() {
    let ev = parse("pre_tool_use", "01_read_etc_hosts.json");
    assert_eq!(ev.action_type, ActionType::FileRead);
    assert_eq!(ev.payload["tool_input"]["file_path"], "/etc/hosts");
}

#[test]
fn pre_tool_use_bash_maps_to_command_exec() {
    let ev = parse("pre_tool_use", "05_bash_simple.json");
    assert_eq!(ev.action_type, ActionType::CommandExec);
}

#[test]
fn pre_tool_use_bash_destructive_does_not_panic() {
    // Phase-2 will hand this to the policy evaluator and expect a
    // Block. For now, the adapter just parses cleanly.
    let ev = parse("pre_tool_use", "06_bash_destructive.json");
    assert_eq!(ev.action_type, ActionType::CommandExec);
    assert_eq!(
        ev.payload["tool_input"]["command"].as_str().unwrap(),
        "rm -rf /"
    );
}

#[test]
fn pre_tool_use_task_maps_to_subagent_start() {
    let ev = parse("pre_tool_use", "07_task_subagent.json");
    assert_eq!(ev.action_type, ActionType::SubagentStart);
}

#[test]
fn pre_tool_use_mcp_collapses_to_tool_use() {
    let ev = parse("pre_tool_use", "08_mcp_tool_call.json");
    assert_eq!(ev.action_type, ActionType::ToolUse);
    assert!(ev
        .payload
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .starts_with("mcp__"));
}

#[test]
fn subagent_attribution_extracted_from_inline_fields() {
    // gryph PR #38: detected by *presence* of agent_id + agent_type,
    // not by hook event name.
    let ev = parse("pre_tool_use", "09_subagent_invocation.json");
    let sub = ev.subagent.expect("subagent context populated");
    assert_eq!(sub.subagent_id, "ag-uuid-9000");
    assert_eq!(sub.subagent_type, "general-purpose");
    assert_eq!(
        sub.parent_session_id.as_deref(),
        Some("claude-session-09-parent")
    );
}

#[test]
fn post_tool_use_array_response_does_not_crash() {
    // gryph PR #32: real MCP tool responses are sometimes arrays.
    let ev = parse("post_tool_use", "04_mcp_array_response.json");
    assert!(ev.payload["tool_response"].is_array());
}

#[test]
fn post_tool_use_null_response_does_not_crash() {
    // gryph PR #32: also null.
    let ev = parse("post_tool_use", "05_mcp_null_response.json");
    assert!(ev.payload["tool_response"].is_null());
}

#[test]
fn user_prompt_submit_carries_prompt_text() {
    let ev = parse("user_prompt_submit", "01_simple_prompt.json");
    assert_eq!(ev.action_type, ActionType::UserPromptSubmit);
    assert!(ev.payload["prompt"]
        .as_str()
        .unwrap_or("")
        .contains("unit test"));
}

#[test]
fn session_start_action_type_maps_correctly() {
    let ev = parse("session_start", "01_basic.json");
    assert_eq!(ev.action_type, ActionType::SessionStart);
}

#[test]
fn correlation_key_is_populated_for_every_fixture_with_session_id() {
    let adapter = ClaudeCodeAdapter::new();
    for hook_type in hook_type_dirs() {
        for (file_name, bytes) in fixtures_in(&hook_type) {
            let ev = adapter.parse_event(&hook_type, &bytes).unwrap();
            // session_start, session_end, etc., still get a
            // correlation_key (sha256 of agent + session id) — even
            // empty session id produces a deterministic key.
            assert!(
                !ev.correlation_key.is_empty(),
                "fixture {hook_type}/{file_name} has empty correlation_key"
            );
            assert_eq!(
                ev.correlation_key.len(),
                64,
                "fixture {hook_type}/{file_name}: correlation_key not 64-char hex"
            );
        }
    }
}

fn parse(hook_type: &str, file_name: &str) -> CodeEvent {
    let path = Path::new(FIXTURE_ROOT).join(hook_type).join(file_name);
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    ClaudeCodeAdapter::new()
        .parse_event(hook_type, &bytes)
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}
