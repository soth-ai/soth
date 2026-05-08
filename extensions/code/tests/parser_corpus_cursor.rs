//! Cursor adapter fixture-corpus integration test.
//!
//! Mirrors `parser_corpus.rs` (Claude Code) but for the Cursor adapter.
//! Walks `tests/fixtures/cursor/<hook_type>/*.json` and runs every
//! file through `CursorAdapter::parse_event`. Fixtures are ported from
//! gryph's `agent/cursor/testdata/` — gryph upstream is the closest
//! thing to a captured-payload corpus we have today; replace with
//! locally-captured payloads as we observe them in production.

use std::fs;
use std::path::Path;

use soth_code::adapter::{Adapter, CursorAdapter};
use soth_code::event::{ActionType, CodeEvent};

const FIXTURE_ROOT: &str = "tests/fixtures/cursor";

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

#[test]
fn corpus_meets_minimum_size() {
    let mut total = 0;
    for hook_type in hook_type_dirs() {
        total += fixtures_in(&hook_type).len();
    }
    assert!(
        total >= 10,
        "cursor fixture corpus has {total} payloads; per-agent minimum is 10"
    );
}

#[test]
fn every_fixture_parses() {
    let adapter = CursorAdapter::new();
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
    assert!(count > 0);
}

#[test]
fn before_shell_execution_maps_to_command_exec() {
    let ev = parse("before_shell_execution", "01_basic.json");
    assert_eq!(ev.action_type, ActionType::CommandExec);
    assert!(ev.payload["command"].is_string());
}

#[test]
fn before_read_file_maps_to_file_read() {
    let ev = parse("before_read_file", "01_basic.json");
    assert_eq!(ev.action_type, ActionType::FileRead);
    assert!(ev.payload["file_path"].is_string());
}

#[test]
fn after_file_edit_maps_to_file_write() {
    let ev = parse("after_file_edit", "01_basic.json");
    assert_eq!(ev.action_type, ActionType::FileWrite);
}

#[test]
fn pre_tool_use_shell_maps_to_command_exec() {
    let ev = parse("pre_tool_use", "01_shell.json");
    assert_eq!(ev.action_type, ActionType::CommandExec);
}

#[test]
fn before_submit_prompt_maps_to_user_prompt_submit() {
    let ev = parse("before_submit_prompt", "01_basic.json");
    assert_eq!(ev.action_type, ActionType::UserPromptSubmit);
}

#[test]
fn correlation_key_populated_for_every_fixture() {
    let adapter = CursorAdapter::new();
    for hook_type in hook_type_dirs() {
        for (file_name, bytes) in fixtures_in(&hook_type) {
            let ev = adapter.parse_event(&hook_type, &bytes).unwrap();
            assert_eq!(
                ev.correlation_key.len(),
                64,
                "fixture {hook_type}/{file_name}: correlation_key not 64-char hex"
            );
        }
    }
}

#[test]
fn conversation_id_extracted_as_session() {
    // Cursor uses conversation_id as its session identifier; the
    // adapter must populate agent_native_session_id from it.
    let ev = parse("pre_tool_use", "01_shell.json");
    assert!(!ev.agent_native_session_id.is_empty());
    assert_eq!(ev.payload["conversation_id"], ev.agent_native_session_id);
}

fn parse(hook_type: &str, file_name: &str) -> CodeEvent {
    let path = Path::new(FIXTURE_ROOT).join(hook_type).join(file_name);
    let bytes = fs::read(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    CursorAdapter::new()
        .parse_event(hook_type, &bytes)
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}
