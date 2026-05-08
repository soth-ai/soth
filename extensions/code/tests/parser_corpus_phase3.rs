//! Phase 3 multi-agent fixture corpus.
//!
//! For each Phase-3 adapter (Pi Agent, Gemini CLI, Codex, Windsurf,
//! OpenCode), walk the agent's fixture directory and assert every
//! payload parses cleanly. The directory layout is shaped by gryph's
//! upstream filename conventions — fixtures are named after what
//! they represent (e.g. `pre_tool_use_bash`, `tool_call_read`)
//! rather than the canonical hook_type the adapter expects, so this
//! test treats the directory name as the hook_type hint and relies
//! on each adapter's permissive fallback (unknown hook_type →
//! `ActionType::Notification`) rather than asserting specific
//! action_type mappings here. The per-hook semantic mappings are
//! pinned in each adapter's own unit tests.
//!
//! Failure here means: parser crashes on a real upstream payload
//! shape — the gryph PR #29 / #32 / #38 class of regression. CI red
//! light is the right response.

use std::fs;
use std::path::Path;

use soth_code::adapter::{
    Adapter, CodexAdapter, GeminiCliAdapter, OpenCodeAdapter, PiAgentAdapter, WindsurfAdapter,
};

const FIXTURE_ROOT: &str = "tests/fixtures";

struct AgentCase {
    name: &'static str,
    dir: &'static str,
    adapter: Box<dyn Adapter>,
}

fn agents() -> Vec<AgentCase> {
    vec![
        AgentCase {
            name: "pi_agent",
            dir: "pi_agent",
            adapter: Box::new(PiAgentAdapter::new()),
        },
        AgentCase {
            name: "gemini_cli",
            dir: "gemini_cli",
            adapter: Box::new(GeminiCliAdapter::new()),
        },
        AgentCase {
            name: "codex",
            dir: "codex",
            adapter: Box::new(CodexAdapter::new()),
        },
        AgentCase {
            name: "windsurf",
            dir: "windsurf",
            adapter: Box::new(WindsurfAdapter::new()),
        },
        AgentCase {
            name: "opencode",
            dir: "opencode",
            adapter: Box::new(OpenCodeAdapter::new()),
        },
    ]
}

fn hook_type_dirs(agent_dir: &str) -> Vec<String> {
    let root = Path::new(FIXTURE_ROOT).join(agent_dir);
    fs::read_dir(&root)
        .unwrap_or_else(|_| panic!("fixture root {} must exist", root.display()))
        .filter_map(|e| {
            let e = e.ok()?;
            if !e.file_type().ok()?.is_dir() {
                return None;
            }
            Some(e.file_name().to_string_lossy().into_owned())
        })
        .collect()
}

fn fixtures_in(agent_dir: &str, hook_type: &str) -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(FIXTURE_ROOT).join(agent_dir).join(hook_type);
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
fn every_phase3_agent_has_fixtures() {
    for case in agents() {
        let dirs = hook_type_dirs(case.dir);
        assert!(
            !dirs.is_empty(),
            "agent {} has no fixture directories — port from gryph testdata",
            case.name
        );
    }
}

#[test]
fn every_fixture_parses_for_every_agent() {
    let mut total = 0;
    for case in agents() {
        for hook_type in hook_type_dirs(case.dir) {
            for (file_name, bytes) in fixtures_in(case.dir, &hook_type) {
                let result = case.adapter.parse_event(&hook_type, &bytes);
                assert!(
                    result.is_ok(),
                    "agent {} fixture {hook_type}/{file_name} failed: {:?}",
                    case.name,
                    result.err()
                );
                let ev = result.unwrap();
                // Adapter name self-identification — a regression
                // here means an adapter's `name()` drifted from the
                // dispatch table in `for_agent()`.
                assert_eq!(
                    ev.agent, case.name,
                    "agent {} parsed event reports agent={}",
                    case.name, ev.agent
                );
                // correlation_key is populated for every event
                // (sha256 hex of agent + native session id, even if
                // session id is empty).
                assert_eq!(
                    ev.correlation_key.len(),
                    64,
                    "agent {} fixture {hook_type}/{file_name}: correlation_key not 64-char hex",
                    case.name
                );
                total += 1;
            }
        }
    }
    assert!(total >= 30, "Phase-3 corpus expected ≥30 fixtures across all agents, got {total}");
}

#[test]
fn each_agent_meets_minimum_fixture_count() {
    // Per docs/gryph/implementation.md D-2: each new adapter ships
    // ≥10 captured payloads (Phase 1 gate). Phase 3 keeps this bar.
    for case in agents() {
        let count: usize = hook_type_dirs(case.dir)
            .iter()
            .map(|h| fixtures_in(case.dir, h).len())
            .sum();
        let minimum = 10;
        assert!(
            count >= minimum,
            "agent {} has {count} fixtures; minimum is {minimum}. Capture more from real \
             {} sessions or extend gryph testdata.",
            case.name,
            case.name
        );
    }
}
