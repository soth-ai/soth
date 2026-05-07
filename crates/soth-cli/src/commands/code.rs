//! `soth code` command family — synchronous policy gate at the AI
//! coding agent's hook boundary. See `docs/gryph/plan.md` §10 for the
//! architecture; this module is the CLI surface that the agent's
//! `spawnSync` invocation ultimately hits.
//!
//! Group 3 ships `hook` (smoke E2E) + `status`. Group 4 (D-5/D-6)
//! lands `install` / `uninstall` / `doctor` / `tail`.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use soth_code::paths::CodePaths;
use soth_code::CodeExtension;

#[derive(Debug, Clone, Subcommand)]
pub enum CodeCommands {
    /// Hook entry point invoked by the agent's spawnSync. Reads the
    /// hook payload from stdin, runs the soth-code pipeline (parse →
    /// redact → classify → policy → enqueue), and writes the agent's
    /// native blocking-shape response back. Exit code: 0 = allow,
    /// 2 = block (per-agent contract). Not intended to be run
    /// interactively except for smoke testing.
    Hook(HookArgs),

    /// Print extension status: installed/enabled, queue depth, adapter
    /// health.
    Status(StatusArgs),
}

#[derive(Debug, Clone, Args)]
pub struct HookArgs {
    /// Adapter name (e.g. "claude_code").
    #[arg(long)]
    pub agent: String,

    /// Native hook type (e.g. "pre_tool_use", "user_prompt_submit").
    #[arg(long = "type", value_name = "HOOK_TYPE")]
    pub hook_type: String,

    /// Override the data-root directory. Tests use a tempdir; default
    /// resolves under ~/.soth/ via [`CodePaths::from_default_root`].
    #[arg(long, hide = true)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct StatusArgs {
    /// Output format. `text` (default) is the human-readable summary;
    /// `json` for scripts.
    #[arg(long, default_value = "text")]
    pub format: StatusFormat,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum StatusFormat {
    Text,
    Json,
}

pub async fn run(action: CodeCommands, _global_config: Option<PathBuf>) -> Result<()> {
    match action {
        CodeCommands::Hook(args) => run_hook(args),
        CodeCommands::Status(args) => run_status(args),
    }
}

/// Hook subprocess. Calls `std::process::exit` directly with the
/// adapter-chosen exit code so the agent observes the precise value
/// (0 = allow, 2 = block under Claude Code / Pi Agent contracts, etc.).
/// Never returns on the hot path; `Ok(())` is unreachable in practice.
fn run_hook(args: HookArgs) -> Result<()> {
    let paths = match args.root {
        Some(root) => CodePaths::from_root(&root),
        None => CodePaths::from_default_root(),
    };
    let stdin = soth_code::read_stdin_to_end().context("reading hook stdin payload")?;
    match soth_code::run_hook(&args.agent, &args.hook_type, &stdin, &paths) {
        Ok(outcome) => {
            soth_code::write_outcome(&outcome).ok();
            // The adapter's `AdapterResponse` is the contract — exit
            // with whatever code it chose. Group 3 stub always Allow → 0.
            // Group 4+ adapters return per-agent block codes.
            let raw = match &outcome.decision {
                soth_code::HookDecision::Allow => 0,
                soth_code::HookDecision::Block { .. } => 2, // gryph PR #22 default
                soth_code::HookDecision::Error(_) => 1,
            };
            std::process::exit(raw);
        }
        Err(e) => {
            // Parse / I/O / unknown-agent errors. Exit 1 (not 2) — we
            // never want a tooling error to *block* the agent action
            // unless on_policy_error: block is configured (Group 5
            // wires that path in).
            let mut stderr = std::io::stderr().lock();
            writeln!(
                stderr,
                "{{\"error\":\"{}\",\"agent\":\"{}\",\"hook_type\":\"{}\"}}",
                e,
                args.agent,
                args.hook_type
            )
            .ok();
            std::process::exit(1);
        }
    }
}

fn run_status(args: StatusArgs) -> Result<()> {
    use soth_extensions::{Extension, ExtensionRuntimeContext};

    let ext = CodeExtension::with_defaults();
    let ctx = ExtensionRuntimeContext::from_defaults();
    let st = ext.status(&ctx);
    match args.format {
        StatusFormat::Text => {
            println!("name: {}", st.name);
            println!("version: {}", st.version);
            println!("archetype: {:?}", st.archetype);
            println!("installed: {}", st.installed);
            println!("enabled: {}", st.enabled);
            println!("healthy: {}", st.healthy);
        }
        StatusFormat::Json => {
            // Minimal JSON shape — full schema lands when `ExtensionStatus`
            // gains `Serialize`. For Group 3 a hand-built object is
            // enough to confirm the smoke E2E.
            println!(
                "{{\"name\":\"{}\",\"version\":\"{}\",\"installed\":{},\"enabled\":{},\"healthy\":{}}}",
                st.name, st.version, st.installed, st.enabled, st.healthy
            );
        }
    }
    Ok(())
}
