//! `soth code` command family — synchronous policy gate at the AI
//! coding agent's hook boundary. See `docs/gryph/plan.md` §10 for the
//! architecture; this module is the CLI surface that the agent's
//! `spawnSync` invocation ultimately hits.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use soth_code::install::{
    default_claude_settings_path, default_codex_hooks_path, default_cursor_hooks_path,
    default_gemini_settings_path, default_opencode_plugin_path, default_pi_agent_plugin_path,
    default_windsurf_hooks_path, install_claude_code, install_codex, install_cursor,
    install_gemini_cli, install_opencode, install_pi_agent, install_windsurf,
    uninstall_claude_code, uninstall_codex, uninstall_cursor, uninstall_gemini_cli,
    uninstall_opencode, uninstall_pi_agent, uninstall_windsurf,
};
use soth_code::paths::CodePaths;
use soth_code::CodeExtension;

#[derive(Debug, Clone, Subcommand)]
pub enum CodeCommands {
    /// Hook entry point invoked by the agent's spawnSync. Reads the
    /// hook payload from stdin, runs the soth-code pipeline (parse →
    /// detect → policy → enqueue), and writes the agent's native
    /// blocking-shape response back. Exit code: 0 = allow,
    /// 2 = block (per-agent contract). Not intended to be run
    /// interactively except for smoke testing.
    Hook(HookArgs),

    /// Install soth-code hooks into an agent's native config.
    Install(InstallArgs),

    /// Remove soth-managed hook entries from an agent's config.
    /// User-authored entries are preserved.
    Uninstall(UninstallArgs),

    /// Print extension status: installed/enabled, queue depth.
    Status(StatusArgs),

    /// Diagnostics: resolved paths, install state, queue size,
    /// adapter availability. Always uses the same path resolver as
    /// the runtime (gryph PR #37).
    Doctor(DoctorArgs),

    /// Print recent action events from the queue file. Defaults to
    /// the last 10 lines; pass `-n -1` for the whole queue.
    Tail(TailArgs),
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

#[derive(Debug, Clone, Args)]
pub struct InstallArgs {
    /// Target agent. v0 supports `claude_code`; more in subsequent groups.
    #[arg(long, default_value = "claude_code")]
    pub target: String,

    /// Override the agent's settings file path (e.g. for tests or
    /// non-default installs). Default resolves per-target —
    /// `~/.claude/settings.json` for `claude_code`.
    #[arg(long)]
    pub settings_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct UninstallArgs {
    #[arg(long, default_value = "claude_code")]
    pub target: String,

    #[arg(long)]
    pub settings_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct DoctorArgs {
    /// Override the data-root directory (mostly for tests).
    #[arg(long, hide = true)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct TailArgs {
    /// Override the data-root directory.
    #[arg(long, hide = true)]
    pub root: Option<PathBuf>,

    /// Number of recent events to print. `-1` prints everything.
    #[arg(long, short = 'n', default_value_t = 10)]
    pub history: i32,

    /// Output format.
    #[arg(long, default_value = "compact")]
    pub format: TailFormat,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum TailFormat {
    Compact,
    Json,
}

pub async fn run(action: CodeCommands, _global_config: Option<PathBuf>) -> Result<()> {
    match action {
        CodeCommands::Hook(args) => run_hook(args),
        CodeCommands::Install(args) => run_install(args),
        CodeCommands::Uninstall(args) => run_uninstall(args),
        CodeCommands::Status(args) => run_status(args),
        CodeCommands::Doctor(args) => run_doctor(args),
        CodeCommands::Tail(args) => run_tail(args),
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

fn run_install(args: InstallArgs) -> Result<()> {
    let report = match args.target.as_str() {
        "claude_code" => {
            let path = resolve_install_path(&args, default_claude_settings_path, "~/.claude/settings.json")?;
            install_claude_code(&path, None).context("install claude_code hooks")?
        }
        "cursor" => {
            let path = resolve_install_path(&args, default_cursor_hooks_path, "~/.cursor/hooks.json")?;
            install_cursor(&path, None).context("install cursor hooks")?
        }
        "gemini_cli" | "gemini" => {
            let path = resolve_install_path(&args, default_gemini_settings_path, "~/.gemini/settings.json")?;
            install_gemini_cli(&path, None).context("install gemini_cli hooks")?
        }
        "codex" => {
            let path = resolve_install_path(&args, default_codex_hooks_path, "~/.codex/hooks.json")?;
            install_codex(&path, None).context("install codex hooks")?
        }
        "windsurf" => {
            let path = resolve_install_path(&args, default_windsurf_hooks_path, "~/.codeium/windsurf/hooks.json")?;
            install_windsurf(&path, None).context("install windsurf hooks")?
        }
        "pi_agent" | "piagent" => {
            let path = resolve_install_path(&args, default_pi_agent_plugin_path, "~/.pi/agent/extensions/soth-code.ts")?;
            install_pi_agent(&path, None).context("install pi_agent plugin")?
        }
        "opencode" => {
            let path = resolve_install_path(&args, default_opencode_plugin_path, "~/.config/opencode/plugins/soth-code.mjs")?;
            install_opencode(&path, None).context("install opencode plugin")?
        }
        other => anyhow::bail!(
            "unknown target '{other}': supported targets are `claude_code`, `cursor`, \
             `gemini_cli`, `codex`, `windsurf`, `pi_agent`, `opencode`. \
             OpenClaw is deferred (gryph PR #31 unstable upstream)."
        ),
    };
    println!("settings: {}", report.settings_path.display());
    if let Some(bak) = &report.backup_path {
        println!("backup:   {}", bak.display());
    }
    println!("binary:   {}", report.binary_path.display());
    if !report.hooks_added.is_empty() {
        println!("added:    {}", report.hooks_added.join(", "));
    }
    if !report.hooks_already_present.is_empty() {
        println!("already:  {}", report.hooks_already_present.join(", "));
    }
    Ok(())
}

fn run_uninstall(args: UninstallArgs) -> Result<()> {
    let (path, kind) = match args.target.as_str() {
        "claude_code" => (
            resolve_uninstall_path(&args, default_claude_settings_path, "~/.claude/settings.json")?,
            UninstallKind::ClaudeCode,
        ),
        "cursor" => (
            resolve_uninstall_path(&args, default_cursor_hooks_path, "~/.cursor/hooks.json")?,
            UninstallKind::Cursor,
        ),
        "gemini_cli" | "gemini" => (
            resolve_uninstall_path(&args, default_gemini_settings_path, "~/.gemini/settings.json")?,
            UninstallKind::Gemini,
        ),
        "codex" => (
            resolve_uninstall_path(&args, default_codex_hooks_path, "~/.codex/hooks.json")?,
            UninstallKind::Codex,
        ),
        "windsurf" => (
            resolve_uninstall_path(&args, default_windsurf_hooks_path, "~/.codeium/windsurf/hooks.json")?,
            UninstallKind::Windsurf,
        ),
        "pi_agent" | "piagent" => (
            resolve_uninstall_path(&args, default_pi_agent_plugin_path, "~/.pi/agent/extensions/soth-code.ts")?,
            UninstallKind::PiAgent,
        ),
        "opencode" => (
            resolve_uninstall_path(&args, default_opencode_plugin_path, "~/.config/opencode/plugins/soth-code.mjs")?,
            UninstallKind::OpenCode,
        ),
        other => anyhow::bail!(
            "unknown target '{other}': supported targets are `claude_code`, `cursor`, \
             `gemini_cli`, `codex`, `windsurf`, `pi_agent`, `opencode`"
        ),
    };
    if !path.exists() {
        println!("nothing to uninstall — {} does not exist", path.display());
        return Ok(());
    }
    match kind {
        UninstallKind::ClaudeCode => uninstall_claude_code(&path).context("uninstall claude_code hooks")?,
        UninstallKind::Cursor => uninstall_cursor(&path).context("uninstall cursor hooks")?,
        UninstallKind::Gemini => uninstall_gemini_cli(&path).context("uninstall gemini_cli hooks")?,
        UninstallKind::Codex => uninstall_codex(&path).context("uninstall codex hooks")?,
        UninstallKind::Windsurf => uninstall_windsurf(&path).context("uninstall windsurf hooks")?,
        UninstallKind::PiAgent => uninstall_pi_agent(&path).context("uninstall pi_agent plugin")?,
        UninstallKind::OpenCode => uninstall_opencode(&path).context("uninstall opencode plugin")?,
    }
    println!("settings: {}", path.display());
    println!("removed soth-managed hook entries");
    Ok(())
}

enum UninstallKind {
    ClaudeCode,
    Cursor,
    Gemini,
    Codex,
    Windsurf,
    PiAgent,
    OpenCode,
}

fn resolve_install_path(
    args: &InstallArgs,
    default: fn() -> Option<PathBuf>,
    label: &str,
) -> Result<PathBuf> {
    args.settings_path
        .clone()
        .or_else(default)
        .ok_or_else(|| anyhow::anyhow!("could not determine {label} — pass --settings-path"))
}

fn resolve_uninstall_path(
    args: &UninstallArgs,
    default: fn() -> Option<PathBuf>,
    label: &str,
) -> Result<PathBuf> {
    args.settings_path
        .clone()
        .or_else(default)
        .ok_or_else(|| anyhow::anyhow!("could not determine {label} — pass --settings-path"))
}

fn run_doctor(args: DoctorArgs) -> Result<()> {
    // Single-source path resolver — the gryph PR #37 contract.
    // Doctor must not have its own resolution path that disagrees
    // with the runtime hook handler.
    let paths = match args.root {
        Some(root) => CodePaths::from_root(&root),
        None => CodePaths::from_default_root(),
    };
    let exists = |p: &std::path::Path| if p.exists() { "✓" } else { "·" };
    println!("paths:");
    println!("  db        {} {}", exists(&paths.db), paths.db.display());
    println!("  queue     {} {}", exists(&paths.queue), paths.queue.display());
    println!("  config    {} {}", exists(&paths.config), paths.config.display());
    println!(
        "  plugin    {} {}",
        exists(&paths.plugin_dir),
        paths.plugin_dir.display()
    );
    println!("  blobs     {} {}", exists(&paths.blob_dir), paths.blob_dir.display());

    if let Some(claude_settings) = default_claude_settings_path() {
        let installed = match fs::read_to_string(&claude_settings) {
            Ok(content) => content.contains("\"_soth_managed\""),
            Err(_) => false,
        };
        println!("agents:");
        println!(
            "  claude_code {} settings={} installed={}",
            exists(&claude_settings),
            claude_settings.display(),
            installed
        );
    }

    let queue_lines = match fs::read_to_string(&paths.queue) {
        Ok(s) => s.lines().count(),
        Err(_) => 0,
    };
    println!("queue:");
    println!("  events    {queue_lines} rows");
    Ok(())
}

fn run_tail(args: TailArgs) -> Result<()> {
    let paths = match args.root {
        Some(root) => CodePaths::from_root(&root),
        None => CodePaths::from_default_root(),
    };
    let content = match fs::read_to_string(&paths.queue) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "queue file does not exist yet ({}); run `soth code hook ...` first",
                paths.queue.display()
            );
            return Ok(());
        }
        Err(e) => return Err(e).context("read queue file"),
    };
    let lines: Vec<&str> = content.lines().collect();
    let take = if args.history < 0 {
        lines.len()
    } else {
        std::cmp::min(args.history as usize, lines.len())
    };
    let start = lines.len().saturating_sub(take);
    for line in &lines[start..] {
        match args.format {
            TailFormat::Json => println!("{line}"),
            TailFormat::Compact => print_compact(line),
        }
    }
    Ok(())
}

fn print_compact(line: &str) {
    // Best-effort compact rendering — falls back to raw line on parse
    // failure so operators always see what's in the queue.
    let parsed: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            println!("{line}");
            return;
        }
    };
    let event = &parsed["event"];
    let meta = &event["context"]["metadata"];
    let decision_kind = parsed["decision"]["kind"]["kind"].as_str().unwrap_or("?");
    let agent = meta["agent"].as_str().unwrap_or("?");
    let action = meta["action_type"].as_str().unwrap_or("?");
    let hook = meta["hook_type"].as_str().unwrap_or("?");
    let session = meta["agent_native_session_id"].as_str().unwrap_or("?");
    let artifacts = event["artifacts"].as_array().map(|a| a.len()).unwrap_or(0);
    let event_id = event["event_id"].as_str().unwrap_or("?");
    println!(
        "[action] {decision_kind:<5} {agent}/{hook} {action} session={session} \
         artifacts={artifacts} event_id={event_id}"
    );
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
