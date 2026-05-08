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
use soth_code::{CodeCaptureMode as SothCodeCaptureMode, HookCaptureConfig};

use crate::cli_config::{self, CodeCaptureMode as CliCodeCaptureMode};
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

    /// Manage the CEL policy bundle that the hook handler
    /// evaluates against on every action. Subcommands:
    /// `install-default` (bake the shipped starter pack),
    /// `apply <path>` (verify + copy a custom signed bundle),
    /// `show` (print the active bundle's rules).
    #[command(subcommand)]
    Policy(PolicyCommands),

    /// Print the per-agent historian usage-coverage audit table.
    /// This verdict gates the proxy's A→C bypass trajectory
    /// (plan §10.11): the proxy refuses to bypass an agent
    /// until its historian playbook is audited to extract
    /// authoritative `usage` blocks per assistant turn.
    AuditStatus,
}

#[derive(Debug, Clone, Subcommand)]
pub enum PolicyCommands {
    /// Sign + write the bundled starter rule pack to
    /// `~/.soth/code-policy.bundle`. Uses a built-in dev signing
    /// key — clearly marked in the bundle metadata. Production
    /// deployments should replace this with a cloud-signed
    /// bundle via `soth code policy apply`.
    InstallDefault(PolicyInstallDefaultArgs),

    /// Copy an externally-signed bundle to
    /// `~/.soth/code-policy.bundle`. Verifies the signature
    /// before writing — a malformed or unsigned file is
    /// rejected.
    Apply(PolicyApplyArgs),

    /// Print the rules in the active bundle (system + org).
    Show(PolicyShowArgs),
}

#[derive(Debug, Clone, Args)]
pub struct PolicyInstallDefaultArgs {
    /// Where to write the signed bundle. Default
    /// `~/.soth/code-policy.bundle`, which is the path the hook
    /// handler reads.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Override the org_id stamped into the bundle metadata.
    /// Default `local-dev` — the built-in dev key indicates
    /// this is a non-prod bundle.
    #[arg(long, default_value = "local-dev")]
    pub org_id: String,
}

#[derive(Debug, Clone, Args)]
pub struct PolicyApplyArgs {
    /// Path to the signed bundle JSON file to install.
    pub bundle: PathBuf,

    /// Where to copy the verified bundle. Default
    /// `~/.soth/code-policy.bundle`.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct PolicyShowArgs {
    /// Optional override for the bundle path. Default
    /// `~/.soth/code-policy.bundle`.
    #[arg(long)]
    pub bundle: Option<PathBuf>,
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
        CodeCommands::Policy(cmd) => match cmd {
            PolicyCommands::InstallDefault(args) => run_policy_install_default(args),
            PolicyCommands::Apply(args) => run_policy_apply(args),
            PolicyCommands::Show(args) => run_policy_show(args),
        },
        CodeCommands::AuditStatus => run_audit_status(_global_config),
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
    // Resolve capture config from soth.yaml. Default Metadata when no
    // config or no `code.capture` block — raw payload stays in the
    // hook subprocess's memory and never reaches the queue. Operators
    // opting into Audit or Full have explicitly set the YAML knob.
    let capture = resolve_capture_config();
    match soth_code::run_hook(&args.agent, &args.hook_type, &stdin, &paths, &capture) {
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

/// Load the `code.capture` block from `~/.soth/soth.yaml` and
/// translate to the soth-code-side type. Returns the default
/// (`Metadata`, 64 KiB cap) if no config is present or parseable —
/// safe-default semantics keep raw payload off the wire when the
/// operator hasn't explicitly opted in.
fn resolve_capture_config() -> HookCaptureConfig {
    let cfg = cli_config::load_effective_config(None, None).unwrap_or_default();
    let cap = &cfg.extensions.code.capture;
    HookCaptureConfig {
        mode: match cap.mode {
            CliCodeCaptureMode::Metadata => SothCodeCaptureMode::Metadata,
            CliCodeCaptureMode::Audit => SothCodeCaptureMode::Audit,
            CliCodeCaptureMode::Full => SothCodeCaptureMode::Full,
        },
        max_payload_bytes: cap.max_payload_bytes,
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

// ── policy subcommand ─────────────────────────────────────────────

/// Built-in dev signing key for `soth code policy install-default`.
/// Deterministic — every host that runs `install-default` produces a
/// bundle signed by the same key, so the runtime can verify locally
/// without a key-distribution dance. **NOT** suitable for prod
/// deployments: production bundles should be signed by the cloud's
/// rotated key and pushed via `soth code policy apply` (or the
/// future automatic bundle-delivery channel).
const DEV_SIGNING_SEED: [u8; 32] = [
    0x73, 0x6f, 0x74, 0x68, 0x2d, 0x63, 0x6f, 0x64, 0x65, 0x2d, 0x64, 0x65, 0x76, 0x2d, 0x70, 0x6f,
    0x6c, 0x69, 0x63, 0x79, 0x2d, 0x76, 0x31, 0x2d, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x21, 0x21, 0x21,
];

/// JSON source of the starter rule pack. Bundled at compile time —
/// embedded into the binary so `soth code policy install-default`
/// works on a fresh host with no extra files.
const DEFAULT_RULES_JSON: &str =
    include_str!("../../../../extensions/code/policies/code-default-rules.json");

#[derive(serde::Deserialize)]
struct DefaultRulesSource {
    #[serde(default)]
    system_rules: Vec<soth_policy::RuleDefinition>,
    #[serde(default)]
    org_rules: Vec<soth_policy::RuleDefinition>,
    #[serde(default)]
    org_patterns: soth_policy::OrgPatterns,
    #[serde(default)]
    budget_limits: soth_policy::BudgetLimits,
}

fn run_policy_install_default(args: PolicyInstallDefaultArgs) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::SystemTime;

    let source: DefaultRulesSource = serde_json::from_str(DEFAULT_RULES_JSON)
        .context("parse embedded code-default-rules.json")?;

    let signed_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let payload = soth_policy::PolicyBundlePayload {
        metadata: soth_policy::PolicyBundleMetadata {
            bundle_version: format!("soth-code-default-{signed_at}"),
            schema_version: "1".to_string(),
            org_id: args.org_id,
            signed_at,
        },
        system_rules: source.system_rules,
        org_rules: source.org_rules,
        org_patterns: source.org_patterns,
        budget_limits: source.budget_limits,
    };

    let key = SigningKey::from_bytes(&DEV_SIGNING_SEED);
    let payload_bytes =
        serde_json::to_vec(&payload).context("serialize default policy payload for signing")?;
    let signature = key.sign(&payload_bytes);
    let envelope = soth_policy::SignedPolicyBundle {
        payload,
        signature: B64.encode(signature.to_bytes()),
        public_key: B64.encode(key.verifying_key().to_bytes()),
    };

    let out_path = match args.out {
        Some(p) => p,
        None => default_bundle_path()
            .context("could not determine default bundle path — pass --out")?,
    };
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let envelope_bytes =
        serde_json::to_vec_pretty(&envelope).context("serialize signed policy envelope")?;
    fs::write(&out_path, &envelope_bytes)
        .with_context(|| format!("write policy bundle to {}", out_path.display()))?;

    let total_rules = envelope.payload.system_rules.len() + envelope.payload.org_rules.len();
    println!(
        "wrote signed dev bundle: {} ({} rule{}, dev-key signed)",
        out_path.display(),
        total_rules,
        if total_rules == 1 { "" } else { "s" }
    );
    println!(
        "the hook handler reads from this path automatically; \
         override with SOTH_CODE_POLICY_BUNDLE if needed."
    );
    Ok(())
}

fn run_policy_apply(args: PolicyApplyArgs) -> Result<()> {
    let bytes = fs::read(&args.bundle)
        .with_context(|| format!("read policy bundle: {}", args.bundle.display()))?;
    // Run the same verifier the hook handler uses — fails closed
    // if the signature doesn't validate.
    soth_policy::load_bundle_from_bytes(&bytes)
        .with_context(|| format!("verify policy bundle at {}", args.bundle.display()))?;

    let out_path = match args.out {
        Some(p) => p,
        None => default_bundle_path()
            .context("could not determine default bundle path — pass --out")?,
    };
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    fs::write(&out_path, &bytes)
        .with_context(|| format!("write policy bundle to {}", out_path.display()))?;
    println!(
        "applied verified policy bundle from {} → {}",
        args.bundle.display(),
        out_path.display()
    );
    Ok(())
}

fn run_policy_show(args: PolicyShowArgs) -> Result<()> {
    let path = match args.bundle {
        Some(p) => p,
        None => default_bundle_path().context("could not determine default bundle path")?,
    };
    if !path.exists() {
        println!("no bundle at {} — run `soth code policy install-default` first", path.display());
        return Ok(());
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let bundle = soth_policy::load_bundle_from_bytes(&bytes)
        .with_context(|| format!("verify {}", path.display()))?;
    println!("bundle: {}", path.display());
    println!("  bundle_version: {}", bundle.metadata.bundle_version);
    println!("  schema_version: {}", bundle.metadata.schema_version);
    println!("  org_id:         {}", bundle.metadata.org_id);
    println!("  signed_at:      {}", bundle.metadata.signed_at);
    println!(
        "  rules:          {} system + {} org",
        bundle.system_rules.rules.len(),
        bundle.org_rules.rules.len()
    );
    for r in bundle.system_rules.rules.iter().chain(bundle.org_rules.rules.iter()) {
        println!("    [{:?}] {} — {}", r.rule_kind, r.rule_id, r.cel_expr);
    }
    Ok(())
}

fn default_bundle_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SOTH_CODE_POLICY_BUNDLE") {
        return Some(PathBuf::from(p));
    }
    dirs::home_dir().map(|h| h.join(".soth").join("code-policy.bundle"))
}

// ── audit-status subcommand ─────────────────────────────────────────

fn run_audit_status(config_path: Option<PathBuf>) -> Result<()> {
    // Read the effective config from disk so the table reflects
    // whatever the operator has flipped — including future
    // hand-edits like `historian.adapters.cursor.usage_coverage_audited
    // = true` after running the per-agent audit. Default-only
    // path lands when no config exists.
    let cfg = cli_config::load_effective_config(config_path.as_ref(), None).unwrap_or_default();
    let h = &cfg.extensions.historian;
    let proxy = &cfg.forward_proxy;

    println!("Historian usage-coverage audit (plan §9 / §10.11)");
    println!();
    println!("  {:<14} {:<8} audited_at                     caveats", "agent", "audited");
    println!("  {}", "-".repeat(80));

    // Stable, plan-defined ordering: claude_code first
    // (confirmed), then the six pending agents.
    let canonical_order = [
        "claude_code",
        "cursor",
        "openai_codex",
        "gemini_cli",
        "pi_agent",
        "windsurf",
        "opencode",
    ];
    let mut seen = std::collections::HashSet::new();
    for agent in canonical_order {
        seen.insert(agent.to_string());
        let entry = h.adapters.get(agent);
        print_audit_row(agent, entry);
    }
    // Catch any extra agents the operator added by hand.
    for (agent, entry) in &h.adapters {
        if !seen.contains(agent) {
            print_audit_row(agent, Some(entry));
        }
    }

    // Show the bypass-eligibility outcome the runtime would
    // actually compute, so operators see the link between
    // their `proxy.bypass_agents` config knob and the audit
    // verdicts.
    println!();
    if proxy.bypass_agents.is_empty() {
        println!("forward_proxy.bypass_agents: empty — no agents in bypass mode.");
    } else {
        let (allowed, dropped) = proxy.audited_bypass_agents(h);
        println!("forward_proxy.bypass_agents → audit-eligibility filter:");
        for entry in &allowed {
            println!("  ✓ {entry} — passes audit, will bypass at proxy");
        }
        for entry in &dropped {
            println!("  ✗ {entry} — DROPPED, agent not audited");
        }
    }

    Ok(())
}

fn print_audit_row(
    agent: &str,
    entry: Option<&cli_config::HistorianAdapterAudit>,
) {
    let (audited, audited_at, caveats) = match entry {
        Some(a) => (
            if a.usage_coverage_audited { "yes" } else { "no" },
            a.audited_at.as_deref().unwrap_or("—"),
            a.caveats.as_deref().unwrap_or(""),
        ),
        None => ("no", "—", ""),
    };
    println!(
        "  {:<14} {:<8} {:<30} {}",
        agent, audited, audited_at, caveats
    );
}
