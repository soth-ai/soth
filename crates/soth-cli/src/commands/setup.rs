//! Setup wizard commands.
//!
//! Provides guided setup orchestration for CA generation, proxy setup,
//! MCP client wrapping, and shell environment configuration.

use crate::commands;
use crate::commands::proxy::ProxyCommands;
use crate::style;
use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const DEFAULT_PROXY_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_CA_DIR: &str = "~/.soth/ca";
const WIZARD_BEGIN_MARKER: &str = "# >>> SOTH Setup Wizard >>>";
const WIZARD_END_MARKER: &str = "# <<< SOTH Setup Wizard <<<";

#[derive(Debug, Clone, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    Open,
    Strict,
}

impl std::fmt::Display for FailMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Strict => write!(f, "strict"),
        }
    }
}

/// Setup subcommands.
#[derive(Subcommand, Debug)]
pub enum SetupCommands {
    /// Run installation wizard
    Wizard(WizardArgs),
    /// Diagnose setup health and configuration drift
    Doctor,
    /// Roll back setup-managed changes
    Rollback {
        /// Setup ID to roll back (defaults to latest state)
        setup_id: Option<String>,
        /// Skip confirmation prompts
        #[arg(long)]
        yes: bool,
    },
    /// Uninstall setup-managed integration
    Uninstall {
        /// Skip confirmation prompts
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Args, Debug, Clone)]
pub struct WizardArgs {
    /// Non-interactive mode (requires --yes)
    #[arg(long)]
    pub non_interactive: bool,

    /// Accept defaults and apply changes
    #[arg(long)]
    pub yes: bool,

    /// Preview actions without writing changes
    #[arg(long)]
    pub dry_run: bool,

    /// Shell to configure (bash, zsh, fish)
    #[arg(long)]
    pub shell: Option<String>,

    /// Skip enabling system proxy settings
    #[arg(long)]
    pub skip_proxy_on: bool,

    /// Skip wrapping MCP client configs
    #[arg(long)]
    pub skip_wrap: bool,

    /// Additional MCP config file path to wrap (repeatable)
    #[arg(long = "mcp-config", value_name = "PATH")]
    pub mcp_config: Vec<PathBuf>,

    /// Wrap only --mcp-config paths (skip built-in MCP client discovery)
    #[arg(long)]
    pub only_mcp_config: bool,

    /// Skip writing shell environment block
    #[arg(long)]
    pub skip_shell_env: bool,

    /// Wizard fail mode for wrap/proxy integration
    #[arg(long, value_enum, default_value_t = FailMode::Open)]
    pub fail_mode: FailMode,
}

#[derive(Debug, Clone)]
struct PreflightContext {
    shell: String,
    shell_file: Option<PathBuf>,
    ca_cert_path: PathBuf,
    ca_key_path: PathBuf,
    state_path: PathBuf,
    setups_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SetupState {
    setup_id: String,
    created_at: String,
    wizard_version: u32,
    proxy_url: String,
    shell: String,
    shell_file: Option<String>,
    ca_cert_path: String,
    ca_key_path: String,
    fail_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SetupStatus {
    InProgress,
    Completed,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StepState {
    ca_generated: bool,
    proxy_enabled: bool,
    wrap_applied: bool,
    shell_env_written: bool,
    state_written: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupEntry {
    original_path: String,
    backup_path: Option<String>,
    existed_before: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SetupManifest {
    setup_id: String,
    created_at: String,
    completed_at: Option<String>,
    rolled_back_at: Option<String>,
    status: SetupStatus,
    error: Option<String>,
    fail_mode: String,
    proxy_url: String,
    shell: String,
    shell_file: Option<String>,
    backups: Vec<BackupEntry>,
    steps: StepState,
}

struct SetupTransaction {
    dir: PathBuf,
    backups_dir: PathBuf,
    manifest_path: PathBuf,
    manifest: SetupManifest,
    backup_index: HashSet<String>,
}

impl SetupTransaction {
    fn start(preflight: &PreflightContext, fail_mode: &FailMode) -> Result<Self> {
        let setup_id = Uuid::new_v4().to_string();
        let dir = preflight.setups_dir.join(&setup_id);
        let backups_dir = dir.join("backups");
        fs::create_dir_all(&backups_dir).with_context(|| {
            format!("failed to create transaction dir {}", backups_dir.display())
        })?;

        let manifest = SetupManifest {
            setup_id,
            created_at: Utc::now().to_rfc3339(),
            completed_at: None,
            rolled_back_at: None,
            status: SetupStatus::InProgress,
            error: None,
            fail_mode: fail_mode.to_string(),
            proxy_url: DEFAULT_PROXY_URL.to_string(),
            shell: preflight.shell.clone(),
            shell_file: preflight
                .shell_file
                .as_ref()
                .map(|path| path.display().to_string()),
            backups: Vec::new(),
            steps: StepState::default(),
        };

        let manifest_path = dir.join("manifest.json");
        let tx = Self {
            dir,
            backups_dir,
            manifest_path,
            manifest,
            backup_index: HashSet::new(),
        };
        tx.persist_manifest()?;
        Ok(tx)
    }

    fn setup_id(&self) -> &str {
        &self.manifest.setup_id
    }

    fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    fn set_step_ca_generated(&mut self) -> Result<()> {
        self.manifest.steps.ca_generated = true;
        self.persist_manifest()
    }

    fn set_step_proxy_enabled(&mut self) -> Result<()> {
        self.manifest.steps.proxy_enabled = true;
        self.persist_manifest()
    }

    fn set_step_wrap_applied(&mut self) -> Result<()> {
        self.manifest.steps.wrap_applied = true;
        self.persist_manifest()
    }

    fn set_step_shell_env_written(&mut self) -> Result<()> {
        self.manifest.steps.shell_env_written = true;
        self.persist_manifest()
    }

    fn set_step_state_written(&mut self) -> Result<()> {
        self.manifest.steps.state_written = true;
        self.persist_manifest()
    }

    fn ensure_backup(&mut self, path: &Path) -> Result<()> {
        let original = normalize_path(path);
        let key = original.display().to_string();
        if self.backup_index.contains(&key) {
            return Ok(());
        }

        let existed_before = original.exists();
        let backup_path = if existed_before {
            let idx = self.manifest.backups.len();
            let file_name = original
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("file");
            let target =
                self.backups_dir
                    .join(format!("{:04}_{}", idx, sanitize_file_name(file_name)));
            fs::copy(&original, &target).with_context(|| {
                format!(
                    "failed to backup {} to {}",
                    original.display(),
                    target.display()
                )
            })?;
            Some(target.display().to_string())
        } else {
            None
        };

        self.manifest.backups.push(BackupEntry {
            original_path: key.clone(),
            backup_path,
            existed_before,
        });
        self.backup_index.insert(key);
        self.persist_manifest()
    }

    fn complete(&mut self) -> Result<()> {
        self.manifest.status = SetupStatus::Completed;
        self.manifest.completed_at = Some(Utc::now().to_rfc3339());
        self.manifest.error = None;
        self.persist_manifest()
    }

    fn fail(&mut self, error: &str) -> Result<()> {
        self.manifest.status = SetupStatus::Failed;
        self.manifest.error = Some(error.to_string());
        self.persist_manifest()
    }

    fn persist_manifest(&self) -> Result<()> {
        if let Some(parent) = self.manifest_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let body = serde_json::to_string_pretty(&self.manifest)?;
        fs::write(&self.manifest_path, body)
            .with_context(|| format!("failed to write {}", self.manifest_path.display()))
    }
}

pub async fn run(action: SetupCommands) -> Result<()> {
    match action {
        SetupCommands::Wizard(args) => run_wizard(args).await,
        SetupCommands::Doctor => run_doctor().await,
        SetupCommands::Rollback { setup_id, yes } => run_rollback(setup_id, yes).await,
        SetupCommands::Uninstall { yes } => run_uninstall(yes).await,
    }
}

async fn run_wizard(args: WizardArgs) -> Result<()> {
    if args.non_interactive && !args.yes {
        bail!("--non-interactive requires --yes");
    }
    if args.only_mcp_config && args.mcp_config.is_empty() {
        bail!("--only-mcp-config requires at least one --mcp-config PATH");
    }

    let preflight = run_preflight(args.shell.clone())?;
    let mut tx = if args.dry_run {
        None
    } else {
        Some(SetupTransaction::start(&preflight, &args.fail_mode)?)
    };
    let setup_id = tx
        .as_ref()
        .map(|t| t.setup_id().to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    style::header("SOTH Setup Wizard");
    style::kv("Mode", if args.dry_run { "dry-run" } else { "apply" });
    style::kv("Shell", &preflight.shell);
    style::kv("Proxy", DEFAULT_PROXY_URL);
    style::kv("Fail mode", &args.fail_mode.to_string());
    if !args.mcp_config.is_empty() {
        style::kv("Extra MCP configs", &args.mcp_config.len().to_string());
    }
    if args.only_mcp_config {
        style::kv("MCP mode", "custom-only");
    }
    style::kv("Setup ID", &setup_id);
    println!();

    if !args.yes && !prompt_yes_no("Proceed with setup?", true)? {
        style::warning("Setup cancelled.");
        style::footer();
        return Ok(());
    }

    let outcome = run_wizard_steps(&args, &preflight, &setup_id, &mut tx).await;

    match outcome {
        Ok(()) => {
            if let Some(ref mut transaction) = tx {
                transaction.complete()?;
            }

            println!();
            style::success("Setup wizard completed.");
            if let Some(shell_file) = preflight.shell_file {
                style::kv("Shell file", &shell_file.display().to_string());
            }
            style::kv("State file", &preflight.state_path.display().to_string());
            if let Some(transaction) = tx {
                style::kv(
                    "Manifest",
                    &transaction.manifest_path().display().to_string(),
                );
                style::kv("Transaction", &transaction.dir.display().to_string());
            }
            style::footer();
            Ok(())
        }
        Err(error) => {
            if let Some(ref mut transaction) = tx {
                let _ = transaction.fail(&error.to_string());
                style::warning(&format!(
                    "Setup failed. Use 'soth setup rollback {}' to restore previous files.",
                    transaction.setup_id()
                ));
                style::kv(
                    "Manifest",
                    &transaction.manifest_path().display().to_string(),
                );
            }
            style::footer();
            Err(error)
        }
    }
}

async fn run_wizard_steps(
    args: &WizardArgs,
    preflight: &PreflightContext,
    setup_id: &str,
    tx: &mut Option<SetupTransaction>,
) -> Result<()> {
    style::step(1, 5, "Ensuring CA certificate");
    let ca_exists = preflight.ca_cert_path.exists() && preflight.ca_key_path.exists();
    if ca_exists {
        style::step_done(1, 5, "CA certificate already present");
    } else if args.dry_run {
        style::step_done(1, 5, "Would generate CA certificate");
    } else {
        if let Some(ref mut transaction) = tx {
            transaction.ensure_backup(&preflight.ca_cert_path)?;
            transaction.ensure_backup(&preflight.ca_key_path)?;
        }
        commands::proxy::run(ProxyCommands::SetupCa {
            no_trust: false,
            output: DEFAULT_CA_DIR.to_string(),
        })
        .await?;
        if let Some(ref mut transaction) = tx {
            transaction.set_step_ca_generated()?;
        }
        style::step_done(1, 5, "CA certificate ensured");
    }

    style::step(2, 5, "Configuring proxy");
    if args.skip_proxy_on {
        style::step_done(2, 5, "Skipped proxy enablement");
    } else if args.dry_run {
        style::step_done(2, 5, "Would enable system proxy");
    } else {
        commands::proxy::run(ProxyCommands::On { port: Some(8080) }).await?;
        if let Some(ref mut transaction) = tx {
            transaction.set_step_proxy_enabled()?;
        }
        style::step_done(2, 5, "System proxy enabled");
    }

    style::step(3, 5, "Wrapping MCP client configs");
    if args.skip_wrap {
        style::step_done(3, 5, "Skipped MCP wrap injection");
    } else {
        let custom_config_paths = resolve_mcp_config_paths(&args.mcp_config);
        if args.only_mcp_config {
            if !args.dry_run {
                if let Some(ref mut transaction) = tx {
                    for path in &custom_config_paths {
                        transaction.ensure_backup(path)?;
                    }
                }
            }
            let soth_path = commands::install::find_soth_binary()?;
            for path in &custom_config_paths {
                let status = commands::install::wrap_config_file(path, &soth_path, args.dry_run)?;
                style::kv(&format!("Custom {}", path.display()), &status);
            }
        } else {
            if !args.dry_run {
                let mut config_paths = commands::install::discover_config_paths();
                for path in &custom_config_paths {
                    if !config_paths.contains(path) {
                        config_paths.push(path.clone());
                    }
                }
                if let Some(ref mut transaction) = tx {
                    for path in config_paths {
                        transaction.ensure_backup(&path)?;
                    }
                }
            }
            commands::install::run_install(None, args.dry_run).await?;
            if !custom_config_paths.is_empty() {
                let soth_path = commands::install::find_soth_binary()?;
                for path in &custom_config_paths {
                    let status =
                        commands::install::wrap_config_file(path, &soth_path, args.dry_run)?;
                    style::kv(&format!("Custom {}", path.display()), &status);
                }
            }
        }
        if !args.dry_run {
            if let Some(ref mut transaction) = tx {
                transaction.set_step_wrap_applied()?;
            }
        }
        style::step_done(3, 5, "MCP client wrap step completed");
    }

    style::step(4, 5, "Configuring shell proxy environment");
    if args.skip_shell_env {
        style::step_done(4, 5, "Skipped shell configuration");
    } else if let Some(ref shell_file) = preflight.shell_file {
        if args.dry_run {
            style::step_done(4, 5, "Would update shell RC managed block");
        } else {
            if let Some(ref mut transaction) = tx {
                transaction.ensure_backup(shell_file)?;
            }
            upsert_managed_shell_block(shell_file, &preflight.shell, DEFAULT_PROXY_URL)?;
            if let Some(ref mut transaction) = tx {
                transaction.set_step_shell_env_written()?;
            }
            style::step_done(4, 5, "Shell managed block updated");
        }
    } else {
        style::warning("Shell RC path unsupported; skipping persistent env block.");
        style::step_done(4, 5, "Shell configuration skipped");
    }

    style::step(5, 5, "Persisting setup state");
    if args.dry_run {
        style::step_done(5, 5, "Would write setup-state metadata");
    } else {
        if let Some(ref mut transaction) = tx {
            transaction.ensure_backup(&preflight.state_path)?;
        }

        let state = SetupState {
            setup_id: setup_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
            wizard_version: 1,
            proxy_url: DEFAULT_PROXY_URL.to_string(),
            shell: preflight.shell.clone(),
            shell_file: preflight
                .shell_file
                .as_ref()
                .map(|path| path.display().to_string()),
            ca_cert_path: preflight.ca_cert_path.display().to_string(),
            ca_key_path: preflight.ca_key_path.display().to_string(),
            fail_mode: args.fail_mode.to_string(),
        };
        write_setup_state(&preflight.state_path, &state)?;
        if let Some(ref mut transaction) = tx {
            transaction.set_step_state_written()?;
        }
        style::step_done(5, 5, "Setup state persisted");
    }

    Ok(())
}

async fn run_doctor() -> Result<()> {
    let preflight = run_preflight(None)?;

    style::header("SOTH Setup Doctor");

    let mut healthy = true;

    let ca_ok = preflight.ca_cert_path.exists() && preflight.ca_key_path.exists();
    style::kv_colored("CA files", if ca_ok { "present" } else { "missing" }, ca_ok);
    healthy &= ca_ok;

    let state_ok = preflight.state_path.exists();
    style::kv_colored(
        "Setup state",
        if state_ok { "present" } else { "missing" },
        state_ok,
    );
    healthy &= state_ok;

    if let Some(ref shell_file) = preflight.shell_file {
        let shell_ok = has_managed_shell_block(shell_file).unwrap_or(false);
        style::kv_colored(
            "Shell managed block",
            if shell_ok { "present" } else { "missing" },
            shell_ok,
        );
        healthy &= shell_ok;
    } else {
        style::warning("Shell RC path unsupported for persistent block checks.");
    }

    if let Some(latest_id) = resolve_setup_id(None, &preflight.state_path).ok() {
        let manifest_path = manifest_path_for_setup(&preflight, &latest_id);
        let manifest_ok = manifest_path.exists();
        style::kv_colored(
            "Latest manifest",
            if manifest_ok { "present" } else { "missing" },
            manifest_ok,
        );
        if manifest_ok {
            if let Ok(manifest) = read_manifest(&manifest_path) {
                style::kv("Latest setup_id", &manifest.setup_id);
                style::kv(
                    "Latest status",
                    &format!("{:?}", manifest.status).to_lowercase(),
                );
            }
        }
    }

    println!();
    style::subtitle("Proxy Status");
    if let Err(error) = commands::proxy::run(ProxyCommands::Status).await {
        style::warning(&format!("Proxy status command failed: {error}"));
        healthy = false;
    }

    println!();
    style::subtitle("MCP Wrap Status");
    if let Err(error) = commands::install::run_status().await {
        style::warning(&format!("Install status command failed: {error}"));
        healthy = false;
    }

    println!();
    if healthy {
        style::success("Doctor checks passed.");
        style::footer();
        return Ok(());
    }

    style::warning("Doctor detected setup issues. Re-run: soth setup wizard");
    style::footer();
    bail!("setup doctor reported unhealthy state")
}

async fn run_rollback(setup_id: Option<String>, yes: bool) -> Result<()> {
    let preflight = run_preflight(None)?;
    let resolved_setup_id = resolve_setup_id(setup_id, &preflight.state_path)?;
    let manifest_path = manifest_path_for_setup(&preflight, &resolved_setup_id);
    let mut manifest = read_manifest(&manifest_path).with_context(|| {
        format!(
            "failed to read setup manifest for rollback: {}",
            manifest_path.display()
        )
    })?;

    style::header("SOTH Setup Rollback");
    style::kv("Setup ID", &resolved_setup_id);
    style::kv("Manifest", &manifest_path.display().to_string());

    if !yes && !prompt_yes_no("Rollback setup-managed changes?", false)? {
        style::warning("Rollback cancelled.");
        style::footer();
        return Ok(());
    }

    restore_backup_entries(&manifest.backups)?;

    if manifest.steps.proxy_enabled {
        if let Err(error) = commands::proxy::run(ProxyCommands::Off).await {
            style::warning(&format!("Failed to disable proxy during rollback: {error}"));
        }
    }

    manifest.status = SetupStatus::RolledBack;
    manifest.rolled_back_at = Some(Utc::now().to_rfc3339());
    manifest.error = None;
    write_manifest(&manifest_path, &manifest)?;

    style::success("Rollback completed.");
    style::footer();
    Ok(())
}

async fn run_uninstall(yes: bool) -> Result<()> {
    let preflight = run_preflight(None)?;

    style::header("SOTH Setup Uninstall");
    if !yes && !prompt_yes_no("Remove setup-managed configuration?", false)? {
        style::warning("Uninstall cancelled.");
        style::footer();
        return Ok(());
    }

    run_uninstall_internal(&preflight, true).await?;
    style::success("Uninstall completed.");
    style::footer();
    Ok(())
}

async fn run_uninstall_internal(preflight: &PreflightContext, remove_state: bool) -> Result<()> {
    if let Err(error) = commands::proxy::run(ProxyCommands::Off).await {
        style::warning(&format!("Failed to disable proxy: {error}"));
    }

    if let Err(error) = commands::install::run_uninstall(None).await {
        style::warning(&format!("Failed to unwrap MCP configs: {error}"));
    }

    if let Some(ref shell_file) = preflight.shell_file {
        if let Err(error) = remove_managed_shell_block(shell_file) {
            style::warning(&format!("Failed to remove shell managed block: {error}"));
        }
    }

    if remove_state && preflight.state_path.exists() {
        fs::remove_file(&preflight.state_path).with_context(|| {
            format!(
                "failed to remove setup state file {}",
                preflight.state_path.display()
            )
        })?;
    }

    Ok(())
}

fn run_preflight(shell_override: Option<String>) -> Result<PreflightContext> {
    let home = dirs::home_dir().context("home directory not found")?;

    let shell = detect_shell(shell_override);
    let shell_file = shell_rc_path(&home, &shell);
    let state_path = home.join(".soth").join("setup-state.json");
    let ca_dir = home.join(".soth").join("ca");
    let setups_dir = home.join(".soth").join("setups");

    Ok(PreflightContext {
        shell,
        shell_file,
        ca_cert_path: ca_dir.join("ca.crt"),
        ca_key_path: ca_dir.join("ca.key"),
        state_path,
        setups_dir,
    })
}

fn detect_shell(shell_override: Option<String>) -> String {
    if let Some(shell) = shell_override {
        return normalize_shell_name(&shell);
    }

    if let Ok(shell) = env::var("SHELL") {
        if let Some(name) = Path::new(&shell).file_name().and_then(|n| n.to_str()) {
            return normalize_shell_name(name);
        }
    }

    "zsh".to_string()
}

fn normalize_shell_name(shell: &str) -> String {
    match shell.to_ascii_lowercase().as_str() {
        "bash" => "bash".to_string(),
        "zsh" => "zsh".to_string(),
        "fish" => "fish".to_string(),
        other => other.to_string(),
    }
}

fn shell_rc_path(home: &Path, shell: &str) -> Option<PathBuf> {
    match shell {
        "bash" => Some(home.join(".bashrc")),
        "zsh" => Some(home.join(".zshrc")),
        "fish" => Some(home.join(".config").join("fish").join("config.fish")),
        _ => None,
    }
}

fn write_setup_state(path: &Path, state: &SetupState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create state dir {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(state)?;
    fs::write(path, body).with_context(|| format!("failed to write {}", path.display()))
}

fn has_managed_shell_block(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read shell file {}", path.display()))?;
    Ok(content.contains(WIZARD_BEGIN_MARKER) && content.contains(WIZARD_END_MARKER))
}

fn upsert_managed_shell_block(path: &Path, shell: &str, proxy_url: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create shell directory {}", parent.display()))?;
    }

    let existing = if path.exists() {
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?
    } else {
        String::new()
    };

    let content_without_block = strip_managed_block(&existing);
    let block = render_shell_block(shell, proxy_url);
    let mut next = content_without_block.trim_end().to_string();
    if !next.is_empty() {
        next.push_str("\n\n");
    }
    next.push_str(&block);
    next.push('\n');

    fs::write(path, next).with_context(|| format!("failed to write {}", path.display()))
}

fn remove_managed_shell_block(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let existing =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut next = strip_managed_block(&existing).trim_end().to_string();
    if !next.is_empty() {
        next.push('\n');
    }
    fs::write(path, next).with_context(|| format!("failed to write {}", path.display()))
}

fn strip_managed_block(content: &str) -> String {
    let Some(start) = content.find(WIZARD_BEGIN_MARKER) else {
        return content.to_string();
    };
    let Some(end_rel) = content[start..].find(WIZARD_END_MARKER) else {
        return content.to_string();
    };
    let end = start + end_rel + WIZARD_END_MARKER.len();

    let mut result = String::new();
    result.push_str(&content[..start]);
    if end < content.len() {
        result.push_str(&content[end..]);
    }
    result
}

fn render_shell_block(shell: &str, proxy_url: &str) -> String {
    let ca_path = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("~"))
        .join(".soth")
        .join("ca")
        .join("ca.crt")
        .display()
        .to_string();

    match shell {
        "fish" => format!(
            "{WIZARD_BEGIN_MARKER}\n\
             # Managed by: soth setup wizard\n\
             set -gx HTTP_PROXY {proxy_url}\n\
             set -gx HTTPS_PROXY {proxy_url}\n\
             set -gx http_proxy {proxy_url}\n\
             set -gx https_proxy {proxy_url}\n\
             set -gx SSL_CERT_FILE {ca_path}\n\
             set -gx REQUESTS_CA_BUNDLE {ca_path}\n\
             set -gx NODE_EXTRA_CA_CERTS {ca_path}\n\
             set -gx NO_PROXY localhost,127.0.0.1,::1\n\
             {WIZARD_END_MARKER}"
        ),
        _ => format!(
            "{WIZARD_BEGIN_MARKER}\n\
             # Managed by: soth setup wizard\n\
             export HTTP_PROXY={proxy_url}\n\
             export HTTPS_PROXY={proxy_url}\n\
             export http_proxy={proxy_url}\n\
             export https_proxy={proxy_url}\n\
             export SSL_CERT_FILE={ca_path}\n\
             export REQUESTS_CA_BUNDLE={ca_path}\n\
             export NODE_EXTRA_CA_CERTS={ca_path}\n\
             export NO_PROXY=localhost,127.0.0.1,::1\n\
             {WIZARD_END_MARKER}"
        ),
    }
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    print!("{prompt} {suffix} ");
    io::stdout().flush().context("failed to flush stdout")?;

    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .context("failed to read prompt input")?;
    let value = line.trim().to_ascii_lowercase();

    if value.is_empty() {
        return Ok(default_yes);
    }
    if value == "y" || value == "yes" {
        return Ok(true);
    }
    if value == "n" || value == "no" {
        return Ok(false);
    }
    Ok(default_yes)
}

fn normalize_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    match env::current_dir() {
        Ok(cwd) => cwd.join(path),
        Err(_) => path.to_path_buf(),
    }
}

fn expand_user_path(path: &Path) -> PathBuf {
    if let Some(raw) = path.to_str() {
        if raw == "~" {
            if let Some(home) = dirs::home_dir() {
                return home;
            }
        }
        if let Some(stripped) = raw.strip_prefix("~/") {
            if let Some(home) = dirs::home_dir() {
                return home.join(stripped);
            }
        }
    }
    normalize_path(path)
}

fn resolve_mcp_config_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut resolved = Vec::new();
    let mut seen = HashSet::new();

    for path in paths {
        let expanded = expand_user_path(path);
        let key = expanded.display().to_string();
        if seen.insert(key) {
            resolved.push(expanded);
        }
    }

    resolved
}

fn sanitize_file_name(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn manifest_path_for_setup(preflight: &PreflightContext, setup_id: &str) -> PathBuf {
    preflight.setups_dir.join(setup_id).join("manifest.json")
}

fn resolve_setup_id(requested: Option<String>, state_path: &Path) -> Result<String> {
    if let Some(id) = requested {
        return Ok(id);
    }

    let state = read_setup_state(state_path)?;
    Ok(state.setup_id)
}

fn read_setup_state(path: &Path) -> Result<SetupState> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read setup state {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse setup state {}", path.display()))
}

fn write_manifest(path: &Path, manifest: &SetupManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(manifest)?;
    fs::write(path, body).with_context(|| format!("failed to write {}", path.display()))
}

fn read_manifest(path: &Path) -> Result<SetupManifest> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read manifest {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse manifest {}", path.display()))
}

fn restore_backup_entries(entries: &[BackupEntry]) -> Result<()> {
    for entry in entries.iter().rev() {
        let original_path = PathBuf::from(&entry.original_path);

        if entry.existed_before {
            let backup_path = entry
                .backup_path
                .as_ref()
                .with_context(|| format!("missing backup path for {}", original_path.display()))?;
            let backup_path = PathBuf::from(backup_path);

            if let Some(parent) = original_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }

            fs::copy(&backup_path, &original_path).with_context(|| {
                format!(
                    "failed to restore {} from {}",
                    original_path.display(),
                    backup_path.display()
                )
            })?;
        } else if original_path.exists() {
            if original_path.is_file() {
                fs::remove_file(&original_path)
                    .with_context(|| format!("failed to remove {}", original_path.display()))?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_managed_block() {
        let input =
            "line1\n# >>> SOTH Setup Wizard >>>\nexport A=1\n# <<< SOTH Setup Wizard <<<\nline2\n";
        let output = strip_managed_block(input);
        assert!(output.contains("line1"));
        assert!(output.contains("line2"));
        assert!(!output.contains("export A=1"));
    }

    #[test]
    fn test_render_shell_block_contains_markers() {
        let block = render_shell_block("zsh", "http://127.0.0.1:8080");
        assert!(block.contains(WIZARD_BEGIN_MARKER));
        assert!(block.contains(WIZARD_END_MARKER));
        assert!(block.contains("HTTP_PROXY"));
    }

    #[test]
    fn test_normalize_shell_name() {
        assert_eq!(normalize_shell_name("zsh"), "zsh");
        assert_eq!(normalize_shell_name("BASH"), "bash");
    }

    #[test]
    fn test_expand_user_path_tilde() {
        let path = expand_user_path(Path::new("~/tmp/file.json"));
        assert!(path.is_absolute());
        assert!(path.display().to_string().contains("tmp/file.json"));
    }

    #[test]
    fn test_resolve_mcp_config_paths_dedupes() {
        let paths = vec![
            PathBuf::from("~/tmp/a.json"),
            PathBuf::from("~/tmp/a.json"),
            PathBuf::from("./tmp/b.json"),
        ];
        let resolved = resolve_mcp_config_paths(&paths);
        assert_eq!(resolved.len(), 2);
    }

    #[test]
    fn test_restore_backup_entries_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("file.txt");
        let backup = temp.path().join("backup.txt");
        let created = temp.path().join("created.txt");

        fs::write(&original, "old").unwrap();
        fs::copy(&original, &backup).unwrap();
        fs::write(&original, "new").unwrap();
        fs::write(&created, "temporary").unwrap();

        let entries = vec![
            BackupEntry {
                original_path: original.display().to_string(),
                backup_path: Some(backup.display().to_string()),
                existed_before: true,
            },
            BackupEntry {
                original_path: created.display().to_string(),
                backup_path: None,
                existed_before: false,
            },
        ];

        restore_backup_entries(&entries).unwrap();

        assert_eq!(fs::read_to_string(&original).unwrap(), "old");
        assert!(!created.exists());
    }
}
