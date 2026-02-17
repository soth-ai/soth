//! Setup wizard commands.
//!
//! Provides guided setup orchestration for CA generation, proxy setup,
//! MCP client wrapping, and shell environment configuration.

use crate::cli_config;
use crate::commands;
use crate::style;
use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{Args, Subcommand, ValueEnum};
#[path = "setup_flow.rs"]
mod setup_flow;
#[path = "setup_helpers.rs"]
mod setup_helpers;
use serde::{Deserialize, Serialize};
use setup_flow::{run_doctor, run_preflight, run_rollback, run_uninstall, SetupTransaction};
use setup_helpers::{
    detect_shell, has_managed_shell_block, manifest_path_for_setup, normalize_path, prompt_yes_no,
    read_manifest, remove_managed_shell_block, resolve_mcp_config_paths, resolve_setup_id,
    restore_backup_entries, sanitize_file_name, shell_rc_path, upsert_managed_shell_block,
    write_manifest, write_setup_state,
};
use soth_core::config::SothConfig;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

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

fn proxy_url(config: &SothConfig) -> String {
    format!("http://{}", config.forward_proxy.socket_addr())
}

pub async fn run(action: SetupCommands, global_config_path: Option<PathBuf>) -> Result<()> {
    let config = cli_config::load_effective_config(global_config_path.as_ref(), None)?;
    match action {
        SetupCommands::Wizard(args) => run_wizard(args, &config, global_config_path).await,
        SetupCommands::Doctor => run_doctor(&config, global_config_path).await,
        SetupCommands::Rollback { setup_id, yes } => {
            run_rollback(setup_id, yes, &config, global_config_path).await
        }
        SetupCommands::Uninstall { yes } => run_uninstall(yes, &config, global_config_path).await,
    }
}

async fn run_wizard(
    args: WizardArgs,
    config: &SothConfig,
    global_config_path: Option<PathBuf>,
) -> Result<()> {
    if args.non_interactive && !args.yes {
        bail!("--non-interactive requires --yes");
    }
    if args.only_mcp_config && args.mcp_config.is_empty() {
        bail!("--only-mcp-config requires at least one --mcp-config PATH");
    }

    let preflight = run_preflight(args.shell.clone(), config)?;
    let proxy_url = proxy_url(config);
    let mut tx = if args.dry_run {
        None
    } else {
        Some(SetupTransaction::start(
            &preflight,
            &args.fail_mode,
            &proxy_url,
        )?)
    };
    let setup_id = tx
        .as_ref()
        .map(|t| t.setup_id().to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    style::header("SOTH Setup Wizard");
    style::kv("Mode", if args.dry_run { "dry-run" } else { "apply" });
    style::kv("Shell", &preflight.shell);
    style::kv("Proxy", &proxy_url);
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

    let outcome = run_wizard_steps(
        &args,
        &preflight,
        &proxy_url,
        setup_id.as_str(),
        &mut tx,
        global_config_path,
        config,
    )
    .await;

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
                style::kv("Transaction", &transaction.dir().display().to_string());
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
    proxy_url: &str,
    setup_id: &str,
    tx: &mut Option<SetupTransaction>,
    global_config_path: Option<PathBuf>,
    config: &SothConfig,
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
        let ca_output_dir = preflight
            .ca_cert_path
            .parent()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| ".".to_string());
        commands::proxy::run_setup_ca(false, Some(ca_output_dir), global_config_path.clone())
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
        commands::proxy::run_on(Some(config.forward_proxy.port), global_config_path.clone())
            .await?;
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
            upsert_managed_shell_block(shell_file, &preflight.shell, proxy_url)?;
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
            proxy_url: proxy_url.to_string(),
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

#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;
