//! Helper utilities for setup wizard shell/state/manifest handling.

use super::{
    BackupEntry, PreflightContext, SetupManifest, SetupState, WIZARD_BEGIN_MARKER,
    WIZARD_END_MARKER,
};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub(super) fn detect_shell(shell_override: Option<String>) -> String {
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

pub(super) fn normalize_shell_name(shell: &str) -> String {
    match shell.to_ascii_lowercase().as_str() {
        "bash" => "bash".to_string(),
        "zsh" => "zsh".to_string(),
        "fish" => "fish".to_string(),
        other => other.to_string(),
    }
}

pub(super) fn shell_rc_path(home: &Path, shell: &str) -> Option<PathBuf> {
    match shell {
        "bash" => Some(home.join(".bashrc")),
        "zsh" => Some(home.join(".zshrc")),
        "fish" => Some(home.join(".config").join("fish").join("config.fish")),
        _ => None,
    }
}

pub(super) fn write_setup_state(path: &Path, state: &SetupState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create state dir {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(state)?;
    fs::write(path, body).with_context(|| format!("failed to write {}", path.display()))
}

pub(super) fn has_managed_shell_block(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read shell file {}", path.display()))?;
    Ok(content.contains(WIZARD_BEGIN_MARKER) && content.contains(WIZARD_END_MARKER))
}

pub(super) fn upsert_managed_shell_block(path: &Path, shell: &str, proxy_url: &str) -> Result<()> {
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

pub(super) fn remove_managed_shell_block(path: &Path) -> Result<()> {
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

pub(super) fn strip_managed_block(content: &str) -> String {
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

pub(super) fn render_shell_block(shell: &str, proxy_url: &str) -> String {
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
             set -gx CURL_CA_BUNDLE {ca_path}\n\
             set -gx GIT_SSL_CAINFO {ca_path}\n\
             set -gx AWS_CA_BUNDLE {ca_path}\n\
             set -gx NO_PROXY localhost,127.0.0.1,::1\n\
             set -gx no_proxy localhost,127.0.0.1,::1\n\
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
             export CURL_CA_BUNDLE={ca_path}\n\
             export GIT_SSL_CAINFO={ca_path}\n\
             export AWS_CA_BUNDLE={ca_path}\n\
             export NO_PROXY=localhost,127.0.0.1,::1\n\
             export no_proxy=localhost,127.0.0.1,::1\n\
             {WIZARD_END_MARKER}"
        ),
    }
}

pub(super) fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
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

pub(super) fn normalize_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    match env::current_dir() {
        Ok(cwd) => cwd.join(path),
        Err(_) => path.to_path_buf(),
    }
}

pub(super) fn expand_user_path(path: &Path) -> PathBuf {
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

pub(super) fn resolve_mcp_config_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
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

pub(super) fn sanitize_file_name(value: &str) -> String {
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

pub(super) fn manifest_path_for_setup(preflight: &PreflightContext, setup_id: &str) -> PathBuf {
    preflight.setups_dir.join(setup_id).join("manifest.json")
}

pub(super) fn resolve_setup_id(requested: Option<String>, state_path: &Path) -> Result<String> {
    if let Some(id) = requested {
        return Ok(id);
    }

    let state = read_setup_state(state_path)?;
    Ok(state.setup_id)
}

pub(super) fn read_setup_state(path: &Path) -> Result<SetupState> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read setup state {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse setup state {}", path.display()))
}

pub(super) fn write_manifest(path: &Path, manifest: &SetupManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(manifest)?;
    fs::write(path, body).with_context(|| format!("failed to write {}", path.display()))
}

pub(super) fn read_manifest(path: &Path) -> Result<SetupManifest> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read manifest {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse manifest {}", path.display()))
}

pub(super) fn restore_backup_entries(entries: &[BackupEntry]) -> Result<()> {
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
        } else if original_path.exists() && original_path.is_file() {
            fs::remove_file(&original_path)
                .with_context(|| format!("failed to remove {}", original_path.display()))?;
        }
    }

    Ok(())
}
