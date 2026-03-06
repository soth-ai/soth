use crate::cli_config::{self, SothConfig};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const SHELL_SYNC_ENV: &str = "SOTH_SHELL_SYNC";
const SHELL_PATCH_FILE_ENV: &str = "SOTH_SHELL_PATCH_FILE";
const SNAPSHOT_FILE: &str = "shell_env_snapshot.json";

const ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "CURL_CA_BUNDLE",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellKind {
    Bash,
    Zsh,
    Fish,
}

impl ShellKind {
    fn from_sync_env(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "fish" => Some(Self::Fish),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct EnvSnapshot {
    shell: String,
    values: BTreeMap<String, Option<String>>,
}

pub(crate) fn emit_activate_patch(config_path: Option<&PathBuf>) -> Result<()> {
    let Some(shell) = current_shell_kind() else {
        return Ok(());
    };
    let Some(patch_file) = patch_file_path() else {
        return Ok(());
    };

    let config = cli_config::load_effective_config(config_path, None)?;
    let snapshot_path = snapshot_path();
    let snapshot = if snapshot_path.exists() {
        load_snapshot(snapshot_path.as_path()).unwrap_or_else(|_| capture_snapshot(shell))
    } else {
        capture_snapshot(shell)
    };
    save_snapshot(snapshot_path.as_path(), &snapshot)?;

    let desired = desired_env_values(&config);
    let commands = render_apply_commands(shell, &desired);
    write_patch_file(patch_file.as_path(), commands.as_slice())?;
    Ok(())
}

pub(crate) fn emit_deactivate_patch() -> Result<()> {
    let Some(shell) = current_shell_kind() else {
        return Ok(());
    };
    let Some(patch_file) = patch_file_path() else {
        return Ok(());
    };

    let snapshot_path = snapshot_path();
    if !snapshot_path.exists() {
        write_patch_file(patch_file.as_path(), &[])?;
        return Ok(());
    }
    let snapshot = load_snapshot(snapshot_path.as_path())?;
    let commands = render_restore_commands(shell, &snapshot.values);
    write_patch_file(patch_file.as_path(), commands.as_slice())?;
    let _ = std::fs::remove_file(snapshot_path);
    Ok(())
}

pub(crate) fn render_hook(shell: ShellKind) -> String {
    match shell {
        ShellKind::Bash | ShellKind::Zsh => {
            let shell_value = match shell {
                ShellKind::Bash => "bash",
                ShellKind::Zsh => "zsh",
                ShellKind::Fish => unreachable!(),
            };
            format!(
                r#"
soth() {{
  local __soth_patch_file
  __soth_patch_file="$(mktemp "${{TMPDIR:-/tmp}}/soth-shell-env.XXXXXX")" || return 1
  SOTH_SHELL_SYNC={shell_value} SOTH_SHELL_PATCH_FILE="$__soth_patch_file" command soth "$@"
  local __soth_rc=$?
  if [ -s "$__soth_patch_file" ]; then
    # shellcheck source=/dev/null
    . "$__soth_patch_file"
  fi
  rm -f "$__soth_patch_file"
  return $__soth_rc
}}
"#
            )
        }
        ShellKind::Fish => r#"
function soth
  set -l __soth_patch_file (mktemp -t soth-shell-env.XXXXXX)
  env SOTH_SHELL_SYNC=fish SOTH_SHELL_PATCH_FILE=$__soth_patch_file command soth $argv
  set -l __soth_rc $status
  if test -s $__soth_patch_file
    source $__soth_patch_file
  end
  rm -f $__soth_patch_file
  return $__soth_rc
end
"#
        .to_string(),
    }
}

fn current_shell_kind() -> Option<ShellKind> {
    let value = std::env::var(SHELL_SYNC_ENV).ok()?;
    ShellKind::from_sync_env(value.as_str())
}

fn patch_file_path() -> Option<PathBuf> {
    let raw = std::env::var(SHELL_PATCH_FILE_ENV).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(PathBuf::from(trimmed))
}

fn snapshot_path() -> PathBuf {
    let home = if let Ok(value) = std::env::var("SOTH_HOME_DIR") {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            default_home()
        } else {
            PathBuf::from(trimmed)
        }
    } else {
        default_home()
    };
    home.join("run").join(SNAPSHOT_FILE)
}

fn default_home() -> PathBuf {
    dirs::home_dir()
        .map(|home| home.join(".soth"))
        .unwrap_or_else(|| PathBuf::from(".soth"))
}

fn capture_snapshot(shell: ShellKind) -> EnvSnapshot {
    let mut values = BTreeMap::new();
    for key in ENV_KEYS {
        values.insert(
            (*key).to_string(),
            std::env::var(key)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
        );
    }
    EnvSnapshot {
        shell: match shell {
            ShellKind::Bash => "bash".to_string(),
            ShellKind::Zsh => "zsh".to_string(),
            ShellKind::Fish => "fish".to_string(),
        },
        values,
    }
}

fn load_snapshot(path: &Path) -> Result<EnvSnapshot> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading {}", path.display()))?;
    serde_json::from_str(raw.as_str()).with_context(|| format!("failed parsing {}", path.display()))
}

fn save_snapshot(path: &Path, snapshot: &EnvSnapshot) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(snapshot).context("serialize env snapshot")?;
    std::fs::write(path, body).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

fn desired_env_values(config: &SothConfig) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    let proxy_addr = format!("http://{}", config.forward_proxy.socket_addr());
    let no_proxy = "localhost,127.0.0.1,::1".to_string();
    let ca_paths = super::ca_health::resolve_ca_paths(config);
    let ca_path = ca_paths.trust_cert_path.display().to_string();

    values.insert("HTTP_PROXY".to_string(), proxy_addr.clone());
    values.insert("HTTPS_PROXY".to_string(), proxy_addr.clone());
    values.insert("http_proxy".to_string(), proxy_addr.clone());
    values.insert("https_proxy".to_string(), proxy_addr);
    values.insert("NO_PROXY".to_string(), no_proxy.clone());
    values.insert("no_proxy".to_string(), no_proxy);
    values.insert("SSL_CERT_FILE".to_string(), ca_path.clone());
    values.insert("REQUESTS_CA_BUNDLE".to_string(), ca_path.clone());
    values.insert("NODE_EXTRA_CA_CERTS".to_string(), ca_path.clone());
    values.insert("CURL_CA_BUNDLE".to_string(), ca_path);
    values
}

fn render_apply_commands(shell: ShellKind, values: &BTreeMap<String, String>) -> Vec<String> {
    let mut commands = Vec::with_capacity(values.len());
    for (key, value) in values {
        commands.push(match shell {
            ShellKind::Bash | ShellKind::Zsh => {
                format!("export {}={}", key, shell_quote(value.as_str()))
            }
            ShellKind::Fish => {
                format!("set -gx {} {}", key, fish_quote(value.as_str()))
            }
        });
    }
    commands
}

fn render_restore_commands(
    shell: ShellKind,
    values: &BTreeMap<String, Option<String>>,
) -> Vec<String> {
    let mut commands = Vec::with_capacity(values.len() * 2);
    for key in ENV_KEYS {
        let value = values.get(*key).cloned().flatten();
        match (shell, value) {
            (ShellKind::Bash | ShellKind::Zsh, Some(value)) => {
                commands.push(format!("export {}={}", key, shell_quote(value.as_str())))
            }
            (ShellKind::Bash | ShellKind::Zsh, None) => commands.push(format!("unset {}", key)),
            (ShellKind::Fish, Some(value)) => {
                commands.push(format!("set -gx {} {}", key, fish_quote(value.as_str())))
            }
            (ShellKind::Fish, None) => {
                commands.push(format!("set -e {}", key));
                commands.push(format!("set -e -g {}", key));
                commands.push(format!("set -e -U {}", key));
            }
        }
    }
    commands
}

fn shell_quote(value: &str) -> String {
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{}'", escaped)
}

fn fish_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{}'", escaped)
}

fn write_patch_file(path: &Path, commands: &[String]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    let mut body = String::new();
    for line in commands {
        body.push_str(line);
        body.push('\n');
    }
    std::fs::write(path, body).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_config::SothConfig;
    use std::env;

    fn with_temp_home<T>(f: impl FnOnce(&tempfile::TempDir) -> T + std::panic::UnwindSafe) -> T {
        let guard = crate::commands::proxy::lock_test_env();
        let temp = tempfile::tempdir().expect("tempdir");
        let soth_home = temp.path().join(".soth");
        let old_home = env::var_os("HOME");
        let old_soth_home = env::var_os("SOTH_HOME_DIR");
        let old_sync = env::var_os(SHELL_SYNC_ENV);
        let old_patch = env::var_os(SHELL_PATCH_FILE_ENV);
        let old_http_proxy = env::var_os("HTTP_PROXY");

        unsafe {
            env::set_var("HOME", temp.path());
            env::set_var("SOTH_HOME_DIR", &soth_home);
        }

        let result = std::panic::catch_unwind(|| f(&temp));

        match old_home {
            Some(value) => unsafe { env::set_var("HOME", value) },
            None => unsafe { env::remove_var("HOME") },
        }
        match old_soth_home {
            Some(value) => unsafe { env::set_var("SOTH_HOME_DIR", value) },
            None => unsafe { env::remove_var("SOTH_HOME_DIR") },
        }
        match old_sync {
            Some(value) => unsafe { env::set_var(SHELL_SYNC_ENV, value) },
            None => unsafe { env::remove_var(SHELL_SYNC_ENV) },
        }
        match old_patch {
            Some(value) => unsafe { env::set_var(SHELL_PATCH_FILE_ENV, value) },
            None => unsafe { env::remove_var(SHELL_PATCH_FILE_ENV) },
        }
        match old_http_proxy {
            Some(value) => unsafe { env::set_var("HTTP_PROXY", value) },
            None => unsafe { env::remove_var("HTTP_PROXY") },
        }

        drop(guard);
        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    #[test]
    fn render_hook_contains_expected_sync_env() {
        assert!(render_hook(ShellKind::Bash).contains("SOTH_SHELL_SYNC=bash"));
        assert!(render_hook(ShellKind::Zsh).contains("SOTH_SHELL_SYNC=zsh"));
        assert!(render_hook(ShellKind::Fish).contains("SOTH_SHELL_SYNC=fish"));
    }

    #[test]
    fn activate_then_deactivate_restores_http_proxy() {
        with_temp_home(|temp| {
            let config_path = temp.path().join("soth.yaml");
            let config = SothConfig::default();
            crate::cli_config::write_config(config_path.as_path(), &config).expect("write config");
            let patch_path = temp.path().join("patch.sh");

            unsafe {
                env::set_var(SHELL_SYNC_ENV, "bash");
                env::set_var(SHELL_PATCH_FILE_ENV, &patch_path);
                env::set_var("HTTP_PROXY", "http://previous-proxy:8888");
            }

            emit_activate_patch(Some(&config_path)).expect("activate patch");
            let activated = std::fs::read_to_string(&patch_path).expect("read activate patch");
            assert!(activated.contains("export HTTP_PROXY="));
            assert!(activated.contains("127.0.0.1:8080"));

            emit_deactivate_patch().expect("deactivate patch");
            let restored = std::fs::read_to_string(&patch_path).expect("read restore patch");
            assert!(restored.contains("http://previous-proxy:8888"));
        });
    }
}
