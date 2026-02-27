//! Start proxy runtime command.

use super::daemon;
use crate::cli_config::{self, SothConfig};
use crate::style;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::process::{Child, Command};

/// Run the start command.
pub async fn run(
    port: Option<u16>,
    config_path: Option<PathBuf>,
    quiet: bool,
    foreground: bool,
    daemon_child: bool,
    no_autostart: bool,
) -> Result<()> {
    if !foreground && !daemon_child {
        return daemon::run_start_daemon(port, config_path, quiet, no_autostart).await;
    }

    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    let cert_path = cli_config::expand_tilde(Path::new(config.forward_proxy.ca.cert_path.as_str()));
    let key_path = cli_config::expand_tilde(Path::new(config.forward_proxy.ca.key_path.as_str()));
    if !cert_path.exists() || !key_path.exists() {
        anyhow::bail!("CA certificate not found. Run `soth setup-ca` first.");
    }

    let generated_path = write_proxy_config(&config, port)?;
    let mut child = spawn_proxy_process(generated_path.as_path())
        .await
        .context("spawn soth-proxy process")?;

    if foreground {
        if !quiet {
            style::success("Proxy started in foreground mode.");
            style::info("Press Ctrl+C to stop.");
        }
        return wait_with_ctrl_c(&mut child).await;
    }

    wait_as_daemon_child(&mut child).await
}

async fn spawn_proxy_process(config_path: &Path) -> Result<Child> {
    let proxy_bin = resolve_proxy_binary()?;
    let mut cmd = Command::new(proxy_bin);
    cmd.env("SOTH_PROXY_CONFIG", config_path);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());
    cmd.spawn()
        .map_err(|error| anyhow::anyhow!("failed launching soth-proxy: {error}"))
}

async fn wait_with_ctrl_c(child: &mut Child) -> Result<()> {
    tokio::select! {
        status = child.wait() => {
            let status = status.context("failed waiting for soth-proxy process")?;
            if status.success() {
                Ok(())
            } else {
                anyhow::bail!("soth-proxy exited with status {status}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            terminate_child(child).await?;
            Ok(())
        }
    }
}

async fn wait_as_daemon_child(child: &mut Child) -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).context("listen for SIGTERM")?;
        let mut interrupt = signal(SignalKind::interrupt()).context("listen for SIGINT")?;
        tokio::select! {
            status = child.wait() => {
                let status = status.context("failed waiting for soth-proxy process")?;
                if status.success() {
                    Ok(())
                } else {
                    anyhow::bail!("soth-proxy exited with status {status}");
                }
            }
            _ = term.recv() => {
                terminate_child(child).await?;
                Ok(())
            }
            _ = interrupt.recv() => {
                terminate_child(child).await?;
                Ok(())
            }
        }
    }
    #[cfg(not(unix))]
    {
        let status = child
            .wait()
            .await
            .context("failed waiting for soth-proxy process")?;
        if status.success() {
            Ok(())
        } else {
            anyhow::bail!("soth-proxy exited with status {status}");
        }
    }
}

async fn terminate_child(child: &mut Child) -> Result<()> {
    let _ = child.start_kill();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await;
    Ok(())
}

fn write_proxy_config(config: &SothConfig, port_override: Option<u16>) -> Result<PathBuf> {
    let root = soth_home_dir().join("run");
    std::fs::create_dir_all(&root)
        .with_context(|| format!("failed creating {}", root.display()))?;

    let path = root.join("proxy.generated.toml");
    let sync_enabled = config.cloud.enabled
        && config
            .cloud
            .api_key
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
    let ca_cert_path =
        cli_config::expand_tilde(Path::new(config.forward_proxy.ca.cert_path.as_str()));
    let ca_key_path =
        cli_config::expand_tilde(Path::new(config.forward_proxy.ca.key_path.as_str()));
    let generated = GeneratedProxyConfig {
        db_path: cli_config::resolved_db_path(config).display().to_string(),
        org_id: config
            .cloud
            .tags
            .get("workspace_id")
            .cloned()
            .unwrap_or_else(|| "local-org".to_string()),
        team_id: config
            .cloud
            .tags
            .get("team_id")
            .cloned()
            .unwrap_or_else(|| "local-team".to_string()),
        device_id_hash: config
            .cloud
            .tags
            .get("device_id")
            .cloned()
            .unwrap_or_else(|| "local-device".to_string()),
        mitm: GeneratedMitmConfig {
            bind: format!(
                "{}:{}",
                config.forward_proxy.address,
                port_override.unwrap_or(config.forward_proxy.port)
            ),
            ca_cert_path: ca_cert_path.display().to_string(),
            ca_key_path: ca_key_path.display().to_string(),
        },
        bundle: GeneratedBundleConfig {
            bundle_dir: cli_config::expand_tilde(Path::new(config.bundle.bundle_dir.as_str()))
                .display()
                .to_string(),
            vendor_pubkey_hex: config.bundle.vendor_pubkey_hex.clone(),
        },
        sync: GeneratedSyncConfig {
            enabled: sync_enabled,
            endpoint: config.cloud.endpoint.clone(),
            api_key: config.cloud.api_key.clone().unwrap_or_default(),
            sync_interval_secs: config.cloud.sync_interval_secs.max(5),
        },
        telemetry: GeneratedTelemetryConfig {
            enabled: sync_enabled && config.exchange.enabled,
        },
    };

    let body = toml::to_string_pretty(&generated).context("serialize proxy TOML")?;
    std::fs::write(&path, body).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(path)
}

fn soth_home_dir() -> PathBuf {
    if let Ok(value) = std::env::var("SOTH_HOME_DIR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    dirs::home_dir()
        .map(|home| home.join(".soth"))
        .unwrap_or_else(|| PathBuf::from(".soth"))
}

fn resolve_proxy_binary() -> Result<PathBuf> {
    if let Ok(value) = std::env::var("SOTH_PROXY_BIN") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }

    if let Ok(current) = std::env::current_exe() {
        let sibling = current.with_file_name("soth-proxy");
        if sibling.exists() {
            return Ok(sibling);
        }
    }

    which::which("soth-proxy").context("could not locate `soth-proxy` executable")
}

#[derive(Debug, Serialize)]
struct GeneratedProxyConfig {
    db_path: String,
    org_id: String,
    team_id: String,
    device_id_hash: String,
    mitm: GeneratedMitmConfig,
    bundle: GeneratedBundleConfig,
    sync: GeneratedSyncConfig,
    telemetry: GeneratedTelemetryConfig,
}

#[derive(Debug, Serialize)]
struct GeneratedMitmConfig {
    bind: String,
    ca_cert_path: String,
    ca_key_path: String,
}

#[derive(Debug, Serialize)]
struct GeneratedBundleConfig {
    bundle_dir: String,
    vendor_pubkey_hex: String,
}

#[derive(Debug, Serialize)]
struct GeneratedSyncConfig {
    enabled: bool,
    endpoint: String,
    api_key: String,
    sync_interval_secs: u64,
}

#[derive(Debug, Serialize)]
struct GeneratedTelemetryConfig {
    enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_temp_home<T>(f: impl FnOnce(std::path::PathBuf) -> T + std::panic::UnwindSafe) -> T {
        let guard = crate::commands::proxy::lock_test_env();
        let temp = tempfile::tempdir().expect("tempdir");
        let old_home = std::env::var_os("HOME");
        let old_soth_home = std::env::var_os("SOTH_HOME_DIR");
        let soth_home = temp.path().join(".soth");
        unsafe {
            std::env::set_var("HOME", temp.path());
            std::env::set_var("SOTH_HOME_DIR", &soth_home);
        }

        let result = std::panic::catch_unwind(|| f(temp.path().to_path_buf()));

        match old_home {
            Some(value) => unsafe {
                std::env::set_var("HOME", value);
            },
            None => unsafe {
                std::env::remove_var("HOME");
            },
        }
        match old_soth_home {
            Some(value) => unsafe {
                std::env::set_var("SOTH_HOME_DIR", value);
            },
            None => unsafe {
                std::env::remove_var("SOTH_HOME_DIR");
            },
        }
        drop(guard);

        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    #[test]
    fn generated_proxy_config_includes_ca_paths_and_port_override() {
        with_temp_home(|home| {
            let mut config = SothConfig::default();
            config.forward_proxy.address = "127.0.0.1".to_string();
            config.forward_proxy.port = 8080;
            config.forward_proxy.ca.cert_path = home
                .join("certs")
                .join("custom-ca.pem")
                .display()
                .to_string();
            config.forward_proxy.ca.key_path = home
                .join("certs")
                .join("custom-ca-key.pem")
                .display()
                .to_string();
            config.bundle.bundle_dir = home.join("bundle").display().to_string();
            config.bundle.vendor_pubkey_hex = "11".repeat(32);

            let generated = write_proxy_config(&config, Some(9999)).expect("write proxy config");
            let raw = std::fs::read_to_string(&generated).expect("read generated config");
            let value: toml::Value = toml::from_str(raw.as_str()).expect("parse generated toml");

            assert_eq!(
                value
                    .get("mitm")
                    .and_then(|v| v.get("bind"))
                    .and_then(toml::Value::as_str),
                Some("127.0.0.1:9999")
            );
            assert_eq!(
                value
                    .get("mitm")
                    .and_then(|v| v.get("ca_cert_path"))
                    .and_then(toml::Value::as_str),
                Some(config.forward_proxy.ca.cert_path.as_str())
            );
            assert_eq!(
                value
                    .get("mitm")
                    .and_then(|v| v.get("ca_key_path"))
                    .and_then(toml::Value::as_str),
                Some(config.forward_proxy.ca.key_path.as_str())
            );
        });
    }
}
