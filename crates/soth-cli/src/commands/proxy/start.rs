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
    let root = dirs::home_dir()
        .map(|home| home.join(".soth").join("run"))
        .unwrap_or_else(|| PathBuf::from(".soth/run"));
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
