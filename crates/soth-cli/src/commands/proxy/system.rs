//! System proxy auto-configuration
//!
//! Commands for configuring the system to route traffic through SOTH proxy:
//! - `soth on` - Enable system proxy settings
//! - `soth off` - Disable system proxy settings

use crate::style;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Network services to configure on macOS
const MACOS_NETWORK_SERVICES: &[&str] = &["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"];

/// Default proxy port
const DEFAULT_PROXY_PORT: u16 = 8080;
const SYSTEM_PROXY_STATE_FILE: &str = "system_proxy_state.json";
const SYSTEM_PROXY_OWNER_FILE: &str = "system_proxy_owner.id";

/// Domains to bypass proxy (localhost and local network).
const PROXY_BYPASS_DOMAINS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "::1",
    "*.local",
    "192.168.*",
    "10.*",
    "172.16.*",
    "172.17.*",
    "172.18.*",
    "172.19.*",
    "172.20.*",
    "172.21.*",
    "172.22.*",
    "172.23.*",
    "172.24.*",
    "172.25.*",
    "172.26.*",
    "172.27.*",
    "172.28.*",
    "172.29.*",
    "172.30.*",
    "172.31.*",
];

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemProxyState {
    schema_version: u32,
    platform: String,
    owner_id: String,
    created_at_unix_secs: u64,
    port: u16,
    #[cfg(target_os = "macos")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    macos: Option<MacosProxySnapshot>,
    #[cfg(target_os = "linux")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    linux: Option<LinuxProxySnapshot>,
    #[cfg(target_os = "windows")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    windows: Option<WindowsProxySnapshot>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MacosProxySnapshot {
    services: Vec<MacosServiceSnapshot>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MacosServiceSnapshot {
    service: String,
    web: ProxyEndpointSnapshot,
    secure: ProxyEndpointSnapshot,
    bypass_domains: Vec<String>,
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProxyEndpointSnapshot {
    enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LinuxProxySnapshot {
    mode: String,
    http: ProxyEndpointSnapshot,
    https: ProxyEndpointSnapshot,
    ignore_hosts: Vec<String>,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WindowsProxySnapshot {
    enabled: bool,
    proxy_server: Option<String>,
    proxy_override: Option<String>,
}

/// Enable system proxy settings
pub async fn enable(port: Option<u16>) -> Result<()> {
    enable_internal(port, true).await
}

async fn enable_internal(port: Option<u16>, print_user_output: bool) -> Result<()> {
    let proxy_port = port.unwrap_or(DEFAULT_PROXY_PORT);
    let proxy_addr = format!("127.0.0.1:{proxy_port}");
    #[cfg(target_os = "linux")]
    let mut managed_apply = true;
    #[cfg(not(target_os = "linux"))]
    let managed_apply = true;

    if print_user_output {
        println!(
            "{} Configuring system to use SOTH proxy at {}",
            style::ARROW_RIGHT,
            style::highlight(&proxy_addr)
        );
    }

    #[cfg(target_os = "macos")]
    {
        configure_macos_proxy(true, proxy_port, print_user_output).await?;
    }

    #[cfg(target_os = "linux")]
    {
        managed_apply = configure_linux_proxy(true, proxy_port, print_user_output).await?;
    }

    #[cfg(target_os = "windows")]
    {
        configure_windows_proxy(true, proxy_port, print_user_output).await?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = proxy_port;
        let _ = print_user_output;
        anyhow::bail!(
            "system proxy automation is not supported on this OS ({})",
            std::env::consts::OS
        );
    }

    if print_user_output {
        if managed_apply {
            println!("\n{} System proxy enabled", style::success_prefix());
            println!("   All HTTPS traffic will now route through SOTH proxy");
            println!(
                "   {} AI traffic: MITM intercepted (inspection enabled)",
                style::INFO
            );
            println!(
                "   {} Other traffic: Tunneled (no inspection)",
                style::ARROW_RIGHT
            );
            println!(
                "   {} Bypass: localhost, 127.0.0.1, *.local, private IPs",
                style::ARROW_RIGHT
            );

            // Check if CA is trusted
            let ca_path = get_ca_path();
            if !ca_path.exists() {
                println!(
                    "\n{} CA certificate not found. Run: {}",
                    style::WARNING,
                    style::highlight("soth setup-ca")
                );
            }
        } else {
            println!(
                "\n{} System proxy was not auto-configured on this Linux desktop",
                style::WARNING
            );
            println!("   Apply the printed shell instructions manually.");
        }
    }

    Ok(())
}

/// Disable system proxy settings
pub async fn disable() -> Result<()> {
    disable_internal(true).await
}

/// Disable system proxy settings without printing user-facing output.
pub async fn disable_quiet() -> Result<()> {
    disable_internal(false).await
}

async fn disable_internal(print_user_output: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    let mut managed_apply = true;
    #[cfg(not(target_os = "linux"))]
    let managed_apply = true;

    if print_user_output {
        println!(
            "{} Removing system proxy configuration...",
            style::ARROW_RIGHT
        );
    }

    #[cfg(target_os = "macos")]
    {
        configure_macos_proxy(false, 0, print_user_output).await?;
    }

    #[cfg(target_os = "linux")]
    {
        managed_apply = configure_linux_proxy(false, 0, print_user_output).await?;
    }

    #[cfg(target_os = "windows")]
    {
        configure_windows_proxy(false, 0, print_user_output).await?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = print_user_output;
        anyhow::bail!(
            "system proxy automation is not supported on this OS ({})",
            std::env::consts::OS
        );
    }

    if print_user_output {
        if managed_apply {
            println!("\n{} System proxy disabled", style::success_prefix());
            println!("   Direct connections restored");
        } else {
            println!(
                "\n{} No managed Linux system proxy backend detected; manual cleanup may still be required.",
                style::WARNING
            );
        }
    }

    Ok(())
}

/// Show current system proxy status
#[allow(dead_code)]
pub async fn status() -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        return check_macos_proxy_status().await;
    }

    #[cfg(target_os = "linux")]
    {
        return check_linux_proxy_status().await;
    }

    #[cfg(target_os = "windows")]
    {
        return check_windows_proxy_status().await;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        anyhow::bail!(
            "system proxy status is not supported on this OS ({})",
            std::env::consts::OS
        );
    }

    #[allow(unreachable_code)]
    Ok(false)
}

fn get_ca_path() -> PathBuf {
    soth_home_dir().join("certs").join("soth-mitm-ca.pem")
}

fn soth_home_dir() -> PathBuf {
    if let Ok(value) = std::env::var("SOTH_HOME_DIR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".soth")
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn system_proxy_state_path() -> PathBuf {
    soth_home_dir().join("run").join(SYSTEM_PROXY_STATE_FILE)
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn load_system_proxy_state() -> Result<Option<SystemProxyState>> {
    let path = system_proxy_state_path();
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed reading system proxy state {}", path.display()))?;
    let state = serde_json::from_str::<SystemProxyState>(&raw)
        .with_context(|| format!("failed parsing system proxy state {}", path.display()))?;
    Ok(Some(state))
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn save_system_proxy_state(state: &SystemProxyState) -> Result<()> {
    let path = system_proxy_state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed creating proxy state directory {}", parent.display())
        })?;
    }
    let body = serde_json::to_string_pretty(state)?;
    std::fs::write(&path, body)
        .with_context(|| format!("failed writing system proxy state {}", path.display()))?;
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn remove_system_proxy_state() {
    let _ = std::fs::remove_file(system_proxy_state_path());
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|v| v.as_secs())
        .unwrap_or(0)
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn system_proxy_owner_path() -> PathBuf {
    soth_home_dir().join("run").join(SYSTEM_PROXY_OWNER_FILE)
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn load_system_proxy_owner_id() -> Result<Option<String>> {
    let path = system_proxy_owner_path();
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed reading system proxy owner id {}", path.display()))?;
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    Ok(Some(value.to_string()))
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn save_system_proxy_owner_id(owner_id: &str) -> Result<()> {
    let path = system_proxy_owner_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed creating proxy owner directory {}", parent.display())
        })?;
    }
    std::fs::write(&path, format!("{owner_id}\n"))
        .with_context(|| format!("failed writing system proxy owner id {}", path.display()))?;
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn local_system_proxy_owner_id() -> Result<String> {
    if let Some(owner_id) = load_system_proxy_owner_id()? {
        return Ok(owner_id);
    }
    let owner_id = uuid::Uuid::new_v4().to_string();
    save_system_proxy_owner_id(&owner_id)?;
    Ok(owner_id)
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn assert_state_owner_matches_local(state: &SystemProxyState) -> Result<()> {
    match load_system_proxy_owner_id()? {
        Some(local_owner_id) => {
            if local_owner_id == state.owner_id {
                Ok(())
            } else {
                anyhow::bail!(
                    "system proxy state owner mismatch (state={}, local={}): refusing restore",
                    state.owner_id,
                    local_owner_id
                )
            }
        }
        None => {
            // One-time migration for older installs without explicit owner marker.
            save_system_proxy_owner_id(&state.owner_id)?;
            Ok(())
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn merge_proxy_bypass_domains(existing: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut merged = Vec::new();

    for domain in existing {
        let value = domain.trim();
        if value.is_empty() {
            continue;
        }
        let key = value.to_ascii_lowercase();
        if seen.insert(key) {
            merged.push(value.to_string());
        }
    }

    for domain in PROXY_BYPASS_DOMAINS {
        let key = domain.to_ascii_lowercase();
        if seen.insert(key) {
            merged.push((*domain).to_string());
        }
    }
    merged
}

// === macOS Implementation ===

#[cfg(target_os = "macos")]
async fn configure_macos_proxy(enable: bool, port: u16, print_user_output: bool) -> Result<()> {
    let services = get_macos_network_services()?;

    if enable {
        if let Some(existing_state) = load_system_proxy_state()? {
            if existing_state.platform != "macos" {
                anyhow::bail!(
                    "system proxy state exists for platform {} and cannot be modified by macOS flow",
                    existing_state.platform
                );
            }
            assert_state_owner_matches_local(&existing_state)?;
        } else {
            let snapshot = capture_macos_proxy_snapshot(&services)?;
            let owner_id = local_system_proxy_owner_id()?;
            let state = SystemProxyState {
                schema_version: 1,
                platform: "macos".to_string(),
                owner_id,
                created_at_unix_secs: now_unix_secs(),
                port,
                macos: Some(snapshot),
            };
            save_system_proxy_state(&state)?;
        }

        for service in &services {
            run_networksetup(&["-setwebproxy", service, "127.0.0.1", &port.to_string()])?;
            run_networksetup(&["-setwebproxystate", service, "on"])?;
            run_networksetup(&[
                "-setsecurewebproxy",
                service,
                "127.0.0.1",
                &port.to_string(),
            ])?;
            run_networksetup(&["-setsecurewebproxystate", service, "on"])?;

            let current_bypass = get_macos_proxy_bypass_domains(service).unwrap_or_default();
            let merged = merge_proxy_bypass_domains(&current_bypass);
            set_macos_proxy_bypass_domains(service, &merged)?;
            info!("Enabled proxy for network service: {}", service);
        }
    } else if let Some(state) = load_system_proxy_state()? {
        if state.platform == "macos" {
            assert_state_owner_matches_local(&state)?;
            if let Some(snapshot) = state.macos.as_ref() {
                restore_macos_proxy_snapshot(snapshot)?;
            } else {
                anyhow::bail!(
                    "system proxy state found for macOS but snapshot payload is missing; refusing blind proxy disable"
                );
            }
            remove_system_proxy_state();
        } else {
            anyhow::bail!(
                "system proxy state exists for platform {} and cannot be safely restored on macOS",
                state.platform
            );
        }
    } else {
        // Fail-open + safety: never attempt a blind disable without a known snapshot.
        // If the proxy appears inactive, treat this as idempotent success.
        // If loopback proxies are active, preserve them and warn (manual intervention).
        let active_loopback_services = list_macos_services_using_loopback_proxy(&services);
        if active_loopback_services.is_empty() {
            warn!(
                "System proxy state missing during macOS disable; no loopback proxy active, treating as no-op"
            );
            if print_user_output {
                println!(
                    "   {} System proxy state missing; no loopback proxy active (no-op).",
                    style::INFO
                );
            }
            return Ok(());
        }

        let service_list = active_loopback_services.join(", ");
        warn!(
            services = %service_list,
            "System proxy state missing during macOS disable; preserving active loopback proxies (no blind changes)"
        );
        if print_user_output {
            println!(
                "   {} System proxy state missing; preserving active loopback proxy settings for: {}",
                style::WARNING,
                service_list
            );
            println!(
                "   {} If this is stale SOTH state, run: soth on --port {}  then  soth off",
                style::INFO,
                port
            );
        }
        return Ok(());
    }

    if print_user_output {
        if services.is_empty() {
            println!(
                "   {} No network services found to configure",
                style::WARNING
            );
        } else {
            for service in &services {
                println!("   {} Configured: {}", style::CHECK, service);
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn is_loopback_host(host: &str) -> bool {
    matches!(
        host.trim().to_ascii_lowercase().as_str(),
        "127.0.0.1" | "localhost" | "::1"
    )
}

#[cfg(target_os = "macos")]
fn list_macos_services_using_loopback_proxy(services: &[String]) -> Vec<String> {
    let mut active = Vec::new();
    for service in services {
        let web = get_macos_proxy_endpoint(service, false).ok();
        let secure = get_macos_proxy_endpoint(service, true).ok();

        let web_enabled = web
            .as_ref()
            .map(|snapshot| {
                snapshot.enabled
                    && snapshot
                        .host
                        .as_deref()
                        .map(is_loopback_host)
                        .unwrap_or(false)
            })
            .unwrap_or(false);

        let secure_enabled = secure
            .as_ref()
            .map(|snapshot| {
                snapshot.enabled
                    && snapshot
                        .host
                        .as_deref()
                        .map(is_loopback_host)
                        .unwrap_or(false)
            })
            .unwrap_or(false);

        if web_enabled || secure_enabled {
            active.push(service.clone());
        }
    }
    active
}

#[cfg(target_os = "macos")]
fn capture_macos_proxy_snapshot(services: &[String]) -> Result<MacosProxySnapshot> {
    let mut snapshots = Vec::with_capacity(services.len());
    for service in services {
        let web = get_macos_proxy_endpoint(service, false)?;
        let secure = get_macos_proxy_endpoint(service, true)?;
        let bypass_domains = get_macos_proxy_bypass_domains(service).unwrap_or_default();
        snapshots.push(MacosServiceSnapshot {
            service: service.clone(),
            web,
            secure,
            bypass_domains,
        });
    }
    Ok(MacosProxySnapshot {
        services: snapshots,
    })
}

#[cfg(target_os = "macos")]
fn restore_macos_proxy_snapshot(snapshot: &MacosProxySnapshot) -> Result<()> {
    for service in &snapshot.services {
        restore_macos_proxy_endpoint(&service.service, false, &service.web)?;
        restore_macos_proxy_endpoint(&service.service, true, &service.secure)?;
        set_macos_proxy_bypass_domains(&service.service, &service.bypass_domains)?;
        info!(
            "Restored proxy state for network service: {}",
            service.service
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn get_macos_network_services() -> Result<Vec<String>> {
    let output = Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()
        .context("Failed to list network services")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "networksetup -listallnetworkservices failed: {} {}",
            stdout.trim(),
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("AuthorizationCreate() failed")
        || stdout.contains("requires admin privileges")
    {
        anyhow::bail!("unable to read macOS network services: {}", stdout.trim());
    }
    let mut services = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        // Skip the header line and disabled services (marked with *)
        if line.is_empty()
            || line.starts_with('*')
            || line.contains("denotes")
            || line.contains("AuthorizationCreate() failed")
            || line.contains("requires admin privileges")
            || line.starts_with("** Error")
        {
            continue;
        }
        // Check if this is a known/common service we should configure
        if MACOS_NETWORK_SERVICES.iter().any(|s| line.contains(s)) || line.contains("Ethernet") {
            services.push(line.to_string());
        }
    }

    // If no known services found, try all active ones
    if services.is_empty() {
        for line in stdout.lines() {
            let line = line.trim();
            if !line.is_empty()
                && !line.starts_with('*')
                && !line.contains("denotes")
                && !line.contains("AuthorizationCreate() failed")
                && !line.contains("requires admin privileges")
                && !line.starts_with("** Error")
            {
                services.push(line.to_string());
            }
        }
    }

    debug!("Found network services: {:?}", services);
    Ok(services)
}

#[cfg(target_os = "macos")]
fn run_networksetup(args: &[&str]) -> Result<()> {
    debug!("Running: networksetup {:?}", args);
    let output = Command::new("networksetup")
        .args(args)
        .output()
        .with_context(|| format!("Failed to run networksetup {args:?}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let combined = format!("{} {}", stdout.trim(), stderr.trim());

        // Skip known non-fatal "service not found" cases only.
        if combined.contains("not recognized") || combined.contains("not exist") {
            debug!("networksetup warning: {}", combined);
            return Ok(());
        }

        // Fail fast on auth/permission errors and other command failures.
        anyhow::bail!("networksetup {:?} failed: {}", args, combined.trim());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_networksetup_read(args: &[&str]) -> Result<String> {
    debug!("Running (read): networksetup {:?}", args);
    let output = Command::new("networksetup")
        .args(args)
        .output()
        .with_context(|| format!("Failed to run networksetup {args:?}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "networksetup {:?} failed: {} {}",
            args,
            stdout.trim(),
            stderr.trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(target_os = "macos")]
fn parse_macos_proxy_endpoint(stdout: &str) -> ProxyEndpointSnapshot {
    let mut enabled = false;
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("Enabled:") {
            enabled = value.trim().eq_ignore_ascii_case("yes");
        } else if let Some(value) = trimmed.strip_prefix("Server:") {
            let value = value.trim();
            if !value.is_empty() {
                host = Some(value.to_string());
            }
        } else if let Some(value) = trimmed.strip_prefix("Port:") {
            port = value.trim().parse::<u16>().ok();
        }
    }
    ProxyEndpointSnapshot {
        enabled,
        host,
        port,
    }
}

#[cfg(target_os = "macos")]
fn get_macos_proxy_endpoint(service: &str, secure: bool) -> Result<ProxyEndpointSnapshot> {
    let stdout = if secure {
        run_networksetup_read(&["-getsecurewebproxy", service])?
    } else {
        run_networksetup_read(&["-getwebproxy", service])?
    };
    Ok(parse_macos_proxy_endpoint(&stdout))
}

#[cfg(target_os = "macos")]
fn restore_macos_proxy_endpoint(
    service: &str,
    secure: bool,
    snapshot: &ProxyEndpointSnapshot,
) -> Result<()> {
    let (set_cmd, state_cmd) = if secure {
        ("-setsecurewebproxy", "-setsecurewebproxystate")
    } else {
        ("-setwebproxy", "-setwebproxystate")
    };

    if snapshot.enabled {
        let host = snapshot.host.as_deref().unwrap_or("127.0.0.1");
        let port = snapshot.port.unwrap_or(DEFAULT_PROXY_PORT).to_string();
        run_networksetup(&[set_cmd, service, host, &port])?;
        run_networksetup(&[state_cmd, service, "on"])?;
    } else {
        run_networksetup(&[state_cmd, service, "off"])?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn get_macos_proxy_bypass_domains(service: &str) -> Result<Vec<String>> {
    let stdout = run_networksetup_read(&["-getproxybypassdomains", service])?;
    if stdout
        .to_ascii_lowercase()
        .contains("there aren't any bypass domains")
    {
        return Ok(Vec::new());
    }
    let mut domains = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("currently set to") || trimmed.contains("bypass domains") {
            continue;
        }
        domains.push(trimmed.to_string());
    }
    Ok(domains)
}

#[cfg(target_os = "macos")]
fn set_macos_proxy_bypass_domains(service: &str, domains: &[String]) -> Result<()> {
    let mut args = vec!["-setproxybypassdomains", service];
    for domain in domains {
        args.push(domain.as_str());
    }
    run_networksetup(&args)
}

#[cfg(target_os = "macos")]
async fn check_macos_proxy_status() -> Result<bool> {
    let services = get_macos_network_services()?;

    for service in &services {
        let output = Command::new("networksetup")
            .args(["-getsecurewebproxy", service])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("Enabled: Yes") {
            return Ok(true);
        }
    }

    Ok(false)
}

// === Linux Implementation ===

#[cfg(target_os = "linux")]
async fn configure_linux_proxy(enable: bool, port: u16, print_user_output: bool) -> Result<bool> {
    // Try GNOME gsettings first
    if which::which("gsettings").is_ok() {
        configure_gnome_proxy(enable, port, print_user_output)?;
        return Ok(true);
    }

    // Fall back to environment variable instructions
    if print_user_output {
        if enable {
            println!("   {} Add to your shell profile:", style::INFO);
            println!("      export https_proxy=\"http://127.0.0.1:{}\"", port);
            println!("      export HTTPS_PROXY=\"http://127.0.0.1:{}\"", port);
            println!("      export no_proxy=\"localhost,127.0.0.1,::1,*.local\"");
            println!("      export NO_PROXY=\"localhost,127.0.0.1,::1,*.local\"");
        } else {
            println!("   {} Remove from your shell profile:", style::INFO);
            println!("      unset https_proxy HTTPS_PROXY no_proxy NO_PROXY");
        }
    }

    Ok(false)
}

#[cfg(target_os = "linux")]
fn configure_gnome_proxy(enable: bool, port: u16, print_user_output: bool) -> Result<()> {
    if enable {
        if let Some(existing_state) = load_system_proxy_state()? {
            if existing_state.platform != "linux" {
                anyhow::bail!(
                    "system proxy state exists for platform {} and cannot be modified by Linux flow",
                    existing_state.platform
                );
            }
            assert_state_owner_matches_local(&existing_state)?;
        } else {
            let snapshot = capture_linux_proxy_snapshot()?;
            let owner_id = local_system_proxy_owner_id()?;
            let state = SystemProxyState {
                schema_version: 1,
                platform: "linux".to_string(),
                owner_id,
                created_at_unix_secs: now_unix_secs(),
                port,
                linux: Some(snapshot),
            };
            save_system_proxy_state(&state)?;
        }

        run_gsettings(&["set", "org.gnome.system.proxy", "mode", "'manual'"])?;
        run_gsettings(&["set", "org.gnome.system.proxy.https", "host", "'127.0.0.1'"])?;
        run_gsettings(&[
            "set",
            "org.gnome.system.proxy.https",
            "port",
            &port.to_string(),
        ])?;
        run_gsettings(&["set", "org.gnome.system.proxy.http", "host", "'127.0.0.1'"])?;
        run_gsettings(&[
            "set",
            "org.gnome.system.proxy.http",
            "port",
            &port.to_string(),
        ])?;

        let existing_ignore_hosts = get_linux_ignore_hosts().unwrap_or_default();
        let merged_ignore_hosts = merge_proxy_bypass_domains(&existing_ignore_hosts);
        let ignore_hosts_literal = format!(
            "[{}]",
            merged_ignore_hosts
                .iter()
                .map(|value| format!("'{}'", value.replace('\'', "\\'")))
                .collect::<Vec<_>>()
                .join(", ")
        );
        run_gsettings(&[
            "set",
            "org.gnome.system.proxy",
            "ignore-hosts",
            ignore_hosts_literal.as_str(),
        ])?;
        if print_user_output {
            println!("   {} Configured GNOME proxy settings", style::CHECK);
        }
    } else {
        if let Some(state) = load_system_proxy_state()? {
            if state.platform == "linux" {
                assert_state_owner_matches_local(&state)?;
                if let Some(snapshot) = state.linux.as_ref() {
                    restore_linux_proxy_snapshot(snapshot)?;
                } else {
                    anyhow::bail!(
                        "system proxy state found for linux but snapshot payload is missing; refusing blind proxy disable"
                    );
                }
                remove_system_proxy_state();
            } else {
                anyhow::bail!(
                    "system proxy state exists for platform {} and cannot be safely restored on Linux",
                    state.platform
                );
            }
        } else {
            anyhow::bail!("system proxy state missing; refusing blind Linux proxy disable");
        }
        if print_user_output {
            println!("   {} Restored GNOME proxy settings", style::CHECK);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn capture_linux_proxy_snapshot() -> Result<LinuxProxySnapshot> {
    Ok(LinuxProxySnapshot {
        mode: get_linux_proxy_mode().unwrap_or_else(|| "none".to_string()),
        http: ProxyEndpointSnapshot {
            enabled: false,
            host: get_linux_proxy_host("http"),
            port: get_linux_proxy_port("http"),
        },
        https: ProxyEndpointSnapshot {
            enabled: false,
            host: get_linux_proxy_host("https"),
            port: get_linux_proxy_port("https"),
        },
        ignore_hosts: get_linux_ignore_hosts().unwrap_or_default(),
    })
}

#[cfg(target_os = "linux")]
fn restore_linux_proxy_snapshot(snapshot: &LinuxProxySnapshot) -> Result<()> {
    run_gsettings(&[
        "set",
        "org.gnome.system.proxy",
        "mode",
        format!("'{}'", snapshot.mode).as_str(),
    ])?;

    if let Some(host) = snapshot.http.host.as_deref() {
        run_gsettings(&[
            "set",
            "org.gnome.system.proxy.http",
            "host",
            format!("'{host}'").as_str(),
        ])?;
    }
    if let Some(port) = snapshot.http.port {
        run_gsettings(&[
            "set",
            "org.gnome.system.proxy.http",
            "port",
            &port.to_string(),
        ])?;
    }

    if let Some(host) = snapshot.https.host.as_deref() {
        run_gsettings(&[
            "set",
            "org.gnome.system.proxy.https",
            "host",
            format!("'{host}'").as_str(),
        ])?;
    }
    if let Some(port) = snapshot.https.port {
        run_gsettings(&[
            "set",
            "org.gnome.system.proxy.https",
            "port",
            &port.to_string(),
        ])?;
    }

    let ignore_hosts_literal = format!(
        "[{}]",
        snapshot
            .ignore_hosts
            .iter()
            .map(|value| format!("'{}'", value.replace('\'', "\\'")))
            .collect::<Vec<_>>()
            .join(", ")
    );
    run_gsettings(&[
        "set",
        "org.gnome.system.proxy",
        "ignore-hosts",
        ignore_hosts_literal.as_str(),
    ])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_gsettings(args: &[&str]) -> Result<()> {
    let output = Command::new("gsettings")
        .args(args)
        .output()
        .with_context(|| format!("Failed to run gsettings {:?}", args))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "gsettings {:?} failed: {} {}",
            args,
            stdout.trim(),
            stderr.trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_gsettings_get(schema: &str, key: &str) -> Option<String> {
    let output = Command::new("gsettings")
        .args(["get", schema, key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(target_os = "linux")]
fn parse_gsettings_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "nothing" {
        return None;
    }
    Some(trimmed.trim_matches('\'').to_string())
}

#[cfg(target_os = "linux")]
fn parse_gsettings_u16(value: &str) -> Option<u16> {
    value.trim().parse::<u16>().ok()
}

#[cfg(target_os = "linux")]
fn parse_gsettings_list(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Vec::new();
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    inner
        .split(',')
        .filter_map(|item| {
            let normalized = item.trim().trim_matches('\'').trim().to_string();
            if normalized.is_empty() {
                None
            } else {
                Some(normalized)
            }
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn get_linux_proxy_mode() -> Option<String> {
    run_gsettings_get("org.gnome.system.proxy", "mode").and_then(|raw| parse_gsettings_string(&raw))
}

#[cfg(target_os = "linux")]
fn get_linux_proxy_host(protocol: &str) -> Option<String> {
    let schema = format!("org.gnome.system.proxy.{protocol}");
    run_gsettings_get(&schema, "host").and_then(|raw| parse_gsettings_string(&raw))
}

#[cfg(target_os = "linux")]
fn get_linux_proxy_port(protocol: &str) -> Option<u16> {
    let schema = format!("org.gnome.system.proxy.{protocol}");
    run_gsettings_get(&schema, "port").and_then(|raw| parse_gsettings_u16(&raw))
}

#[cfg(target_os = "linux")]
fn get_linux_ignore_hosts() -> Option<Vec<String>> {
    run_gsettings_get("org.gnome.system.proxy", "ignore-hosts")
        .map(|raw| parse_gsettings_list(&raw))
}

#[cfg(target_os = "linux")]
async fn check_linux_proxy_status() -> Result<bool> {
    if which::which("gsettings").is_ok() {
        let output = Command::new("gsettings")
            .args(["get", "org.gnome.system.proxy", "mode"])
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Ok(stdout.contains("manual"));
    }

    // Check environment variables
    Ok(std::env::var("https_proxy").is_ok() || std::env::var("HTTPS_PROXY").is_ok())
}

// === Windows Implementation ===

#[cfg(target_os = "windows")]
async fn configure_windows_proxy(enable: bool, port: u16, print_user_output: bool) -> Result<()> {
    use std::os::windows::process::CommandExt;

    let proxy_server = format!("127.0.0.1:{}", port);
    let proxy_bypass = "localhost;127.0.0.1;::1;*.local;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;<local>";

    if enable {
        if let Some(existing_state) = load_system_proxy_state()? {
            if existing_state.platform != "windows" {
                anyhow::bail!(
                    "system proxy state exists for platform {} and cannot be modified by Windows flow",
                    existing_state.platform
                );
            }
            assert_state_owner_matches_local(&existing_state)?;
        } else {
            let owner_id = local_system_proxy_owner_id()?;
            let state = SystemProxyState {
                schema_version: 1,
                platform: "windows".to_string(),
                owner_id,
                created_at_unix_secs: now_unix_secs(),
                port,
                windows: Some(capture_windows_proxy_snapshot()?),
            };
            save_system_proxy_state(&state)?;
        }
        apply_windows_proxy_manual(&proxy_server, proxy_bypass)?;
        if print_user_output {
            println!("   {} Configured Windows proxy settings", style::CHECK);
        }
    } else {
        if let Some(state) = load_system_proxy_state()? {
            if state.platform != "windows" {
                anyhow::bail!(
                    "system proxy state exists for platform {} and cannot be safely restored on Windows",
                    state.platform
                );
            }
            assert_state_owner_matches_local(&state)?;
            if let Some(snapshot) = state.windows.as_ref() {
                restore_windows_proxy_snapshot(snapshot)?;
            } else {
                anyhow::bail!(
                    "system proxy state found for windows but snapshot payload is missing; refusing blind proxy disable"
                );
            }
            remove_system_proxy_state();
        } else {
            anyhow::bail!("system proxy state missing; refusing blind Windows proxy disable");
        }
        if print_user_output {
            println!("   {} Restored Windows proxy settings", style::CHECK);
        }
    }

    // Notify system of proxy change
    let _ = Command::new("cmd")
        .args(["/C", "RUNDLL32.EXE", "inetcpl.cpl,LaunchConnectionDialog"])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output();

    Ok(())
}

#[cfg(target_os = "windows")]
fn apply_windows_proxy_manual(proxy_server: &str, proxy_bypass: &str) -> Result<()> {
    run_reg_add(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "ProxyEnable",
        "REG_DWORD",
        "1",
    )?;
    run_reg_add(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "ProxyServer",
        "REG_SZ",
        proxy_server,
    )?;
    run_reg_add(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "ProxyOverride",
        "REG_SZ",
        proxy_bypass,
    )?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn capture_windows_proxy_snapshot() -> Result<WindowsProxySnapshot> {
    Ok(WindowsProxySnapshot {
        enabled: read_windows_proxy_enabled()?,
        proxy_server: read_windows_string_value("ProxyServer")?,
        proxy_override: read_windows_string_value("ProxyOverride")?,
    })
}

#[cfg(target_os = "windows")]
fn restore_windows_proxy_snapshot(snapshot: &WindowsProxySnapshot) -> Result<()> {
    run_reg_add(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "ProxyEnable",
        "REG_DWORD",
        if snapshot.enabled { "1" } else { "0" },
    )?;

    match snapshot.proxy_server.as_deref() {
        Some(value) if !value.trim().is_empty() => run_reg_add(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyServer",
            "REG_SZ",
            value,
        )?,
        _ => run_reg_delete(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyServer",
        )?,
    }

    match snapshot.proxy_override.as_deref() {
        Some(value) if !value.trim().is_empty() => run_reg_add(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyOverride",
            "REG_SZ",
            value,
        )?,
        _ => run_reg_delete(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyOverride",
        )?,
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn parse_windows_reg_value(stdout: &str, value_name: &str) -> Option<(String, String)> {
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        if !name.eq_ignore_ascii_case(value_name) {
            continue;
        }
        let Some(value_type) = parts.next() else {
            continue;
        };
        let data = parts.collect::<Vec<_>>().join(" ");
        return Some((value_type.to_string(), data.trim().to_string()));
    }
    None
}

#[cfg(target_os = "windows")]
fn query_windows_reg_value(value_name: &str) -> Result<Option<(String, String)>> {
    use std::os::windows::process::CommandExt;

    let output = Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            value_name,
        ])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .with_context(|| format!("Failed to query registry value {value_name}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr.contains("unable to find") || stderr.contains("cannot find") {
            return Ok(None);
        }
        anyhow::bail!(
            "Failed querying registry value {}: {}",
            value_name,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_windows_reg_value(&stdout, value_name))
}

#[cfg(target_os = "windows")]
fn read_windows_proxy_enabled() -> Result<bool> {
    let Some((value_type, value)) = query_windows_reg_value("ProxyEnable")? else {
        return Ok(false);
    };
    if !value_type.eq_ignore_ascii_case("REG_DWORD") {
        return Ok(false);
    }
    let normalized = value.trim();
    if let Some(hex) = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("0X"))
    {
        return Ok(u32::from_str_radix(hex, 16).unwrap_or(0) != 0);
    }
    Ok(normalized.parse::<u32>().unwrap_or(0) != 0)
}

#[cfg(target_os = "windows")]
fn read_windows_string_value(value_name: &str) -> Result<Option<String>> {
    let Some((value_type, value)) = query_windows_reg_value(value_name)? else {
        return Ok(None);
    };
    if !value_type.eq_ignore_ascii_case("REG_SZ")
        && !value_type.eq_ignore_ascii_case("REG_EXPAND_SZ")
    {
        return Ok(None);
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

#[cfg(target_os = "windows")]
fn run_reg_delete(key: &str, value: &str) -> Result<()> {
    use std::os::windows::process::CommandExt;

    let output = Command::new("reg")
        .args(["delete", key, "/v", value, "/f"])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .context("Failed to run reg delete command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if stderr.contains("unable to find") || stderr.contains("cannot find") {
            return Ok(());
        }
        anyhow::bail!(
            "Failed to delete registry value {}: {}",
            value,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_reg_add(key: &str, value: &str, value_type: &str, data: &str) -> Result<()> {
    use std::os::windows::process::CommandExt;

    let output = Command::new("reg")
        .args(["add", key, "/v", value, "/t", value_type, "/d", data, "/f"])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .context("Failed to run reg command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to set registry: {}", stderr);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn check_windows_proxy_status() -> Result<bool> {
    read_windows_proxy_enabled()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn with_temp_home<T>(f: impl FnOnce() -> T) -> T {
        let guard = crate::commands::proxy::lock_test_env();
        let temp = tempfile::tempdir().expect("tempdir");
        let old_home = env::var_os("HOME");
        let old_soth_home = env::var_os("SOTH_HOME_DIR");
        let soth_home = temp.path().join(".soth");
        unsafe {
            env::set_var("HOME", temp.path());
            env::set_var("SOTH_HOME_DIR", &soth_home);
        }
        let result = f();
        match old_home {
            Some(value) => unsafe {
                env::set_var("HOME", value);
            },
            None => unsafe {
                env::remove_var("HOME");
            },
        }
        match old_soth_home {
            Some(value) => unsafe {
                env::set_var("SOTH_HOME_DIR", value);
            },
            None => unsafe {
                env::remove_var("SOTH_HOME_DIR");
            },
        }
        drop(guard);
        result
    }

    #[test]
    fn test_get_ca_path() {
        let path = get_ca_path();
        assert!(path.to_string_lossy().contains(".soth"));
        assert!(path.to_string_lossy().contains("soth-mitm-ca.pem"));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn test_merge_proxy_bypass_domains_preserves_existing_and_adds_defaults() {
        let merged =
            merge_proxy_bypass_domains(&["example.com".to_string(), "localhost".to_string()]);
        assert!(merged.contains(&"example.com".to_string()));
        assert!(merged.contains(&"localhost".to_string()));
        assert!(merged.contains(&"127.0.0.1".to_string()));
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn test_local_owner_id_persists() {
        with_temp_home(|| {
            let first = local_system_proxy_owner_id().expect("owner id");
            let second = local_system_proxy_owner_id().expect("owner id");
            assert_eq!(first, second);
        });
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn test_owner_mismatch_is_rejected() {
        with_temp_home(|| {
            save_system_proxy_owner_id("owner-a").expect("save owner");
            let state = SystemProxyState {
                schema_version: 1,
                platform: {
                    #[cfg(target_os = "macos")]
                    {
                        "macos".to_string()
                    }
                    #[cfg(target_os = "linux")]
                    {
                        "linux".to_string()
                    }
                    #[cfg(target_os = "windows")]
                    {
                        "windows".to_string()
                    }
                },
                owner_id: "owner-b".to_string(),
                created_at_unix_secs: 0,
                port: 8080,
                #[cfg(target_os = "macos")]
                macos: Some(MacosProxySnapshot {
                    services: Vec::new(),
                }),
                #[cfg(target_os = "linux")]
                linux: Some(LinuxProxySnapshot {
                    mode: "none".to_string(),
                    http: ProxyEndpointSnapshot {
                        enabled: false,
                        host: None,
                        port: None,
                    },
                    https: ProxyEndpointSnapshot {
                        enabled: false,
                        host: None,
                        port: None,
                    },
                    ignore_hosts: Vec::new(),
                }),
                #[cfg(target_os = "windows")]
                windows: Some(WindowsProxySnapshot {
                    enabled: false,
                    proxy_server: None,
                    proxy_override: None,
                }),
            };
            let result = assert_state_owner_matches_local(&state);
            assert!(result.is_err());
        });
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_windows_reg_value_dword() {
        let sample = r#"
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ProxyEnable    REG_DWORD    0x1
"#;
        let parsed = parse_windows_reg_value(sample, "ProxyEnable");
        assert_eq!(parsed, Some(("REG_DWORD".to_string(), "0x1".to_string())));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_windows_reg_value_string() {
        let sample = r#"
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ProxyServer    REG_SZ    127.0.0.1:18881
"#;
        let parsed = parse_windows_reg_value(sample, "ProxyServer");
        assert_eq!(
            parsed,
            Some(("REG_SZ".to_string(), "127.0.0.1:18881".to_string()))
        );
    }
}
