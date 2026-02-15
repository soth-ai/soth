//! System proxy auto-configuration
//!
//! Commands for configuring the system to route traffic through SOTH proxy:
//! - `soth on` - Enable system proxy settings
//! - `soth off` - Disable system proxy settings

use crate::style;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, info};

/// Network services to configure on macOS
const MACOS_NETWORK_SERVICES: &[&str] = &["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"];

/// Default proxy port
const DEFAULT_PROXY_PORT: u16 = 8080;

/// Enable system proxy settings
pub async fn enable(port: Option<u16>) -> Result<()> {
    enable_internal(port, true).await
}

/// Enable system proxy settings without printing user-facing output.
pub async fn enable_quiet(port: Option<u16>) -> Result<()> {
    enable_internal(port, false).await
}

async fn enable_internal(port: Option<u16>, print_user_output: bool) -> Result<()> {
    let proxy_port = port.unwrap_or(DEFAULT_PROXY_PORT);
    let proxy_addr = format!("127.0.0.1:{}", proxy_port);

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
        configure_linux_proxy(true, proxy_port, print_user_output).await?;
    }

    #[cfg(target_os = "windows")]
    {
        configure_windows_proxy(true, proxy_port, print_user_output).await?;
    }

    if print_user_output {
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
                style::highlight("soth runtime setup-ca")
            );
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
        configure_linux_proxy(false, 0, print_user_output).await?;
    }

    #[cfg(target_os = "windows")]
    {
        configure_windows_proxy(false, 0, print_user_output).await?;
    }

    if print_user_output {
        println!("\n{} System proxy disabled", style::success_prefix());
        println!("   Direct connections restored");
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

    #[allow(unreachable_code)]
    Ok(false)
}

fn get_ca_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".soth")
        .join("ca")
        .join("ca.crt")
}

// === macOS Implementation ===

/// Domains to bypass proxy (localhost and local network)
const PROXY_BYPASS_DOMAINS: &str = "localhost,127.0.0.1,::1,*.local,192.168.*,10.*,172.16.*,172.17.*,172.18.*,172.19.*,172.20.*,172.21.*,172.22.*,172.23.*,172.24.*,172.25.*,172.26.*,172.27.*,172.28.*,172.29.*,172.30.*,172.31.*";

#[cfg(target_os = "macos")]
async fn configure_macos_proxy(enable: bool, port: u16, print_user_output: bool) -> Result<()> {
    // Get list of network services
    let services = get_macos_network_services()?;

    for service in &services {
        if enable {
            // Enable web proxy (HTTP)
            run_networksetup(&["-setwebproxy", service, "127.0.0.1", &port.to_string()])?;
            run_networksetup(&["-setwebproxystate", service, "on"])?;

            // Enable secure web proxy (HTTPS)
            run_networksetup(&[
                "-setsecurewebproxy",
                service,
                "127.0.0.1",
                &port.to_string(),
            ])?;
            run_networksetup(&["-setsecurewebproxystate", service, "on"])?;

            // Set proxy bypass domains (critical to avoid localhost loops)
            run_networksetup(&["-setproxybypassdomains", service, PROXY_BYPASS_DOMAINS])?;

            info!("Enabled proxy for network service: {}", service);
        } else {
            // Disable web proxy
            run_networksetup(&["-setwebproxystate", service, "off"])?;

            // Disable secure web proxy
            run_networksetup(&["-setsecurewebproxystate", service, "off"])?;

            // Clear proxy bypass domains
            run_networksetup(&["-setproxybypassdomains", service, ""])?;

            info!("Disabled proxy for network service: {}", service);
        }
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
fn get_macos_network_services() -> Result<Vec<String>> {
    let output = Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()
        .context("Failed to list network services")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut services = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        // Skip the header line and disabled services (marked with *)
        if line.is_empty() || line.starts_with('*') || line.contains("denotes") {
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
            if !line.is_empty() && !line.starts_with('*') && !line.contains("denotes") {
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
        .with_context(|| format!("Failed to run networksetup {:?}", args))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Some errors are expected (e.g., service doesn't exist)
        if !stderr.contains("not recognized") && !stderr.contains("not exist") {
            debug!("networksetup warning: {}", stderr);
        }
    }
    Ok(())
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
async fn configure_linux_proxy(enable: bool, port: u16, print_user_output: bool) -> Result<()> {
    // Try GNOME gsettings first
    if which::which("gsettings").is_ok() {
        configure_gnome_proxy(enable, port, print_user_output)?;
        return Ok(());
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

    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_gnome_proxy(enable: bool, port: u16, print_user_output: bool) -> Result<()> {
    if enable {
        // Set proxy mode to manual
        run_gsettings(&["set", "org.gnome.system.proxy", "mode", "'manual'"])?;
        // Set HTTPS proxy
        run_gsettings(&["set", "org.gnome.system.proxy.https", "host", "'127.0.0.1'"])?;
        run_gsettings(&[
            "set",
            "org.gnome.system.proxy.https",
            "port",
            &port.to_string(),
        ])?;
        // Set HTTP proxy
        run_gsettings(&["set", "org.gnome.system.proxy.http", "host", "'127.0.0.1'"])?;
        run_gsettings(&[
            "set",
            "org.gnome.system.proxy.http",
            "port",
            &port.to_string(),
        ])?;
        // Set ignore hosts (bypass proxy for local addresses)
        run_gsettings(&[
            "set",
            "org.gnome.system.proxy",
            "ignore-hosts",
            "\"['localhost', '127.0.0.0/8', '::1', '*.local']\"",
        ])?;
        if print_user_output {
            println!("   {} Configured GNOME proxy settings", style::CHECK);
        }
    } else {
        // Set proxy mode to none
        run_gsettings(&["set", "org.gnome.system.proxy", "mode", "'none'"])?;
        if print_user_output {
            println!("   {} Disabled GNOME proxy settings", style::CHECK);
        }
    }
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
        debug!("gsettings warning: {}", stderr);
    }
    Ok(())
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
    // Windows proxy bypass list
    let proxy_bypass = "localhost;127.0.0.1;::1;*.local;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;<local>";

    if enable {
        // Enable proxy
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
            &proxy_server,
        )?;
        // Set proxy bypass (ProxyOverride)
        run_reg_add(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyOverride",
            "REG_SZ",
            proxy_bypass,
        )?;
        if print_user_output {
            println!("   {} Configured Windows proxy settings", style::CHECK);
        }
    } else {
        // Disable proxy
        run_reg_add(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyEnable",
            "REG_DWORD",
            "0",
        )?;
        if print_user_output {
            println!("   {} Disabled Windows proxy settings", style::CHECK);
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
    use std::os::windows::process::CommandExt;

    let output = Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyEnable",
        ])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains("0x1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ca_path() {
        let path = get_ca_path();
        assert!(path.to_string_lossy().contains(".soth"));
        assert!(path.to_string_lossy().contains("ca.crt"));
    }
}
