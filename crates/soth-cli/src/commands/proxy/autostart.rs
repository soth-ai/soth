//! Cross-platform autostart registration for the sensor daemon.
//!
//! Goal: once the daemon is started explicitly, persist startup registration so
//! it comes back on boot/login without requiring manual re-configuration.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "soth-proxy";

fn resolve_abs_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir().context("failed resolving current working directory")?;
    Ok(cwd.join(path))
}

fn build_args(port: u16, config_path: Option<&PathBuf>) -> Result<Vec<String>> {
    let mut args = vec![
        "start".to_string(),
        "--foreground".to_string(),
        "--quiet".to_string(),
        "--port".to_string(),
        port.to_string(),
    ];
    if let Some(config_path) = config_path {
        let abs = resolve_abs_path(config_path)?;
        args.push("--config".to_string());
        args.push(abs.display().to_string());
    }
    Ok(args)
}

fn current_exe() -> Result<PathBuf> {
    std::env::current_exe().context("failed resolving current executable for autostart")
}

pub fn ensure_enabled(port: u16, config_path: Option<&PathBuf>) -> Result<String> {
    let exe = current_exe()?;
    let args = build_args(port, config_path)?;
    #[cfg(target_os = "macos")]
    {
        ensure_macos_launch_agent(&exe, &args)
    }
    #[cfg(target_os = "linux")]
    {
        ensure_linux_autostart(&exe, &args)
    }
    #[cfg(target_os = "windows")]
    {
        ensure_windows_run_key(&exe, &args)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = exe;
        let _ = args;
        Ok("autostart unsupported on this OS".to_string())
    }
}

#[cfg(target_os = "macos")]
fn ensure_macos_launch_agent(exe: &Path, args: &[String]) -> Result<String> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("home directory not found"))?;
    let launch_agents = home.join("Library").join("LaunchAgents");
    std::fs::create_dir_all(&launch_agents).with_context(|| {
        format!(
            "failed creating launch agents directory {}",
            launch_agents.display()
        )
    })?;

    let label = "ai.soth.proxy";
    let plist_path = launch_agents.join(format!("{label}.plist"));
    let mut program_arguments = String::new();
    program_arguments.push_str(&format!(
        "    <string>{}</string>\n",
        xml_escape(&exe.display().to_string())
    ));
    for arg in args {
        program_arguments.push_str(&format!("    <string>{}</string>\n", xml_escape(arg)));
    }
    let logs_dir = home.join(".soth").join("logs");
    std::fs::create_dir_all(&logs_dir).ok();
    let stdout_path = logs_dir.join("proxy-autostart.log");

    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{program_arguments}  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{}</string>
  <key>StandardErrorPath</key>
  <string>{}</string>
</dict>
</plist>
"#,
        xml_escape(&stdout_path.display().to_string()),
        xml_escape(&stdout_path.display().to_string())
    );
    std::fs::write(&plist_path, body)
        .with_context(|| format!("failed writing launch agent {}", plist_path.display()))?;

    let uid = unsafe { libc::geteuid() }.to_string();
    let gui_target = format!("gui/{uid}/{label}");
    let user_target = format!("user/{uid}/{label}");

    let _ = Command::new("launchctl")
        .args(["bootout", &gui_target])
        .status();

    let bootstrap_gui = Command::new("launchctl")
        .args([
            "bootstrap",
            &format!("gui/{uid}"),
            &plist_path.display().to_string(),
        ])
        .status();
    if !bootstrap_gui
        .map(|status| status.success())
        .unwrap_or(false)
    {
        let _ = Command::new("launchctl")
            .args([
                "bootstrap",
                &format!("user/{uid}"),
                &plist_path.display().to_string(),
            ])
            .status();
    }
    let _ = Command::new("launchctl")
        .args(["enable", &gui_target])
        .status();
    let _ = Command::new("launchctl")
        .args(["kickstart", "-k", &gui_target])
        .status()
        .or_else(|_| {
            Command::new("launchctl")
                .args(["kickstart", "-k", &user_target])
                .status()
        });

    Ok(format!(
        "launchd enabled ({label}) at {}",
        plist_path.display()
    ))
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "linux")]
fn ensure_linux_autostart(exe: &Path, args: &[String]) -> Result<String> {
    if which::which("systemctl").is_ok() {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("home directory not found"))?;
        let user_dir = home.join(".config").join("systemd").join("user");
        std::fs::create_dir_all(&user_dir).with_context(|| {
            format!(
                "failed creating systemd user directory {}",
                user_dir.display()
            )
        })?;

        let unit_path = user_dir.join(format!("{SERVICE_NAME}.service"));
        let exec = render_exec_start(exe, args);
        let body = format!(
            "[Unit]\nDescription=SOTH Proxy Sensor\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={exec}\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n"
        );
        std::fs::write(&unit_path, body)
            .with_context(|| format!("failed writing {}", unit_path.display()))?;

        run_linux_cmd(&["systemctl", "--user", "daemon-reload"])?;
        run_linux_cmd(&["systemctl", "--user", "enable", "--now", SERVICE_NAME])?;
        if let Ok(user) = std::env::var("USER") {
            let _ = Command::new("loginctl")
                .args(["enable-linger", &user])
                .status();
        }

        return Ok(format!(
            "systemd --user enabled ({SERVICE_NAME}) at {}",
            unit_path.display()
        ));
    }

    let home = dirs::home_dir().ok_or_else(|| anyhow!("home directory not found"))?;
    let autostart_dir = home.join(".config").join("autostart");
    std::fs::create_dir_all(&autostart_dir).with_context(|| {
        format!(
            "failed creating XDG autostart directory {}",
            autostart_dir.display()
        )
    })?;
    let desktop_path = autostart_dir.join("soth-proxy.desktop");
    let exec = shell_escape_command(exe, args);
    let body = format!(
        "[Desktop Entry]\nType=Application\nName=SOTH Proxy\nExec={exec}\nX-GNOME-Autostart-enabled=true\nNoDisplay=true\n"
    );
    std::fs::write(&desktop_path, body)
        .with_context(|| format!("failed writing {}", desktop_path.display()))?;

    Ok(format!(
        "XDG autostart enabled at {}",
        desktop_path.display()
    ))
}

#[cfg(target_os = "linux")]
fn run_linux_cmd(cmd: &[&str]) -> Result<()> {
    let (program, rest) = cmd.split_first().ok_or_else(|| anyhow!("empty command"))?;
    let status = Command::new(program)
        .args(rest)
        .status()
        .with_context(|| format!("failed running command {:?}", cmd))?;
    if !status.success() {
        anyhow::bail!("command {:?} exited with status {}", cmd, status);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn render_exec_start(exe: &Path, args: &[String]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(systemd_escape_arg(&exe.display().to_string()));
    parts.extend(args.iter().map(|arg| systemd_escape_arg(arg)));
    parts.join(" ")
}

#[cfg(target_os = "linux")]
fn systemd_escape_arg(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "-_./=:".contains(ch))
    {
        return value.to_string();
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(target_os = "linux")]
fn shell_escape_command(exe: &Path, args: &[String]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(shell_escape(&exe.display().to_string()));
    parts.extend(args.iter().map(|arg| shell_escape(arg)));
    parts.join(" ")
}

#[cfg(target_os = "linux")]
fn shell_escape(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "-_./=:".contains(ch))
    {
        return value.to_string();
    }
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

#[cfg(target_os = "windows")]
fn ensure_windows_run_key(exe: &Path, args: &[String]) -> Result<String> {
    use std::os::windows::process::CommandExt;

    let mut commandline = windows_quote_arg(&exe.display().to_string());
    for arg in args {
        commandline.push(' ');
        commandline.push_str(&windows_quote_arg(arg));
    }

    let output = Command::new("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "SothProxy",
            "/t",
            "REG_SZ",
            "/d",
            &commandline,
            "/f",
        ])
        .creation_flags(0x08000000)
        .output()
        .context("failed configuring Windows startup Run key")?;
    if !output.status.success() {
        anyhow::bail!(
            "failed setting Windows startup Run key: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok("windows Run key enabled (HKCU\\...\\Run\\SothProxy)".to_string())
}

#[cfg(target_os = "windows")]
fn windows_quote_arg(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_string();
    }
    if !value.contains([' ', '\t', '"']) {
        return value.to_string();
    }
    let escaped = value.replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_args_includes_foreground_and_port() {
        let args = build_args(8080, None).expect("args");
        assert!(args.iter().any(|v| v == "--foreground"));
        assert!(args.iter().any(|v| v == "--quiet"));
        assert!(args.iter().any(|v| v == "8080"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_escape_quotes_spaces() {
        let escaped = systemd_escape_arg("/tmp/soth path/bin");
        assert!(escaped.starts_with('"'));
        assert!(escaped.ends_with('"'));
    }
}
