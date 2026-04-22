//! Cross-platform autostart registration for the sensor daemon.
//!
//! Goal: once the daemon is started explicitly, persist startup registration so
//! it comes back on boot/login without requiring manual re-configuration.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "soth-proxy";

#[cfg(target_os = "macos")]
const MACOS_SERVICE_LABEL: &str = "ai.soth.proxy";

#[cfg(target_os = "linux")]
const XDG_AUTOSTART_FILE: &str = "soth-proxy.desktop";

#[cfg(target_os = "windows")]
const WINDOWS_RUN_KEY_VALUE: &str = "SothProxy";

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
        "--daemon-child".to_string(),
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

pub fn supports_managed_mode() -> bool {
    cfg!(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    ))
}

pub fn start_managed(port: u16, config_path: Option<&PathBuf>) -> Result<String> {
    ensure_enabled(port, config_path)
}

pub fn stop_managed_runtime_only() -> Result<Option<String>> {
    #[cfg(target_os = "macos")]
    {
        return stop_macos_launch_agent_runtime_only().map(Some);
    }
    #[cfg(target_os = "linux")]
    {
        return stop_linux_runtime_only().map(Some);
    }
    #[cfg(target_os = "windows")]
    {
        return Ok(Some(
            "windows runtime stop is handled by pid lifecycle; autostart registration preserved"
                .to_string(),
        ));
    }
    #[allow(unreachable_code)]
    Ok(None)
}

pub fn managed_status() -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("home directory not found"))?;
        let label = MACOS_SERVICE_LABEL;
        let plist_path = home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{label}.plist"));
        let state = if plist_path.exists() {
            "enabled"
        } else {
            "disabled"
        };
        return Ok(format!("launchd {state} ({label})"));
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(home) = dirs::home_dir() {
            let unit_path = home
                .join(".config")
                .join("systemd")
                .join("user")
                .join(format!("{SERVICE_NAME}.service"));
            if unit_path.exists() {
                return Ok(format!(
                    "systemd --user enabled ({SERVICE_NAME}) at {}",
                    unit_path.display()
                ));
            }
            let desktop_path = home
                .join(".config")
                .join("autostart")
                .join(XDG_AUTOSTART_FILE);
            if desktop_path.exists() {
                return Ok(format!(
                    "XDG autostart enabled at {}",
                    desktop_path.display()
                ));
            }
        }
        return Ok("linux autostart disabled".to_string());
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;

        let output = Command::new("reg")
            .args([
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                WINDOWS_RUN_KEY_VALUE,
            ])
            .creation_flags(0x08000000)
            .output()
            .context("failed querying Windows startup Run key")?;
        if output.status.success() {
            return Ok(format!(
                "windows Run key enabled (HKCU\\...\\Run\\{})",
                WINDOWS_RUN_KEY_VALUE
            ));
        }
        return Ok(format!(
            "windows Run key disabled (HKCU\\...\\Run\\{})",
            WINDOWS_RUN_KEY_VALUE
        ));
    }
    #[allow(unreachable_code)]
    Ok("autostart unsupported on this OS".to_string())
}

#[cfg(target_os = "macos")]
fn stop_macos_launch_agent_runtime_only() -> Result<String> {
    let label = MACOS_SERVICE_LABEL;
    let uid = unsafe { libc::geteuid() }.to_string();
    let gui_target = format!("gui/{uid}/{label}");
    let user_target = format!("user/{uid}/{label}");
    let _ = launchctl_silent(["bootout", &gui_target]);
    let _ = launchctl_silent(["bootout", &user_target]);
    Ok(format!(
        "launchd stopped ({label}); startup registration preserved"
    ))
}

#[cfg(target_os = "macos")]
fn launchctl_silent<const N: usize>(args: [&str; N]) -> Result<()> {
    let output = Command::new("launchctl")
        .args(args)
        .output()
        .context("failed running launchctl")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if stderr.contains("no such process")
        || stderr.contains("could not find service")
        || stderr.contains("service is disabled")
        || stderr.contains("not loaded")
    {
        return Ok(());
    }
    anyhow::bail!(
        "launchctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
fn stop_linux_runtime_only() -> Result<String> {
    if which::which("systemctl").is_ok() {
        let _ = run_linux_cmd(&["systemctl", "--user", "stop", SERVICE_NAME]);
        return Ok(format!(
            "systemd --user stopped ({SERVICE_NAME}); startup registration preserved"
        ));
    }
    Ok("linux runtime stop handled by pid lifecycle; autostart registration preserved".to_string())
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

    let label = MACOS_SERVICE_LABEL;
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
    std::fs::create_dir_all(&logs_dir).with_context(|| {
        format!(
            "failed creating launch agent log directory {}",
            logs_dir.display()
        )
    })?;
    let stdout_path = logs_dir.join("edge-autostart.log");

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

    let _ = launchctl_silent(["bootout", &gui_target]);
    let _ = launchctl_silent(["bootout", &user_target]);

    let plist_path_str = plist_path.display().to_string();
    let gui_domain = format!("gui/{uid}");
    let user_domain = format!("user/{uid}");

    let bootstrap_domain = match launchctl_require_success(&[
        "bootstrap",
        &gui_domain,
        &plist_path_str,
    ]) {
        Ok(()) => "gui",
        Err(gui_error) => {
            launchctl_require_success(&["bootstrap", &user_domain, &plist_path_str]).map_err(
                |user_error| {
                    anyhow!(
                        "failed to bootstrap launchd service in both gui and user domains.\nGUI error: {gui_error}\nUSER error: {user_error}"
                    )
                },
            )?;
            "user"
        }
    };

    let (primary_target, secondary_target) = if bootstrap_domain == "gui" {
        (gui_target.as_str(), user_target.as_str())
    } else {
        (user_target.as_str(), gui_target.as_str())
    };

    if let Err(primary_error) = launchctl_require_success(&["enable", primary_target]) {
        launchctl_require_success(&["enable", secondary_target]).map_err(|secondary_error| {
            anyhow!(
                "failed to enable launchd service.\nPrimary ({primary_target}) error: {primary_error}\nSecondary ({secondary_target}) error: {secondary_error}"
            )
        })?;
    }

    if let Err(primary_error) = launchctl_require_success(&["kickstart", "-k", primary_target]) {
        launchctl_require_success(&["kickstart", "-k", secondary_target]).map_err(
            |secondary_error| {
                anyhow!(
                    "failed to kickstart launchd service.\nPrimary ({primary_target}) error: {primary_error}\nSecondary ({secondary_target}) error: {secondary_error}"
                )
            },
        )?;
    }

    Ok(format!(
        "launchd enabled ({label}) at {} (domain: {bootstrap_domain})",
        plist_path.display(),
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

#[cfg(target_os = "macos")]
fn launchctl_require_success(args: &[&str]) -> Result<()> {
    let output = Command::new("launchctl")
        .args(args)
        .output()
        .with_context(|| format!("failed running launchctl {}", args.join(" ")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let details = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "no launchctl output".to_string()
    };
    anyhow::bail!(
        "launchctl {} failed with status {}: {}",
        args.join(" "),
        output.status,
        details
    );
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
            "[Unit]\nDescription=SOTH Edge Sensor\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={exec}\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n"
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
    let desktop_path = autostart_dir.join(XDG_AUTOSTART_FILE);
    let exec = shell_escape_command(exe, args);
    let body = format!(
        "[Desktop Entry]\nType=Application\nName=SOTH Edge\nExec={exec}\nX-GNOME-Autostart-enabled=true\nNoDisplay=true\n"
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
    use std::net::{SocketAddr, TcpStream};
    use std::os::windows::process::CommandExt;
    use std::process::Stdio;
    use std::time::Duration;

    // Windows process creation flags (see winbase.h).
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

    // Step 1: register the HKCU Run key so the daemon comes back on next login.
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
            WINDOWS_RUN_KEY_VALUE,
            "/t",
            "REG_SZ",
            "/d",
            &commandline,
            "/f",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .context("failed configuring Windows startup Run key")?;
    if !output.status.success() {
        anyhow::bail!(
            "failed setting Windows startup Run key: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    // Step 2: skip the immediate spawn if a daemon is already listening on
    // the configured port. Without this check, re-running `soth up` while
    // the daemon is up races with the existing bind and the new child exits
    // with `os error 10048` (address in use).
    let port = extract_port_from_args(args).unwrap_or(8080);
    let probe_addr: SocketAddr = ([127u8, 0, 0, 1], port).into();
    let already_running =
        TcpStream::connect_timeout(&probe_addr, Duration::from_millis(200)).is_ok();

    if already_running {
        return Ok(format!(
            "windows Run key enabled (HKCU\\...\\Run\\{}); daemon already listening on 127.0.0.1:{}",
            WINDOWS_RUN_KEY_VALUE, port
        ));
    }

    // Step 3: spawn the daemon now. The Run key only fires at next user
    // login, so this immediate spawn is what makes `soth up` unblock on a
    // fresh install. Detached from the shell's process group so it survives
    // the parent exit.
    let log_path = dirs::home_dir()
        .ok_or_else(|| anyhow!("home directory not found"))?
        .join(".soth")
        .join("logs")
        .join("proxy.log");
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating proxy log directory {}", parent.display()))?;
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed opening proxy log file {}", log_path.display()))?;
    let log_clone = log_file
        .try_clone()
        .context("failed cloning proxy log file handle for stderr")?;

    Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_clone))
        .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .context("failed spawning SOTH proxy daemon on Windows")?;

    Ok(format!(
        "windows Run key enabled (HKCU\\...\\Run\\{}) and daemon spawned",
        WINDOWS_RUN_KEY_VALUE
    ))
}

#[cfg(target_os = "windows")]
fn extract_port_from_args(args: &[String]) -> Option<u16> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--port" {
            return iter.next().and_then(|v| v.parse().ok());
        }
        if let Some(rest) = arg.strip_prefix("--port=") {
            return rest.parse().ok();
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_quote_arg(value: &str) -> String {
    // Follows the CommandLineToArgvW rules documented at
    // https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw
    //
    // Key rules:
    //   * 2n backslashes + `"` → n backslashes + begin/end quote
    //   * 2n+1 backslashes + `"` → n backslashes + literal `"`
    //   * Trailing backslashes before the closing `"` must also be doubled.
    if value.is_empty() {
        return "\"\"".to_string();
    }
    if !value.contains([' ', '\t', '\n', '\x0B', '"']) {
        return value.to_string();
    }

    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    let mut backslashes = 0usize;
    for c in value.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // Escape any backslashes preceding the quote (double them) and the quote itself.
                for _ in 0..(2 * backslashes + 1) {
                    result.push('\\');
                }
                result.push('"');
                backslashes = 0;
            }
            _ => {
                for _ in 0..backslashes {
                    result.push('\\');
                }
                backslashes = 0;
                result.push(c);
            }
        }
    }
    // Double any trailing backslashes before the closing quote.
    for _ in 0..(2 * backslashes) {
        result.push('\\');
    }
    result.push('"');
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_args_includes_daemon_child_and_port() {
        let args = build_args(8080, None).expect("args");
        assert!(args.iter().any(|v| v == "--daemon-child"));
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

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_quote_handles_simple_path() {
        assert_eq!(windows_quote_arg("C:\\soth\\bin.exe"), "C:\\soth\\bin.exe");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_quote_handles_spaces() {
        assert_eq!(
            windows_quote_arg("C:\\Program Files\\soth\\bin.exe"),
            "\"C:\\Program Files\\soth\\bin.exe\""
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_quote_doubles_trailing_backslashes() {
        // "C:\\path with space\\" → "\"C:\\path with space\\\\\""
        assert_eq!(
            windows_quote_arg("C:\\path with space\\"),
            "\"C:\\path with space\\\\\""
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_quote_escapes_embedded_quote() {
        // a"b → "a\"b"
        assert_eq!(windows_quote_arg("a\"b"), "\"a\\\"b\"");
        // a\"b → "a\\\"b"   (the `\` before `"` is doubled + quote escaped)
        assert_eq!(windows_quote_arg("a\\\"b"), "\"a\\\\\\\"b\"");
    }
}
