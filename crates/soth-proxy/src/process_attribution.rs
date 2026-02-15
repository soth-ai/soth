use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub name: String,
    pub executable: Option<String>,
    pub app_type: String,
    pub attribution_source: String,
    pub attribution_confidence: f64,
}

#[derive(Debug, Clone)]
pub struct ProcessAttribution {
    enabled: bool,
    lookup_timeout: Duration,
    cache_ttl: Duration,
    cache: Arc<Mutex<HashMap<SocketAddr, CacheEntry>>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    value: Option<ProcessIdentity>,
    expires_at: Instant,
}

impl ProcessAttribution {
    pub fn new(lookup_timeout: Duration, cache_ttl: Duration) -> Self {
        Self {
            enabled: cfg!(target_os = "macos") || cfg!(target_os = "linux"),
            lookup_timeout,
            cache_ttl,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn resolve(&self, client_addr: SocketAddr) -> Option<ProcessIdentity> {
        if !self.enabled {
            return None;
        }

        if let Some(cached) = self.get_cached(client_addr) {
            return cached;
        }

        let resolved = self.resolve_uncached(client_addr).await;
        self.put_cached(client_addr, resolved.clone());
        resolved
    }

    fn get_cached(&self, client_addr: SocketAddr) -> Option<Option<ProcessIdentity>> {
        let now = Instant::now();
        let mut cache = self.cache.lock();
        let entry = cache.get(&client_addr).cloned();
        match entry {
            Some(entry) if entry.expires_at > now => Some(entry.value),
            Some(_) => {
                cache.remove(&client_addr);
                None
            }
            None => None,
        }
    }

    fn put_cached(&self, client_addr: SocketAddr, value: Option<ProcessIdentity>) {
        let mut cache = self.cache.lock();
        cache.insert(
            client_addr,
            CacheEntry {
                value,
                expires_at: Instant::now() + self.cache_ttl,
            },
        );
    }

    async fn resolve_uncached(&self, client_addr: SocketAddr) -> Option<ProcessIdentity> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            return resolve_with_lsof(client_addr, self.lookup_timeout).await;
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = client_addr;
            None
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn resolve_with_lsof(client_addr: SocketAddr, timeout: Duration) -> Option<ProcessIdentity> {
    use tokio::process::Command;

    let selector = format!("-iTCP@{}:{}", client_addr.ip(), client_addr.port());
    let output = tokio::time::timeout(
        timeout,
        Command::new("lsof")
            .args(["-nP", &selector, "-sTCP:ESTABLISHED", "-Fpcn"])
            .output(),
    )
    .await
    .ok()?
    .ok()?;

    if !output.status.success() {
        return None;
    }

    let (pid, name, exact_socket_match) = parse_lsof_output(&output.stdout, client_addr)?;
    let executable = lookup_executable(pid, timeout).await;
    let app_type = classify_app_type(name.as_str(), executable.as_deref());
    let confidence = if exact_socket_match { 0.95 } else { 0.75 };
    let attribution_source = if exact_socket_match {
        "socket_owner_exact"
    } else {
        "socket_owner_fallback"
    };

    Some(ProcessIdentity {
        pid,
        name,
        executable,
        app_type,
        attribution_source: attribution_source.to_string(),
        attribution_confidence: confidence,
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn lookup_executable(pid: u32, timeout: Duration) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let path = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
        if let Ok(target) = tokio::time::timeout(timeout, tokio::fs::read_link(&path))
            .await
            .ok()?
        {
            let value = target.to_string_lossy().trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }

    use tokio::process::Command;

    let half_timeout = timeout
        .checked_div(2)
        .unwrap_or_else(|| Duration::from_millis(10));
    let pid_str = pid.to_string();
    let output = tokio::time::timeout(
        half_timeout.max(Duration::from_millis(10)),
        Command::new("ps")
            .args(["-p", &pid_str, "-o", "command="])
            .output(),
    )
    .await
    .ok()?
    .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn parse_lsof_output(stdout: &[u8], client_addr: SocketAddr) -> Option<(u32, String, bool)> {
    let text = String::from_utf8_lossy(stdout);
    let selector = format!("{}:{}", client_addr.ip(), client_addr.port());

    let mut current_pid: Option<u32> = None;
    let mut current_cmd: Option<String> = None;
    let mut fallback: Option<(u32, String)> = None;

    for line in text.lines() {
        let mut chars = line.chars();
        let Some(prefix) = chars.next() else {
            continue;
        };
        let value = chars.as_str().trim();
        match prefix {
            'p' => {
                current_pid = value.parse::<u32>().ok();
                current_cmd = None;
            }
            'c' => {
                if !value.is_empty() {
                    current_cmd = Some(value.to_string());
                }
            }
            'n' => {
                if let Some(pid) = current_pid {
                    let cmd = current_cmd.clone().unwrap_or_else(|| "unknown".to_string());
                    if fallback.is_none() {
                        fallback = Some((pid, cmd.clone()));
                    }
                    if value.contains(&selector) {
                        return Some((pid, cmd, true));
                    }
                }
            }
            _ => {}
        }
    }

    fallback.map(|(pid, cmd)| (pid, cmd, false))
}

fn classify_app_type(name: &str, executable: Option<&str>) -> String {
    let mut haystack = name.to_ascii_lowercase();
    if let Some(exec) = executable {
        haystack.push(' ');
        haystack.push_str(exec.to_ascii_lowercase().as_str());
    }

    let contains_any = |items: &[&str]| items.iter().any(|item| haystack.contains(item));
    if contains_any(&[
        "chrome",
        "firefox",
        "safari",
        "edge",
        "brave",
        "arc",
        "opera",
        "chromium",
    ]) {
        return "browser".to_string();
    }
    if contains_any(&[
        "claude-code",
        "codex",
        "terminal",
        "bash",
        "zsh",
        "fish",
        "sh ",
        "python",
        "node",
        "npm",
        "pnpm",
        "yarn",
        "cargo",
        "go ",
    ]) {
        return "cli".to_string();
    }
    if contains_any(&[
        "cursor",
        "code",
        "windsurf",
        "jetbrains",
        "zed",
        "xcode",
        "vim",
        "nvim",
    ]) {
        return "editor".to_string();
    }
    if contains_any(&["service", "daemon", "systemd", "launchd"]) {
        return "service".to_string();
    }
    if executable
        .map(|value| value.to_ascii_lowercase().contains(".app/"))
        .unwrap_or(false)
    {
        return "desktop_app".to_string();
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lsof_prefers_matching_socket_line() {
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let sample = b"p1234\ncCodex\nn127.0.0.1:7777->127.0.0.1:3001\np5678\ncClaude\nn127.0.0.1:8081->127.0.0.1:3001\n";
        let parsed = parse_lsof_output(sample, addr).unwrap();
        assert_eq!(parsed.0, 5678);
        assert_eq!(parsed.1, "Claude");
        assert!(parsed.2);
    }

    #[test]
    fn parse_lsof_falls_back_to_first_seen_process() {
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let sample = b"p1234\ncCodex\nn127.0.0.1:7777->127.0.0.1:3001\n";
        let parsed = parse_lsof_output(sample, addr).unwrap();
        assert_eq!(parsed.0, 1234);
        assert_eq!(parsed.1, "Codex");
        assert!(!parsed.2);
    }

    #[test]
    fn classify_app_type_detects_browser_and_editor_and_cli() {
        assert_eq!(classify_app_type("Google Chrome", None), "browser");
        assert_eq!(classify_app_type("Cursor", None), "editor");
        assert_eq!(classify_app_type("claude-code", None), "cli");
        assert_eq!(
            classify_app_type("Unknown", Some("/Applications/Figma.app/Contents/MacOS/Figma")),
            "desktop_app"
        );
    }
}
