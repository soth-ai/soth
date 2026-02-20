use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_PARENT_WALK_DEPTH: usize = 10;

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

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Debug, Clone)]
struct ProcessTableRow {
    ppid: u32,
    name: String,
}

impl ProcessAttribution {
    pub fn new(requested_enabled: bool, lookup_timeout: Duration, cache_ttl: Duration) -> Self {
        Self {
            enabled: requested_enabled
                && (cfg!(target_os = "macos")
                    || cfg!(target_os = "linux")
                    || cfg!(target_os = "windows")),
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
        if let Some(identity) =
            resolve_with_native_socket_owner(client_addr, self.lookup_timeout).await
        {
            return Some(identity);
        }

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(identity) = resolve_with_lsof(client_addr, self.lookup_timeout).await {
            return Some(identity);
        }

        resolve_with_ps_fallback(client_addr, self.lookup_timeout).await
    }
}

async fn build_process_identity(
    pid: u32,
    raw_name: String,
    attribution_source: &str,
    attribution_confidence: f64,
    timeout: Duration,
) -> ProcessIdentity {
    let executable = lookup_executable(pid, timeout).await;
    let name = normalize_process_name(raw_name, executable.as_deref());
    let app_type = classify_app_type(name.as_str(), executable.as_deref());

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if should_attempt_parent_walk(name.as_str(), app_type.as_str()) {
        if let Some(parent_identity) = resolve_parent_process_identity(
            pid,
            attribution_source,
            attribution_confidence,
            timeout,
        )
        .await
        {
            return parent_identity;
        }
    }

    ProcessIdentity {
        pid,
        name,
        executable,
        app_type,
        attribution_source: attribution_source.to_string(),
        attribution_confidence,
    }
}

async fn resolve_with_native_socket_owner(
    client_addr: SocketAddr,
    timeout: Duration,
) -> Option<ProcessIdentity> {
    #[cfg(target_os = "linux")]
    if let Some((pid, raw_name, exact_socket_match)) = resolve_with_ss(client_addr, timeout).await {
        let (source, confidence) = if exact_socket_match {
            ("socket_owner_native_ss_exact", 0.98)
        } else {
            ("socket_owner_native_ss_fallback", 0.82)
        };
        return Some(build_process_identity(pid, raw_name, source, confidence, timeout).await);
    }

    #[cfg(target_os = "windows")]
    if let Some((pid, raw_name, exact_socket_match)) =
        resolve_with_windows_tcp_table(client_addr, timeout).await
    {
        let (source, confidence) = if exact_socket_match {
            ("socket_owner_native_tcp_table_exact", 0.96)
        } else {
            ("socket_owner_native_tcp_table_fallback", 0.80)
        };
        return Some(build_process_identity(pid, raw_name, source, confidence, timeout).await);
    }

    let _ = client_addr;
    let _ = timeout;
    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn resolve_with_lsof(client_addr: SocketAddr, timeout: Duration) -> Option<ProcessIdentity> {
    use tokio::process::Command;

    // Query by TCP port to avoid IPv4/IPv6 formatting mismatches in lsof filters.
    let selector = format!("-iTCP:{}", client_addr.port());
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

    let (pid, raw_name, exact_socket_match) = parse_lsof_output(&output.stdout, client_addr)?;
    let attribution_source = if exact_socket_match {
        "socket_owner_exact"
    } else {
        "socket_owner_fallback"
    };
    let confidence = if exact_socket_match { 0.95 } else { 0.75 };

    Some(build_process_identity(pid, raw_name, attribution_source, confidence, timeout).await)
}

#[cfg(target_os = "linux")]
async fn resolve_with_ss(
    client_addr: SocketAddr,
    timeout: Duration,
) -> Option<(u32, String, bool)> {
    use tokio::process::Command;

    let output = tokio::time::timeout(timeout, Command::new("ss").args(["-Hntp"]).output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() {
        return None;
    }

    parse_ss_output(&output.stdout, client_addr)
}

#[cfg(target_os = "windows")]
async fn resolve_with_windows_tcp_table(
    client_addr: SocketAddr,
    timeout: Duration,
) -> Option<(u32, String, bool)> {
    use tokio::process::Command;

    let output = tokio::time::timeout(
        timeout,
        Command::new("netstat").args(["-ano", "-p", "tcp"]).output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }

    let (pid, exact_socket_match) = parse_windows_netstat_output(&output.stdout, client_addr)?;
    let process_name = lookup_process_name_windows(pid, timeout)
        .await
        .unwrap_or_else(|| "unknown".to_string());
    Some((pid, process_name, exact_socket_match))
}

#[cfg(target_os = "windows")]
async fn lookup_process_name_windows(pid: u32, timeout: Duration) -> Option<String> {
    use tokio::process::Command;

    let filter = format!("PID eq {pid}");
    let output = tokio::time::timeout(
        timeout,
        Command::new("tasklist")
            .args(["/FI", &filter, "/FO", "CSV", "/NH"])
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_tasklist_row(text.lines().next()?.trim()).map(|(_, name)| name)
}

async fn resolve_with_ps_fallback(
    client_addr: SocketAddr,
    timeout: Duration,
) -> Option<ProcessIdentity> {
    // Conservative fallback for local proxy mode only.
    if !client_addr.ip().is_loopback() {
        return None;
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use tokio::process::Command;

        let output = tokio::time::timeout(
            timeout,
            Command::new("ps").args(["-axo", "pid=,comm="]).output(),
        )
        .await
        .ok()?
        .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let self_pid = std::process::id();
        let mut singleton: Option<(u32, String)> = None;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(pid_raw) = parts.next() else {
                continue;
            };
            let Ok(pid) = pid_raw.parse::<u32>() else {
                continue;
            };
            if pid == self_pid {
                continue;
            }
            let name = parts.collect::<Vec<_>>().join(" ");
            if name.is_empty() || name.eq_ignore_ascii_case("soth") {
                continue;
            }
            if !is_ps_fallback_candidate(name.as_str()) {
                continue;
            }
            if singleton.is_some() {
                return None;
            }
            singleton = Some((pid, name));
        }

        if let Some((pid, raw_name)) = singleton {
            return Some(
                build_process_identity(pid, raw_name, "process_scan_singleton", 0.20, timeout)
                    .await,
            );
        }
        return None;
    }

    #[cfg(target_os = "windows")]
    {
        use tokio::process::Command;

        let output = tokio::time::timeout(
            timeout,
            Command::new("tasklist")
                .args(["/FO", "CSV", "/NH"])
                .output(),
        )
        .await
        .ok()?
        .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let mut singleton: Option<(u32, String)> = None;

        for line in text.lines() {
            if let Some((pid, name)) = parse_tasklist_row(line) {
                if !is_ps_fallback_candidate(name.as_str()) {
                    continue;
                }
                if singleton.is_some() {
                    return None;
                }
                singleton = Some((pid, name));
            }
        }

        if let Some((pid, raw_name)) = singleton {
            return Some(
                build_process_identity(pid, raw_name, "process_scan_singleton", 0.20, timeout)
                    .await,
            );
        }
        return None;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = timeout;
        None
    }
}

fn should_attempt_parent_walk(name: &str, app_type: &str) -> bool {
    if matches!(app_type, "service") || is_system_helper_process_name(name) {
        return true;
    }
    if is_generic_shell_process(name) {
        return true;
    }
    app_type == "unknown" && is_low_signal_process_name(name)
}

fn is_low_signal_process_name(name: &str) -> bool {
    let trimmed = name.trim();
    trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("unknown")
        || looks_like_version_token(trimmed)
}

fn is_system_helper_process_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "webkit.networking",
        "webkit.webcontent",
        "webkit.gpu",
        "nsurlsessiond",
        "cfnetwork",
        "networkserviceproxy",
        "xpcproxy",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_generic_shell_process(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "sh" | "bash" | "zsh" | "fish" | "node" | "python" | "npm" | "pnpm" | "yarn" | "cargo"
    )
}

fn is_responsible_parent_candidate(name: &str, executable: Option<&str>) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("soth") {
        return false;
    }
    if is_system_helper_process_name(trimmed) {
        return false;
    }

    let app_type = classify_app_type(trimmed, executable);
    if matches!(app_type.as_str(), "browser" | "editor" | "desktop_app") {
        return true;
    }
    if app_type == "cli" {
        return !is_generic_shell_process(trimmed);
    }
    false
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn resolve_parent_process_identity(
    pid: u32,
    attribution_source: &str,
    attribution_confidence: f64,
    timeout: Duration,
) -> Option<ProcessIdentity> {
    let table = load_unix_process_table(timeout).await?;
    let per_hop_timeout = timeout
        .checked_div(8)
        .unwrap_or_else(|| Duration::from_millis(25))
        .max(Duration::from_millis(15))
        .min(Duration::from_millis(100));

    let mut current_pid = pid;
    for _ in 0..MAX_PARENT_WALK_DEPTH {
        let parent_pid = table.get(&current_pid)?.ppid;
        if parent_pid == 0 || parent_pid == current_pid {
            break;
        }
        let parent_row = table.get(&parent_pid)?;
        let parent_executable = lookup_executable(parent_pid, per_hop_timeout).await;
        let parent_name =
            normalize_process_name(parent_row.name.clone(), parent_executable.as_deref());
        let parent_app_type = classify_app_type(parent_name.as_str(), parent_executable.as_deref());
        if is_responsible_parent_candidate(parent_name.as_str(), parent_executable.as_deref()) {
            return Some(ProcessIdentity {
                pid: parent_pid,
                name: parent_name,
                executable: parent_executable,
                app_type: parent_app_type,
                attribution_source: format!("{attribution_source}_parent_walk"),
                attribution_confidence: attribution_confidence.min(0.90).max(0.55),
            });
        }
        current_pid = parent_pid;
    }

    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn load_unix_process_table(timeout: Duration) -> Option<HashMap<u32, ProcessTableRow>> {
    use tokio::process::Command;

    let output = tokio::time::timeout(
        timeout,
        Command::new("ps")
            .args(["-axo", "pid=,ppid=,comm="])
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(parse_unix_process_table(&output.stdout))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn parse_unix_process_table(stdout: &[u8]) -> HashMap<u32, ProcessTableRow> {
    let mut table = HashMap::new();
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(pid_raw) = parts.next() else {
            continue;
        };
        let Some(ppid_raw) = parts.next() else {
            continue;
        };
        let Ok(pid) = pid_raw.parse::<u32>() else {
            continue;
        };
        let Ok(ppid) = ppid_raw.parse::<u32>() else {
            continue;
        };
        let name = parts.collect::<Vec<_>>().join(" ").trim().to_string();
        if name.is_empty() {
            continue;
        }
        table.insert(pid, ProcessTableRow { ppid, name });
    }
    table
}

fn is_ps_fallback_candidate(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "codex",
        "claude",
        "cursor",
        "windsurf",
        "chatgpt",
        "anthropic",
        "warp",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

#[cfg(any(target_os = "linux", test))]
fn parse_ss_output(stdout: &[u8], client_addr: SocketAddr) -> Option<(u32, String, bool)> {
    let text = String::from_utf8_lossy(stdout);
    let self_pid = std::process::id();
    let mut generic_match: Option<(u32, String, bool)> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let head = line
            .split_once(" users:")
            .map(|(prefix, _)| prefix)
            .unwrap_or(line);
        let tokens: Vec<&str> = head.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }
        let local_socket = tokens[tokens.len() - 2];
        let exact_socket_match = socket_token_matches_client(local_socket, client_addr, true);
        let fallback_socket_match = socket_token_matches_client(local_socket, client_addr, false);
        if !fallback_socket_match {
            continue;
        }

        let Some(pid) = extract_pid_marker(line) else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        let process_name =
            extract_first_quoted_value(line).unwrap_or_else(|| "unknown".to_string());
        if process_name.eq_ignore_ascii_case("soth") {
            continue;
        }
        if exact_socket_match {
            return Some((pid, process_name, true));
        }
        if generic_match.is_none() {
            generic_match = Some((pid, process_name, false));
        }
    }

    generic_match
}

#[cfg(any(target_os = "windows", test))]
fn parse_windows_netstat_output(stdout: &[u8], client_addr: SocketAddr) -> Option<(u32, bool)> {
    let text = String::from_utf8_lossy(stdout);
    let self_pid = std::process::id();
    let mut generic_match: Option<(u32, bool)> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(proto) = parts.next() else {
            continue;
        };
        if !proto.eq_ignore_ascii_case("tcp") {
            continue;
        }
        let Some(local) = parts.next() else {
            continue;
        };
        let _foreign = parts.next();
        let _state = parts.next();
        let Some(pid_raw) = parts.next() else {
            continue;
        };
        let Ok(pid) = pid_raw.parse::<u32>() else {
            continue;
        };
        if pid == self_pid {
            continue;
        }

        let exact_socket_match = socket_token_matches_client(local, client_addr, true);
        let fallback_socket_match = socket_token_matches_client(local, client_addr, false);
        if !fallback_socket_match {
            continue;
        }
        if exact_socket_match {
            return Some((pid, true));
        }
        if generic_match.is_none() {
            generic_match = Some((pid, false));
        }
    }

    generic_match
}

#[cfg(any(target_os = "windows", test))]
fn parse_tasklist_row(line: &str) -> Option<(u32, String)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    if line.starts_with("INFO:") {
        return None;
    }
    let mut parts = line.split(',');
    let image_name = parts.next()?.trim().trim_matches('"');
    let pid_raw = parts.next()?.trim().trim_matches('"');
    let pid = pid_raw.parse::<u32>().ok()?;
    let normalized_name = image_name
        .trim_end_matches(".exe")
        .trim_end_matches(".EXE")
        .to_string();
    if normalized_name.is_empty() {
        None
    } else {
        Some((pid, normalized_name))
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn extract_pid_marker(line: &str) -> Option<u32> {
    let marker = "pid=";
    let start = line.find(marker)? + marker.len();
    let digits: String = line[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<u32>().ok()
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn extract_first_quoted_value(line: &str) -> Option<String> {
    let start = line.find('"')? + 1;
    let rest = &line[start..];
    let end = rest.find('"')?;
    let value = rest[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn socket_token_matches_client(
    token: &str,
    client_addr: SocketAddr,
    require_exact_ip: bool,
) -> bool {
    let Some((candidate_ip, candidate_port)) = parse_socket_token(token) else {
        return false;
    };
    if candidate_port != client_addr.port() {
        return false;
    }

    match candidate_ip {
        Some(ip) => ip_matches(ip, client_addr.ip()),
        None => !require_exact_ip,
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn parse_socket_token(token: &str) -> Option<(Option<std::net::IpAddr>, u16)> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }

    if token.starts_with('[') {
        let end = token.find(']')?;
        let host = &token[1..end];
        let rest = token.get(end + 1..)?.trim();
        let port = rest.strip_prefix(':')?.parse::<u16>().ok()?;
        return Some((parse_candidate_ip(host), port));
    }

    let (host, port_raw) = token.rsplit_once(':')?;
    let port = port_raw.parse::<u16>().ok()?;
    Some((parse_candidate_ip(host), port))
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn parse_candidate_ip(host: &str) -> Option<std::net::IpAddr> {
    let host = host.trim();
    if host.is_empty()
        || host == "*"
        || host == "0.0.0.0"
        || host == "::"
        || host.eq_ignore_ascii_case("[::]")
    {
        return None;
    }
    let host = host.split('%').next().unwrap_or(host);
    host.parse::<std::net::IpAddr>().ok()
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn ip_matches(candidate: std::net::IpAddr, target: std::net::IpAddr) -> bool {
    if candidate == target {
        return true;
    }
    match (candidate, target) {
        (std::net::IpAddr::V6(v6), std::net::IpAddr::V4(v4))
        | (std::net::IpAddr::V4(v4), std::net::IpAddr::V6(v6)) => {
            v6.to_ipv4().map(|mapped| mapped == v4).unwrap_or(false)
        }
        _ => false,
    }
}

fn normalize_process_name(raw_name: String, executable: Option<&str>) -> String {
    let trimmed = raw_name.trim();
    if !trimmed.is_empty() && !looks_like_version_token(trimmed) {
        return trimmed.to_string();
    }

    if let Some(candidate) = process_name_from_executable(executable) {
        if !looks_like_version_token(candidate.as_str()) {
            return candidate;
        }
    }

    "unknown".to_string()
}

fn process_name_from_executable(executable: Option<&str>) -> Option<String> {
    let executable = executable?.trim();
    if executable.is_empty() {
        return None;
    }

    let mut candidate = if executable.contains('/') {
        executable.rsplit('/').next().unwrap_or(executable).trim()
    } else {
        executable
            .split_whitespace()
            .next()
            .unwrap_or(executable)
            .trim()
    }
    .trim_matches('"')
    .trim();

    if candidate.is_empty() {
        return None;
    }

    if candidate.ends_with(".app") {
        candidate = candidate.trim_end_matches(".app").trim();
    }
    if candidate.ends_with(".exe") {
        candidate = candidate.trim_end_matches(".exe").trim();
    }

    if candidate.is_empty() {
        None
    } else {
        Some(candidate.to_string())
    }
}

fn looks_like_version_token(value: &str) -> bool {
    let value = value.trim().trim_start_matches(['v', 'V']);
    if value.is_empty() || !value.contains('.') {
        return false;
    }

    let mut saw_digit = false;
    for ch in value.chars() {
        if ch.is_ascii_digit() {
            saw_digit = true;
            continue;
        }
        if matches!(ch, '.' | '-' | '_' | '+') {
            continue;
        }
        return false;
    }
    saw_digit
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
    let raw_selector = format!("{}:{}", client_addr.ip(), client_addr.port());
    let bracketed_selector = format!("[{}]:{}", client_addr.ip(), client_addr.port());
    let selector_candidates = [raw_selector.as_str(), bracketed_selector.as_str()];
    let self_pid = std::process::id();

    let mut current_pid: Option<u32> = None;
    let mut current_cmd: Option<String> = None;
    let mut generic_match: Option<(u32, String, bool)> = None;

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
                    let matches_selector = selector_candidates
                        .iter()
                        .any(|selector| value.contains(selector));
                    if pid == self_pid || !matches_selector {
                        continue;
                    }
                    // Never attribute traffic to the proxy binary itself, even if a sibling
                    // process shares the same command name.
                    if cmd.eq_ignore_ascii_case("soth") {
                        continue;
                    }
                    // Prefer the client-side socket owner entry:
                    //   "<client_ip:client_port>-><proxy_ip:proxy_port>"
                    let prefers_client_owner = selector_candidates
                        .iter()
                        .any(|selector| value.starts_with(selector));
                    if prefers_client_owner {
                        return Some((pid, cmd, true));
                    }
                    if generic_match.is_none() {
                        generic_match = Some((pid, cmd, false));
                    }
                }
            }
            _ => {}
        }
    }

    generic_match
}

fn classify_app_type(name: &str, executable: Option<&str>) -> String {
    let mut haystack = name.to_ascii_lowercase();
    if let Some(exec) = executable {
        haystack.push(' ');
        haystack.push_str(exec.to_ascii_lowercase().as_str());
    }

    let contains_any = |items: &[&str]| items.iter().any(|item| haystack.contains(item));
    if contains_any(&[
        "chrome", "firefox", "safari", "edge", "brave", "arc", "opera", "chromium",
    ]) {
        return "browser".to_string();
    }
    if contains_any(&[
        "claude-code",
        "claude-cli",
        "claude --",
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
    fn parse_lsof_requires_matching_socket_line() {
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let sample = b"p1234\ncCodex\nn127.0.0.1:7777->127.0.0.1:3001\n";
        assert!(parse_lsof_output(sample, addr).is_none());
    }

    #[test]
    fn parse_lsof_ignores_proxy_self_pid_and_selects_client_owner() {
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let self_pid = std::process::id();
        let sample = format!(
            "p{self_pid}\ncSoth\nn127.0.0.1:3001->127.0.0.1:8081\np9876\ncWarp\nn127.0.0.1:8081->127.0.0.1:3001\n"
        );
        let parsed = parse_lsof_output(sample.as_bytes(), addr).unwrap();
        assert_eq!(parsed.0, 9876);
        assert_eq!(parsed.1, "Warp");
        assert!(parsed.2);
    }

    #[test]
    fn parse_lsof_ignores_sibling_soth_process_name() {
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let sample =
            b"p3456\ncsoth\nn127.0.0.1:8081->127.0.0.1:3001\np9876\ncWarp\nn127.0.0.1:8081->127.0.0.1:3001\n";
        let parsed = parse_lsof_output(sample, addr).unwrap();
        assert_eq!(parsed.0, 9876);
        assert_eq!(parsed.1, "Warp");
        assert!(parsed.2);
    }

    #[test]
    fn parse_lsof_fallback_match_marks_non_exact_confidence() {
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        // Selector appears in the line but not as client-owner prefix.
        let sample = b"p9876\ncWarp\nn127.0.0.1:3001->127.0.0.1:8081\n";
        let parsed = parse_lsof_output(sample, addr).unwrap();
        assert_eq!(parsed.0, 9876);
        assert_eq!(parsed.1, "Warp");
        assert!(!parsed.2);
    }

    #[test]
    fn classify_app_type_detects_browser_and_editor_and_cli() {
        assert_eq!(classify_app_type("Google Chrome", None), "browser");
        assert_eq!(classify_app_type("Cursor", None), "editor");
        assert_eq!(classify_app_type("claude-code", None), "cli");
        assert_eq!(
            classify_app_type("2.1.47", Some("claude --resume 1234")),
            "cli"
        );
        assert_eq!(
            classify_app_type(
                "Unknown",
                Some("/Applications/Figma.app/Contents/MacOS/Figma")
            ),
            "desktop_app"
        );
    }

    #[test]
    fn normalize_process_name_replaces_version_only_name_with_executable_name() {
        let normalized = normalize_process_name("2.1.45".to_string(), Some("claude"));
        assert_eq!(normalized, "claude");
    }

    #[test]
    fn normalize_process_name_uses_unknown_when_only_version_is_available() {
        let normalized = normalize_process_name("2.1.45".to_string(), None);
        assert_eq!(normalized, "unknown");
    }

    #[test]
    fn parse_socket_token_handles_ipv4_ipv6_and_wildcard() {
        assert_eq!(
            parse_socket_token("127.0.0.1:8080"),
            Some((Some("127.0.0.1".parse().unwrap()), 8080))
        );
        assert_eq!(
            parse_socket_token("[::1]:3000"),
            Some((Some("::1".parse().unwrap()), 3000))
        );
        assert_eq!(parse_socket_token("*:443"), Some((None, 443)));
    }

    #[test]
    fn socket_token_matching_respects_exact_vs_fallback() {
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        assert!(socket_token_matches_client("127.0.0.1:8081", addr, true));
        assert!(!socket_token_matches_client("*:8081", addr, true));
        assert!(socket_token_matches_client("*:8081", addr, false));
    }

    #[test]
    fn parse_ss_output_prefers_exact_socket_owner() {
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let sample = b"ESTAB 0 0 127.0.0.1:9999 127.0.0.1:8081 users:((\"fallback\",pid=1234,fd=11))\nESTAB 0 0 127.0.0.1:8081 127.0.0.1:3001 users:((\"codex\",pid=5678,fd=12))\n";
        let parsed = parse_ss_output(sample, addr).unwrap();
        assert_eq!(parsed.0, 5678);
        assert_eq!(parsed.1, "codex");
        assert!(parsed.2);
    }

    #[test]
    fn parse_windows_netstat_output_prefers_exact_socket_owner() {
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let sample = b"  TCP    127.0.0.1:9999   127.0.0.1:8081   ESTABLISHED   1234\n  TCP    127.0.0.1:8081   127.0.0.1:3001   ESTABLISHED   5678\n";
        let parsed = parse_windows_netstat_output(sample, addr).unwrap();
        assert_eq!(parsed.0, 5678);
        assert!(parsed.1);
    }

    #[test]
    fn parse_tasklist_row_extracts_name_and_pid() {
        let row = "\"Code.exe\",\"4108\",\"Console\",\"1\",\"238,252 K\"";
        let parsed = parse_tasklist_row(row).unwrap();
        assert_eq!(parsed.0, 4108);
        assert_eq!(parsed.1, "Code");
    }

    #[test]
    fn system_helper_detection_matches_known_macos_service_names() {
        assert!(is_system_helper_process_name("com.apple.nsurlsessiond"));
        assert!(is_system_helper_process_name("com.apple.WebKit.Networking"));
        assert!(!is_system_helper_process_name("Cursor"));
    }

    #[test]
    fn responsible_parent_candidate_rejects_shells_and_accepts_apps() {
        assert!(!is_responsible_parent_candidate("zsh", Some("/bin/zsh")));
        assert!(is_responsible_parent_candidate(
            "Terminal",
            Some("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal")
        ));
        assert!(is_responsible_parent_candidate("Cursor", None));
    }

    #[test]
    fn parent_walk_triggers_for_low_signal_processes() {
        assert!(should_attempt_parent_walk("node", "cli"));
        assert!(should_attempt_parent_walk("unknown", "unknown"));
        assert!(should_attempt_parent_walk("2.1.45", "unknown"));
        assert!(!should_attempt_parent_walk("Codex", "cli"));
        assert!(!should_attempt_parent_walk("Cursor", "editor"));
    }
}
