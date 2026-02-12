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
            enabled: cfg!(target_os = "macos"),
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
        #[cfg(target_os = "macos")]
        {
            use tokio::process::Command;

            let selector = format!("-iTCP@{}:{}", client_addr.ip(), client_addr.port());
            let output = tokio::time::timeout(
                self.lookup_timeout,
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

            let (pid, name) = parse_lsof_output(&output.stdout, client_addr)?;
            let executable = lookup_executable(pid, self.lookup_timeout).await;
            return Some(ProcessIdentity {
                pid,
                name,
                executable,
            });
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = client_addr;
            None
        }
    }
}

#[cfg(target_os = "macos")]
async fn lookup_executable(pid: u32, timeout: Duration) -> Option<String> {
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

fn parse_lsof_output(stdout: &[u8], client_addr: SocketAddr) -> Option<(u32, String)> {
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
                        return Some((pid, cmd));
                    }
                }
            }
            _ => {}
        }
    }

    fallback
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
    }

    #[test]
    fn parse_lsof_falls_back_to_first_seen_process() {
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let sample = b"p1234\ncCodex\nn127.0.0.1:7777->127.0.0.1:3001\n";
        let parsed = parse_lsof_output(sample, addr).unwrap();
        assert_eq!(parsed.0, 1234);
        assert_eq!(parsed.1, "Codex");
    }
}
