//! Adaptive learned TLS passthrough state for cert-pinned hosts.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LearnedEntry {
    learned_at: DateTime<Utc>,
    reason: String,
    failure_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct LearnedState {
    entries: Vec<(String, LearnedEntry)>,
}

#[derive(Debug, Clone)]
struct ConnectFailureState {
    first_seen: Instant,
    failure_count: u32,
}

/// Runtime learned passthrough table.
///
/// Hosts in this table bypass MITM interception and are tunneled directly.
pub struct LearnedPassthrough {
    entries: Arc<DashMap<String, LearnedEntry>>,
    failures: Arc<DashMap<String, ConnectFailureState>>,
    protected_patterns: Arc<Vec<String>>,
    ignore_patterns: Arc<Vec<String>>,
    state_path: PathBuf,
    max_age: Duration,
}

impl LearnedPassthrough {
    pub fn new(
        state_path: PathBuf,
        protected_patterns: Vec<String>,
        ignore_patterns: Vec<String>,
        max_age: Duration,
    ) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            failures: Arc::new(DashMap::new()),
            protected_patterns: Arc::new(protected_patterns),
            ignore_patterns: Arc::new(ignore_patterns),
            state_path,
            max_age,
        }
    }

    pub fn load(&self) {
        let data = match fs::read_to_string(&self.state_path) {
            Ok(data) => data,
            Err(_) => return,
        };
        let state = match serde_json::from_str::<LearnedState>(&data) {
            Ok(state) => state,
            Err(error) => {
                warn!(
                    path = %self.state_path.display(),
                    error = %error,
                    "Failed to parse learned passthrough state"
                );
                return;
            }
        };

        for (host, entry) in state.entries {
            if self.is_protected(&host) || self.is_expired(entry.learned_at) {
                continue;
            }
            self.entries.insert(host, entry);
        }
    }

    pub fn persist(&self) {
        if let Some(parent) = self.state_path.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                warn!(
                    path = %parent.display(),
                    error = %error,
                    "Failed to create learned passthrough state directory"
                );
                return;
            }
        }

        let state = LearnedState {
            entries: self
                .entries
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect(),
        };

        let json = match serde_json::to_string_pretty(&state) {
            Ok(json) => json,
            Err(error) => {
                warn!(error = %error, "Failed to serialize learned passthrough state");
                return;
            }
        };

        if let Err(error) = fs::write(&self.state_path, json) {
            warn!(
                path = %self.state_path.display(),
                error = %error,
                "Failed to persist learned passthrough state"
            );
        }
    }

    pub fn active_count(&self) -> usize {
        self.entries.len()
    }

    pub fn should_passthrough(&self, host: &str) -> bool {
        if self.is_ignored(host) {
            return true;
        }
        if self.is_protected(host) {
            self.entries.remove(host);
            return false;
        }
        if let Some(entry) = self.entries.get(host) {
            if self.is_expired(entry.learned_at) {
                drop(entry);
                self.entries.remove(host);
                self.persist();
                return false;
            }
            return true;
        }
        false
    }

    pub fn record_intercept_failure(
        &self,
        host: &str,
        failure_threshold: u32,
        failure_window: Duration,
        reason: &str,
    ) -> bool {
        if self.is_protected(host) || self.should_passthrough(host) {
            return false;
        }

        let now = Instant::now();
        let threshold = failure_threshold.max(1);

        let mut state = self
            .failures
            .entry(host.to_string())
            .or_insert(ConnectFailureState {
                first_seen: now,
                failure_count: 0,
            });

        if now.duration_since(state.first_seen) > failure_window {
            state.first_seen = now;
            state.failure_count = 0;
        }
        state.failure_count += 1;

        if state.failure_count < threshold {
            return false;
        }

        let failure_count = state.failure_count;
        drop(state);
        self.failures.remove(host);
        self.entries.insert(
            host.to_string(),
            LearnedEntry {
                learned_at: Utc::now(),
                reason: reason.to_string(),
                failure_count,
            },
        );
        self.persist();
        true
    }

    pub fn record_decrypted_request(&self, host: &str) {
        self.failures.remove(host);
        if self.entries.contains_key(host) && !self.is_ignored(host) {
            self.entries.remove(host);
            self.persist();
        }
    }

    fn is_ignored(&self, host: &str) -> bool {
        self.ignore_patterns
            .iter()
            .any(|pattern| host_matches_pattern(host, pattern))
    }

    fn is_protected(&self, host: &str) -> bool {
        self.protected_patterns
            .iter()
            .any(|pattern| host_matches_pattern(host, pattern))
    }

    fn is_expired(&self, learned_at: DateTime<Utc>) -> bool {
        let Ok(max_age) = chrono::Duration::from_std(self.max_age) else {
            return false;
        };
        Utc::now().signed_duration_since(learned_at) > max_age
    }
}

fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let host = host.to_ascii_lowercase();
    let pattern = pattern.trim().to_ascii_lowercase();
    if pattern.is_empty() {
        return false;
    }
    if !pattern.contains('*') {
        return host == pattern;
    }

    if pattern.matches('*').count() > 1 {
        return false;
    }

    let mut parts = pattern.splitn(2, '*');
    let prefix = parts.next().unwrap_or_default();
    let suffix = parts.next().unwrap_or_default();
    host.starts_with(prefix) && host.ends_with(suffix)
}

#[cfg(test)]
mod tests {
    use super::LearnedPassthrough;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn protected_host_is_never_learned() {
        let dir = tempdir().unwrap();
        let learned = LearnedPassthrough::new(
            dir.path().join("lp.json"),
            vec!["api.openai.com".to_string()],
            vec![],
            Duration::from_secs(3600),
        );
        for _ in 0..5 {
            let _ = learned.record_intercept_failure(
                "api.openai.com",
                3,
                Duration::from_secs(60),
                "tls_handshake_failed",
            );
        }
        assert!(!learned.should_passthrough("api.openai.com"));
        assert_eq!(learned.active_count(), 0);
    }

    #[test]
    fn learns_after_threshold() {
        let dir = tempdir().unwrap();
        let learned = LearnedPassthrough::new(
            dir.path().join("lp.json"),
            vec![],
            vec![],
            Duration::from_secs(3600),
        );
        assert!(!learned.record_intercept_failure(
            "example.com",
            3,
            Duration::from_secs(60),
            "tls_handshake_failed",
        ));
        assert!(!learned.record_intercept_failure(
            "example.com",
            3,
            Duration::from_secs(60),
            "tls_handshake_failed",
        ));
        assert!(learned.record_intercept_failure(
            "example.com",
            3,
            Duration::from_secs(60),
            "tls_handshake_failed",
        ));
        assert!(learned.should_passthrough("example.com"));
    }

    #[test]
    fn success_clears_learning() {
        let dir = tempdir().unwrap();
        let learned = LearnedPassthrough::new(
            dir.path().join("lp.json"),
            vec![],
            vec![],
            Duration::from_secs(3600),
        );
        for _ in 0..3 {
            let _ = learned.record_intercept_failure(
                "example.com",
                3,
                Duration::from_secs(60),
                "tls_handshake_failed",
            );
        }
        assert!(learned.should_passthrough("example.com"));
        learned.record_decrypted_request("example.com");
        assert!(!learned.should_passthrough("example.com"));
    }

    #[test]
    fn persists_and_loads_state() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("lp.json");
        {
            let learned = LearnedPassthrough::new(
                state_path.clone(),
                vec![],
                vec![],
                Duration::from_secs(3600),
            );
            for _ in 0..3 {
                let _ = learned.record_intercept_failure(
                    "example.com",
                    3,
                    Duration::from_secs(60),
                    "tls_handshake_failed",
                );
            }
            assert!(learned.should_passthrough("example.com"));
        }
        let learned2 =
            LearnedPassthrough::new(state_path, vec![], vec![], Duration::from_secs(3600));
        learned2.load();
        assert!(learned2.should_passthrough("example.com"));
    }

    #[test]
    fn ignored_host_always_passthrough() {
        let dir = tempdir().unwrap();
        let learned = LearnedPassthrough::new(
            dir.path().join("lp.json"),
            vec![],
            vec!["chatgpt.com".to_string()],
            Duration::from_secs(3600),
        );
        assert!(learned.should_passthrough("chatgpt.com"));
        assert_eq!(learned.active_count(), 0);
    }
}
