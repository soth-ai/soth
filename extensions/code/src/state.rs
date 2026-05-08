//! Per-host installation state for soth-code hooks.
//!
//! Persisted to `~/.soth/installed.json` so `soth up` can answer
//! "is this agent already wired?" without re-reading every
//! agent's settings file and grepping for the soth-managed
//! marker.  Two roles:
//!
//! 1. **Idempotency**: re-running `soth up` shouldn't re-install
//!    hooks for agents already wired by an earlier run.  The
//!    state file's presence in the per-agent map means
//!    "installed at least once."
//!
//! 2. **Repair drift detection**: each entry records the
//!    `binary_path` the install used.  When `soth` itself moves
//!    (e.g. the operator brewed a new version that landed at a
//!    different prefix), an `up --repair-hooks` flow can
//!    compare current binary vs. stored binary and re-install
//!    when they drift.
//!
//! The state file is *not* the source of truth — the agent's
//! own settings file is.  This is a fast-path cache + audit
//! trail.  When state and on-disk truth diverge (operator
//! manually edited `~/.claude/settings.json`), the state file
//! gets re-aligned on the next `up`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstalledHostState {
    /// Schema version.  Bump when the persisted shape changes
    /// in a non-additive way.
    #[serde(default = "default_schema_version")]
    pub version: u32,

    /// Per-agent install records, keyed by adapter name
    /// (`claude_code`, `cursor`, …).  Missing entries mean
    /// "never installed by this host's `soth up`."
    #[serde(default)]
    pub hooks: BTreeMap<String, AgentInstallRecord>,
}

fn default_schema_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInstallRecord {
    /// RFC 3339 timestamp of the most recent successful install.
    pub installed_at: String,
    /// Settings / plugin file that the install wrote to.  Same
    /// path the runtime hook handler reads from when the agent
    /// fires.
    pub settings_path: PathBuf,
    /// Absolute path of the `soth` binary the install pointed
    /// at.  Drift detection compares this against the current
    /// `current_exe()` to decide if the hook entry needs
    /// re-pointing after a binary upgrade.
    pub binary_path: PathBuf,
}

impl InstalledHostState {
    /// Default path: `~/.soth/installed.json`.
    pub fn default_path() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".soth").join("installed.json"))
    }

    /// Load state from disk.  Returns `Default::default()`
    /// (empty map) if the file doesn't exist — that's the
    /// "first run" path, not an error.  Real I/O / parse
    /// errors do propagate so an operator with a corrupted
    /// state file knows something's wrong rather than the
    /// system silently re-installing every agent each boot.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parse install state at {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("read install state at {}", path.display())),
        }
    }

    /// Atomically write state to disk: tempfile + rename, with
    /// the parent directory created if missing.  Atomic write
    /// avoids the partial-write window during which a crashed
    /// `up` would leave a half-written state file that fails to
    /// parse on next boot.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(self).context("serialize install state")?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes)
            .with_context(|| format!("write tmp install state at {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename tmp install state to {}", path.display()))?;
        Ok(())
    }

    /// Mark an agent as installed at the current moment, with
    /// the given settings + binary paths.  Overwrites any prior
    /// entry — the latest install wins.
    pub fn record_install(&mut self, agent: &str, settings: PathBuf, binary: PathBuf) {
        self.hooks.insert(
            agent.to_string(),
            AgentInstallRecord {
                installed_at: chrono::Utc::now().to_rfc3339(),
                settings_path: settings,
                binary_path: binary,
            },
        );
    }

    /// Remove the agent's record on uninstall — keeps the state
    /// file aligned with on-disk reality.
    pub fn record_uninstall(&mut self, agent: &str) {
        self.hooks.remove(agent);
    }

    /// True when the recorded `binary_path` for the agent
    /// differs from the current binary path, i.e. the soth
    /// binary moved since the install.  False when the agent
    /// isn't in state (caller should treat that as "not
    /// installed yet" and run a fresh install).
    pub fn binary_drifted(&self, agent: &str, current_binary: &Path) -> bool {
        self.hooks
            .get(agent)
            .map(|r| r.binary_path != current_binary)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_returns_empty_when_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("installed.json");
        let state = InstalledHostState::load(&path).expect("missing file is ok");
        assert!(state.hooks.is_empty());
        assert_eq!(state.version, 0); // serde default for u32 when no file
    }

    #[test]
    fn save_then_load_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("installed.json");
        let mut state = InstalledHostState {
            version: 1,
            hooks: BTreeMap::new(),
        };
        state.record_install(
            "claude_code",
            PathBuf::from("/x/.claude/settings.json"),
            PathBuf::from("/usr/local/bin/soth"),
        );
        state.save(&path).expect("save");
        let loaded = InstalledHostState::load(&path).expect("load");
        assert_eq!(loaded.hooks.len(), 1);
        let rec = loaded.hooks.get("claude_code").unwrap();
        assert_eq!(rec.binary_path, PathBuf::from("/usr/local/bin/soth"));
        assert_eq!(rec.settings_path, PathBuf::from("/x/.claude/settings.json"));
    }

    #[test]
    fn binary_drifted_detects_path_change() {
        let mut state = InstalledHostState::default();
        state.record_install(
            "claude_code",
            PathBuf::from("/x/.claude/settings.json"),
            PathBuf::from("/old/path/soth"),
        );
        assert!(state.binary_drifted("claude_code", Path::new("/new/path/soth")));
        assert!(!state.binary_drifted("claude_code", Path::new("/old/path/soth")));
        // Unknown agent: not drifted — caller should treat as
        // "not installed at all" and run fresh.
        assert!(!state.binary_drifted("cursor", Path::new("/new/path/soth")));
    }

    #[test]
    fn save_uses_atomic_write_via_tempfile() {
        // Pin the atomic-write contract: a save shouldn't leave
        // a `.tmp` file behind.  Without rename-into-place, a
        // partial save could orphan the tmp file and confuse
        // future load() readers if the path scheme changed.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("installed.json");
        let state = InstalledHostState::default();
        state.save(&path).expect("save");
        assert!(path.exists());
        let tmp_residue = path.with_extension("json.tmp");
        assert!(!tmp_residue.exists(), "tmp file must be renamed away");
    }
}
