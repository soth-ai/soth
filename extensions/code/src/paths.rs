//! Single-source path resolution for the `soth-code` extension.
//!
//! Every consumer of `soth-code`'s on-disk layout — runtime hook handler,
//! `soth code status`, `soth code doctor`, the dashboard's diagnostic view
//! — resolves paths through this module. CI enforces the rule by grep-test
//! (no other module in this crate is allowed to call `dirs::config_dir()`
//! / `dirs::home_dir()` directly).
//!
//! Why: gryph's bug report PR #37 found that `gryph doctor` and
//! `gryph uninstall --purge` resolved the DB path one way, while the
//! runtime writer used a different resolution under XDG env vars on
//! macOS/Windows. The result was a doctor that reported "DB present"
//! while the actual writer was elsewhere, and an uninstall that missed
//! the real DB. Single-source resolution prevents that class of bug.

use std::path::{Path, PathBuf};

/// All filesystem paths owned by the `soth-code` extension.
#[derive(Debug, Clone)]
pub struct CodePaths {
    /// SQLite store for adapter health metrics + (Phase 5) action history
    /// search index.
    pub db: PathBuf,
    /// Governance queue file consumed by the telemetry batcher
    /// (`~/.soth/queue/code.queue`).
    pub queue: PathBuf,
    /// YAML config file for the extension.
    pub config: PathBuf,
    /// Directory for embedded JS/TS plugin assets shipped to OpenCode and
    /// Pi Agent (written here by `soth code install`).
    pub plugin_dir: PathBuf,
    /// Directory for large-payload blob storage (Phase 5 follow-up; see
    /// `docs/gryph/plan.md` §10.12 / §11). Holds responses larger than
    /// the configured inline threshold.
    pub blob_dir: PathBuf,
    /// Per-host install state file recording which agent hooks
    /// (`claude_code`, `cursor`, …) have been wired by `soth code
    /// install`. Source of truth for `soth code status`'s
    /// `installed` field — `code.yaml` is for tuning knobs and may
    /// legitimately be absent on a host with hooks installed.
    pub installed_state: PathBuf,
}

impl CodePaths {
    /// Default paths under `~/.soth/`. Used by the runtime hook handler,
    /// `soth code status`, `soth code doctor`, and any dashboard
    /// diagnostic view.
    pub fn from_default_root() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Self::from_root(&home.join(".soth"))
    }

    /// Paths rooted at an arbitrary directory. Tests use this with a
    /// `tempfile::TempDir` to keep filesystem writes isolated.
    pub fn from_root(root: &Path) -> Self {
        Self {
            db: root.join("code.db"),
            queue: root.join("queue").join("code.queue"),
            config: root.join("code.yaml"),
            plugin_dir: root.join("code").join("plugins"),
            blob_dir: root.join("code").join("blobs"),
            installed_state: root.join("installed.json"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_root_layout_is_stable() {
        let root = PathBuf::from("/test/.soth");
        let p = CodePaths::from_root(&root);
        assert_eq!(p.db, PathBuf::from("/test/.soth/code.db"));
        assert_eq!(
            p.queue,
            PathBuf::from("/test/.soth/queue/code.queue"),
            "queue file must match ExtensionRuntimeContext::governance_queue_file(\"code\")"
        );
        assert_eq!(p.config, PathBuf::from("/test/.soth/code.yaml"));
        assert_eq!(p.plugin_dir, PathBuf::from("/test/.soth/code/plugins"));
        assert_eq!(p.blob_dir, PathBuf::from("/test/.soth/code/blobs"));
        assert_eq!(
            p.installed_state,
            PathBuf::from("/test/.soth/installed.json"),
            "installed_state must match InstalledHostState::default_path()"
        );
    }

    #[test]
    fn from_default_root_is_under_home() {
        let p = CodePaths::from_default_root();
        // The exact home dir varies by environment; just assert the layout
        // shape matches what `from_root` would produce.
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        assert_eq!(p.db, home.join(".soth").join("code.db"));
    }

    #[test]
    fn queue_path_matches_extensions_runtime_context() {
        // The queue path must equal what
        // `ExtensionRuntimeContext::governance_queue_file("code")` produces,
        // since the telemetry batcher uses that helper to find queue files.
        // Tested indirectly here: the structure `<root>/queue/<name>.queue`
        // matches the helper's `queue_dir.join("code.queue")` shape when
        // `data_dir = root` and `queue_dir = root/queue`.
        let p = CodePaths::from_root(Path::new("/test/.soth"));
        assert_eq!(p.queue.parent().unwrap(), Path::new("/test/.soth/queue"));
        assert_eq!(p.queue.file_name().unwrap(), "code.queue");
    }
}
