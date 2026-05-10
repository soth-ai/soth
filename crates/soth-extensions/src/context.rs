use std::path::PathBuf;

// ---------------------------------------------------------------------------
// ExtensionRuntimeContext — runtime paths and identity for extensions
// ---------------------------------------------------------------------------
//
// Named ExtensionRuntimeContext to avoid collision with soth_core::ExtensionContext
// which is per-event metadata attached to GovernableEvents.

#[derive(Debug, Clone)]
pub struct ExtensionRuntimeContext {
    pub data_dir: PathBuf,
    pub queue_dir: PathBuf,
    pub db_path: PathBuf,
    pub bundle_path: PathBuf,
    pub org_id: String,
    pub device_id: String,
    pub user_id_hmac: String,
    pub bundle_version: String,
    pub proxy_version: String,
}

impl ExtensionRuntimeContext {
    /// Queue file for GovernableEvents from governance extensions.
    pub fn governance_queue_file(&self, name: &str) -> PathBuf {
        self.queue_dir.join(format!("{name}.queue"))
    }

    /// Queue file for ObservationEvents from passive observer extensions.
    /// .obs.queue suffix allows the drain loop to distinguish by glob.
    pub fn observation_queue_file(&self, name: &str) -> PathBuf {
        self.queue_dir.join(format!("{name}.obs.queue"))
    }

    /// Load context from `~/.soth/` defaults.
    ///
    /// `bundle_path` must point at the same directory the proxy installs
    /// runtime bundles to (`bundle.bundle_dir` in soth.yaml, default
    /// `~/.soth/bundle/`). Historian's `ClassifyEnricher` calls
    /// `soth_classify::load_bundle(&ctx.bundle_path)` and silently falls
    /// back to `KeywordClassifier` when the directory is missing — so
    /// every historian-emitted event ships with `use_case_label = Unknown`.
    ///
    /// This previously joined `"current"` (`~/.soth/bundle/current/`) to
    /// support a versioned-layout design (`bundle/<version>/`,
    /// `bundle/current` symlinking the active version) that was never
    /// actually implemented in `install_runtime_bundle_files` — the
    /// install path always wrote files flat into `bundle/`, so the
    /// `current` subdir was a dead reference.
    ///
    /// Falls back to empty strings for identity fields when config is
    /// unavailable.
    pub fn from_defaults() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let data_dir = home.join(".soth");
        Self {
            queue_dir: data_dir.join("queue"),
            db_path: data_dir.join("soth.db"),
            bundle_path: data_dir.join("bundle"),
            data_dir,
            org_id: String::new(),
            device_id: String::new(),
            user_id_hmac: String::new(),
            bundle_version: String::new(),
            proxy_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin: historian's `bundle_path` must match the proxy's
    /// `bundle.bundle_dir` default (also `~/.soth/bundle/` in
    /// `soth-proxy/src/config.rs`). Drift here is silent — classify
    /// enrichment falls back to a stub and every historian event
    /// ships `Unknown` until a developer notices in telemetry.
    #[test]
    fn from_defaults_bundle_path_has_no_current_subdir() {
        let ctx = ExtensionRuntimeContext::from_defaults();
        let last = ctx
            .bundle_path
            .file_name()
            .expect("bundle_path has a final component")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            last, "bundle",
            "bundle_path must end in 'bundle/' — joining 'current' breaks historian classify because no installer writes that subdir"
        );
        assert_eq!(
            ctx.bundle_path,
            ctx.data_dir.join("bundle"),
            "bundle_path must be `<data_dir>/bundle/`, the same path the proxy's install_runtime_bundle_files writes to"
        );
    }
}
