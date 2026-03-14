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
    /// Falls back to empty strings for identity fields when config is unavailable.
    pub fn from_defaults() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let data_dir = home.join(".soth");
        Self {
            queue_dir: data_dir.join("queue"),
            db_path: data_dir.join("soth.db"),
            bundle_path: data_dir.join("bundle").join("current"),
            data_dir,
            org_id: String::new(),
            device_id: String::new(),
            user_id_hmac: String::new(),
            bundle_version: String::new(),
            proxy_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}
