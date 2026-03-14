use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use sha2::{Digest, Sha256};

#[allow(dead_code)]
#[path = "../src/bundle_runtime.rs"]
mod bundle_runtime;

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn write_bundle_dir(bundle_dir: &Path, version: &str, assets: &HashMap<String, Vec<u8>>) {
    std::fs::create_dir_all(bundle_dir).expect("create bundle dir");
    for (relative_path, bytes) in assets {
        let full_path = bundle_dir.join(relative_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).expect("create bundle asset parent");
        }
        std::fs::write(&full_path, bytes).expect("write bundle asset");
    }

    let mut asset_entries = assets
        .iter()
        .map(|(path, bytes)| soth_bundle::AssetEntry {
            path: path.clone(),
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        })
        .collect::<Vec<_>>();
    asset_entries.sort_by(|left, right| left.path.cmp(&right.path));

    let manifest = soth_bundle::BundleManifest {
        version: version.to_string(),
        created_at: 1_772_689_000,
        bundle_id: None,
        model_version: None,
        policy_version: None,
        org_id: None,
        issued_at: None,
        expires_at: None,
        vendor_sig: String::new(),
        org_approval_sig: None,
        assets: asset_entries,
        scope: soth_bundle::BundleScope::default(),
    };
    std::fs::write(
        bundle_dir.join("manifest.json"),
        serde_json::to_vec(&manifest).expect("serialize manifest"),
    )
    .expect("write bundle manifest");
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct SothHomeGuard {
    previous: Option<std::ffi::OsString>,
}

impl SothHomeGuard {
    fn set(path: &Path) -> Self {
        let previous = std::env::var_os("SOTH_HOME_DIR");
        unsafe {
            std::env::set_var("SOTH_HOME_DIR", path);
        }
        Self { previous }
    }
}

impl Drop for SothHomeGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => unsafe { std::env::set_var("SOTH_HOME_DIR", value) },
            None => unsafe { std::env::remove_var("SOTH_HOME_DIR") },
        }
    }
}

#[test]
fn startup_fallback_contract_uses_last_known_good_and_marks_runtime_degraded() {
    let _guard = env_lock().lock().expect("env lock");
    let test_root = std::env::temp_dir().join(format!(
        "soth_proxy_bundle_fallback_{}",
        uuid::Uuid::new_v4()
    ));
    let soth_home = test_root.join(".soth");
    let primary_bundle_dir = soth_home.join("bundle");
    let fallback_bundle_dir = soth_home.join("bundle.last_known_good");

    let mut assets = HashMap::new();
    let detect_bundle = serde_json::to_vec(&soth_core::OwnedDetectBundle::default())
        .expect("serialize detect bundle");
    assets.insert("detect/bundle.json".to_string(), detect_bundle);

    write_bundle_dir(&fallback_bundle_dir, "bundle-fallback-v1", &assets);
    write_bundle_dir(&primary_bundle_dir, "bundle-primary-v1", &assets);
    {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(primary_bundle_dir.join("detect/bundle.json"))
            .expect("open primary detect bundle for corruption");
        file.write_all(b"x").expect("corrupt primary detect bundle");
    }

    let _home_guard = SothHomeGuard::set(soth_home.as_path());
    let db = Arc::new(Mutex::new(
        rusqlite::Connection::open_in_memory().expect("open sqlite db"),
    ));
    let verification = soth_bundle::VerificationOptions {
        verify_vendor_signature: false,
        require_verified_bundle: false,
        org_approval_pubkey: None,
    };

    let (_watcher, handle, source) = bundle_runtime::init_bundle_watcher_with_fallback(
        primary_bundle_dir.as_path(),
        &[0u8; 32],
        Arc::new(soth_bundle::OrgSignedConfig::default()),
        db,
        verification,
    )
    .expect("startup should fallback to last-known-good bundle");

    assert_eq!(format!("{source:?}"), "FallbackLastKnownGood");
    assert_eq!(handle.current().version, "bundle-fallback-v1");

    let runtime_state_path = soth_home.join("run").join("proxy.bundle_runtime.json");
    let runtime_state = std::fs::read_to_string(&runtime_state_path)
        .expect("read runtime bundle state file after fallback startup");
    let json: serde_json::Value =
        serde_json::from_str(runtime_state.as_str()).expect("parse runtime bundle state JSON");
    assert_eq!(
        json.get("startup_bundle_source")
            .and_then(|value| value.as_str()),
        Some("fallback_last_known_good")
    );
    let startup_error = json
        .get("startup_error")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(
        startup_error.contains("asset size mismatch"),
        "expected startup error context in runtime state; got: {startup_error}"
    );

    let _ = std::fs::remove_dir_all(test_root);
}
