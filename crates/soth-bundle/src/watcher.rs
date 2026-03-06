use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use arc_swap::ArcSwap;
use rusqlite::Connection;
use tokio::sync::watch;

use crate::db;
use crate::error::BundleError;
use crate::loader;
use crate::manifest::OrgSignedConfig;
use crate::{LoadedBundle, VerificationOptions};

#[derive(Clone)]
pub struct BundleHandle {
    inner: Arc<ArcSwap<LoadedBundle>>,
    tx: watch::Sender<u64>,
    rx: watch::Receiver<u64>,
    generation: Arc<AtomicU64>,
}

impl BundleHandle {
    pub fn load(&self) -> Arc<LoadedBundle> {
        self.inner.load_full()
    }

    pub fn current(&self) -> Arc<LoadedBundle> {
        self.load()
    }

    pub fn swap(&self, new: LoadedBundle) {
        self.inner.store(Arc::new(new));
        let next = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = self.tx.send(next);
    }

    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.rx.changed().await
    }
}

pub struct BundleWatcher {
    inner: Arc<ArcSwap<LoadedBundle>>,
    tx: watch::Sender<u64>,
    generation: Arc<AtomicU64>,
    vendor_pubkey: [u8; 32],
    org_config: Arc<OrgSignedConfig>,
    db: Arc<Mutex<Connection>>,
    verification: VerificationOptions,
}

impl BundleWatcher {
    pub fn new(
        initial: LoadedBundle,
        vendor_pubkey: [u8; 32],
        org_config: Arc<OrgSignedConfig>,
        db: Arc<Mutex<Connection>>,
        verification: VerificationOptions,
    ) -> Result<(Self, BundleHandle), BundleError> {
        let inner = Arc::new(ArcSwap::from_pointee(initial));
        let generation = Arc::new(AtomicU64::new(0));
        let (tx, rx) = watch::channel(0u64);

        let watcher = Self {
            inner: inner.clone(),
            tx: tx.clone(),
            generation: generation.clone(),
            vendor_pubkey,
            org_config,
            db,
            verification,
        };
        let handle = BundleHandle {
            inner,
            tx,
            rx,
            generation,
        };
        Ok((watcher, handle))
    }

    pub fn install(
        &self,
        manifest_bytes: &[u8],
        assets: HashMap<String, Vec<u8>>,
    ) -> Result<String, BundleError> {
        let new_bundle = loader::load_from_bytes_with_options(
            manifest_bytes,
            assets,
            &self.vendor_pubkey,
            &self.org_config,
            self.verification,
        )?;
        let version = new_bundle.version.clone();

        let conn = self.db.lock().map_err(|_| BundleError::DbMutexPoisoned)?;
        // Persist installed bundle metadata before in-memory swap so restart
        // recovery can still discover the new version if send() fails.
        db::record_bundle_installed(&conn, &new_bundle)?;
        db::record_policy_config(&conn, &new_bundle)?;
        drop(conn);

        self.inner.store(Arc::new(new_bundle));
        let next = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.tx
            .send(next)
            .map_err(|_| BundleError::WatcherChannelClosed)?;

        Ok(version)
    }

    pub fn supersede_previous(&self, previous_version: &str) -> Result<(), BundleError> {
        let conn = self.db.lock().map_err(|_| BundleError::DbMutexPoisoned)?;
        db::mark_superseded(&conn, previous_version)?;
        drop(conn);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use rusqlite::params;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::loader;
    use crate::manifest::{canonical_manifest_bytes, AssetEntry, BundleManifest, BundleScope};
    use crate::verify::sha256_hex;

    fn signed_policy_bundle_bytes() -> Vec<u8> {
        let payload = soth_policy::sync_policy::PolicyBundlePayload {
            metadata: soth_policy::sync_policy::PolicyBundleMetadata {
                bundle_version: "policy-v1".to_string(),
                schema_version: "1".to_string(),
                org_id: "demo-org".to_string(),
                signed_at: 1_772_000_001,
            },
            system_rules: Vec::new(),
            org_rules: Vec::new(),
            org_patterns: soth_policy::sync_policy::OrgPatterns::default(),
            budget_limits: soth_policy::sync_policy::BudgetLimits::default(),
        };
        let key = SigningKey::from_bytes(&[13u8; 32]);
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let signature = key.sign(payload_bytes.as_slice());
        let envelope = soth_policy::sync_policy::SignedPolicyBundle {
            payload,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            public_key: base64::engine::general_purpose::STANDARD
                .encode(key.verifying_key().to_bytes()),
        };
        serde_json::to_vec(&envelope).expect("serialize envelope")
    }

    fn signed_manifest_bytes(
        version: &str,
        assets: &HashMap<String, Vec<u8>>,
        vendor: &SigningKey,
    ) -> Vec<u8> {
        let mut entries: Vec<AssetEntry> = assets
            .iter()
            .map(|(path, bytes)| AssetEntry {
                path: path.clone(),
                sha256: sha256_hex(bytes.as_slice()),
                size_bytes: bytes.len() as u64,
            })
            .collect();
        entries.sort_by(|left, right| left.path.cmp(&right.path));

        let mut manifest = BundleManifest {
            version: version.to_string(),
            created_at: 1_772_000_100,
            bundle_id: None,
            model_version: None,
            policy_version: None,
            org_id: None,
            issued_at: None,
            expires_at: None,
            vendor_sig: String::new(),
            org_approval_sig: None,
            assets: entries,
            scope: BundleScope::default(),
        };
        let canonical = canonical_manifest_bytes(&manifest).expect("canonical");
        manifest.vendor_sig = hex::encode(vendor.sign(canonical.as_slice()).to_bytes());
        serde_json::to_vec(&manifest).expect("serialize manifest")
    }

    #[tokio::test]
    async fn installs_new_bundle_and_notifies_handle() {
        let vendor = SigningKey::from_bytes(&[41u8; 32]);
        let org = OrgSignedConfig::default();

        let initial_assets = HashMap::from([(
            "policy/policy_bundle.json".to_string(),
            signed_policy_bundle_bytes(),
        )]);
        let initial_manifest = signed_manifest_bytes("bundle-v1", &initial_assets, &vendor);
        let initial = loader::load_from_bytes(
            initial_manifest.as_slice(),
            initial_assets,
            &vendor.verifying_key().to_bytes(),
            &org,
        )
        .expect("initial bundle");

        let db_file = NamedTempFile::new().expect("temp db");
        let db = Arc::new(Mutex::new(Connection::open(db_file.path()).expect("db")));
        let (watcher, mut handle) = BundleWatcher::new(
            initial,
            vendor.verifying_key().to_bytes(),
            Arc::new(org),
            db,
            VerificationOptions::default(),
        )
        .expect("watcher");

        let next_assets = HashMap::from([(
            "policy/policy_bundle.json".to_string(),
            signed_policy_bundle_bytes(),
        )]);
        let next_manifest = signed_manifest_bytes("bundle-v2", &next_assets, &vendor);
        watcher
            .install(next_manifest.as_slice(), next_assets)
            .expect("install");

        handle.changed().await.expect("watch changed");
        assert_eq!(handle.current().version, "bundle-v2");
    }

    #[tokio::test]
    async fn rejects_invalid_bundle_and_keeps_current() {
        let vendor = SigningKey::from_bytes(&[42u8; 32]);
        let org = OrgSignedConfig::default();

        let assets = HashMap::from([(
            "policy/policy_bundle.json".to_string(),
            signed_policy_bundle_bytes(),
        )]);
        let manifest = signed_manifest_bytes("bundle-v1", &assets, &vendor);
        let initial = loader::load_from_bytes(
            manifest.as_slice(),
            assets,
            &vendor.verifying_key().to_bytes(),
            &org,
        )
        .expect("initial bundle");

        let db_file = NamedTempFile::new().expect("temp db");
        let db = Arc::new(Mutex::new(Connection::open(db_file.path()).expect("db")));
        let (watcher, handle) = BundleWatcher::new(
            initial,
            vendor.verifying_key().to_bytes(),
            Arc::new(org),
            db,
            VerificationOptions::default(),
        )
        .expect("watcher");

        let bad_assets = HashMap::from([(
            "policy/policy_bundle.json".to_string(),
            b"tampered".to_vec(),
        )]);
        let bad_manifest = signed_manifest_bytes("bundle-v2", &bad_assets, &vendor);
        let err = watcher.install(bad_manifest.as_slice(), bad_assets);
        assert!(err.is_err());
        assert_eq!(handle.current().version, "bundle-v1");
    }

    #[tokio::test]
    async fn persists_bundle_install_before_watch_send() {
        let vendor = SigningKey::from_bytes(&[43u8; 32]);
        let org = OrgSignedConfig::default();

        let initial_assets = HashMap::from([(
            "policy/policy_bundle.json".to_string(),
            signed_policy_bundle_bytes(),
        )]);
        let initial_manifest = signed_manifest_bytes("bundle-v1", &initial_assets, &vendor);
        let initial = loader::load_from_bytes(
            initial_manifest.as_slice(),
            initial_assets,
            &vendor.verifying_key().to_bytes(),
            &org,
        )
        .expect("initial bundle");

        let db_file = NamedTempFile::new().expect("temp db");
        let db_path = db_file.path().to_path_buf();
        let db = Arc::new(Mutex::new(Connection::open(&db_path).expect("db")));
        let (watcher, handle) = BundleWatcher::new(
            initial,
            vendor.verifying_key().to_bytes(),
            Arc::new(org),
            db,
            VerificationOptions::default(),
        )
        .expect("watcher");

        drop(handle);

        let next_assets = HashMap::from([(
            "policy/policy_bundle.json".to_string(),
            signed_policy_bundle_bytes(),
        )]);
        let next_manifest = signed_manifest_bytes("bundle-v2", &next_assets, &vendor);

        let result = watcher.install(next_manifest.as_slice(), next_assets);
        assert!(matches!(result, Err(BundleError::WatcherChannelClosed)));

        let conn = Connection::open(&db_path).expect("open db verify");
        let status: String = conn
            .query_row(
                "SELECT status
                 FROM intelligence_bundles
                 WHERE bundle_version = ?1",
                params!["bundle-v2"],
                |row| row.get(0),
            )
            .expect("bundle row should be persisted before send");
        assert_eq!(status, "ACTIVE");
    }
}
