use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use soth_sync::registry_puller::RegistryPuller;
use soth_sync::BundleWatcher;

#[derive(Default)]
struct RegistryHits {
    bundle_current_calls: usize,
    legacy_version_calls: usize,
    legacy_bundle_calls: usize,
    bundle_ack_calls: usize,
}

#[derive(Clone)]
struct RegistryState {
    payload: Arc<Vec<u8>>,
    payload_sha256: String,
    bundle_version: String,
    hits: Arc<Mutex<RegistryHits>>,
}

async fn bundle_current_handler(State(state): State<RegistryState>) -> impl IntoResponse {
    if let Ok(mut hits) = state.hits.lock() {
        hits.bundle_current_calls = hits.bundle_current_calls.saturating_add(1);
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        "etag",
        HeaderValue::from_str(format!("\"{}\"", state.payload_sha256).as_str())
            .unwrap_or_else(|_| HeaderValue::from_static("\"invalid\"")),
    );
    headers.insert(
        "x-soth-bundle-version",
        HeaderValue::from_str(state.bundle_version.as_str())
            .unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );
    headers.insert(
        "x-soth-bundle-hash",
        HeaderValue::from_str(state.payload_sha256.as_str())
            .unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );

    (StatusCode::OK, headers, state.payload.as_ref().clone())
}

async fn legacy_version_handler(State(state): State<RegistryState>) -> impl IntoResponse {
    if let Ok(mut hits) = state.hits.lock() {
        hits.legacy_version_calls = hits.legacy_version_calls.saturating_add(1);
    }
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "not_found"
        })),
    )
}

async fn legacy_bundle_handler(State(state): State<RegistryState>) -> impl IntoResponse {
    if let Ok(mut hits) = state.hits.lock() {
        hits.legacy_bundle_calls = hits.legacy_bundle_calls.saturating_add(1);
    }
    (StatusCode::NOT_FOUND, Vec::<u8>::new())
}

async fn bundle_ack_handler(State(state): State<RegistryState>) -> impl IntoResponse {
    if let Ok(mut hits) = state.hits.lock() {
        hits.bundle_ack_calls = hits.bundle_ack_calls.saturating_add(1);
    }
    Json(json!({
        "ok": true
    }))
}

async fn start_registry_server(state: RegistryState) -> Option<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.ok()?;
    let addr = listener.local_addr().ok()?;
    let app = Router::new()
        .route("/v1/bundle/current", get(bundle_current_handler))
        .route("/v1/bundle/ack", axum::routing::post(bundle_ack_handler))
        .route("/api/v1/registry/version", get(legacy_version_handler))
        .route("/api/v1/registry/bundle", get(legacy_bundle_handler))
        .with_state(state);

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Some(format!("http://{}", addr))
}

#[derive(Clone)]
struct BundleWatcherAdapter {
    state: Arc<Mutex<BundleInstallState>>,
}

#[derive(Default)]
struct BundleInstallState {
    install_calls: usize,
    installed_version: Option<String>,
}

impl BundleWatcher for BundleWatcherAdapter {
    fn install_bundle(
        &self,
        manifest_bytes: &[u8],
        _assets: HashMap<String, Vec<u8>>,
    ) -> anyhow::Result<String> {
        let manifest: Value = serde_json::from_slice(manifest_bytes)?;
        let version = manifest
            .get("version")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("manifest.version missing"))?
            .to_string();

        let mut guard = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("bundle install state poisoned"))?;
        guard.install_calls = guard.install_calls.saturating_add(1);
        guard.installed_version = Some(version.clone());
        Ok(version)
    }
}

#[derive(Serialize)]
struct CanonicalManifest<'a> {
    version: &'a str,
    created_at: i64,
    vendor_sig: &'a str,
    org_approval_sig: Option<&'a str>,
    assets: Vec<&'a Value>,
    scope: &'a Value,
}

fn canonical_manifest_bytes(manifest: &Value) -> Vec<u8> {
    let mut assets: Vec<&Value> = manifest
        .get("assets")
        .and_then(|value| value.as_array())
        .map(|items| items.iter().collect::<Vec<_>>())
        .unwrap_or_default();
    assets.sort_by(|left, right| {
        left.get("path")
            .and_then(|value| value.as_str())
            .cmp(&right.get("path").and_then(|value| value.as_str()))
    });
    let scope = manifest.get("scope").unwrap_or(&Value::Null);
    serde_json::to_vec(&CanonicalManifest {
        version: manifest
            .get("version")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown"),
        created_at: manifest
            .get("created_at")
            .and_then(|value| value.as_i64())
            .unwrap_or_default(),
        vendor_sig: "",
        org_approval_sig: manifest
            .get("org_approval_sig")
            .and_then(|value| value.as_str()),
        assets,
        scope,
    })
    .expect("serialize canonical manifest")
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(format!("{:02x}", byte).as_str());
    }
    out
}

fn signed_manifest_bytes(
    version: &str,
    assets: &HashMap<String, Vec<u8>>,
    vendor_signing_key: &SigningKey,
) -> Vec<u8> {
    let mut entries: Vec<Value> = assets
        .iter()
        .map(|(path, bytes)| {
            json!({
                "path": path,
                "sha256": format!("{:x}", Sha256::digest(bytes)),
                "size_bytes": bytes.len() as u64
            })
        })
        .collect();
    entries.sort_by(|left, right| {
        left.get("path")
            .and_then(|value| value.as_str())
            .cmp(&right.get("path").and_then(|value| value.as_str()))
    });

    let mut manifest = json!({
        "version": version,
        "created_at": 1_772_000_000i64,
        "vendor_sig": "",
        "org_approval_sig": null,
        "assets": entries,
        "scope": {
            "intercept_https": false,
            "intercept_http": false,
            "process_filter": null,
            "capture_modes": []
        }
    });

    let signature = vendor_signing_key.sign(canonical_manifest_bytes(&manifest).as_slice());
    manifest["vendor_sig"] = Value::String(hex_encode(signature.to_bytes().as_slice()));
    serde_json::to_vec(&manifest).expect("serialize signed manifest")
}

#[tokio::test]
async fn bundle_sync_channel2_contract_installs_into_bundle_watcher() {
    let vendor = SigningKey::from_bytes(&[29u8; 32]);

    let temp = TempDir::new().expect("temp dir");

    let next_manifest = signed_manifest_bytes("bundle-v2", &HashMap::new(), &vendor);
    let manifest_value: Value =
        serde_json::from_slice(next_manifest.as_slice()).expect("decode signed manifest value");
    let payload = serde_json::to_vec(&json!({
        "manifest": manifest_value,
        "assets": {}
    }))
    .expect("serialize channel2 payload");
    let payload_sha256 = format!("{:x}", Sha256::digest(payload.as_slice()));

    let hits = Arc::new(Mutex::new(RegistryHits::default()));
    let state = RegistryState {
        payload: Arc::new(payload),
        payload_sha256: payload_sha256.clone(),
        bundle_version: "bundle-v2".to_string(),
        hits: hits.clone(),
    };
    let Some(endpoint) = start_registry_server(state).await else {
        eprintln!(
            "Skipping bundle_sync_channel2_contract_installs_into_bundle_watcher: cannot bind localhost listener"
        );
        return;
    };

    let install_state = Arc::new(Mutex::new(BundleInstallState::default()));
    let adapter = Arc::new(BundleWatcherAdapter {
        state: install_state.clone(),
    });
    let cache_path = temp.path().join("registry_cache.json");
    let puller = RegistryPuller::new(endpoint, "test-key", cache_path).with_bundle_watcher(adapter);

    let outcome = puller.refresh_now().await.expect("refresh from registry");
    assert!(outcome.checked);
    assert!(outcome.downloaded);
    assert_eq!(outcome.version.as_deref(), Some("bundle-v2"));
    let installed = install_state.lock().expect("install state lock");
    assert_eq!(installed.install_calls, 1);
    assert_eq!(installed.installed_version.as_deref(), Some("bundle-v2"));

    let guard = hits.lock().expect("hits lock");
    assert!(guard.bundle_current_calls >= 1);
    assert_eq!(guard.legacy_version_calls, 0);
    assert_eq!(guard.legacy_bundle_calls, 0);
}
