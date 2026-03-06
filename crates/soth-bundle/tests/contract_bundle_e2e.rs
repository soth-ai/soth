use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use soth_bundle::{
    load_from_bytes, AssetEntry, BundleError, BundleManifest, BundleScope, BundleWatcher,
    OrgSignedConfig, VerificationOptions,
};
use tempfile::NamedTempFile;

const DETECT_FIXTURE_BYTES: &[u8] =
    include_bytes!("../../soth-detect/tests/fixtures/registry_bundle_cache.detect_bundle.json");

#[derive(serde::Serialize)]
struct CanonicalManifest<'a> {
    version: &'a str,
    created_at: i64,
    vendor_sig: &'a str,
    org_approval_sig: Option<&'a str>,
    assets: Vec<&'a AssetEntry>,
    scope: &'a BundleScope,
}

fn canonical_manifest_bytes(manifest: &BundleManifest) -> Vec<u8> {
    let mut assets: Vec<&AssetEntry> = manifest.assets.iter().collect();
    assets.sort_by(|left, right| left.path.cmp(&right.path));
    serde_json::to_vec(&CanonicalManifest {
        version: manifest.version.as_str(),
        created_at: manifest.created_at,
        vendor_sig: "",
        org_approval_sig: manifest.org_approval_sig.as_deref(),
        assets,
        scope: &manifest.scope,
    })
    .expect("serialize canonical manifest")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn signed_policy_bundle_bytes(version: &str) -> Vec<u8> {
    let payload = soth_policy::sync_policy::PolicyBundlePayload {
        metadata: soth_policy::sync_policy::PolicyBundleMetadata {
            bundle_version: version.to_string(),
            schema_version: "1".to_string(),
            org_id: "test-org".to_string(),
            signed_at: 1_772_000_000,
        },
        system_rules: Vec::new(),
        org_rules: Vec::new(),
        org_patterns: soth_policy::sync_policy::OrgPatterns::default(),
        budget_limits: soth_policy::sync_policy::BudgetLimits::default(),
    };
    let key = SigningKey::from_bytes(&[23u8; 32]);
    let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
    let signature = key.sign(payload_bytes.as_slice());
    let envelope = soth_policy::sync_policy::SignedPolicyBundle {
        payload,
        signature: B64.encode(signature.to_bytes()),
        public_key: B64.encode(key.verifying_key().to_bytes()),
    };
    serde_json::to_vec(&envelope).expect("serialize policy envelope")
}

fn sample_gating_bundle_bytes(primary_host: &str) -> Vec<u8> {
    let mut gating = soth_core::GatingBundle::default();
    gating.gates.order = vec![
        soth_core::GateStage::Stage0Tls,
        soth_core::GateStage::Stage1AppOrigin,
        soth_core::GateStage::Stage2Whitelist,
        soth_core::GateStage::Stage3Blacklist,
        soth_core::GateStage::Stage4AppType,
        soth_core::GateStage::Stage5HostOrigin,
        soth_core::GateStage::Intercept,
    ];
    gating
        .gates
        .stage0_tls
        .tls_intercept_hosts
        .insert(primary_host.to_string());
    gating
        .gates
        .stage0_tls
        .passthrough_domains
        .insert(".*.apple.com$".to_string());
    gating
        .gates
        .stage5_host_origin
        .allowed_host_origins
        .insert("chatgpt.com".to_string());
    gating
        .entities
        .providers
        .push(soth_core::EntityTrafficRules {
            entity_id: "openai".to_string(),
            capture_mode: soth_core::CaptureMode::MetadataOnly,
            hosts: vec![soth_core::HostRule {
                pattern: primary_host.to_string(),
                methods: vec!["POST".to_string()],
                paths: soth_core::PathRules {
                    allow: vec!["/v1/chat/completions".to_string()],
                    deny_exact: vec!["/v1/models".to_string()],
                    deny_glob: vec!["/v1/internal/**".to_string()],
                },
                priority: None,
            }],
            api_format: None,
            entity_type: None,
            pricing: None,
            capture: None,
            detection: None,
        });
    serde_json::to_vec(&gating).expect("serialize gating bundle")
}

fn bundle_assets(
    detect_bytes: Vec<u8>,
    host: &str,
    policy_version: &str,
) -> HashMap<String, Vec<u8>> {
    HashMap::from([
        (
            "policy/policy_bundle.json".to_string(),
            signed_policy_bundle_bytes(policy_version),
        ),
        ("detect/bundle.json".to_string(), detect_bytes),
        (
            "gating/bundle.json".to_string(),
            sample_gating_bundle_bytes(host),
        ),
    ])
}

fn signed_manifest_bytes(
    version: &str,
    scope: BundleScope,
    assets: &HashMap<String, Vec<u8>>,
    vendor_key: &SigningKey,
) -> Vec<u8> {
    let mut entries = assets
        .iter()
        .map(|(path, bytes)| AssetEntry {
            path: path.clone(),
            sha256: sha256_hex(bytes.as_slice()),
            size_bytes: bytes.len() as u64,
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.path.cmp(&right.path));

    let mut manifest = BundleManifest {
        version: version.to_string(),
        created_at: 1_772_000_001,
        bundle_id: None,
        model_version: None,
        policy_version: None,
        org_id: None,
        issued_at: None,
        expires_at: None,
        vendor_sig: String::new(),
        org_approval_sig: None,
        assets: entries,
        scope,
    };
    manifest.vendor_sig = hex::encode(
        vendor_key
            .sign(canonical_manifest_bytes(&manifest).as_slice())
            .to_bytes(),
    );
    serde_json::to_vec(&manifest).expect("serialize signed manifest")
}

fn permissive_org_config() -> OrgSignedConfig {
    OrgSignedConfig {
        allows_https_intercept: true,
        allows_http_intercept: true,
        process_filter: None,
        allowed_capture_modes: vec![
            "metadata_only".to_string(),
            "sensitive_artifacts".to_string(),
            "full_content".to_string(),
        ],
    }
}

fn scope_allowed(scope: &BundleScope, org: &OrgSignedConfig) -> bool {
    if scope.intercept_https && !org.allows_https_intercept {
        return false;
    }
    if scope.intercept_http && !org.allows_http_intercept {
        return false;
    }

    let allowed_modes = org
        .allowed_capture_modes
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    for mode in &scope.capture_modes {
        if !allowed_modes.contains(mode.as_str()) {
            return false;
        }
    }

    match (&org.process_filter, &scope.process_filter) {
        (Some(_), None) => false,
        (Some(org_filter), Some(bundle_filter)) => {
            let allowed = org_filter
                .iter()
                .map(String::as_str)
                .collect::<HashSet<_>>();
            bundle_filter
                .iter()
                .all(|entry| allowed.contains(entry.as_str()))
        }
        _ => true,
    }
}

#[test]
fn bundle_watcher_e2e_hot_swap_and_db_contract() {
    let vendor = SigningKey::from_bytes(&[91u8; 32]);
    let org = permissive_org_config();
    let vendor_pubkey = vendor.verifying_key().to_bytes();

    let initial_assets = bundle_assets(
        serde_json::to_vec(&soth_detect::OwnedDetectBundle::default()).expect("default detect"),
        "api.openai.com",
        "policy-v1",
    );
    let initial_manifest = signed_manifest_bytes(
        "bundle-v1",
        BundleScope {
            intercept_https: false,
            intercept_http: false,
            process_filter: None,
            capture_modes: vec!["metadata_only".to_string()],
        },
        &initial_assets,
        &vendor,
    );
    let initial_loaded = load_from_bytes(
        initial_manifest.as_slice(),
        initial_assets,
        &vendor_pubkey,
        &org,
    )
    .expect("load initial bundle");

    let db_file = NamedTempFile::new().expect("temp sqlite file");
    let db_path = db_file.path().to_path_buf();
    let db = Arc::new(Mutex::new(Connection::open(&db_path).expect("open sqlite")));

    let (watcher, handle) = BundleWatcher::new(
        initial_loaded,
        vendor_pubkey,
        Arc::new(org),
        db,
        VerificationOptions::default(),
    )
    .expect("create watcher");

    let next_assets = bundle_assets(
        DETECT_FIXTURE_BYTES.to_vec(),
        "api.anthropic.com",
        "policy-v2",
    );
    let next_manifest = signed_manifest_bytes(
        "bundle-v2",
        BundleScope {
            intercept_https: false,
            intercept_http: false,
            process_filter: None,
            capture_modes: vec![
                "metadata_only".to_string(),
                "sensitive_artifacts".to_string(),
            ],
        },
        &next_assets,
        &vendor,
    );

    let installed = watcher
        .install(next_manifest.as_slice(), next_assets)
        .expect("install v2");
    assert_eq!(installed, "bundle-v2");

    let current = handle.current();
    assert_eq!(current.version, "bundle-v2");
    assert!(!current.detect.domain_index.is_empty());
    assert!(
        current
            .gating
            .gates
            .stage0_tls
            .passthrough_domains
            .contains("*.apple.com"),
        "gating passthrough patterns should be normalized on load"
    );
    assert!(current
        .gating
        .gates
        .stage0_tls
        .tls_intercept_hosts
        .contains("api.anthropic.com"));

    let verify = Connection::open(&db_path).expect("open db for verification");
    let bundle_status: String = verify
        .query_row(
            "SELECT status
             FROM intelligence_bundles
             WHERE bundle_version = ?1",
            params!["bundle-v2"],
            |row| row.get(0),
        )
        .expect("bundle row");
    assert_eq!(bundle_status, "ACTIVE");

    let policy_rows: i64 = verify
        .query_row("SELECT COUNT(*) FROM active_policy_config", [], |row| {
            row.get(0)
        })
        .expect("policy count");
    assert_eq!(policy_rows, 1);
}

#[test]
fn bundle_large_scope_matrix_corpus_e2e() {
    let vendor = SigningKey::from_bytes(&[92u8; 32]);
    let vendor_pubkey = vendor.verifying_key().to_bytes();
    let detect = serde_json::to_vec(&soth_detect::OwnedDetectBundle::default())
        .expect("serialize default detect");

    let assets = bundle_assets(detect, "api.openai.com", "policy-corpus");

    let mut passed = 0usize;
    let mut rejected = 0usize;
    for idx in 0..240u32 {
        let org = OrgSignedConfig {
            allows_https_intercept: idx % 5 != 0,
            allows_http_intercept: idx % 7 != 0,
            process_filter: if idx % 4 == 0 {
                Some(vec![
                    "com.cursor.app".to_string(),
                    "com.openai.chatgpt".to_string(),
                ])
            } else {
                None
            },
            allowed_capture_modes: if idx % 6 == 0 {
                vec!["metadata_only".to_string()]
            } else {
                vec![
                    "metadata_only".to_string(),
                    "sensitive_artifacts".to_string(),
                    "full_content".to_string(),
                ]
            },
        };

        let capture_modes = match idx % 4 {
            0 => vec!["metadata_only".to_string()],
            1 => vec!["sensitive_artifacts".to_string()],
            2 => vec!["full_content".to_string()],
            _ => vec!["metadata_only".to_string(), "full_content".to_string()],
        };

        let process_filter = match idx % 5 {
            0 => None,
            1 => Some(vec!["com.cursor.app".to_string()]),
            2 => Some(vec![
                "com.cursor.app".to_string(),
                "com.openai.chatgpt".to_string(),
            ]),
            3 => Some(vec!["com.extra.ai".to_string()]),
            _ => Some(vec!["com.openai.chatgpt".to_string()]),
        };

        let scope = BundleScope {
            intercept_https: idx % 3 == 0,
            intercept_http: idx % 4 == 0,
            process_filter,
            capture_modes,
        };

        let manifest = signed_manifest_bytes(
            format!("bundle-corpus-{idx}").as_str(),
            scope.clone(),
            &assets,
            &vendor,
        );

        let expected_ok = scope_allowed(&scope, &org);
        let out = load_from_bytes(manifest.as_slice(), assets.clone(), &vendor_pubkey, &org);
        if expected_ok {
            assert!(
                out.is_ok(),
                "case {idx} expected success but failed with error: {}",
                out.err().map(|error| error.to_string()).unwrap_or_default()
            );
            passed += 1;
        } else {
            assert!(
                matches!(out, Err(BundleError::ScopeExpansionRefused { .. })),
                "case {idx} expected scope rejection"
            );
            rejected += 1;
        }
    }

    assert!(
        passed >= 120,
        "expected at least 120 passing cases, got {passed}"
    );
    assert!(
        rejected >= 40,
        "expected at least 40 rejected cases, got {rejected}"
    );
}

#[test]
fn bundle_home_detect_fixture_optional_smoke() {
    let Some(home) = std::env::var_os("HOME") else {
        eprintln!("Skipping home detect fixture smoke: HOME is not set");
        return;
    };
    let detect_path = PathBuf::from(home)
        .join(".soth")
        .join("registry_bundle_cache.detect_bundle.json");
    if !detect_path.exists() {
        eprintln!(
            "Skipping home detect fixture smoke: bundle not found at {}",
            detect_path.display()
        );
        return;
    }

    let detect_bytes = std::fs::read(detect_path.as_path()).expect("read home detect bundle");
    let detect: soth_detect::OwnedDetectBundle =
        serde_json::from_slice(detect_bytes.as_slice()).expect("parse home detect bundle");
    assert!(
        !detect.domain_index.is_empty(),
        "home detect bundle should have provider/domain mappings"
    );

    let vendor = SigningKey::from_bytes(&[93u8; 32]);
    let vendor_pubkey = vendor.verifying_key().to_bytes();
    let org = permissive_org_config();
    let assets = bundle_assets(detect_bytes, "api.openai.com", "policy-home");
    let manifest = signed_manifest_bytes(
        "bundle-home-smoke",
        BundleScope {
            intercept_https: false,
            intercept_http: false,
            process_filter: None,
            capture_modes: vec!["metadata_only".to_string()],
        },
        &assets,
        &vendor,
    );
    let loaded = load_from_bytes(manifest.as_slice(), assets, &vendor_pubkey, &org)
        .expect("home detect bundle should load through soth-bundle");
    assert!(!loaded.detect.domain_index.is_empty());
}
