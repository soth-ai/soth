use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use http::{HeaderMap, HeaderValue};
use rusqlite::Connection;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use uuid::Uuid;

use soth_bundle::{AssetEntry, BundleManifest, BundleScope, OrgSignedConfig};
use soth_core::{
    AppType, CaptureMode, EntityCatalog, EntityTrafficRules, GateConfig, GateDefaults,
    GatingBundle, HostRule, IdentityEntry, IdentityIndex, NonCatalogedAction, PathRules,
    ProcessAction, Stage0Config, Stage1Config, Stage2Config, Stage3Config, Stage4Config,
    Stage5Config, UnknownAppAction,
};
use soth_proxy::config::{GateAction, PipelineConfig};
use soth_proxy::{db, ProxyHandler};

#[derive(Serialize)]
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
        version: &manifest.version,
        created_at: manifest.created_at,
        vendor_sig: "",
        org_approval_sig: manifest.org_approval_sig.as_deref(),
        assets,
        scope: &manifest.scope,
    })
    .expect("serialize canonical manifest")
}

fn signed_manifest_bytes(
    version: &str,
    assets: &HashMap<String, Vec<u8>>,
    vendor_signing_key: &SigningKey,
) -> Vec<u8> {
    let mut entries: Vec<AssetEntry> = assets
        .iter()
        .map(|(path, bytes)| AssetEntry {
            path: path.clone(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            size_bytes: bytes.len() as u64,
        })
        .collect();
    entries.sort_by(|left, right| left.path.cmp(&right.path));

    let mut manifest = BundleManifest {
        version: version.to_string(),
        created_at: 1_772_000_020,
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

    let signature = vendor_signing_key.sign(canonical_manifest_bytes(&manifest).as_slice());
    manifest.vendor_sig = hex::encode(signature.to_bytes());
    serde_json::to_vec(&manifest).expect("serialize signed manifest")
}

fn detect_bundle_with_openai_catalog() -> soth_core::OwnedDetectBundle {
    let mut detect = soth_core::OwnedDetectBundle::default();
    detect
        .domain_index
        .insert("api.openai.com".to_string(), "openai".to_string());
    detect.llm_providers.insert(
        "openai".to_string(),
        soth_core::ProviderEntry {
            provider_id: Some("openai".to_string()),
            name: Some("openai".to_string()),
            api_format: Some("openai_rest".to_string()),
            provider_type: None,
            pricing: None,
            capture: None,
            detection: None,
            matching_rules: vec![],
        },
    );
    detect
}

fn gating_bundle(include_openai_passthrough: bool) -> GatingBundle {
    let mut passthrough = HashSet::new();
    if include_openai_passthrough {
        passthrough.insert("api.openai.com".to_string());
    }

    let hosts = HashMap::from([(
        "com.google.chrome".to_string(),
        IdentityEntry {
            entity_id: "chrome".to_string(),
            app_type: AppType::Host,
            capture_mode: CaptureMode::MetadataOnly,
            action: ProcessAction::Intercept,
            enabled: None,
            host_filter: None,
            host_list_ref: None,
        },
    )]);
    let non_hosts = HashMap::from([
        (
            "com.cursor".to_string(),
            IdentityEntry {
                entity_id: "cursor".to_string(),
                app_type: AppType::NonHost,
                capture_mode: CaptureMode::MetadataOnly,
                action: ProcessAction::Intercept,
                enabled: None,
                host_filter: None,
                host_list_ref: None,
            },
        ),
        (
            "com.blocked.app".to_string(),
            IdentityEntry {
                entity_id: "blocked".to_string(),
                app_type: AppType::NonHost,
                capture_mode: CaptureMode::MetadataOnly,
                action: ProcessAction::Block,
                enabled: None,
                host_filter: None,
                host_list_ref: None,
            },
        ),
    ]);

    let provider_rules = EntityTrafficRules {
        entity_id: "openai".to_string(),
        capture_mode: CaptureMode::SensitiveArtifacts,
        hosts: vec![HostRule {
            pattern: "api.openai.com".to_string(),
            methods: vec!["POST".to_string()],
            paths: PathRules {
                deny_exact: vec!["/v1/models".to_string()],
                deny_glob: vec!["*/deny/*".to_string()],
                allow: vec!["/v1/chat/completions*".to_string()],
            },
            priority: None,
        }],
        api_format: None,
        entity_type: None,
        pricing: None,
        capture: None,
        detection: None,
    };

    GatingBundle {
        identity_index: IdentityIndex { hosts, non_hosts },
        gates: GateConfig {
            order: vec![
                soth_core::GateStage::Stage0Tls,
                soth_core::GateStage::Stage1AppOrigin,
                soth_core::GateStage::Stage2Whitelist,
                soth_core::GateStage::Stage3Blacklist,
                soth_core::GateStage::Stage4AppType,
                soth_core::GateStage::Stage5HostOrigin,
                soth_core::GateStage::Intercept,
            ],
            defaults: GateDefaults {
                sensor_enabled: true,
                fail_open_on_config_error: true,
                unknown_app_action: UnknownAppAction::Skip,
                non_cataloged_host_action: NonCatalogedAction::Skip,
                discovery: soth_core::DiscoveryConfig::default(),
                source_unknown_app_action: None,
                source_whitelisted_unknown_app_action: None,
                source_non_whitelisted_host_action: None,
                source_browser_default_action: None,
            },
            stage0_tls: Stage0Config {
                tls_intercept_hosts: HashSet::from(["api.openai.com".to_string()]),
                passthrough_domains: passthrough,
                enable_discovery: true,
            },
            stage1_app_origin: Stage1Config {
                skip_if_unresolved_process: true,
            },
            stage2_whitelist: Stage2Config {
                allow_empty_means_allow_all_except_denied: true,
            },
            stage3_blacklist: Stage3Config {
                blacklisted_keywords: vec!["telemetry".to_string(), "sentry".to_string()],
                blacklisted_path_substrings: vec!["/monitoring".to_string()],
                blacklisted_host_substrings: Vec::new(),
                graphql_operation_blacklist: Vec::new(),
                graphql_operation_blacklist_enabled: false,
                match_type: soth_core::BlacklistMatchType::CaseInsensitiveSubstring,
            },
            stage4_app_type: Stage4Config {
                derive_from_identity_index: true,
            },
            stage5_host_origin: Stage5Config {
                allowed_host_origins: HashSet::from(["chatgpt.com".to_string()]),
                skip_for_discovery_capture: true,
            },
        },
        entities: EntityCatalog {
            providers: vec![provider_rules],
            web_apps: Vec::new(),
            native_apps: Vec::new(),
        },
    }
}

fn build_handler(
    db_path: &Path,
    pipeline_config: PipelineConfig,
    detect_bundle: soth_core::OwnedDetectBundle,
    gating_bundle: GatingBundle,
) -> ProxyHandler {
    let vendor = SigningKey::from_bytes(&[93u8; 32]);
    let vendor_pubkey = vendor.verifying_key().to_bytes();

    let mut assets = HashMap::new();
    assets.insert(
        "detect/bundle.json".to_string(),
        serde_json::to_vec(&detect_bundle).expect("serialize detect bundle"),
    );
    assets.insert(
        "gating/bundle.json".to_string(),
        serde_json::to_vec(&gating_bundle).expect("serialize gating bundle"),
    );

    let manifest = signed_manifest_bytes("bundle-gating-v1", &assets, &vendor);
    let loaded = soth_bundle::load_from_bytes(
        manifest.as_slice(),
        assets,
        &vendor_pubkey,
        &OrgSignedConfig::default(),
    )
    .expect("load bundle");

    let bundle_db = Arc::new(Mutex::new(
        Connection::open(db_path).expect("open bundle db"),
    ));
    let (_watcher, handle) = soth_bundle::BundleWatcher::new(
        loaded,
        vendor_pubkey,
        Arc::new(OrgSignedConfig::default()),
        bundle_db,
        soth_bundle::VerificationOptions::default(),
    )
    .expect("create bundle watcher");

    let proxy_db = Arc::new(Mutex::new(db::open(db_path).expect("open proxy db")));
    ProxyHandler::new(
        handle,
        None,
        None,
        proxy_db,
        pipeline_config,
        soth_classify::ClassifyConfig::default(),
        soth_proxy::classify_task::RuntimeConfig::default(),
        "org-test".to_string(),
        "team-test".to_string(),
        "device-test".to_string(),
        "secret-test".to_string(),
    )
}

fn sample_connection_meta(
    connection_id: Uuid,
    bundle_id: Option<&str>,
) -> Arc<soth_mitm::ConnectionMeta> {
    Arc::new(soth_mitm::ConnectionMeta {
        connection_id,
        socket_family: soth_mitm::SocketFamily::TcpV4 {
            local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10_001),
            remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
        },
        process_info: bundle_id.map(|id| soth_mitm::ProcessInfo {
            pid: 42,
            bundle_id: Some(id.to_string()),
            exe_name: None,
            exe_path: None,
            parent_pid: None,
            parent_process_name: None,
        }),
        tls_info: None,
    })
}

fn sample_request(
    connection_id: Uuid,
    host: &str,
    method: &str,
    path: &str,
    bundle_id: Option<&str>,
    origin: Option<&str>,
) -> soth_mitm::RawRequest {
    let mut headers = HeaderMap::new();
    headers.insert(
        "host",
        HeaderValue::from_str(host).expect("valid host header"),
    );
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    if let Some(origin) = origin {
        headers.insert(
            "origin",
            HeaderValue::from_str(origin).expect("valid origin header"),
        );
    }

    soth_mitm::RawRequest {
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body: Bytes::from_static(
            br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}"#,
        ),
        connection_meta: sample_connection_meta(connection_id, bundle_id),
    }
}

fn sample_response(connection_id: Uuid) -> soth_mitm::RawResponse {
    soth_mitm::RawResponse {
        status: 200,
        headers: HeaderMap::new(),
        body: Bytes::from_static(br#"{"usage":{"prompt_tokens":3,"completion_tokens":5}}"#),
        connection_meta: sample_connection_meta(connection_id, None),
    }
}

fn intercept_row_count(db_path: &Path) -> i64 {
    let conn = Connection::open(db_path).expect("open db for query");
    conn.query_row("SELECT COUNT(*) FROM intercept_records", [], |row| {
        row.get(0)
    })
    .expect("count intercept rows")
}

async fn wait_for_intercept_rows(db_path: &Path, min_rows: i64) {
    for _ in 0..120 {
        if intercept_row_count(db_path) >= min_rows {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for intercept row count >= {min_rows}");
}

#[test]
fn gating_bundle_e2e_stage0_passthrough_wins() {
    let db_path = std::env::temp_dir().join(format!("soth-proxy-gating-{}.db", Uuid::new_v4()));
    let mut pipeline = PipelineConfig::default();
    pipeline.unknown_app_action = Some(GateAction::Intercept);

    let handler = build_handler(
        db_path.as_path(),
        pipeline,
        detect_bundle_with_openai_catalog(),
        gating_bundle(true),
    );

    use soth_mitm::InterceptHandler;
    assert!(!handler.should_intercept_tls("api.openai.com:443", None));

    let _ = std::fs::remove_file(db_path);
}

#[tokio::test]
async fn gating_bundle_e2e_http_stages() {
    let db_path = std::env::temp_dir().join(format!("soth-proxy-gating-{}.db", Uuid::new_v4()));
    let mut pipeline = PipelineConfig::default();
    pipeline.unknown_app_action = Some(GateAction::Intercept);

    let handler = build_handler(
        db_path.as_path(),
        pipeline,
        detect_bundle_with_openai_catalog(),
        gating_bundle(false),
    );

    use soth_mitm::InterceptHandler;

    assert!(handler.should_intercept_tls("api.openai.com:443", None));

    let blocked = sample_request(
        Uuid::new_v4(),
        "api.openai.com",
        "POST",
        "/v1/chat/completions",
        Some("com.blocked.app"),
        None,
    );
    let blocked_decision = handler.on_request(&blocked).await;
    assert!(matches!(
        blocked_decision,
        soth_mitm::HandlerDecision::Block { status: 403, .. }
    ));

    let denied_exact = sample_request(
        Uuid::new_v4(),
        "api.openai.com",
        "POST",
        "/v1/models",
        Some("com.cursor"),
        None,
    );
    let denied_exact_decision = handler.on_request(&denied_exact).await;
    assert_eq!(denied_exact_decision, soth_mitm::HandlerDecision::Allow);
    assert_eq!(intercept_row_count(db_path.as_path()), 0);

    let blacklisted = sample_request(
        Uuid::new_v4(),
        "api.openai.com",
        "POST",
        "/v1/chat/completions?from=telemetry",
        Some("com.cursor"),
        None,
    );
    let blacklisted_decision = handler.on_request(&blacklisted).await;
    assert_eq!(blacklisted_decision, soth_mitm::HandlerDecision::Allow);
    assert_eq!(intercept_row_count(db_path.as_path()), 0);

    let host_no_origin = sample_request(
        Uuid::new_v4(),
        "api.openai.com",
        "POST",
        "/v1/chat/completions",
        Some("com.google.chrome"),
        None,
    );
    let host_no_origin_decision = handler.on_request(&host_no_origin).await;
    assert_eq!(host_no_origin_decision, soth_mitm::HandlerDecision::Allow);
    assert_eq!(intercept_row_count(db_path.as_path()), 0);

    let ok_connection = Uuid::new_v4();
    let host_allowed = sample_request(
        ok_connection,
        "api.openai.com",
        "POST",
        "/v1/chat/completions",
        Some("com.google.chrome"),
        Some("https://chatgpt.com"),
    );
    let host_allowed_decision = handler.on_request(&host_allowed).await;
    assert_eq!(host_allowed_decision, soth_mitm::HandlerDecision::Allow);
    handler.on_response(&sample_response(ok_connection)).await;

    wait_for_intercept_rows(db_path.as_path(), 1).await;
    assert!(intercept_row_count(db_path.as_path()) >= 1);

    let _ = std::fs::remove_file(db_path);
}
