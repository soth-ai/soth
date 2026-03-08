use std::collections::{BTreeMap, HashMap};
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
    DecisionReason, GateDecision, GateOutcome, GatingBundle, HostRule, ProcessInfo, RequestHeaders,
    Stage3Config,
};
use soth_proxy::config::{GateAction, PipelineConfig};
use soth_proxy::gating::evaluator::{GateEvaluator, GateOverrides};
use soth_proxy::gating::stage0_tls::HostMatcher;
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

#[derive(Clone)]
struct RuntimeBundles {
    gating: GatingBundle,
    detect: soth_detect::OwnedDetectBundle,
}

#[derive(Clone)]
struct HttpCase {
    name: String,
    host: String,
    method: String,
    path: String,
    bundle_id: String,
    origin: Option<String>,
    expect_decision: GateDecision,
    expect_reason: DecisionReason,
}

#[derive(Clone)]
struct TlsCase {
    name: String,
    sni: String,
    expect: GateDecision,
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
        created_at: 1_772_000_050,
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

fn load_runtime_bundles() -> RuntimeBundles {
    let home = dirs::home_dir().unwrap_or_else(|| Path::new(".").to_path_buf());
    let local_gating = home.join(".soth/registry_bundle_cache.gating_bundle.json");
    let local_detect = home.join(".soth/registry_bundle_cache.detect_bundle.json");

    if local_gating.exists() && local_detect.exists() {
        let gating_bytes = std::fs::read(local_gating).expect("read local gating bundle");
        let detect_bytes = std::fs::read(local_detect).expect("read local detect bundle");
        let mut gating: GatingBundle =
            serde_json::from_slice(gating_bytes.as_slice()).expect("parse local gating bundle");
        gating.normalize_host_patterns_in_place();
        let detect: soth_detect::OwnedDetectBundle =
            serde_json::from_slice(detect_bytes.as_slice()).expect("parse local detect bundle");
        return RuntimeBundles { gating, detect };
    }

    let detect_fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../soth-detect/tests/fixtures/registry_bundle_cache.detect_bundle.json");
    let detect_bytes = std::fs::read(detect_fixture).expect("read detect fixture");
    let detect: soth_detect::OwnedDetectBundle =
        serde_json::from_slice(detect_bytes.as_slice()).expect("parse detect fixture");

    let vendor = SigningKey::from_bytes(&[61u8; 32]);
    let vendor_pubkey = vendor.verifying_key().to_bytes();
    let mut assets = HashMap::new();
    assets.insert("detect/bundle.json".to_string(), detect_bytes);
    let manifest = signed_manifest_bytes("corpus-fallback-bundle", &assets, &vendor);
    let loaded = soth_bundle::load_from_bytes(
        manifest.as_slice(),
        assets,
        &vendor_pubkey,
        &OrgSignedConfig::default(),
    )
    .expect("load fallback bundle");

    RuntimeBundles {
        gating: loaded.gating.as_ref().clone(),
        detect,
    }
}

fn build_handler(
    db_path: &Path,
    pipeline_config: PipelineConfig,
    bundles: &RuntimeBundles,
) -> ProxyHandler {
    let vendor = SigningKey::from_bytes(&[95u8; 32]);
    let vendor_pubkey = vendor.verifying_key().to_bytes();

    let mut assets = HashMap::new();
    assets.insert(
        "detect/bundle.json".to_string(),
        serde_json::to_vec(&bundles.detect).expect("serialize detect bundle"),
    );
    assets.insert(
        "gating/bundle.json".to_string(),
        serde_json::to_vec(&bundles.gating).expect("serialize gating bundle"),
    );

    let manifest = signed_manifest_bytes("corpus-bundle", &assets, &vendor);
    let loaded = soth_bundle::load_from_bytes(
        manifest.as_slice(),
        assets,
        &vendor_pubkey,
        &OrgSignedConfig::default(),
    )
    .expect("load corpus bundle");

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

fn materialize_host(pattern: &str) -> Option<String> {
    let mut p = pattern.trim().to_ascii_lowercase();
    if let Some(exact) = p.strip_prefix('=') {
        p = exact.to_string();
    }
    if p.is_empty() {
        return None;
    }
    p = p.replace('*', "sample");
    p = p
        .split('/')
        .next()
        .unwrap_or(p.as_str())
        .trim()
        .trim_matches('.')
        .to_string();
    if p.ends_with(':') {
        p.pop();
    }
    if p.is_empty() {
        None
    } else {
        Some(p)
    }
}

fn materialize_path(pattern: &str) -> String {
    let mut p = pattern.trim().replace('*', "x");
    if p.is_empty() {
        return "/".to_string();
    }
    if !p.starts_with('/') {
        p = format!("/{p}");
    }
    p
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    if !pattern.contains('*') {
        return pattern == text;
    }
    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');
    let parts: Vec<&str> = pattern.split('*').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return true;
    }
    let mut cursor = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        let is_first = idx == 0;
        let is_last = idx + 1 == parts.len();

        if is_first && !starts_with_wildcard {
            if !text[cursor..].starts_with(part) {
                return false;
            }
            cursor += part.len();
            continue;
        }
        if is_last && !ends_with_wildcard {
            return text.ends_with(part);
        }
        if let Some(offset) = text[cursor..].find(part) {
            cursor += offset + part.len();
        } else {
            return false;
        }
    }
    true
}

fn path_denied_by_host_rule(host_rule: &HostRule, path: &str) -> bool {
    if host_rule.paths.deny_exact.iter().any(|p| p == path) {
        return true;
    }
    host_rule
        .paths
        .deny_glob
        .iter()
        .any(|pattern| glob_match(pattern.as_str(), path))
}

fn choose_safe_path_for_allow(host_rule: &HostRule) -> Option<String> {
    if !host_rule.paths.allow.is_empty() {
        for pattern in &host_rule.paths.allow {
            let path = materialize_path(pattern.as_str());
            if !path_denied_by_host_rule(host_rule, path.as_str()) {
                return Some(path);
            }
        }
        return None;
    }
    let fallback = "/".to_string();
    if path_denied_by_host_rule(host_rule, fallback.as_str()) {
        None
    } else {
        Some(fallback)
    }
}

fn blacklisted(stage3: &Stage3Config, host: &str, path: &str) -> bool {
    let host_lc = host.to_ascii_lowercase();
    if stage3
        .blacklisted_host_substrings
        .iter()
        .any(|needle| !needle.is_empty() && host_lc.contains(needle.to_ascii_lowercase().as_str()))
    {
        return true;
    }
    let path_lc = path.to_ascii_lowercase();
    if stage3
        .blacklisted_keywords
        .iter()
        .any(|needle| !needle.is_empty() && path_lc.contains(needle.to_ascii_lowercase().as_str()))
    {
        return true;
    }
    stage3
        .blacklisted_path_substrings
        .iter()
        .any(|needle| !needle.is_empty() && path_lc.contains(needle.to_ascii_lowercase().as_str()))
}

fn pick_identity(map: &BTreeMap<String, soth_core::IdentityEntry>) -> Option<String> {
    map.keys().find(|k| *k == &k.to_ascii_lowercase()).cloned()
}

fn build_request(
    host: &str,
    method: &str,
    path: &str,
    origin: Option<&str>,
) -> soth_core::RawRequest {
    let mut headers = RequestHeaders::new();
    headers.insert("host".to_string(), host.to_string());
    if let Some(origin) = origin {
        headers.insert("origin".to_string(), origin.to_string());
    }
    soth_core::RawRequest {
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body: Bytes::from_static(br#"{"messages":[{"role":"user","content":"ok"}]}"#),
        connection_meta: soth_core::ConnectionMeta::from_transport(
            Uuid::new_v4(),
            soth_core::SocketFamily::UnixDomain { path: None },
            None,
            None,
        ),
    }
}

fn build_process_info(bundle_id: &str) -> Option<ProcessInfo> {
    Some(ProcessInfo {
        pid: Some(100),
        process_name: Some(bundle_id.to_string()),
        bundle_id: Some(bundle_id.to_string()),
        parent_pid: None,
        parent_process_name: None,
        parent_bundle_id: None,
    })
}

fn choose_disallowed_method(allowed: &[String]) -> Option<String> {
    let candidates = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];
    candidates
        .iter()
        .find(|m| !allowed.iter().any(|a| a.eq_ignore_ascii_case(m)))
        .map(|m| (*m).to_string())
}

fn sorted_set(input: &std::collections::HashSet<String>) -> Vec<String> {
    let mut out = input.iter().cloned().collect::<Vec<_>>();
    out.sort();
    out
}

fn generate_tls_cases(bundle: &GatingBundle) -> Vec<TlsCase> {
    let passthrough = HostMatcher::from_patterns(&bundle.gates.stage0_tls.passthrough_domains);
    let intercept = HostMatcher::from_patterns(&bundle.gates.stage0_tls.tls_intercept_hosts);
    let mut cases = Vec::new();

    for pattern in sorted_set(&bundle.gates.stage0_tls.passthrough_domains)
        .into_iter()
        .take(60)
    {
        if let Some(host) = materialize_host(pattern.as_str()) {
            cases.push(TlsCase {
                name: format!("tls_passthrough::{pattern}"),
                sni: host,
                expect: GateDecision::Passthrough,
            });
        }
    }

    let mut intercept_added = 0usize;
    for pattern in sorted_set(&bundle.gates.stage0_tls.tls_intercept_hosts) {
        if intercept_added >= 160 {
            break;
        }
        let Some(host) = materialize_host(pattern.as_str()) else {
            continue;
        };
        if passthrough.matches(host.as_str()) {
            continue;
        }
        if !intercept.matches(host.as_str()) {
            continue;
        }
        intercept_added += 1;
        cases.push(TlsCase {
            name: format!("tls_intercept::{pattern}"),
            sni: host,
            expect: GateDecision::Intercept,
        });
    }
    cases
}

fn generate_http_cases(bundle: &GatingBundle) -> Vec<HttpCase> {
    let host_identity = pick_identity(
        &bundle
            .identity_index
            .hosts
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
    .unwrap_or_else(|| "com.google.chrome".to_string());
    let non_host_identity = pick_identity(
        &bundle
            .identity_index
            .non_hosts
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
    .unwrap_or_else(|| "com.cursor".to_string());
    let allowed_origin = sorted_set(&bundle.gates.stage5_host_origin.allowed_host_origins)
        .into_iter()
        .find_map(|p| materialize_host(p.as_str()))
        .unwrap_or_else(|| "chatgpt.com".to_string());

    let all_entities = bundle
        .entities
        .providers
        .iter()
        .chain(bundle.entities.web_apps.iter())
        .chain(bundle.entities.native_apps.iter())
        .collect::<Vec<_>>();

    let mut allow_cases = Vec::new();
    let mut deny_exact_cases = Vec::new();
    let mut deny_glob_cases = Vec::new();
    let mut method_cases = Vec::new();
    let mut host_origin_cases = Vec::new();

    for entity in all_entities {
        for host_rule in &entity.hosts {
            let Some(host) = materialize_host(host_rule.pattern.as_str()) else {
                continue;
            };

            if allow_cases.len() < 120 {
                let method = host_rule
                    .methods
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "POST".to_string());
                if let Some(path) = choose_safe_path_for_allow(host_rule) {
                    if !blacklisted(&bundle.gates.stage3_blacklist, host.as_str(), path.as_str()) {
                        allow_cases.push(HttpCase {
                            name: format!("allow::{host}::{path}"),
                            host: host.clone(),
                            method,
                            path,
                            bundle_id: non_host_identity.clone(),
                            origin: None,
                            expect_decision: GateDecision::Intercept,
                            expect_reason: DecisionReason::Intercept,
                        });
                    }
                }
            }

            if deny_exact_cases.len() < 40 {
                if let Some(path) = host_rule.paths.deny_exact.first() {
                    deny_exact_cases.push(HttpCase {
                        name: format!("deny_exact::{host}::{path}"),
                        host: host.clone(),
                        method: host_rule
                            .methods
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "POST".to_string()),
                        path: path.clone(),
                        bundle_id: non_host_identity.clone(),
                        origin: None,
                        expect_decision: GateDecision::Skip,
                        expect_reason: DecisionReason::PathDeniedExact,
                    });
                }
            }

            if deny_glob_cases.len() < 40 {
                if let Some(pattern) = host_rule.paths.deny_glob.first() {
                    deny_glob_cases.push(HttpCase {
                        name: format!("deny_glob::{host}::{pattern}"),
                        host: host.clone(),
                        method: host_rule
                            .methods
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "POST".to_string()),
                        path: materialize_path(pattern.as_str()),
                        bundle_id: non_host_identity.clone(),
                        origin: None,
                        expect_decision: GateDecision::Skip,
                        expect_reason: DecisionReason::PathDeniedGlob,
                    });
                }
            }

            if method_cases.len() < 40 && !host_rule.methods.is_empty() {
                if let Some(disallowed) = choose_disallowed_method(&host_rule.methods) {
                    if let Some(path) = choose_safe_path_for_allow(host_rule) {
                        if !blacklisted(
                            &bundle.gates.stage3_blacklist,
                            host.as_str(),
                            path.as_str(),
                        ) {
                            method_cases.push(HttpCase {
                                name: format!("method_denied::{host}::{path}::{disallowed}"),
                                host: host.clone(),
                                method: disallowed,
                                path,
                                bundle_id: non_host_identity.clone(),
                                origin: None,
                                expect_decision: GateDecision::Skip,
                                expect_reason: DecisionReason::MethodNotAllowed,
                            });
                        }
                    }
                }
            }

            if host_origin_cases.len() < 60 {
                let method = host_rule
                    .methods
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "POST".to_string());
                if let Some(path) = choose_safe_path_for_allow(host_rule) {
                    if !blacklisted(&bundle.gates.stage3_blacklist, host.as_str(), path.as_str()) {
                        host_origin_cases.push(HttpCase {
                            name: format!("host_origin_missing::{host}::{path}"),
                            host: host.clone(),
                            method: method.clone(),
                            path: path.clone(),
                            bundle_id: host_identity.clone(),
                            origin: None,
                            expect_decision: GateDecision::Skip,
                            expect_reason: DecisionReason::HostOriginNotAllowed,
                        });
                        host_origin_cases.push(HttpCase {
                            name: format!("host_origin_ok::{host}::{path}"),
                            host: host.clone(),
                            method,
                            path,
                            bundle_id: host_identity.clone(),
                            origin: Some(format!("https://{allowed_origin}")),
                            expect_decision: GateDecision::Intercept,
                            expect_reason: DecisionReason::Intercept,
                        });
                    }
                }
            }
        }
    }

    let mut out = Vec::new();
    out.extend(allow_cases);
    out.extend(deny_exact_cases);
    out.extend(deny_glob_cases);
    out.extend(method_cases);
    out.extend(host_origin_cases);
    out
}

fn assert_gate_outcome(case: &HttpCase, outcome: &GateOutcome) {
    assert_eq!(
        std::mem::discriminant(&outcome.decision),
        std::mem::discriminant(&case.expect_decision),
        "case={} decision mismatch; got={:?} want={:?}",
        case.name,
        outcome.decision,
        case.expect_decision
    );
    assert_eq!(
        outcome.reason, case.expect_reason,
        "case={} reason mismatch; got={:?} want={:?}",
        case.name, outcome.reason, case.expect_reason
    );
}

#[test]
fn gating_large_corpus_evaluator_in_out() {
    let bundles = load_runtime_bundles();
    let evaluator = GateEvaluator::new(Arc::new(bundles.gating.clone()));

    let tls_cases = generate_tls_cases(&bundles.gating);
    println!("gating corpus tls_cases={}", tls_cases.len());
    assert!(tls_cases.len() >= 120, "insufficient tls corpus size");
    for case in &tls_cases {
        let got = evaluator.evaluate_tls(case.sni.as_str());
        assert_eq!(
            std::mem::discriminant(&got),
            std::mem::discriminant(&case.expect),
            "tls case={} sni={} got={:?} want={:?}",
            case.name,
            case.sni,
            got,
            case.expect
        );
    }

    let http_cases = generate_http_cases(&bundles.gating);
    println!("gating corpus http_cases={}", http_cases.len());
    assert!(http_cases.len() >= 150, "insufficient http corpus size");
    for case in &http_cases {
        let req = build_request(
            case.host.as_str(),
            case.method.as_str(),
            case.path.as_str(),
            case.origin.as_deref(),
        );
        let outcome = evaluator.evaluate_http(
            &req,
            &build_process_info(case.bundle_id.as_str()),
            GateOverrides::default(),
        );
        assert_gate_outcome(case, &outcome);
    }
}

fn sample_mitm_request(connection_id: Uuid, case: &HttpCase) -> soth_mitm::RawRequest {
    let mut headers = HeaderMap::new();
    headers.insert(
        "host",
        HeaderValue::from_str(case.host.as_str()).expect("valid host header"),
    );
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    if let Some(origin) = case.origin.as_ref() {
        headers.insert(
            "origin",
            HeaderValue::from_str(origin.as_str()).expect("valid origin"),
        );
    }

    soth_mitm::RawRequest {
        method: case.method.clone(),
        path: case.path.clone(),
        headers,
        body: Bytes::from_static(
            br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ok"}]}"#,
        ),
        connection_meta: Arc::new(soth_mitm::ConnectionMeta {
            connection_id,
            socket_family: soth_mitm::SocketFamily::TcpV4 {
                local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10_001),
                remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
            },
            process_info: Some(soth_mitm::ProcessInfo {
                pid: 123,
                bundle_id: Some(case.bundle_id.clone()),
                exe_name: None,
                exe_path: None,
                parent_pid: None,
                parent_process_name: None,
            }),
            tls_info: None,
        }),
    }
}

fn sample_mitm_response(connection_id: Uuid) -> soth_mitm::RawResponse {
    soth_mitm::RawResponse {
        status: 200,
        headers: HeaderMap::new(),
        body: Bytes::from_static(br#"{"usage":{"prompt_tokens":2,"completion_tokens":3}}"#),
        connection_meta: Arc::new(soth_mitm::ConnectionMeta {
            connection_id,
            socket_family: soth_mitm::SocketFamily::TcpV4 {
                local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10_001),
                remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
            },
            process_info: None,
            tls_info: None,
        }),
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
    for _ in 0..200 {
        if intercept_row_count(db_path) >= min_rows {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for intercept row count >= {min_rows}");
}

#[tokio::test]
async fn gating_large_corpus_proxy_handler_subset_e2e() {
    let bundles = load_runtime_bundles();
    let evaluator = GateEvaluator::new(Arc::new(bundles.gating.clone()));
    let mut all = generate_http_cases(&bundles.gating);
    all.truncate(80);
    println!("gating corpus proxy_subset_cases={}", all.len());

    let db_path =
        std::env::temp_dir().join(format!("soth-proxy-gating-corpus-{}.db", Uuid::new_v4()));
    let mut pipeline = PipelineConfig::default();
    pipeline.unknown_app_action = Some(GateAction::Intercept);
    let handler = build_handler(db_path.as_path(), pipeline, &bundles);

    use soth_mitm::InterceptHandler;
    let mut expected_intercepts = 0i64;
    for case in &all {
        let req_core = build_request(
            case.host.as_str(),
            case.method.as_str(),
            case.path.as_str(),
            case.origin.as_deref(),
        );
        let expected = evaluator.evaluate_http(
            &req_core,
            &build_process_info(case.bundle_id.as_str()),
            GateOverrides::default(),
        );
        assert_gate_outcome(case, &expected);

        let connection_id = Uuid::new_v4();
        let req = sample_mitm_request(connection_id, case);
        let decision = handler.on_request(&req).await;
        match expected.decision {
            GateDecision::Block { .. } => {
                assert!(
                    matches!(decision, soth_mitm::HandlerDecision::Block { .. }),
                    "case={} expected immediate block",
                    case.name
                );
            }
            GateDecision::Intercept => {
                assert_eq!(decision, soth_mitm::HandlerDecision::Allow);
                expected_intercepts += 1;
                handler
                    .on_response(&sample_mitm_response(connection_id))
                    .await;
            }
            GateDecision::Skip | GateDecision::Passthrough => {
                assert_eq!(decision, soth_mitm::HandlerDecision::Allow);
            }
        }
    }

    if expected_intercepts > 0 {
        wait_for_intercept_rows(db_path.as_path(), expected_intercepts).await;
    }
    println!(
        "gating corpus proxy_subset_expected_intercepts={}",
        expected_intercepts
    );
    assert!(intercept_row_count(db_path.as_path()) >= expected_intercepts);
    let _ = std::fs::remove_file(db_path);
}
