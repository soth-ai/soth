/// TDD parity test: verifies that gating_from_detect() produces equivalent
/// identity_index, entity_catalog, and TLS intercept sets when fed a bundle
/// with v3 matching_rules vs v2 legacy detection+domain_index.
use soth_core::{
    GatingBundle, MatchingRule, SignalKind, SignalMatcher,
};
use soth_detect::{ApplicationEntry, OwnedDetectBundle, ProviderEntry};
use std::collections::HashMap;

// Expose gating_from_detect via the loader module's public load_from_bytes path,
// or use the same data-driven approach: build detect bundles and run gating extraction.
//
// Since gating_from_detect is private, we test it indirectly through the
// public loader by constructing bundles that exercise both code paths.

fn mr(id: &str, priority: u32, requires_all: bool, signals: Vec<SignalMatcher>) -> MatchingRule {
    MatchingRule {
        rule_id: id.to_string(),
        priority,
        requires_all,
        signals,
        ..Default::default()
    }
}

fn sig(kind: SignalKind, pattern: &str) -> SignalMatcher {
    SignalMatcher {
        kind,
        pattern: pattern.to_string(),
        ..Default::default()
    }
}

/// Build a v2 detect bundle with legacy domain_index and detection objects.
fn build_v2_detect() -> OwnedDetectBundle {
    let mut bundle = OwnedDetectBundle::default();

    // Providers.
    bundle.llm_providers.insert(
        "openai".to_string(),
        ProviderEntry {
            provider_id: Some("openai".to_string()),
            name: Some("OpenAI".to_string()),
            api_format: Some("openai".to_string()),
            detection: Some(serde_json::json!({
                "hosts": [{"pattern": "api.openai.com", "paths": {}}]
            })),
            ..Default::default()
        },
    );
    bundle.llm_providers.insert(
        "anthropic".to_string(),
        ProviderEntry {
            provider_id: Some("anthropic".to_string()),
            name: Some("Anthropic".to_string()),
            api_format: Some("anthropic".to_string()),
            detection: Some(serde_json::json!({
                "hosts": [{"pattern": "api.anthropic.com", "paths": {"allow": ["/v1/messages"]}}]
            })),
            ..Default::default()
        },
    );

    // Domain index (v2 canonical).
    bundle.domain_index.insert("api.openai.com".to_string(), "openai".to_string());
    bundle.domain_index.insert("api.anthropic.com".to_string(), "anthropic".to_string());
    bundle.domain_index.insert("chatgpt.com".to_string(), "chatgpt".to_string());
    bundle.domain_index.insert("claude.ai".to_string(), "claude".to_string());

    // Applications.
    bundle.applications.insert(
        "chatgpt".to_string(),
        ApplicationEntry {
            app_id: Some("chatgpt".to_string()),
            name: Some("ChatGPT".to_string()),
            api_format: Some("chatgpt_web".to_string()),
            detection: Some(serde_json::json!({
                "hosts": [{"pattern": "chatgpt.com", "paths": {"allow": ["/backend-api/**/conversation"]}}]
            })),
            ..Default::default()
        },
    );
    bundle.applications.insert(
        "claude".to_string(),
        ApplicationEntry {
            app_id: Some("claude".to_string()),
            name: Some("Claude".to_string()),
            api_format: Some("claude_web".to_string()),
            detection: Some(serde_json::json!({
                "hosts": [{"pattern": "claude.ai", "paths": {"allow": ["/api/organizations/**/completion"]}}]
            })),
            ..Default::default()
        },
    );
    bundle.applications.insert(
        "cursor".to_string(),
        ApplicationEntry {
            app_id: Some("cursor".to_string()),
            name: Some("Cursor".to_string()),
            bundle_ids: vec![
                "com.todesktop.230313mzl4w4u92".to_string(),
                "com.todesktop.cursor".to_string(),
            ],
            process_names: vec!["Cursor".to_string()],
            ..Default::default()
        },
    );
    bundle.applications.insert(
        "claude-code".to_string(),
        ApplicationEntry {
            app_id: Some("claude-code".to_string()),
            name: Some("Claude Code".to_string()),
            bundle_ids: vec!["com.anthropic.claude-code".to_string()],
            process_names: vec!["claude".to_string()],
            ..Default::default()
        },
    );

    bundle
}

/// Build a v3 detect bundle with matching_rules (NO legacy detection or domain_index).
fn build_v3_detect() -> OwnedDetectBundle {
    let mut bundle = OwnedDetectBundle::default();

    // Providers with matching_rules only.
    bundle.llm_providers.insert(
        "openai".to_string(),
        ProviderEntry {
            provider_id: Some("openai".to_string()),
            name: Some("OpenAI".to_string()),
            api_format: Some("openai".to_string()),
            matching_rules: vec![mr("openai-host", 850, true, vec![
                sig(SignalKind::HttpHost, "api.openai.com"),
            ])],
            ..Default::default()
        },
    );
    bundle.llm_providers.insert(
        "anthropic".to_string(),
        ProviderEntry {
            provider_id: Some("anthropic".to_string()),
            name: Some("Anthropic".to_string()),
            api_format: Some("anthropic".to_string()),
            matching_rules: vec![mr("anthropic-host", 850, true, vec![
                sig(SignalKind::HttpHost, "api.anthropic.com"),
            ])],
            ..Default::default()
        },
    );

    // Applications with matching_rules only.
    bundle.applications.insert(
        "chatgpt".to_string(),
        ApplicationEntry {
            app_id: Some("chatgpt".to_string()),
            name: Some("ChatGPT".to_string()),
            api_format: Some("chatgpt_web".to_string()),
            matching_rules: vec![mr("chatgpt-host", 900, true, vec![
                sig(SignalKind::HttpHost, "chatgpt.com"),
            ])],
            ..Default::default()
        },
    );
    bundle.applications.insert(
        "claude".to_string(),
        ApplicationEntry {
            app_id: Some("claude".to_string()),
            name: Some("Claude".to_string()),
            api_format: Some("claude_web".to_string()),
            matching_rules: vec![mr("claude-host", 900, true, vec![
                sig(SignalKind::HttpHost, "claude.ai"),
            ])],
            ..Default::default()
        },
    );
    bundle.applications.insert(
        "cursor".to_string(),
        ApplicationEntry {
            app_id: Some("cursor".to_string()),
            name: Some("Cursor".to_string()),
            matching_rules: vec![
                mr("cursor-bid-1", 1000, false, vec![
                    sig(SignalKind::ProcessBundleId, "com.todesktop.230313mzl4w4u92"),
                ]),
                mr("cursor-bid-2", 1000, false, vec![
                    sig(SignalKind::ProcessBundleId, "com.todesktop.cursor"),
                ]),
                mr("cursor-pname", 950, false, vec![
                    sig(SignalKind::ProcessName, "Cursor"),
                ]),
            ],
            ..Default::default()
        },
    );
    bundle.applications.insert(
        "claude-code".to_string(),
        ApplicationEntry {
            app_id: Some("claude-code".to_string()),
            name: Some("Claude Code".to_string()),
            matching_rules: vec![
                mr("cc-bid", 1000, false, vec![
                    sig(SignalKind::ProcessBundleId, "com.anthropic.claude-code"),
                ]),
                mr("cc-pname", 950, false, vec![
                    sig(SignalKind::ProcessName, "claude"),
                ]),
            ],
            ..Default::default()
        },
    );

    bundle
}

/// Helper: run gating_from_detect indirectly by loading from bytes.
/// We use the `load_from_bytes_with_options` path with verification disabled.
fn build_gating(detect: &OwnedDetectBundle) -> GatingBundle {
    // gating_from_detect is called internally when no gating/bundle.json exists.
    // We can invoke it through the loader by providing only a detect bundle.
    // However, since gating_from_detect is pub(crate), we test its effects
    // through observable properties of the gating bundle.
    //
    // For a direct test, we'll reconstruct what gating_from_detect does:
    // check identity_index and entity_catalog populations.
    //
    // Since the function is not public, we'll use load_from_bytes_with_options
    // with VerificationOptions::skip_all() + empty policy/classify stubs.
    //
    // Actually, let's take a simpler approach: serialize the detect bundle,
    // build minimal manifest + assets, and load through the public API.

    use soth_bundle::{BundleManifest, BundleScope, AssetEntry, OrgSignedConfig};
    use soth_bundle::{VerificationOptions, load_from_bytes_with_options};

    let detect_bytes = serde_json::to_vec(detect).expect("serialize detect");
    let detect_hash = sha256_hex(&detect_bytes);
    // No policy bundle — loader falls back to empty_policy_bundle().
    // No classify model — not needed for gating tests.

    let assets = HashMap::from([
        ("detect/bundle.json".to_string(), detect_bytes.clone()),
    ]);

    let manifest = BundleManifest {
        version: "parity-test".to_string(),
        created_at: 1_000_000,
        bundle_id: None,
        model_version: None,
        policy_version: None,
        org_id: None,
        issued_at: None,
        expires_at: None,
        vendor_sig: String::new(),
        org_approval_sig: None,
        assets: vec![
            AssetEntry {
                path: "detect/bundle.json".to_string(),
                sha256: detect_hash,
                size_bytes: detect_bytes.len() as u64,
            },
        ],
        scope: BundleScope::default(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).expect("serialize manifest");

    let org = OrgSignedConfig {
        allows_https_intercept: false,
        allows_http_intercept: false,
        process_filter: None,
        allowed_capture_modes: Vec::new(),
    };

    let verification = VerificationOptions {
        verify_vendor_signature: false,
        require_verified_bundle: false,
        org_approval_pubkey: None,
    };

    let loaded = load_from_bytes_with_options(
        &manifest_bytes,
        assets,
        &[0u8; 32],
        &org,
        verification,
    )
    .expect("load bundle");

    (*loaded.gating).clone()
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

// ---------------------------------------------------------------------------
// Gating parity tests
// ---------------------------------------------------------------------------

/// Both v2 and v3 bundles should produce identity_index entries for cursor's
/// bundle_ids and process_names.
#[test]
fn gating_identity_index_cursor_parity() {
    let v2_gating = build_gating(&build_v2_detect());
    let v3_gating = build_gating(&build_v3_detect());

    // v2: cursor identity comes from bundle_ids/process_names on ApplicationEntry.
    assert!(
        v2_gating.identity_index.non_hosts.contains_key("com.todesktop.230313mzl4w4u92"),
        "v2 gating should have cursor bundle_id in identity_index"
    );
    assert!(
        v2_gating.identity_index.non_hosts.contains_key("cursor"),
        "v2 gating should have cursor process_name in identity_index"
    );

    // v3: cursor identity comes from matching_rules ProcessBundleId/ProcessName signals.
    assert!(
        v3_gating.identity_index.non_hosts.contains_key("com.todesktop.230313mzl4w4u92"),
        "v3 gating should have cursor bundle_id in identity_index"
    );
    assert!(
        v3_gating.identity_index.non_hosts.contains_key("cursor"),
        "v3 gating should have cursor process_name in identity_index"
    );

    // Both should resolve to the same entity.
    assert_eq!(
        v2_gating.identity_index.non_hosts["com.todesktop.230313mzl4w4u92"].entity_id,
        v3_gating.identity_index.non_hosts["com.todesktop.230313mzl4w4u92"].entity_id,
        "cursor entity_id should match between v2 and v3"
    );
}

/// Both v2 and v3 should produce identity_index entries for claude-code's
/// bundle_id and process_name.
#[test]
fn gating_identity_index_claude_code_parity() {
    let v2_gating = build_gating(&build_v2_detect());
    let v3_gating = build_gating(&build_v3_detect());

    assert!(
        v2_gating.identity_index.non_hosts.contains_key("com.anthropic.claude-code"),
        "v2 gating should have claude-code bundle_id"
    );
    assert!(
        v3_gating.identity_index.non_hosts.contains_key("com.anthropic.claude-code"),
        "v3 gating should have claude-code bundle_id"
    );

    assert_eq!(
        v2_gating.identity_index.non_hosts["com.anthropic.claude-code"].entity_id,
        "claude-code"
    );
    assert_eq!(
        v3_gating.identity_index.non_hosts["com.anthropic.claude-code"].entity_id,
        "claude-code"
    );
}

/// Both v2 and v3 should include provider hosts in TLS intercept set.
#[test]
fn gating_tls_intercept_hosts_parity() {
    let v2_gating = build_gating(&build_v2_detect());
    let v3_gating = build_gating(&build_v3_detect());

    let v2_intercept = &v2_gating.gates.stage0_tls.tls_intercept_hosts;
    let v3_intercept = &v3_gating.gates.stage0_tls.tls_intercept_hosts;

    // Both should contain the main provider hosts.
    for host in &["api.openai.com", "api.anthropic.com"] {
        assert!(
            v2_intercept.contains(*host),
            "v2 tls_intercept_hosts should contain {host}"
        );
        assert!(
            v3_intercept.contains(*host),
            "v3 tls_intercept_hosts should contain {host}"
        );
    }
}

/// Both v2 and v3 should include app hosts in TLS intercept set.
#[test]
fn gating_tls_intercept_app_hosts_parity() {
    let v2_gating = build_gating(&build_v2_detect());
    let v3_gating = build_gating(&build_v3_detect());

    let v2_intercept = &v2_gating.gates.stage0_tls.tls_intercept_hosts;
    let v3_intercept = &v3_gating.gates.stage0_tls.tls_intercept_hosts;

    // v2 gets these from domain_index, v3 from matching_rules HttpHost signals.
    for host in &["chatgpt.com", "claude.ai"] {
        assert!(
            v2_intercept.contains(*host),
            "v2 tls_intercept_hosts should contain {host}"
        );
        assert!(
            v3_intercept.contains(*host),
            "v3 tls_intercept_hosts should contain {host}"
        );
    }
}

/// v3 entity_catalog should contain providers from matching_rules HttpHost signals.
#[test]
fn gating_entity_catalog_providers_from_matching_rules() {
    let v3_gating = build_gating(&build_v3_detect());

    let provider_ids: Vec<&str> = v3_gating
        .entities
        .providers
        .iter()
        .map(|p| p.entity_id.as_str())
        .collect();

    assert!(
        provider_ids.contains(&"openai"),
        "v3 entity catalog should contain openai provider, got: {:?}",
        provider_ids
    );
    assert!(
        provider_ids.contains(&"anthropic"),
        "v3 entity catalog should contain anthropic provider, got: {:?}",
        provider_ids
    );

    // Verify openai has the correct host.
    let openai_entry = v3_gating
        .entities
        .providers
        .iter()
        .find(|p| p.entity_id == "openai")
        .expect("openai should exist");
    assert!(
        openai_entry
            .hosts
            .iter()
            .any(|h| h.pattern == "api.openai.com"),
        "openai entity should have api.openai.com host"
    );
}

/// v3 entity_catalog should contain all actual providers.
/// v2 domain_index conflates apps and providers into the entity catalog,
/// so v2 may have extra entries (chatgpt, claude) that are actually apps.
/// v3 correctly only includes providers with matching_rules HttpHost signals.
#[test]
fn gating_entity_catalog_count_parity() {
    let v2_gating = build_gating(&build_v2_detect());
    let v3_gating = build_gating(&build_v3_detect());

    let v2_ids: std::collections::HashSet<&str> = v2_gating
        .entities
        .providers
        .iter()
        .map(|p| p.entity_id.as_str())
        .collect();
    let v3_ids: std::collections::HashSet<&str> = v3_gating
        .entities
        .providers
        .iter()
        .map(|p| p.entity_id.as_str())
        .collect();

    // v3 should contain the real providers.
    assert!(
        v3_ids.contains("openai"),
        "v3 should have openai, got: {:?}",
        v3_ids
    );
    assert!(
        v3_ids.contains("anthropic"),
        "v3 should have anthropic, got: {:?}",
        v3_ids
    );

    // Every v3 provider should also exist in v2.
    for id in &v3_ids {
        assert!(
            v2_ids.contains(id),
            "v3 provider '{id}' should also be in v2 entity catalog"
        );
    }
}
