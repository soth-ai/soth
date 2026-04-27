/// Find the live native bundle on disk, mirroring the runtime loader's
/// priority order (`soth-bundle/src/loader.rs::NATIVE_BUNDLE_PATHS`):
/// `native/bundle.json` is the canonical location; `detect/bundle.json` is a
/// legacy fallback kept around so older installs keep working.
fn find_real_native_bundle() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    for rel in ["native/bundle.json", "detect/bundle.json"] {
        let path = std::path::PathBuf::from(&home)
            .join(".soth/bundle")
            .join(rel);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

#[test]
fn real_bundle_entity_index_resolves_web_apps() {
    let Some(bundle_path) = find_real_native_bundle() else {
        return; // No real bundle on this machine — skip silently.
    };
    let bytes = std::fs::read(&bundle_path).unwrap();
    let bundle: soth_core::native_bundle::NativeBundle = serde_json::from_slice(&bytes).unwrap();
    let index = soth_bundle::entity_index::entity_index_from_native(&bundle);

    assert!(
        index.resolve_host("chatgpt.com").is_some()
            || index
                .resolve_host_with_rules("chatgpt.com")
                .application
                .is_some(),
        "chatgpt.com should resolve"
    );
    assert!(
        index.resolve_host("claude.ai").is_some()
            || index
                .resolve_host_with_rules("claude.ai")
                .application
                .is_some(),
        "claude.ai should resolve"
    );
    assert!(
        index.resolve_host("gemini.google.com").is_some()
            || index
                .resolve_host_with_rules("gemini.google.com")
                .application
                .is_some(),
        "gemini.google.com should resolve"
    );
}

#[test]
fn real_bundle_gemini_web_format_has_features_after_projection() {
    let Some(bundle_path) = find_real_native_bundle() else {
        return; // No real bundle on this machine — skip silently.
    };
    let bytes = std::fs::read(&bundle_path).unwrap();
    let bundle: soth_core::native_bundle::NativeBundle = serde_json::from_slice(&bytes).unwrap();
    let detect = soth_bundle::detect_from_native(&bundle);

    // gemini_web should have features merged from the gemini format
    let gemini_web = detect
        .rest_formats
        .get("gemini_web")
        .expect("gemini_web format should exist");
    assert!(
        !gemini_web.features.is_empty(),
        "gemini_web should have features merged from gemini format"
    );

    // The chat feature should have form encoding and stream rules
    let chat = gemini_web
        .features
        .iter()
        .find(|f| f.id == "chat")
        .expect("gemini_web should have a chat feature");
    assert_eq!(chat.protocol, "rest");
}
