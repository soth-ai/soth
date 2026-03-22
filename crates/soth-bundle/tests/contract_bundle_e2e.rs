
#[test]
#[cfg(feature = "native-bundle")]
fn real_bundle_entity_index_resolves_web_apps() {
    let home = std::env::var("HOME").unwrap();
    let bundle_path = std::path::PathBuf::from(home).join(".soth/bundle/detect/bundle.json");
    if !bundle_path.exists() {
        eprintln!("SKIP: no real bundle at {:?}", bundle_path);
        return;
    }
    let bytes = std::fs::read(&bundle_path).unwrap();
    let bundle: soth_interface::NativeBundle = serde_json::from_slice(&bytes).unwrap();
    eprintln!("entities: {}, llm_providers: {}, products: {}", bundle.entities.len(), bundle.llm_providers.len(), bundle.products.len());

    let index = soth_bundle::entity_index::entity_index_from_native(&bundle);
    eprintln!("index.len() = {}", index.len());

    for host in &["chatgpt.com", "claude.ai", "gemini.google.com", "api.openai.com", "api.anthropic.com"] {
        let simple = index.resolve_host(host);
        let rules = index.resolve_host_with_rules(host);
        eprintln!(
            "{}: resolve_host={:?}, provider={:?}, app={:?}",
            host,
            simple.map(|e| &e.id),
            rules.provider.as_ref().map(|m| &index.entity_for_host_match(m).id),
            rules.application.as_ref().map(|m| &index.entity_for_host_match(m).id),
        );
    }

    assert!(index.resolve_host("chatgpt.com").is_some() || index.resolve_host_with_rules("chatgpt.com").application.is_some(),
        "chatgpt.com should resolve");
    assert!(index.resolve_host("claude.ai").is_some() || index.resolve_host_with_rules("claude.ai").application.is_some(),
        "claude.ai should resolve");
    assert!(index.resolve_host("gemini.google.com").is_some() || index.resolve_host_with_rules("gemini.google.com").application.is_some(),
        "gemini.google.com should resolve");
}

#[test]
#[cfg(feature = "native-bundle")]
fn real_bundle_gemini_web_format_has_features_after_projection() {
    let home = std::env::var("HOME").unwrap();
    let bundle_path = std::path::PathBuf::from(home).join(".soth/bundle/detect/bundle.json");
    if !bundle_path.exists() {
        eprintln!("SKIP: no real bundle");
        return;
    }
    let bytes = std::fs::read(&bundle_path).unwrap();
    let bundle: soth_interface::NativeBundle = serde_json::from_slice(&bytes).unwrap();
    let detect = soth_bundle::detect_from_native(&bundle);

    // gemini_web should have features merged from the gemini format
    let gemini_web = detect.rest_formats.get("gemini_web")
        .expect("gemini_web format should exist");
    eprintln!("gemini_web features: {}", gemini_web.features.len());
    assert!(
        !gemini_web.features.is_empty(),
        "gemini_web should have features merged from gemini format"
    );

    // The chat feature should have form encoding and stream rules
    let chat = gemini_web.features.iter().find(|f| f.id == "chat")
        .expect("gemini_web should have a chat feature");
    assert_eq!(chat.protocol, "rest");
    eprintln!("chat feature: protocol={}, patterns={}", chat.protocol, chat.patterns.len());
}
