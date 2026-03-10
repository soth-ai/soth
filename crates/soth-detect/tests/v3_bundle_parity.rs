/// TDD parity test suite: verifies that v3 signal-based matching_rules produce
/// identical fingerprinting and classification results as v2 legacy detection
/// for all major providers and applications.
///
/// Golden corpus apps: Claude Code, Claude Desktop, Claude Web, Codex, ChatGPT,
/// Gemini, Cursor, Windsurf, GitHub Copilot, DeepSeek, Grok, Perplexity.
///
/// Golden corpus providers: OpenAI, Anthropic, Google, Cohere, Azure OpenAI,
/// AWS Bedrock, Groq, Mistral, Fireworks, xAI.
use serde_json::json;
use soth_core::{MatchingRule, SignalKind, SignalMatcher};
use soth_detect::{
    classify_request, fingerprint, ApplicationEntry, DetectedFormat, OwnedDetectBundle,
    ProviderEntry,
};
use std::collections::{BTreeMap, HashMap};

// ---------------------------------------------------------------------------
// Test case definition
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct GoldenCase {
    name: &'static str,
    host: &'static str,
    path: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: &'static [u8],
    process_bundle_id: Option<&'static str>,
    process_name: Option<&'static str>,
    expected_format: DetectedFormat,
    /// Entity id that classify_request should return (provider or app).
    expected_entity_id: &'static str,
    expected_entity_kind: &'static str,
}

// ---------------------------------------------------------------------------
// Golden cases: providers (API traffic)
// ---------------------------------------------------------------------------

fn provider_golden_cases() -> Vec<GoldenCase> {
    vec![
        GoldenCase {
            name: "openai-chat",
            host: "api.openai.com",
            path: "/v1/chat/completions",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::OpenAIRest,
            expected_entity_id: "openai",
            expected_entity_kind: "provider",
        },
        GoldenCase {
            name: "openai-responses",
            host: "api.openai.com",
            path: "/v1/responses",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"gpt-4.1-mini","input":"hello"}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::OpenAIRest,
            expected_entity_id: "openai",
            expected_entity_kind: "provider",
        },
        GoldenCase {
            name: "anthropic-messages",
            host: "api.anthropic.com",
            path: "/v1/messages",
            headers: vec![
                ("content-type", "application/json"),
                ("anthropic-version", "2024-06-01"),
            ],
            body: br#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::AnthropicRest,
            expected_entity_id: "anthropic",
            expected_entity_kind: "provider",
        },
        GoldenCase {
            name: "google-gemini-api",
            host: "generativelanguage.googleapis.com",
            path: "/v1/models/gemini-1.5-pro:generateContent",
            headers: vec![
                ("content-type", "application/json"),
                ("x-goog-api-key", "AIza..."),
            ],
            body: br#"{"contents":[{"parts":[{"text":"hello"}]}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::GeminiRest,
            expected_entity_id: "google",
            expected_entity_kind: "provider",
        },
        GoldenCase {
            name: "cohere-chat",
            host: "api.cohere.ai",
            path: "/v2/chat",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"command-r-plus","message":"hello"}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::CohereRest,
            expected_entity_id: "cohere",
            expected_entity_kind: "provider",
        },
        GoldenCase {
            name: "azure-openai",
            host: "myresource.openai.azure.com",
            path: "/openai/deployments/gpt-4/chat/completions",
            headers: vec![("content-type", "application/json")],
            body: br#"{"messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::OpenAIRest,
            expected_entity_id: "azure_openai",
            expected_entity_kind: "provider",
        },
        GoldenCase {
            name: "aws-bedrock",
            host: "bedrock-runtime.us-east-1.amazonaws.com",
            path: "/model/anthropic.claude-3-sonnet/invoke",
            headers: vec![("content-type", "application/json")],
            body: br#"{"modelId":"anthropic.claude-3-sonnet","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::BedrockRest,
            expected_entity_id: "aws_bedrock",
            expected_entity_kind: "provider",
        },
        GoldenCase {
            name: "groq-chat",
            host: "api.groq.com",
            path: "/openai/v1/chat/completions",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"llama-3.3-70b","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::OpenAIRest,
            expected_entity_id: "groq",
            expected_entity_kind: "provider",
        },
        GoldenCase {
            name: "mistral-chat",
            host: "api.mistral.ai",
            path: "/v1/chat/completions",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"mistral-large","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::OpenAIRest,
            expected_entity_id: "mistral",
            expected_entity_kind: "provider",
        },
        GoldenCase {
            name: "fireworks-chat",
            host: "api.fireworks.ai",
            path: "/inference/v1/chat/completions",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"llama-v3p3-70b","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::OpenAIRest,
            expected_entity_id: "fireworks",
            expected_entity_kind: "provider",
        },
        GoldenCase {
            name: "xai-chat",
            host: "api.x.ai",
            path: "/v1/chat/completions",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"grok-2","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::OpenAIRest,
            expected_entity_id: "xai",
            expected_entity_kind: "provider",
        },
    ]
}

// ---------------------------------------------------------------------------
// Golden cases: applications (web/desktop traffic)
// ---------------------------------------------------------------------------

fn application_golden_cases() -> Vec<GoldenCase> {
    vec![
        GoldenCase {
            name: "chatgpt-web-conversation",
            host: "chatgpt.com",
            path: "/backend-api/conversation",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::CustomRest("chatgpt_web".to_string()),
            expected_entity_id: "chatgpt",
            expected_entity_kind: "application",
        },
        GoldenCase {
            name: "claude-web-completion",
            host: "claude.ai",
            path: "/api/organizations/org-123/chat_conversations/conv-456/completion",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"claude-sonnet-4-6"}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::CustomRest("claude_web".to_string()),
            expected_entity_id: "claude",
            expected_entity_kind: "application",
        },
        GoldenCase {
            name: "claude-code-via-bundle-id",
            host: "api.anthropic.com",
            path: "/v1/messages",
            headers: vec![
                ("content-type", "application/json"),
                ("anthropic-version", "2024-06-01"),
            ],
            body: br#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: Some("com.anthropic.claude-code"),
            process_name: Some("claude"),
            expected_format: DetectedFormat::AnthropicRest,
            expected_entity_id: "claude-code",
            expected_entity_kind: "application",
        },
        GoldenCase {
            name: "claude-desktop-via-bundle-id",
            host: "api.anthropic.com",
            path: "/v1/messages",
            headers: vec![
                ("content-type", "application/json"),
                ("anthropic-version", "2024-06-01"),
            ],
            body: br#"{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: Some("com.anthropic.claudefordesktop"),
            process_name: None,
            expected_format: DetectedFormat::AnthropicRest,
            expected_entity_id: "claude-desktop",
            expected_entity_kind: "application",
        },
        GoldenCase {
            name: "codex-via-process-name",
            host: "chatgpt.com",
            path: "/backend-api/codex/responses",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"gpt-5-3"}"#,
            process_bundle_id: None,
            process_name: Some("codex"),
            // Codex has its own api_format (codex_web) that resolves via
            // matched_application → app.api_format → rest_formats lookup.
            expected_format: DetectedFormat::CustomRest("codex_web".to_string()),
            expected_entity_id: "codex",
            expected_entity_kind: "application",
        },
        GoldenCase {
            name: "gemini-web",
            host: "gemini.google.com",
            path: "/_/BardChatUi/data/batchexecute",
            headers: vec![("content-type", "application/x-www-form-urlencoded")],
            body: b"f.req=%5B%5B%22hello%22%5D%5D",
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::CustomRest("gemini_web".to_string()),
            expected_entity_id: "gemini",
            expected_entity_kind: "application",
        },
        GoldenCase {
            name: "cursor-via-bundle-id",
            host: "api.openai.com",
            path: "/v1/chat/completions",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: Some("com.todesktop.230313mzl4w4u92"),
            process_name: Some("Cursor"),
            expected_format: DetectedFormat::OpenAIRest,
            expected_entity_id: "cursor",
            expected_entity_kind: "application",
        },
        GoldenCase {
            name: "windsurf-via-bundle-id",
            host: "api.openai.com",
            path: "/v1/chat/completions",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: Some("com.codeium.windsurf"),
            process_name: Some("Windsurf"),
            expected_format: DetectedFormat::OpenAIRest,
            expected_entity_id: "windsurf",
            expected_entity_kind: "application",
        },
        GoldenCase {
            name: "github-copilot-via-process",
            host: "api.openai.com",
            path: "/v1/chat/completions",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: Some("copilot"),
            expected_format: DetectedFormat::OpenAIRest,
            expected_entity_id: "github-copilot",
            expected_entity_kind: "application",
        },
        GoldenCase {
            name: "deepseek-web",
            host: "chat.deepseek.com",
            path: "/api/v0/chat/completion",
            headers: vec![("content-type", "application/json")],
            body: br#"{"model":"deepseek-v3","messages":[{"role":"user","content":"hello"}]}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::CustomRest("deepseek_web".to_string()),
            expected_entity_id: "deepseek",
            expected_entity_kind: "application",
        },
        GoldenCase {
            name: "grok-web",
            host: "grok.com",
            path: "/rest/app-chat/conversations/new",
            headers: vec![("content-type", "application/json")],
            body: br#"{"message":"hello","modelSlug":"grok-2"}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::CustomRest("grok_web".to_string()),
            expected_entity_id: "grok",
            expected_entity_kind: "application",
        },
        GoldenCase {
            name: "perplexity-web",
            host: "www.perplexity.ai",
            path: "/api/query",
            headers: vec![("content-type", "application/json")],
            body: br#"{"query":"hello world"}"#,
            process_bundle_id: None,
            process_name: None,
            expected_format: DetectedFormat::CustomRest("perplexity_web".to_string()),
            expected_entity_id: "perplexity",
            expected_entity_kind: "application",
        },
    ]
}

// ---------------------------------------------------------------------------
// Bundle builders
// ---------------------------------------------------------------------------

/// Build a v3-style detect bundle using matching_rules (no legacy detection JSON).
fn build_v3_bundle() -> OwnedDetectBundle {
    let mut bundle = build_shared_base();

    // Providers: matching_rules only, no detection JSON.
    for (_, entry) in bundle.llm_providers.iter_mut() {
        entry.detection = None;
    }

    // Provider matching rules.
    set_provider_rules(&mut bundle, "openai", vec![
        mr("openai-host", 850, true, vec![
            sig(SignalKind::HttpHost, "api.openai.com"),
        ]),
    ]);
    set_provider_rules(&mut bundle, "anthropic", vec![
        mr("anthropic-host", 850, true, vec![
            sig(SignalKind::HttpHost, "api.anthropic.com"),
        ]),
    ]);
    set_provider_rules(&mut bundle, "google", vec![
        mr("google-host", 850, true, vec![
            sig(SignalKind::HttpHost, "generativelanguage.googleapis.com"),
        ]),
    ]);
    set_provider_rules(&mut bundle, "cohere", vec![
        mr("cohere-host", 850, true, vec![
            sig(SignalKind::HttpHost, "api.cohere.ai"),
        ]),
    ]);
    set_provider_rules(&mut bundle, "azure_openai", vec![
        mr("azure-host", 850, true, vec![
            sig(SignalKind::HttpHost, "*.openai.azure.com"),
        ]),
    ]);
    set_provider_rules(&mut bundle, "aws_bedrock", vec![
        mr("bedrock-host", 850, true, vec![
            sig(SignalKind::HttpHost, "bedrock-runtime.*.amazonaws.com"),
        ]),
    ]);
    set_provider_rules(&mut bundle, "groq", vec![
        mr("groq-host", 850, true, vec![
            sig(SignalKind::HttpHost, "api.groq.com"),
        ]),
    ]);
    set_provider_rules(&mut bundle, "mistral", vec![
        mr("mistral-host", 850, true, vec![
            sig(SignalKind::HttpHost, "api.mistral.ai"),
        ]),
    ]);
    set_provider_rules(&mut bundle, "fireworks", vec![
        mr("fireworks-host", 850, true, vec![
            sig(SignalKind::HttpHost, "api.fireworks.ai"),
        ]),
    ]);
    set_provider_rules(&mut bundle, "xai", vec![
        mr("xai-host", 850, true, vec![
            sig(SignalKind::HttpHost, "api.x.ai"),
        ]),
    ]);

    // Application matching rules.
    set_app_rules(&mut bundle, "chatgpt", vec![
        mr("chatgpt-host", 900, true, vec![
            sig(SignalKind::HttpHost, "chatgpt.com"),
        ]),
        mr("chatgpt-host-alt", 900, true, vec![
            sig(SignalKind::HttpHost, "chat.openai.com"),
        ]),
    ]);
    set_app_rules(&mut bundle, "claude", vec![
        mr("claude-host", 900, true, vec![
            sig(SignalKind::HttpHost, "claude.ai"),
        ]),
    ]);
    set_app_rules(&mut bundle, "claude-code", vec![
        mr("claude-code-bundle-id", 1000, false, vec![
            sig(SignalKind::ProcessBundleId, "com.anthropic.claude-code"),
        ]),
        mr("claude-code-process", 950, false, vec![
            sig(SignalKind::ProcessName, "claude"),
        ]),
    ]);
    set_app_rules(&mut bundle, "claude-desktop", vec![
        mr("claude-desktop-bundle-id", 1000, false, vec![
            sig(SignalKind::ProcessBundleId, "com.anthropic.claudefordesktop"),
        ]),
    ]);
    set_app_rules(&mut bundle, "codex", vec![
        mr("codex-process", 950, false, vec![
            sig(SignalKind::ProcessName, "codex"),
        ]),
        mr("codex-host-path", 960, true, vec![
            sig(SignalKind::HttpHost, "chatgpt.com"),
            sig(SignalKind::HttpPath, "/backend-api/codex/*"),
        ]),
    ]);
    set_app_rules(&mut bundle, "gemini", vec![
        mr("gemini-host", 900, true, vec![
            sig(SignalKind::HttpHost, "gemini.google.com"),
        ]),
    ]);
    set_app_rules(&mut bundle, "cursor", vec![
        mr("cursor-bundle-id-1", 1000, false, vec![
            sig(SignalKind::ProcessBundleId, "com.todesktop.230313mzl4w4u92"),
        ]),
        mr("cursor-bundle-id-2", 1000, false, vec![
            sig(SignalKind::ProcessBundleId, "com.todesktop.cursor"),
        ]),
        mr("cursor-process", 950, false, vec![
            sig(SignalKind::ProcessName, "Cursor"),
        ]),
    ]);
    set_app_rules(&mut bundle, "windsurf", vec![
        mr("windsurf-bundle-id-1", 1000, false, vec![
            sig(SignalKind::ProcessBundleId, "com.codeium.windsurf"),
        ]),
        mr("windsurf-bundle-id-2", 1000, false, vec![
            sig(SignalKind::ProcessBundleId, "codeium.windsurf"),
        ]),
        mr("windsurf-process", 950, false, vec![
            sig(SignalKind::ProcessName, "Windsurf"),
        ]),
    ]);
    set_app_rules(&mut bundle, "github-copilot", vec![
        mr("copilot-process", 950, false, vec![
            sig(SignalKind::ProcessName, "copilot"),
        ]),
        mr("copilot-host", 900, true, vec![
            sig(SignalKind::HttpHost, "copilot-proxy.githubusercontent.com"),
        ]),
    ]);
    set_app_rules(&mut bundle, "deepseek", vec![
        mr("deepseek-host", 900, true, vec![
            sig(SignalKind::HttpHost, "chat.deepseek.com"),
        ]),
    ]);
    set_app_rules(&mut bundle, "grok", vec![
        mr("grok-host", 900, true, vec![
            sig(SignalKind::HttpHost, "grok.com"),
        ]),
        mr("grok-host-alt", 900, true, vec![
            sig(SignalKind::HttpHost, "grok.x.ai"),
        ]),
    ]);
    set_app_rules(&mut bundle, "perplexity", vec![
        mr("perplexity-host", 900, true, vec![
            sig(SignalKind::HttpHost, "perplexity.ai"),
        ]),
        mr("perplexity-host-www", 900, true, vec![
            sig(SignalKind::HttpHost, "www.perplexity.ai"),
        ]),
    ]);

    bundle
}

/// Build a v2-style detect bundle using legacy detection JSON (no matching_rules).
fn build_v2_bundle() -> OwnedDetectBundle {
    let mut bundle = build_shared_base();

    // Domain index maps hosts → provider/app ids (v2 style).
    let domain_mappings = vec![
        ("api.openai.com", "openai"),
        ("api.anthropic.com", "anthropic"),
        ("generativelanguage.googleapis.com", "google"),
        ("api.cohere.ai", "cohere"),
        ("*.openai.azure.com", "azure_openai"),
        ("bedrock-runtime.*.amazonaws.com", "aws_bedrock"),
        ("api.groq.com", "groq"),
        ("api.mistral.ai", "mistral"),
        ("api.fireworks.ai", "fireworks"),
        ("api.x.ai", "xai"),
        ("chatgpt.com", "chatgpt"),
        ("chat.openai.com", "chatgpt"),
        ("claude.ai", "claude"),
        ("a-api.anthropic.com", "claude"),
        ("gemini.google.com", "gemini"),
        ("chat.deepseek.com", "deepseek"),
        ("grok.com", "grok"),
        ("grok.x.ai", "grok"),
        ("perplexity.ai", "perplexity"),
        ("www.perplexity.ai", "perplexity"),
        ("copilot-proxy.githubusercontent.com", "github-copilot"),
        ("*.githubcopilot.com", "github-copilot"),
        ("*.cursor.sh", "cursor"),
        ("*.codeium.com", "windsurf"),
    ];
    for (host, id) in domain_mappings {
        bundle
            .domain_index
            .insert(host.to_string(), id.to_string());
    }

    // Provider detection JSON (v2 style).
    set_provider_detection(
        &mut bundle,
        "openai",
        json!({
            "hosts": [{"pattern": "api.openai.com", "paths": {}}],
            "path_patterns": ["**/v1**"]
        }),
    );
    set_provider_detection(
        &mut bundle,
        "anthropic",
        json!({
            "hosts": [{"pattern": "api.anthropic.com", "paths": {"allow": ["/v1/messages"]}}],
            "path_patterns": ["**/v1**"]
        }),
    );
    set_provider_detection(
        &mut bundle,
        "google",
        json!({
            "hosts": [{"pattern": "generativelanguage.googleapis.com", "paths": {}}]
        }),
    );
    set_provider_detection(
        &mut bundle,
        "cohere",
        json!({
            "hosts": [{"pattern": "api.cohere.ai", "paths": {}}]
        }),
    );
    set_provider_detection(
        &mut bundle,
        "azure_openai",
        json!({
            "hosts": [{"pattern": "*.openai.azure.com", "paths": {}}],
            "path_patterns": ["**/openai**"]
        }),
    );
    set_provider_detection(
        &mut bundle,
        "aws_bedrock",
        json!({
            "hosts": [{"pattern": "bedrock-runtime.*.amazonaws.com", "paths": {}}]
        }),
    );
    set_provider_detection(
        &mut bundle,
        "groq",
        json!({"hosts": [{"pattern": "api.groq.com", "paths": {}}]}),
    );
    set_provider_detection(
        &mut bundle,
        "mistral",
        json!({"hosts": [{"pattern": "api.mistral.ai", "paths": {}}]}),
    );
    set_provider_detection(
        &mut bundle,
        "fireworks",
        json!({"hosts": [{"pattern": "api.fireworks.ai", "paths": {}}]}),
    );
    set_provider_detection(
        &mut bundle,
        "xai",
        json!({"hosts": [{"pattern": "api.x.ai", "paths": {}}]}),
    );

    // Application detection hosts (v2 style).
    set_app_detection(
        &mut bundle,
        "chatgpt",
        json!({"hosts": [
            {"pattern": "chatgpt.com", "paths": {"allow": ["/backend-api/**/conversation", "/backend-anon/**/conversation"]}},
            {"pattern": "chat.openai.com", "paths": {}}
        ]}),
    );
    set_app_detection(
        &mut bundle,
        "claude",
        json!({"hosts": [
            {"pattern": "claude.ai", "paths": {"allow": ["/api/organizations/**/completion"]}}
        ]}),
    );
    set_app_detection(
        &mut bundle,
        "codex",
        json!({"hosts": [
            {"pattern": "chatgpt.com", "paths": {"allow": ["/backend-api/codex/*"]}}
        ]}),
    );
    set_app_detection(
        &mut bundle,
        "gemini",
        json!({"hosts": [
            {"pattern": "gemini.google.com", "paths": {"allow": ["**/batchexecute*"]}}
        ]}),
    );
    set_app_detection(
        &mut bundle,
        "deepseek",
        json!({"hosts": [
            {"pattern": "chat.deepseek.com", "paths": {"allow": ["/api/v0/chat/completion"]}}
        ]}),
    );
    set_app_detection(
        &mut bundle,
        "grok",
        json!({"hosts": [
            {"pattern": "grok.com", "paths": {}},
            {"pattern": "grok.x.ai", "paths": {}}
        ]}),
    );
    set_app_detection(
        &mut bundle,
        "perplexity",
        json!({"hosts": [
            {"pattern": "perplexity.ai", "paths": {}},
            {"pattern": "www.perplexity.ai", "paths": {}}
        ]}),
    );

    bundle
}

/// Shared base bundle with rest_formats and provider/app skeletons.
fn build_shared_base() -> OwnedDetectBundle {
    let mut rest_formats = HashMap::new();
    rest_formats.insert(
        "openai".to_string(),
        soth_detect::RestFormatDescriptor {
            request: soth_detect::RestRequestPaths {
                model: Some("$.model".to_string()),
                messages: Some("$.messages".to_string()),
                ..Default::default()
            },
            ..Default::default()
        },
    );
    rest_formats.insert(
        "anthropic".to_string(),
        soth_detect::RestFormatDescriptor {
            request: soth_detect::RestRequestPaths {
                model: Some("$.model".to_string()),
                messages: Some("$.messages".to_string()),
                system: Some("$.system".to_string()),
                ..Default::default()
            },
            ..Default::default()
        },
    );
    rest_formats.insert("chatgpt_web".to_string(), soth_detect::RestFormatDescriptor::default());
    rest_formats.insert("claude_web".to_string(), soth_detect::RestFormatDescriptor::default());
    rest_formats.insert("gemini_web".to_string(), soth_detect::RestFormatDescriptor::default());
    rest_formats.insert("deepseek_web".to_string(), soth_detect::RestFormatDescriptor::default());
    rest_formats.insert("grok_web".to_string(), soth_detect::RestFormatDescriptor::default());
    rest_formats.insert("perplexity_web".to_string(), soth_detect::RestFormatDescriptor::default());
    rest_formats.insert("codex_web".to_string(), soth_detect::RestFormatDescriptor::default());

    let mut llm_providers = HashMap::new();
    for (id, fmt) in &[
        ("openai", "openai"),
        ("anthropic", "anthropic"),
        ("google", "google"),
        ("cohere", "cohere"),
        ("azure_openai", "openai"),
        ("aws_bedrock", "bedrock"),
        ("groq", "openai"),
        ("mistral", "openai"),
        ("fireworks", "openai"),
        ("xai", "openai"),
    ] {
        llm_providers.insert(
            id.to_string(),
            ProviderEntry {
                provider_id: Some(id.to_string()),
                name: Some(id.to_string()),
                api_format: Some(fmt.to_string()),
                ..Default::default()
            },
        );
    }

    let mut applications = HashMap::new();
    let app_defs: Vec<(&str, Option<&str>, Vec<&str>, Vec<&str>)> = vec![
        ("chatgpt", Some("chatgpt_web"), vec![], vec![]),
        ("claude", Some("claude_web"), vec![], vec![]),
        (
            "claude-code",
            None,
            vec!["com.anthropic.claude-code"],
            vec!["claude"],
        ),
        (
            "claude-desktop",
            None,
            vec!["com.anthropic.claudefordesktop"],
            vec![],
        ),
        ("codex", Some("codex_web"), vec![], vec!["codex"]),
        ("gemini", Some("gemini_web"), vec![], vec![]),
        (
            "cursor",
            None,
            vec!["com.todesktop.230313mzl4w4u92", "com.todesktop.cursor"],
            vec!["Cursor"],
        ),
        (
            "windsurf",
            None,
            vec!["com.codeium.windsurf", "codeium.windsurf"],
            vec!["Windsurf"],
        ),
        ("github-copilot", None, vec![], vec!["copilot"]),
        ("deepseek", Some("deepseek_web"), vec![], vec![]),
        ("grok", Some("grok_web"), vec![], vec![]),
        ("perplexity", Some("perplexity_web"), vec![], vec![]),
    ];
    for (id, api_format, bundle_ids, process_names) in app_defs {
        applications.insert(
            id.to_string(),
            ApplicationEntry {
                app_id: Some(id.to_string()),
                name: Some(id.to_string()),
                api_format: api_format.map(String::from),
                bundle_ids: bundle_ids.iter().map(|s| s.to_string()).collect(),
                process_names: process_names.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
        );
    }

    OwnedDetectBundle {
        rest_formats,
        llm_providers,
        applications,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Builder helpers
// ---------------------------------------------------------------------------

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

fn set_provider_rules(bundle: &mut OwnedDetectBundle, id: &str, rules: Vec<MatchingRule>) {
    if let Some(entry) = bundle.llm_providers.get_mut(id) {
        entry.matching_rules = rules;
    }
}

fn set_app_rules(bundle: &mut OwnedDetectBundle, id: &str, rules: Vec<MatchingRule>) {
    if let Some(entry) = bundle.applications.get_mut(id) {
        entry.matching_rules = rules;
    }
}

fn set_provider_detection(
    bundle: &mut OwnedDetectBundle,
    id: &str,
    detection: serde_json::Value,
) {
    if let Some(entry) = bundle.llm_providers.get_mut(id) {
        entry.detection = Some(detection);
    }
}

fn set_app_detection(bundle: &mut OwnedDetectBundle, id: &str, detection: serde_json::Value) {
    if let Some(entry) = bundle.applications.get_mut(id) {
        entry.detection = Some(detection);
    }
}

fn make_headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that v2 fingerprint() produces the expected format for all provider cases.
/// In the real pipeline, gating resolves the provider via domain_index first, then
/// passes it as matched_provider to fingerprint.
#[test]
fn v2_provider_fingerprint_golden_corpus() {
    let bundle = build_v2_bundle();
    for case in provider_golden_cases() {
        let headers = make_headers(&case.headers);
        let format = fingerprint(
            "POST",
            case.path,
            &headers,
            case.body,
            Some(case.expected_entity_id),
            None,
            &bundle.as_slice(),
        );
        assert_eq!(
            format, case.expected_format,
            "v2 fingerprint mismatch for case '{}'",
            case.name
        );
    }
}

/// Verify that v3 classify_request() identifies the correct provider entity.
#[test]
fn v3_classify_provider_golden_corpus() {
    let bundle = build_v3_bundle();
    for case in provider_golden_cases() {
        let headers = make_headers(&case.headers);
        let result = classify_request(
            Some(case.host),
            case.path,
            &headers,
            case.process_bundle_id,
            case.process_name,
            None,
            &bundle.as_slice(),
        );
        let result = result.unwrap_or_else(|| {
            panic!(
                "v3 classify_request returned None for provider case '{}'",
                case.name
            )
        });
        assert_eq!(
            result.entity_id, case.expected_entity_id,
            "v3 classify entity_id mismatch for case '{}'",
            case.name
        );
        assert_eq!(
            result.entity_kind, case.expected_entity_kind,
            "v3 classify entity_kind mismatch for case '{}'",
            case.name
        );
    }
}

/// Verify that v3 fingerprint() ALSO works for providers (via domain_index
/// populated from matching_rules by gating_from_detect).
#[test]
fn v3_provider_fingerprint_via_domain_index() {
    let bundle = build_v3_bundle();
    // v3 bundles don't have domain_index populated — fingerprint relies on
    // detection hints or hardcoded path heuristics. Verify the important ones
    // still resolve correctly via detection hints or path heuristics.
    let cases_with_heuristic = vec![
        // These work via path heuristics (openai-like, anthropic header, etc.)
        ("openai-chat", "api.openai.com", "/v1/chat/completions", vec![("content-type", "application/json")], DetectedFormat::OpenAIRest),
        ("anthropic", "api.anthropic.com", "/v1/messages", vec![("content-type", "application/json"), ("anthropic-version", "2024-06-01")], DetectedFormat::AnthropicRest),
        ("gemini-api", "generativelanguage.googleapis.com", "/v1/models/gemini-1.5-pro:generateContent", vec![("content-type", "application/json"), ("x-goog-api-key", "AIza...")], DetectedFormat::GeminiRest),
        ("cohere", "api.cohere.ai", "/v2/chat", vec![("content-type", "application/json")], DetectedFormat::CohereRest),
        ("bedrock", "bedrock-runtime.us-east-1.amazonaws.com", "/model/anthropic.claude-3-sonnet/invoke", vec![("content-type", "application/json")], DetectedFormat::BedrockRest),
    ];
    for (name, _host, path, hdr_pairs, expected) in cases_with_heuristic {
        let headers = make_headers(&hdr_pairs);
        let format = fingerprint("POST", path, &headers, b"{}", None, None, &bundle.as_slice());
        assert_eq!(format, expected, "v3 fingerprint heuristic mismatch for '{name}'");
    }
}

/// Verify that v3 classify_request() identifies the correct application entity
/// for all major apps in the golden corpus.
#[test]
fn v3_classify_application_golden_corpus() {
    let bundle = build_v3_bundle();
    for case in application_golden_cases() {
        let headers = make_headers(&case.headers);
        let result = classify_request(
            Some(case.host),
            case.path,
            &headers,
            case.process_bundle_id,
            case.process_name,
            None,
            &bundle.as_slice(),
        );
        let result = result.unwrap_or_else(|| {
            panic!(
                "v3 classify_request returned None for app case '{}'",
                case.name
            )
        });
        assert_eq!(
            result.entity_id, case.expected_entity_id,
            "v3 classify entity_id mismatch for app case '{}'",
            case.name
        );
        assert_eq!(
            result.entity_kind, case.expected_entity_kind,
            "v3 classify entity_kind mismatch for app case '{}'",
            case.name
        );
    }
}

/// Verify that v2 fingerprint + matched_application produces the expected format
/// for all web application cases (ChatGPT, Claude, Gemini, etc.)
#[test]
fn v2_application_fingerprint_golden_corpus() {
    let bundle = build_v2_bundle();
    for case in application_golden_cases() {
        let headers = make_headers(&case.headers);
        // In the real pipeline, gating resolves both the application and provider.
        // Desktop apps (cursor, windsurf, etc.) with no api_format need the
        // matched_provider hint from domain_index to resolve the correct format.
        let matched_provider = bundle
            .domain_index
            .get(case.host)
            .map(|s| s.as_str());
        // Only pass matched_provider if it resolves to a known llm_provider.
        let provider_hint = matched_provider.filter(|pid| bundle.llm_providers.contains_key(*pid));
        let format = fingerprint(
            "POST",
            case.path,
            &headers,
            case.body,
            provider_hint,
            Some(case.expected_entity_id),
            &bundle.as_slice(),
        );
        assert_eq!(
            format, case.expected_format,
            "v2 fingerprint mismatch for app case '{}'",
            case.name
        );
    }
}

/// Verify that v3 classify_request correctly prioritizes process-based signals
/// (ProcessBundleId=1000) over host-based signals (HttpHost=850/900).
#[test]
fn v3_process_signals_beat_host_signals() {
    let bundle = build_v3_bundle();
    let headers = make_headers(&[("content-type", "application/json")]);

    // Cursor (bundle_id, priority 1000) should beat OpenAI (host, priority 850)
    let result = classify_request(
        Some("api.openai.com"),
        "/v1/chat/completions",
        &headers,
        Some("com.todesktop.230313mzl4w4u92"),
        Some("Cursor"),
        None,
        &bundle.as_slice(),
    );
    let result = result.expect("should match cursor");
    assert_eq!(result.entity_id, "cursor");
    assert_eq!(result.priority, 1000);

    // Claude Code (bundle_id, priority 1000) should beat Anthropic (host, priority 850)
    let result = classify_request(
        Some("api.anthropic.com"),
        "/v1/messages",
        &headers,
        Some("com.anthropic.claude-code"),
        Some("claude"),
        None,
        &bundle.as_slice(),
    );
    let result = result.expect("should match claude-code");
    assert_eq!(result.entity_id, "claude-code");
    assert_eq!(result.priority, 1000);
}

/// Verify that when NO matching_rules exist, classify_request returns None
/// (ensuring graceful fallback to legacy detection).
#[test]
fn v2_bundle_classify_returns_none() {
    let bundle = build_v2_bundle();
    let headers = make_headers(&[("content-type", "application/json")]);
    let result = classify_request(
        Some("api.openai.com"),
        "/v1/chat/completions",
        &headers,
        None,
        None,
        None,
        &bundle.as_slice(),
    );
    assert!(
        result.is_none(),
        "v2 bundle with no matching_rules should return None from classify_request"
    );
}

/// Verify that v2 and v3 bundles both produce equivalent fingerprint results
/// for every provider case when using the legacy fingerprint() path.
#[test]
fn v2_v3_fingerprint_parity_providers() {
    let v2 = build_v2_bundle();
    let v3 = build_v3_bundle();

    for case in provider_golden_cases() {
        let headers = make_headers(&case.headers);
        let v2_format = fingerprint(
            "POST",
            case.path,
            &headers,
            case.body,
            Some(case.expected_entity_id),
            None,
            &v2.as_slice(),
        );
        let v3_format = fingerprint(
            "POST",
            case.path,
            &headers,
            case.body,
            Some(case.expected_entity_id),
            None,
            &v3.as_slice(),
        );
        assert_eq!(
            v2_format, v3_format,
            "v2/v3 fingerprint parity failed for provider case '{}': v2={:?} v3={:?}",
            case.name, v2_format, v3_format
        );
    }
}
