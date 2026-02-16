use super::*;

mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_compiled_bundle_accepts_minimal_valid_shape() {
        let value = json!({
            "version": "2026.02.13-r1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "domain_index": [],
            "providers": {
                "openai": {
                    "id": "openai",
                    "name": "OpenAI",
                    "type": "ai-inference",
                    "domains": ["api.openai.com"]
                }
            },
            "filters": {},
            "pricing": {},
            "stats": {}
        });

        let parsed = parse_compiled_bundle(&value).unwrap();
        assert_eq!(parsed.version, "2026.02.13-r1");
        assert!(parsed.providers.contains_key("openai"));
    }

    #[test]
    fn parse_compiled_bundle_accepts_catalog_style_shape() {
        let value = json!({
            "version": "catalog-v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "local",
            "domain_index": {
                "api.openai.com": {
                    "category": "ai-inference",
                    "pattern_type": "exact",
                    "provider": "openai"
                }
            },
            "providers": {
                "openai": {
                    "name": "OpenAI",
                    "category": "ai-inference",
                    "api_format": "openai",
                    "api_domains": ["api.openai.com"],
                    "detection": {
                        "path_patterns": ["/v1/chat/completions"]
                    }
                }
            },
            "interception_patterns": {
                "api.openai.com": [
                    { "action": "intercept", "path": "/v1/chat/completions" }
                ]
            },
            "pricing": {
                "openai": [
                    {
                        "model_pattern": "gpt-5",
                        "input_per_million": 1.0,
                        "output_per_million": 2.0
                    }
                ]
            }
        });

        let parsed = parse_compiled_bundle(&value).unwrap();
        assert_eq!(parsed.version, "catalog-v1");
        assert_eq!(parsed.domain_index.len(), 1);
        assert!(parsed
            .domain_index
            .first()
            .unwrap()
            .paths
            .contains(&"/v1/chat/completions".to_string()));
        assert_eq!(
            parsed.pricing["openai"]["gpt-5"].input_per_million_usd,
            Some(1.0)
        );
    }

    #[test]
    fn parse_compiled_bundle_collects_feature_object_pattern_paths() {
        let value = json!({
            "version": "catalog-v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "local",
            "domain_index": {
                "claude.ai": {
                    "category": "agent-apps",
                    "pattern_type": "exact",
                    "provider": "claude"
                }
            },
            "providers": {
                "claude": {
                    "name": "Claude",
                    "category": "agent-apps",
                    "api_domains": ["claude.ai"],
                    "features": {
                        "chat": {
                            "patterns": {
                                "request": { "url": "/api/organizations/*/chat_conversations/*/completion", "method": "POST" },
                                "response": { "url": "/api/organizations/*/chat_conversations/*", "method": "GET" }
                            }
                        }
                    }
                }
            },
            "pricing": {}
        });

        let parsed = parse_compiled_bundle(&value).unwrap();
        assert_eq!(parsed.domain_index.len(), 1);
        let entry = parsed.domain_index.first().unwrap();
        assert!(entry
            .paths
            .contains(&"/api/organizations/*/chat_conversations/*/completion".to_string()));
        assert!(entry
            .paths
            .contains(&"/api/organizations/*/chat_conversations/*".to_string()));
    }

    #[test]
    fn parse_compiled_bundle_rejects_missing_providers() {
        let value = json!({
            "version": "2026.02.13-r1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "providers": {}
        });
        let err = parse_compiled_bundle(&value).unwrap_err();
        assert!(err.to_string().contains("at least one provider"));
    }

    #[test]
    fn parse_compiled_bundle_rejects_unknown_domain_provider() {
        let value = json!({
            "version": "2026.02.13-r1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "domain_index": [
                {
                    "host": "api.openai.com",
                    "provider_id": "openai",
                    "entry_type": "ai-inference"
                }
            ],
            "providers": {
                "anthropic": {
                    "id": "anthropic",
                    "name": "Anthropic",
                    "type": "ai-inference"
                }
            }
        });
        let err = parse_compiled_bundle(&value).unwrap_err();
        assert!(err
            .to_string()
            .contains("references unknown provider `openai`"));
    }

    #[test]
    fn parse_compiled_bundle_accepts_sectioned_v2_shape_with_catalog_domains() {
        let value = json!({
            "schema_version": 2,
            "version": "2026.02.13-r2",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "meta": {
                "release_id": "rel-1",
                "sections": {
                    "core": { "required": true },
                    "filters": { "required": true },
                    "catalog": { "required": false },
                    "formats": { "required": false }
                }
            },
            "core": {
                "providers": {
                    "openai": {
                        "id": "openai",
                        "name": "OpenAI",
                        "type": "ai-inference",
                        "api_format": "openai"
                    }
                },
                "domain_index": [
                    {
                        "host": "api.openai.com",
                        "provider_id": "openai",
                        "entry_type": "ai-inference"
                    }
                ],
                "pricing": {
                    "openai": {
                        "gpt-5": {
                            "input_per_million_usd": 1.0,
                            "output_per_million_usd": 2.0
                        }
                    }
                }
            },
            "filters": {
                "whitelist": ["api.openai.com"],
                "passthrough": ["statsig.anthropic.com"]
            },
            "catalog": {
                "domains": ["server.codeium.com", "*.githubcopilot.com"]
            },
            "formats": {
                "openai": { "streaming": { "format": "sse" } }
            }
        });

        let parsed = parse_compiled_bundle(&value).unwrap();
        assert_eq!(parsed.schema_version, 2);
        assert_eq!(parsed.version, "2026.02.13-r2");
        assert_eq!(parsed.domain_index.len(), 1);
        assert_eq!(parsed.providers.len(), 1);
        assert_eq!(parsed.catalog_domains.len(), 2);
        assert!(parsed
            .catalog_domains
            .contains(&"server.codeium.com".to_string()));
        assert!(parsed.meta.is_some());
    }

    #[test]
    fn parse_compiled_bundle_accepts_sectioned_v3_shape_with_entity_ids() {
        let value = json!({
            "schema_version": 3,
            "version": "2026.02.13-r3",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "meta": {
                "release_id": "rel-2",
                "sections": {
                    "core": { "required": true },
                    "filters": { "required": true }
                }
            },
            "core": {
                "providers": {
                    "openai": {
                        "id": "openai",
                        "entity_id": "prv_4n7k2q9m1x",
                        "name": "OpenAI",
                        "type": "ai-inference",
                        "api_format": "openai",
                        "detection": {
                            "ua_rules": [{ "contains": "openai", "agent": "openai" }],
                            "path_rules": [{ "path": "/v1/chat/completions" }]
                        }
                    }
                },
                "domain_index": [
                    {
                        "host": "api.openai.com",
                        "provider_id": "openai",
                        "entry_type": "ai-inference"
                    }
                ],
                "pricing": {}
            },
            "filters": {
                "whitelist": ["api.openai.com"],
                "blacklist": ["tracking"],
                "passthrough": [],
                "noise_keywords": []
            }
        });

        let parsed = parse_compiled_bundle(&value).unwrap();
        assert_eq!(parsed.schema_version, 3);
        let provider = parsed.providers.get("openai").unwrap();
        assert_eq!(provider.entity_id.as_deref(), Some("prv_4n7k2q9m1x"));
        let detection = provider
            .detection
            .as_ref()
            .expect("detection should be parsed");
        assert_eq!(detection.ua_rules.len(), 1);
        assert_eq!(detection.path_rules.len(), 1);
        assert_eq!(
            detection.path_rules[0].reason.as_deref(),
            Some("path_match")
        );
        let entry = parsed.domain_index.first().unwrap();
        assert_eq!(entry.provider_entity_id.as_deref(), Some("prv_4n7k2q9m1x"));
    }
}
