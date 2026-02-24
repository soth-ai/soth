use crate::hash::{canonical_hash, estimate_tokens, hash_content};
use crate::heuristic;
use crate::stream::scan_proto_strings;
use crate::types::{
    DetectBundleSlice, DetectWarning, EndpointType, FormatMeta, GrpcServiceRegistry,
    GrpcServiceSpec, NormalizedRequest, ParseConfidence, ParseError, ParseResult, ParseWarning,
    Provider, RawRequest,
};
use crate::util::{extract_grpc_service_method, grpc_request_path, normalize_unicodeish};
use std::collections::HashMap;

pub struct GrpcParseOutcome {
    pub normalized: NormalizedRequest,
    pub warnings: Vec<DetectWarning>,
}

pub struct DescriptorRegistry<'a> {
    by_key: HashMap<(String, String), &'a GrpcServiceSpec>,
}

impl<'a> DescriptorRegistry<'a> {
    pub fn from_services(services: &'a GrpcServiceRegistry) -> Self {
        let by_key = services
            .services
            .iter()
            .map(|spec| {
                (
                    (
                        spec.service.to_ascii_lowercase(),
                        spec.method.to_ascii_lowercase(),
                    ),
                    spec,
                )
            })
            .collect::<HashMap<_, _>>();

        Self { by_key }
    }

    pub fn get(&self, service: &str, method: &str) -> Option<&'a GrpcServiceSpec> {
        self.by_key
            .get(&(service.to_ascii_lowercase(), method.to_ascii_lowercase()))
            .copied()
    }
}

pub fn parse_grpc(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
) -> ParseResult<GrpcParseOutcome> {
    let mut warnings = Vec::new();

    let grpc_path = grpc_request_path(&req.headers, &req.path);
    let Some((service, method)) = extract_grpc_service_method(grpc_path) else {
        let mut fallback = heuristic::parse(req);
        fallback.provider = Provider::new("grpc");
        fallback.format_meta = FormatMeta::Grpc {
            service: "unknown".to_string(),
            method: "unknown".to_string(),
            proto_package: None,
        };
        fallback.parse_confidence = ParseConfidence::Heuristic;
        fallback
            .parse_warnings
            .push(ParseWarning::GrpcDescriptorMissing(
                "unknown/unknown".to_string(),
            ));
        fallback.canonical_hash = canonical_hash(&fallback);
        return Ok(GrpcParseOutcome {
            normalized: fallback,
            warnings,
        });
    };

    let descriptor_registry = DescriptorRegistry::from_services(bundle.grpc_services);
    let descriptor = descriptor_registry.get(&service, &method);

    if let Some(spec) = descriptor {
        if !spec.is_ai_call {
            return Err(ParseError::NotAnAICall);
        }
    }

    let strings = scan_proto_strings(&req.body);

    if let Some(spec) = descriptor {
        if let Some(normalized) = parse_with_descriptor(&service, &method, spec, &strings) {
            return Ok(GrpcParseOutcome {
                normalized,
                warnings,
            });
        }

        warnings.push(DetectWarning {
            code: "grpc_descriptor_decode_failed",
            detail: format!("descriptor decode failed for {service}/{method}"),
        });
    }

    if let Some(normalized) = parse_with_string_scan(&service, &method, descriptor, &strings) {
        return Ok(GrpcParseOutcome {
            normalized,
            warnings,
        });
    }

    let provider_hint = descriptor
        .and_then(|spec| spec.provider_hint.as_deref())
        .unwrap_or("grpc");

    let mut fallback = heuristic::parse(req);
    fallback.provider = Provider::new(provider_hint);
    fallback.format_meta = FormatMeta::Grpc {
        service: service.clone(),
        method: method.clone(),
        proto_package: descriptor.and_then(|spec| spec.proto_package.clone()),
    };
    fallback.parse_confidence = ParseConfidence::Heuristic;
    fallback
        .parse_warnings
        .push(ParseWarning::GrpcDescriptorMissing(format!(
            "{service}/{method}"
        )));
    fallback.canonical_hash = canonical_hash(&fallback);

    Ok(GrpcParseOutcome {
        normalized: fallback,
        warnings,
    })
}

pub fn parse_grpc_chunk_payload(
    payload: &[u8],
    bundle: &DetectBundleSlice<'_>,
    service: Option<&str>,
    method: Option<&str>,
) -> Option<String> {
    let strings = scan_proto_strings(payload);

    if let (Some(service), Some(method)) = (service, method) {
        if let Some(spec) = bundle.grpc_services.get(service, method) {
            if let Some(content) = descriptor_content_from_strings(spec, &strings) {
                return Some(content);
            }
        }
    }

    best_grpc_content(&strings, 6)
}

pub fn best_grpc_content(strings: &[(u32, String)], min_len: usize) -> Option<String> {
    strings
        .iter()
        .filter(|(_, value)| value.len() >= min_len)
        .max_by_key(|(_, value)| value.len())
        .map(|(_, value)| normalize_unicodeish(value))
}

fn parse_with_descriptor(
    service: &str,
    method: &str,
    spec: &GrpcServiceSpec,
    strings: &[(u32, String)],
) -> Option<NormalizedRequest> {
    let content = descriptor_content_from_strings(spec, strings)?;

    let model = spec
        .field_map
        .get("model")
        .and_then(|field| field_value_by_number(strings, field.field_number));

    let parse_confidence = if model.is_some() {
        ParseConfidence::Full
    } else {
        ParseConfidence::Partial
    };

    let user_content_hash = hash_content(&content);

    let mut normalized = NormalizedRequest {
        parse_confidence,
        parser_id: "grpc-v1",
        schema_version: "1",
        parse_warnings: if model.is_some() {
            Vec::new()
        } else {
            vec![ParseWarning::MissingField("model".to_string())]
        },
        is_ai_call: true,
        provider: Provider::new(spec.provider_hint.as_deref().unwrap_or("grpc")),
        model,
        endpoint_type: EndpointType::Chat,
        system_prompt_hash: None,
        system_prompt_token_estimate: None,
        user_content_hash: user_content_hash.clone(),
        user_content_token_estimate: estimate_tokens(&content),
        conversation_hash: user_content_hash,
        conversation_turn: Some(1),
        has_tool_definitions: false,
        tool_definition_hash: None,
        temperature: None,
        max_tokens: None,
        stream: false,
        top_p: None,
        stop_sequences: Vec::new(),
        estimated_input_tokens: estimate_tokens(&content),
        estimated_cost_usd: 0.0,
        canonical_hash: String::new(),
        format_meta: FormatMeta::Grpc {
            service: service.to_string(),
            method: method.to_string(),
            proto_package: spec.proto_package.clone(),
        },
        content_sample: Some(content),
    };
    normalized.canonical_hash = canonical_hash(&normalized);

    Some(normalized)
}

fn parse_with_string_scan(
    service: &str,
    method: &str,
    descriptor: Option<&GrpcServiceSpec>,
    strings: &[(u32, String)],
) -> Option<NormalizedRequest> {
    let content = best_grpc_content(strings, 20)?;

    let model = descriptor
        .and_then(|spec| spec.field_map.get("model"))
        .and_then(|field| field_value_by_number(strings, field.field_number));

    let provider_hint = descriptor
        .and_then(|spec| spec.provider_hint.as_deref())
        .unwrap_or("grpc");

    let user_content_hash = hash_content(&content);
    let mut normalized = NormalizedRequest {
        parse_confidence: ParseConfidence::Heuristic,
        parser_id: "grpc-heuristic-v1",
        schema_version: "1",
        parse_warnings: vec![ParseWarning::GrpcDescriptorMissing(format!(
            "{service}/{method}"
        ))],
        is_ai_call: true,
        provider: Provider::new(provider_hint),
        model,
        endpoint_type: EndpointType::Chat,
        system_prompt_hash: None,
        system_prompt_token_estimate: None,
        user_content_hash: user_content_hash.clone(),
        user_content_token_estimate: estimate_tokens(&content),
        conversation_hash: user_content_hash,
        conversation_turn: Some(1),
        has_tool_definitions: false,
        tool_definition_hash: None,
        temperature: None,
        max_tokens: None,
        stream: false,
        top_p: None,
        stop_sequences: Vec::new(),
        estimated_input_tokens: estimate_tokens(&content),
        estimated_cost_usd: 0.0,
        canonical_hash: String::new(),
        format_meta: FormatMeta::Grpc {
            service: service.to_string(),
            method: method.to_string(),
            proto_package: descriptor.and_then(|spec| spec.proto_package.clone()),
        },
        content_sample: Some(content),
    };
    normalized.canonical_hash = canonical_hash(&normalized);

    Some(normalized)
}

fn descriptor_content_from_strings(
    spec: &GrpcServiceSpec,
    strings: &[(u32, String)],
) -> Option<String> {
    let content_field = spec.field_map.get("content")?;
    if !content_field.r#type.eq_ignore_ascii_case("string") {
        return None;
    }
    field_value_by_number(strings, content_field.field_number)
}

fn field_value_by_number(strings: &[(u32, String)], field_number: u32) -> Option<String> {
    strings
        .iter()
        .filter(|(field, value)| *field == field_number && !value.is_empty())
        .max_by_key(|(_, value)| value.len())
        .map(|(_, value)| normalize_unicodeish(value))
}
