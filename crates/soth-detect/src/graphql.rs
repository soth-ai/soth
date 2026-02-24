use crate::hash::{canonical_hash, estimate_tokens, hash_content};
use crate::types::{
    DetectBundleSlice, DetectWarning, FormatMeta, GqlOpType, GraphQLOperationRegistry,
    GraphQLOperationSpec, NormalizedRequest, ParseConfidence, ParseError, ParseResult,
    ParseWarning, Provider, RawRequest,
};
use crate::util::{extract_string, json_path, normalize_unicodeish};
use graphql_parser::query as gql;
use serde::Deserialize;
use serde_json::Value;

pub trait ApqStore {
    fn get_query(&self, hash: &str) -> Option<String>;
    fn put_query(&self, hash: String, query: String);
}

#[derive(Default)]
pub struct NoopApqStore;

impl ApqStore for NoopApqStore {
    fn get_query(&self, _hash: &str) -> Option<String> {
        None
    }

    fn put_query(&self, _hash: String, _query: String) {}
}

#[derive(Debug, Deserialize)]
struct GraphQLEnvelope {
    #[serde(rename = "operationName")]
    operation_name: Option<String>,
    query: Option<String>,
    variables: Option<Value>,
    extensions: Option<Value>,
}

pub struct GraphQLParseOutcome {
    pub normalized: NormalizedRequest,
    pub warnings: Vec<DetectWarning>,
}

pub fn parse_graphql(
    req: &RawRequest,
    bundle: &DetectBundleSlice<'_>,
    apq: &dyn ApqStore,
) -> ParseResult<GraphQLParseOutcome> {
    let env: GraphQLEnvelope =
        serde_json::from_slice(&req.body).map_err(|e| ParseError::MalformedBody(e.to_string()))?;

    let apq_hash = persisted_query_hash(env.extensions.as_ref());
    let query_text = resolve_query_text(&env, apq_hash.as_deref(), apq);
    let Some(query_text) = query_text else {
        let mut normalized = heuristic_graphql_parse(&env);
        normalized
            .parse_warnings
            .push(ParseWarning::GraphQLUnknownOperation(
                env.operation_name
                    .clone()
                    .unwrap_or_else(|| "anonymous".to_string()),
            ));
        normalized.canonical_hash = canonical_hash(&normalized);
        return Ok(GraphQLParseOutcome {
            normalized,
            warnings: vec![DetectWarning {
                code: "graphql_apq_cache_miss",
                detail: "persisted query hash missing from APQ cache".to_string(),
            }],
        });
    };

    if let Some(hash) = apq_hash {
        if !query_text.is_empty() {
            apq.put_query(hash, query_text.clone());
        }
    }

    let doc = gql::parse_query::<String>(&query_text)
        .map_err(|error| ParseError::GraphQLSyntax(error.to_string()))?;

    let fragments = collect_fragments(&doc);
    let selected_operation = select_operation(&doc, env.operation_name.as_deref())?;
    let (operation_name, operation_type, selection_set) = operation_parts(selected_operation);

    let resolved_fields = resolve_selection_set(selection_set, &fragments, 0);
    let spec = operation_name
        .as_deref()
        .and_then(|name| bundle.graphql_operations.get(name))
        .or_else(|| infer_from_fields(bundle.graphql_operations, &resolved_fields));

    let Some(spec) = spec else {
        let mut normalized = heuristic_graphql_parse(&env);
        normalized
            .parse_warnings
            .push(ParseWarning::GraphQLUnknownOperation(
                operation_name
                    .clone()
                    .unwrap_or_else(|| "anonymous".to_string()),
            ));
        normalized.canonical_hash = canonical_hash(&normalized);
        return Ok(GraphQLParseOutcome {
            normalized,
            warnings: vec![DetectWarning {
                code: "graphql_unknown_operation",
                detail: format!(
                    "unknown GraphQL operation: {}",
                    operation_name.unwrap_or_else(|| "anonymous".to_string())
                ),
            }],
        });
    };

    if !spec.is_ai_call {
        return Err(ParseError::NotAnAICall);
    }

    let variables = env.variables.as_ref().unwrap_or(&Value::Null);
    let content = spec
        .content_path
        .as_ref()
        .and_then(|path| extract_path(variables, path))
        .and_then(extract_string)
        .map(|value| normalize_unicodeish(&value))
        .ok_or_else(|| {
            ParseError::MissingRequiredField(
                spec.content_path
                    .as_ref()
                    .map(|p| p.join("."))
                    .unwrap_or_else(|| "content_path".to_string()),
            )
        })?;

    let model = spec
        .model_path
        .as_ref()
        .and_then(|path| extract_path(variables, path))
        .and_then(extract_string);

    let system_prompt = spec
        .system_prompt_path
        .as_ref()
        .and_then(|path| extract_path(variables, path))
        .and_then(extract_string);

    let stream = spec
        .stream_path
        .as_ref()
        .and_then(|path| extract_path(variables, path))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let system_prompt_hash = system_prompt.as_ref().map(|value| hash_content(value));
    let system_prompt_token_estimate = system_prompt.as_ref().map(|value| estimate_tokens(value));
    let user_content_hash = hash_content(&content);
    let user_content_token_estimate = estimate_tokens(&content);
    let estimated_input_tokens =
        estimate_tokens(&[system_prompt.clone().unwrap_or_default(), content.clone()].join("\n"));

    let provider = spec
        .provider_hint
        .clone()
        .unwrap_or_else(|| "graphql".to_string());

    let mutation_field = resolved_fields.first().cloned();

    let mut normalized = NormalizedRequest {
        parse_confidence: ParseConfidence::Full,
        parser_id: "graphql-v1",
        schema_version: "1",
        parse_warnings: Vec::new(),
        is_ai_call: true,
        provider: Provider::new(provider),
        model,
        endpoint_type: crate::types::EndpointType::Chat,
        system_prompt_hash,
        system_prompt_token_estimate,
        user_content_hash,
        user_content_token_estimate,
        conversation_hash: hash_content(&content),
        conversation_turn: Some(1),
        has_tool_definitions: false,
        tool_definition_hash: None,
        temperature: None,
        max_tokens: None,
        stream,
        top_p: None,
        stop_sequences: Vec::new(),
        estimated_input_tokens,
        estimated_cost_usd: 0.0,
        canonical_hash: String::new(),
        format_meta: FormatMeta::GraphQL {
            operation_name,
            operation_type,
            mutation_field,
        },
        content_sample: Some(content),
    };
    normalized.canonical_hash = canonical_hash(&normalized);

    Ok(GraphQLParseOutcome {
        normalized,
        warnings: Vec::new(),
    })
}

pub fn parse_graphql_payload_text(payload: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(payload).ok()?;

    if let Some(delta) = json_path(&value, "$.choices[0].delta.content")
        .and_then(extract_string)
        .filter(|value| !value.is_empty())
    {
        return Some(delta);
    }

    if let Some(delta) = json_path(&value, "$.delta.content")
        .and_then(extract_string)
        .filter(|value| !value.is_empty())
    {
        return Some(delta);
    }

    let operation_name = value.get("operationName").and_then(|v| v.as_str());
    let variables = value.get("variables");
    if operation_name.is_some() || variables.is_some() {
        return find_graphql_like_content(variables.unwrap_or(&Value::Null));
    }

    json_path(&value, "$.content")
        .and_then(extract_string)
        .or_else(|| json_path(&value, "$.text").and_then(extract_string))
}

fn persisted_query_hash(extensions: Option<&Value>) -> Option<String> {
    let hash = extensions
        .and_then(|value| value.get("persistedQuery"))
        .and_then(|value| value.get("sha256Hash"))
        .and_then(|value| value.as_str())?;
    if hash.is_empty() {
        None
    } else {
        Some(hash.to_string())
    }
}

fn resolve_query_text(
    env: &GraphQLEnvelope,
    apq_hash: Option<&str>,
    apq: &dyn ApqStore,
) -> Option<String> {
    if let Some(query) = env.query.as_ref() {
        if !query.trim().is_empty() {
            return Some(query.clone());
        }
    }

    let hash = apq_hash?;
    apq.get_query(hash)
}

fn collect_fragments<'a>(
    doc: &'a gql::Document<'a, String>,
) -> std::collections::HashMap<String, &'a gql::FragmentDefinition<'a, String>> {
    let mut fragments = std::collections::HashMap::new();
    for def in &doc.definitions {
        if let gql::Definition::Fragment(fragment) = def {
            fragments.insert(fragment.name.clone(), fragment);
        }
    }
    fragments
}

fn select_operation<'a>(
    doc: &'a gql::Document<'a, String>,
    operation_name: Option<&str>,
) -> ParseResult<&'a gql::OperationDefinition<'a, String>> {
    let mut anonymous: Option<&gql::OperationDefinition<'_, String>> = None;
    for definition in &doc.definitions {
        if let gql::Definition::Operation(operation) = definition {
            match operation_name {
                Some(target) => {
                    if operation_matches_name(operation, target) {
                        return Ok(operation);
                    }
                }
                None => {
                    if anonymous.is_none() {
                        anonymous = Some(operation);
                    }
                }
            }
        }
    }

    anonymous.ok_or_else(|| {
        ParseError::GraphQLUnknownOperation(operation_name.unwrap_or("anonymous").to_string())
    })
}

fn operation_matches_name(operation: &gql::OperationDefinition<'_, String>, target: &str) -> bool {
    match operation {
        gql::OperationDefinition::Query(query) => query.name.as_deref() == Some(target),
        gql::OperationDefinition::Mutation(mutation) => mutation.name.as_deref() == Some(target),
        gql::OperationDefinition::Subscription(subscription) => {
            subscription.name.as_deref() == Some(target)
        }
        gql::OperationDefinition::SelectionSet(_) => target.eq_ignore_ascii_case("anonymous"),
    }
}

fn operation_parts<'a>(
    operation: &'a gql::OperationDefinition<'a, String>,
) -> (Option<String>, GqlOpType, &'a gql::SelectionSet<'a, String>) {
    match operation {
        gql::OperationDefinition::Query(query) => {
            (query.name.clone(), GqlOpType::Query, &query.selection_set)
        }
        gql::OperationDefinition::Mutation(mutation) => (
            mutation.name.clone(),
            GqlOpType::Mutation,
            &mutation.selection_set,
        ),
        gql::OperationDefinition::Subscription(subscription) => (
            subscription.name.clone(),
            GqlOpType::Subscription,
            &subscription.selection_set,
        ),
        gql::OperationDefinition::SelectionSet(selection_set) => {
            (None, GqlOpType::Unknown, selection_set)
        }
    }
}

fn resolve_selection_set(
    selection_set: &gql::SelectionSet<'_, String>,
    fragments: &std::collections::HashMap<String, &gql::FragmentDefinition<'_, String>>,
    depth: usize,
) -> Vec<String> {
    if depth > 8 {
        return Vec::new();
    }

    let mut out = Vec::new();
    for selection in &selection_set.items {
        match selection {
            gql::Selection::Field(field) => {
                out.push(field.name.clone());
                let nested = resolve_selection_set(&field.selection_set, fragments, depth + 1);
                out.extend(nested);
            }
            gql::Selection::FragmentSpread(spread) => {
                if let Some(fragment) = fragments.get(&spread.fragment_name) {
                    let nested =
                        resolve_selection_set(&fragment.selection_set, fragments, depth + 1);
                    out.extend(nested);
                }
            }
            gql::Selection::InlineFragment(inline) => {
                let nested = resolve_selection_set(&inline.selection_set, fragments, depth + 1);
                out.extend(nested);
            }
        }
    }
    out
}

fn infer_from_fields<'a>(
    operations: &'a GraphQLOperationRegistry,
    fields: &[String],
) -> Option<&'a GraphQLOperationSpec> {
    operations.operations.iter().find(|spec| {
        if let Some(content_path) = &spec.content_path {
            if let Some(last) = content_path.last() {
                return fields.iter().any(|field| field.eq_ignore_ascii_case(last));
            }
        }
        false
    })
}

fn extract_path<'a>(root: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut current = root;
    for segment in path {
        current = current.get(segment)?;
    }
    Some(current)
}

fn find_graphql_like_content(value: &Value) -> Option<String> {
    let content_keys = ["content", "message", "prompt", "text", "input", "query"];

    for key in content_keys {
        if let Some(text) = value.get(key).and_then(extract_string) {
            if text.len() > 1 {
                return Some(text);
            }
        }
    }

    if let Some(input) = value.get("input") {
        for key in content_keys {
            if let Some(text) = input.get(key).and_then(extract_string) {
                if text.len() > 1 {
                    return Some(text);
                }
            }
        }
    }

    None
}

fn heuristic_graphql_parse(env: &GraphQLEnvelope) -> NormalizedRequest {
    let variables = env.variables.as_ref().unwrap_or(&Value::Null);
    let content = find_graphql_like_content(variables)
        .unwrap_or_else(|| "[CONTENT_NOT_EXTRACTED]".to_string());
    let model = ["model", "modelId", "model_id", "modelName"]
        .iter()
        .find_map(|key| variables.get(key).and_then(extract_string))
        .or_else(|| {
            variables.get("input").and_then(|input| {
                ["model", "modelId", "model_id", "modelName"]
                    .iter()
                    .find_map(|key| input.get(key).and_then(extract_string))
            })
        });

    let user_content_hash = hash_content(&content);
    let mut normalized = NormalizedRequest {
        parse_confidence: ParseConfidence::Heuristic,
        parser_id: "graphql-heuristic-v1",
        schema_version: "1",
        parse_warnings: Vec::new(),
        is_ai_call: true,
        provider: Provider::new("graphql"),
        model,
        endpoint_type: crate::types::EndpointType::Chat,
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
        format_meta: FormatMeta::GraphQL {
            operation_name: env.operation_name.clone(),
            operation_type: GqlOpType::Unknown,
            mutation_field: None,
        },
        content_sample: if content == "[CONTENT_NOT_EXTRACTED]" {
            None
        } else {
            Some(content)
        },
    };
    normalized.canonical_hash = canonical_hash(&normalized);
    normalized
}
