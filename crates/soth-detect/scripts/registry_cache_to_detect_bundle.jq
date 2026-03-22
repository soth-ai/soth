def app_kind_map($t):
  if $t == "host" then "browser"
  elif $t == "non_host" then "agent_app"
  elif $t == "ide" then "ide"
  elif $t == "cli" then "cli"
  else "unknown"
  end;

def rest_descriptor($v):
  {
    tier: null,
    request: {
      model: ($v.request.model // null),
      messages: ($v.request.messages // null),
      message: ($v.request.message // null),
      chat_history: ($v.request.chat_history // null),
      contents: ($v.request.contents // null),
      system: ($v.request.system // null),
      system_instruction: ($v.request.system_instruction // null),
      tools: ($v.request.tools // null),
      tool_choice: ($v.request.tool_choice // null),
      max_tokens: ($v.request.max_tokens // ($v.request.generation_config.max_output_tokens // null)),
      temperature: ($v.request.temperature // ($v.request.generation_config.temperature // null)),
      top_p: ($v.request.top_p // ($v.request.generation_config.top_p // null)),
      stream: ($v.request.stream // null),
      stop: ($v.request.stop // null)
    },
    response: {
      content: ($v.response.json.extract.content // null),
      model: ($v.response.json.extract.model // null),
      finish_reason: ($v.response.json.extract.finish_reason // null),
      input_tokens: ($v.response.json.extract_usage.input_tokens // ($v.response.json.extract_usage.prompt_tokens // null)),
      output_tokens: ($v.response.json.extract_usage.output_tokens // ($v.response.json.extract_usage.completion_tokens // null)),
      stop_reason: ($v.response.json.extract.stop_reason // null)
    },
    system_in_messages: (($v.request.system // null) == null),
    content_blocks: false,
    chat_history_mode: (($v.request.chat_history // null) != null),
    model_from_url_segment: (if ($v.request.model // "") == "{url_path}" then "/models/" else null end),
    role_map: {},
    model_id_parse: (($v.request.model // "") == "{url_path}"),
    ephemeral_request_fields: []
  };

.bundle as $b
| {
    rest_formats: (
      ($b.formats // {})
      | with_entries(.value = rest_descriptor(.value))
    ),
    graphql_operations: {
      version: null,
      operations: [],
      heuristic_patterns: []
    },
    grpc_services: {
      version: null,
      services: []
    },
    capture_rules: {
      default_mode: "metadata_only",
      full_capture_providers: (
        ($b.llm_providers // {})
        | to_entries
        | map(select((.value.capture.mode // "metadata_only") != "metadata_only") | .key)
      ),
      org_overrides: {
        full_capture_providers: [],
        metadata_only_providers: []
      }
    },
    domain_index: ($b.domain_index // {}),
    detection_index: ($b.detection_index // {}),
    llm_providers: (
      ($b.llm_providers // {})
      | with_entries(
          .value = {
            provider_id: (.value.id // .key),
            name: (.value.name // .key),
            api_format: (.value.api_format // null)
          }
        )
    ),
    applications: (
      ($b.applications // {})
      | with_entries(
          .value = {
            app_id: (.value.id // .key),
            name: (.value.name // .key),
            bundle_ids: (
              (.value.detection.process_rules // [])
              | map(.bundle_id? // empty)
              | map(select(. != null))
              | unique
            ),
            process_names: (
              (.value.detection.process_rules // [])
              | map(.process_name? // empty)
              | map(select(. != null))
              | unique
            )
          }
        )
    ),
    filters: {
      path_keywords: (
        (($b.filters.keywords // [])
         + ($b.filters.path_patterns // [])
         + ($b.filters.domain_patterns // []))
        | unique
      ),
      header_keywords: []
    },
    app_policies: (
      ($b.interception.app_policies // {})
      | with_entries(
          .value = {
            app_id: .key,
            display_name: ($b.applications[.key].name // null),
            app_kind: app_kind_map(.value.app_type // "unknown")
          }
        )
    ),
    browser_policies: {
      allowed_apps: (
        (($b.interception.browser_policies.allowed_apps // [])
         + ($b.interception.browser_policies.allowed_browsers // []))
        | unique
      )
    }
  }
