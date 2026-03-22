def capture_mode($v):
  if ($v // "metadata_only") == "full" then "full"
  elif ($v // "metadata_only") == "sensitive_artifacts" then "sensitive_artifacts"
  else "metadata_only"
  end;

def process_action($v):
  if ($v // "intercept") == "block" then "block"
  elif ($v // "intercept") == "skip" or ($v // "intercept") == "passthrough" then "skip"
  else "intercept"
  end;

def unknown_app_action($v):
  if ($v // "skip") == "block" then "block"
  elif ($v // "skip") == "intercept" or ($v // "skip") == "host_only" then "intercept"
  else "skip"
  end;

def non_cataloged_action($v):
  if ($v // "skip") == "tunnel" or ($v // "skip") == "passthrough" then "passthrough"
  else "skip"
  end;

def normalize_host_pattern:
  tostring
  | ascii_downcase
  | gsub("^\\s+|\\s+$"; "") as $raw
  | ($raw | endswith("$")) as $anchored_end
  | ($raw | contains("*")) as $had_wildcard
  | (
      $raw
      | sub("^[a-z]+://"; "")
      | split("/")[0]
      | sub("^\\^"; "")
      | sub("\\$$"; "")
      | gsub("\\\\."; ".")
      | gsub("\\.\\*"; "*")
      | gsub("\\*\\*+"; "*")
      | sub(":$"; "")
      | gsub("^\\.+|\\.+$"; "")
    ) as $normalized
  | if $normalized == "" then ""
    elif ($anchored_end and ($had_wildcard | not)) then ("=" + $normalized)
    else $normalized
    end;

def host_rule($methods):
  {
    pattern: ((.pattern // "") | normalize_host_pattern),
    methods: ($methods // []),
    paths: {
      deny_exact: (.paths.deny_exact // []),
      deny_glob: (.paths.deny_glob // []),
      allow: (.paths.allow // [])
    }
  };

def entity_rule($entry):
  {
    entity_id: ($entry.value.id // $entry.key),
    capture_mode: capture_mode($entry.value.capture.mode),
    hosts: (
      ($entry.value.detection.hosts // [])
      | map(host_rule($entry.value.capture.methods))
      | map(select((.pattern // "") != ""))
    )
  };

.bundle as $b
| ($detect[0] // {}) as $d
| ($b.interception.app_policies // {}) as $app_policies
| {
    schema_version: 2,
    identity_index: {
      hosts: (
        (
          $app_policies
          | to_entries
          | map(select((.value.app_type // "non_host") == "host")
              | {
                  key: .key,
                  value: {
                    entity_id: .key,
                    app_type: "host",
                    capture_mode: capture_mode(.value.capture_mode),
                    action: process_action(.value.action)
                  }
                })
          | from_entries
        )
        +
        (
          (($b.interception.browser_policies.allowed_apps // [])
           + ($b.interception.browser_policies.allowed_browsers // []))
          | unique
          | map({
              key: .,
              value: {
                entity_id: .,
                app_type: "host",
                capture_mode: "metadata_only",
                action: "intercept"
              }
            })
          | from_entries
        )
      ),
      non_hosts: (
        $app_policies
        | to_entries
        | map(select((.value.app_type // "non_host") != "host")
            | {
                key: .key,
                value: {
                  entity_id: .key,
                  app_type: "non_host",
                  capture_mode: capture_mode(.value.capture_mode),
                  action: process_action(.value.action)
                }
              })
        | from_entries
      )
    },
    gates: {
      order: [
        "stage0_tls",
        "stage1_app_origin",
        "stage2_whitelist",
        "stage3_blacklist",
        "stage4_app_type",
        "stage5_host_origin",
        "intercept"
      ],
      defaults: {
        sensor_enabled: true,
        fail_open_on_config_error: true,
        unknown_app_action: unknown_app_action($b.interception.defaults.whitelisted_unknown_app_action),
        non_cataloged_host_action: non_cataloged_action($b.interception.defaults.non_whitelisted_host_action),
        discovery: {
          unknown_app_daily_limit: 1,
          unknown_domain_daily_limit: 1
        }
      },
      stage0_tls: {
        tls_intercept_hosts: (
          (
            ($b.llm_providers // {})
            | to_entries
            | map(.value.detection.hosts // [] | map(.pattern // empty))
            | add
          ) + (
            ($b.applications // {})
            | to_entries
            | map(.value.detection.hosts // [] | map(.pattern // empty))
            | add
          )
          | map(normalize_host_pattern)
          | map(select(length > 0))
          | unique
        ),
        passthrough_domains: (
          ($d.passthrough_domains // [])
          | map(normalize_host_pattern)
          | map(select(length > 0))
          | unique
        ),
        enable_discovery: true
      },
      stage1_app_origin: {
        skip_if_unresolved_process: true
      },
      stage2_whitelist: {
        allow_empty_means_allow_all_except_denied: true
      },
      stage3_blacklist: {
        blacklisted_keywords: (
          (($b.catalogs.analytics_blocklist // [])
           + ($b.filters.keywords // [])
           + ($b.filters.path_patterns // []))
          | unique
        ),
        blacklisted_path_substrings: ($b.catalogs.analytics_blocklist // []),
        blacklisted_host_substrings: ($b.filters.domain_patterns // []),
        graphql_operation_blacklist: [],
        graphql_operation_blacklist_enabled: false,
        match_type: "case_insensitive_substring"
      },
      stage4_app_type: {
        derive_from_identity_index: true
      },
      stage5_host_origin: {
        allowed_host_origins: (
          ($b.catalogs.ai_catalog // [])
          | map(normalize_host_pattern)
          | map(select(length > 0))
          | unique
        ),
        skip_for_discovery_capture: true
      }
    },
    entities: {
      providers: (
        ($b.llm_providers // {})
        | to_entries
        | map(entity_rule(.))
      ),
      web_apps: (
        ($b.applications // {})
        | to_entries
        | map(entity_rule(.))
      ),
      native_apps: []
    }
  }
