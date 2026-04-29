# soth-conformance-tests

Cross-lane parity harness for the proxy and SDK code paths through
`soth-detect` + `soth-classify`. Lives outside the workspace's default
build set; runs as part of any CI invocation that touches `soth-detect`,
`soth-classify`, or `soth-core`.

## What this catches

For every fixture under `fixtures/*.json`, the harness runs:

- **Proxy lane** &nbsp;&nbsp;&nbsp;`RawRequest` → `soth_detect::process_with_registry` → `soth_classify::classify`
- **SDK lane** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`TypedLlmCall` → `soth_detect::process_normalized` → `soth_classify::classify`

…and asserts the contract-surface fields agree. When they don't, every
diverging field is reported by name so the regression can be debugged
without local replay.

## Layered comparison

The harness has two diff lists by design:

- **Strict** &nbsp;&nbsp;[`compare()`] — fields at parity *today*. Any divergence here fails CI.
- **Advisory** [`compare_advisory()`] — fields with known content-extraction
  divergences. Reported but non-fatal. As `process_normalized` is brought
  into byte-level alignment with the proxy REST parser, fields graduate
  from this list into the strict set.

### Strict set (must match — fail CI on divergence)
- `normalized.provider`, `normalized.model`, `normalized.endpoint_type`
- `normalized.is_ai_call`, `normalized.has_tool_definitions`, `normalized.stream`
- `detect.capture_mode`
- `detect.artifacts` (kind set, sorted)
- `classified.policy_decision.kind`
- `telemetry_event.{provider, model, endpoint_type, capture_mode}`

### Advisory set (printed; not yet at parity)
- `normalized.user_content_hash` &nbsp;— proxy REST parser concatenates
  message content with separators that `process_normalized` doesn't yet
  replicate. The SDK uses last-user-message semantics, but the proxy's
  `extract_messages` path takes more flexible shapes.
- `normalized.conversation_hash` — proxy uses `role:content\n` joined
  format including system-role messages; SDK matches that for OpenAI-style
  but the format isn't yet provider-aware.
- `normalized.system_prompt_hash` — extraction strategy differs between
  `system_in_messages: true` providers (OpenAI/Cohere/Mistral) and
  Anthropic-style separate `system` field.
- `normalized.tool_definition_hash` — proxy hashes the tools-array JSON
  string verbatim; SDK hashes a structural form. Closing this requires
  agreeing on a canonical normalized form for tool definitions.
- `classified.use_case_label`, `classified.volatility_class`,
  `classified.anomaly_flags` — downstream of the above; will fall in line
  once content-extraction parity is achieved.

## Fixture format

Each fixture is a JSON file under `fixtures/`:

```json
{
  "name": "openai_chat_basic",
  "description": "...",
  "axes": {
    "provider": "openai",
    "streaming": false,
    "tools": false,
    "content_class": "clean",
    "format": "rest_chat_completions",
    "capture_mode": "metadata_only"
  },
  "typed_call": {
    "provider": "openai",
    "model": "gpt-4o-mini",
    "messages": [{ "role": "user", "content": "..." }],
    "stream": false
  },
  "raw_request": {
    "method": "POST",
    "path": "/v1/chat/completions",
    "headers": { "host": "api.openai.com", "content-type": "application/json" },
    "body": { ... },
    "matched_provider": "openai"
  }
}
```

The `axes` block is optional metadata used by the coverage tracker; it
does not affect the test execution.

## Coverage taxonomy

The launch target for the corpus is **80 fixtures**, with explicit
coverage of every axis below. Today's MVP corpus exercises a subset.

### Mandatory axes (each must be exercised by ≥1 fixture)
| Axis | Variants |
|---|---|
| `parse_confidence` | Full · Partial · Heuristic |
| `use_case_label` | all 16 `UseCaseLabel` variants |
| `anomaly_flag` | all 8 `AnomalyFlag` variants |
| `policy_decision` | Allow · Block · Redact · Flag · *(Reroute = proxy_only)* |
| `system_rule` | each rule in the default policy bundle fires somewhere |
| `capture_mode` | MetadataOnly · SensitiveArtifacts · Full · FullContent |

### Combinatoric axes
| Axis | Variants |
|---|---|
| `provider` | OpenAI · Anthropic · Cohere · Google · Mistral |
| `streaming` | yes · no |
| `tools` | yes · no |
| `content_class` | clean · code · credential · PII · multi-turn-depth-10+ |

### Format axes
- REST chat completions
- REST messages
- GraphQL (registered + unknown)
- gRPC (when the SDK ships gRPC support)

## Current corpus

| File | Provider | Streaming | Tools | Content |
|---|---|---|---|---|
| `01_openai_chat_basic.json` | openai | no | no | clean |
| `02_openai_chat_streaming_tools.json` | openai | yes | yes | clean |
| `03_anthropic_messages_basic.json` | anthropic | no | no | clean |
| `04_credential_leak_in_user_message.json` | openai | no | no | credential |
| `05_code_in_user_message.json` | openai | no | no | code |
| `06_cohere_chat_basic.json` | cohere | no | no | clean |
| `07_mistral_multiturn.json` | mistral | no | no | clean (3-turn) |

7 fixtures. Path to launch target (80) is incremental — each new
fixture should fill an unexercised axis cell from the matrices above.

## Running locally

```sh
cargo test -p soth-conformance-tests --test parity
cargo test -p soth-conformance-tests --test parity -- --nocapture  # show coverage + advisory output
```

## Adding a fixture

1. Create `fixtures/NN_provider_scenario.json` with both `typed_call` and
   `raw_request`. Both lanes must describe the **same logical call** —
   the proxy's body is the JSON-serialized form of what the typed call
   carries.
2. Tag `axes.*` so the coverage tracker picks up the new cells.
3. Run `cargo test -p soth-conformance-tests`. Strict failures block;
   advisory entries are documented in this README's follow-up section.

## Follow-up parity work

The advisory set above is the next workstream. Closing each entry
typically involves a small targeted change in `soth_detect::engine`'s
`build_normalized_from_typed_call` to match the proxy REST parser's
extraction logic for the corresponding field. PR-by-PR, fields graduate
from advisory to strict and the corpus becomes a stricter contract.
