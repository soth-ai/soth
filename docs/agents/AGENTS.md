# AGENTS.md

Operational guide for Codex instances working in this repository.

## Scope
SOTH is an edge sensor for AI traffic with these capture paths:

- `soth start` / `soth up`: HTTP/HTTPS + WebSocket proxy capture (selective MITM).
- `soth code` (hook): synchronous policy gate + capture at the AI coding agent's
  hook boundary (Claude Code, Cursor, Codex).
- `historian` extension: local AI-tool history ingestion, playbook/config-driven.

Policy, budget, identity/crypto, and observability apply across all paths and normalize into Exchange V2 records.

## Workspace Map
- `crates/soth-cli`: CLI surface and runtime lifecycle (`start/up/down/stop/logs/on/off`, `status`, `doctor`, `init`, `enroll`, `login`, `setup-ca`, `env`, `events`, `bundle`, `config`, `code`, `update`).
- `crates/soth-cli-update-sidecar`: Windows sidecar updater (atomic self-update swap).
- `crates/soth-proxy`: MITM transport + bundle-driven gating/classification + exchange assembly.
- `crates/soth-core`: canonical shared contracts and primitives, including `crypto.rs` (keys, signatures, TLS helpers) and `identity.rs`.
- `crates/soth-api-types`: cloud API wire contract shared between proxy (soth-sync) and SDK (soth-sdk-core).
- `crates/soth-sync`: edge-side cloud sync, exchange upload queue, registry bundle cache refresh.
- `crates/soth-telemetry`: local SQLite telemetry storage and query helpers.
- `crates/soth-bundle`: verified intelligence bundle loading, validation, and hot-swap for classify/policy/detect artifacts.
- `crates/soth-classify`: 7-stage classification pipeline and anomaly scoring.
- `crates/soth-detect`: deterministic detection helpers and host/domain attribution.
- `crates/soth-parse`: format fingerprinting and request/response body parsing for AI API traffic.
- `crates/soth-policy`: synchronous policy bundle evaluation.
- `crates/soth-sdk-core`: public-API facade consumed by the SDK bindings (PyO3 / napi-rs / WASM).
- `crates/soth-conformance-tests`: cross-lane parity harness for soth-detect + soth-classify (proxy vs SDK).
- `extensions/code` (`soth-code`): coding-agent hook capture extension.
- `extensions/historian` (`soth-historian`): AI-tool history ingestion extension.
- `bindings/soth-py`, `bindings/soth-node`, `bindings/soth-edge`: Python (PyO3), Node.js (napi-rs), and edge/WASM SDK bindings.

## Canonical Host Classes
Bundle classification splits traffic into:

1. `ai_inference`
2. `mcp`
3. `agent_apps`

Host lists can still be configured under `forward_proxy.hosts`, but runtime interception/classification is bundle-driven through the edge registry bundle.

## Detection Model
- Proxy: edge registry bundle rules are primary.
- Coding-agent / MCP capture: precedence is `--agent` override, MCP `initialize.clientInfo`, env/process hints, then unknown.
- Events carry detection metadata (`detection_id`, `detection_reason`, `parse_confidence`, `detection_source`).

## Event Encoding
- MCP stdio: `EventSource::Mcp` + `TrafficSource::McpStdio`.
- MCP over HTTP/WS: `EventSource::Mcp` + `TrafficSource::McpHttp`.
- Proxy AI/agent traffic: `EventSource::AiProxy` or `EventSource::AgentApp` + `TrafficSource::ProxyHudsucker`.

## Operational Notes
- Primary local DB path defaults to `~/.soth/logs/events.db`.
- Cloud sync uploads Exchange V2 batches to `/v1/edge/enroll/exchange`.
- Registry bundle cache is read from local cache path and hot-reloaded by runtime components.

## Debug Notes (2026-02-27)
- Gating Stage 3 blacklist scope:
  Current proxy evaluator applies blacklist keyword matching against the full URL string (host + path) and path/body checks.
  This can cause host-level false positives when broad keywords are present in hostnames (for example `cloudflare` or `googleapis`).
  When editing bundle/compiler behavior, decide explicitly whether blacklist keywords are path-only or host+path; if host matching is required, keep a separate host blacklist list to avoid accidental drops.
- Transport failure investigation (`api.tbox.cn`):
  Reproduced that proxy-intercepted HTTPS over HTTP/2 can fail with `connection reset by peer`, while the same endpoint over HTTP/1.1 succeeds end-to-end.
  Evidence:
  - `curl -x http://127.0.0.1:5074 --http1.1 https://api.tbox.cn/` -> `200`
  - `curl -x http://127.0.0.1:5074 --http2 https://api.tbox.cn/` -> reset / `code=000`
  - `curl --noproxy '*' --http2 https://api.tbox.cn/` negotiates `ALPN: http/1.1` (upstream does not support h2)
  - TLS gate trace still shows `tls_intercept_catalog`, but no HTTP gate event is emitted on failed HTTP/2 requests.
  Root cause:
  - In the proxy MITM transport (`crates/soth-proxy/src/handler.rs`), when downstream negotiates h2 but upstream negotiates non-h2, the flow can fail instead of protocol downgrading.
  Current guidance:
  - For gating corpus/debug traffic, force HTTP/1.1 for h2-incompatible hosts to avoid transport false negatives.
  - Fix direction: add host-level `disable_h2` override (or h2->h1 downgrade path) so downstream ALPN does not advertise/commit h2 for those hosts.

## Open Work

Active engineering work is tracked in
[GitHub Issues](https://github.com/soth-ai/soth/issues). When picking up an
item, file (or claim) the issue first so we don't double-up.

## Backlog — Dead Telemetry Variables

Remaining `TelemetryEvent` fields that are declared but never receive meaningful values. Tracked here for future work.

### ~~`import_categories`~~ — DONE (2026-03-07)
Wired end-to-end: soth-detect `engine.rs` now collects `DetectedImportCategory` from `TreeSitterResult` during code artifact scanning, deduplicates, and stores on `DetectResult.import_categories`. `core_output.rs` maps `DetectedImportCategory` → `soth_core::ImportCategory`. Stage 7 reads from `detect_result.import_categories` and populates both the telemetry event and `SensitiveCodeFlags` (network, file_io, crypto, auth).

### ~~`code_fraction`~~ — DONE (2026-03-07)
Added `code_fraction: f32` to `soth_core::TelemetryEvent`. Stage 7 computes an approximate code fraction from CodeBlock artifact count and `estimated_input_tokens`. The soth-sync sender maps it to the cloud-facing `api_types::TelemetryEvent.code_fraction` field (previously hardcoded `None`).

### `estimated_output_tokens` — needs response-path amendment (Medium)
Response usage (`output_tokens`) is already extracted in `response.rs` and applied to the session store via `apply_response_usage()`. However the telemetry event is pushed in `classify_task.rs` on the request path *before* the response arrives. Wiring this requires either: (a) a follow-up amendment event pushed when the response arrives, or (b) delaying the telemetry push until response usage is captured. Both are architectural changes to the telemetry pipeline.

**Current state**: `NormalizedRequest.estimated_output_tokens` exists as `Option<u32>` and is wired through the exfiltration check in stage 5 anomaly and into the telemetry event. The detect-level parsers don't populate it yet because they only see the request, not the response. The field is ready to receive data from two possible sources:
1. **Response-path amendment** — After `apply_response_usage()` runs, push a lightweight amendment event (or update the pending event in a queue) with the actual output token count from the provider's `usage` response field. This is the cleanest approach but requires a new `TelemetryPipeline::amend(event_id, patch)` method and a brief hold window.
2. **Session carry-forward** — Use the previous request's response usage (already in `SessionSnapshot`) as an estimate for the current request. Less accurate but zero architectural change. `SessionSnapshot.total_output_tokens` / request count gives a per-request average.

**Key files**: `crates/soth-proxy/src/response.rs` (extracts usage), `crates/soth-proxy/src/classify_task.rs` (pushes telemetry event), `crates/soth-telemetry/src/lib.rs` (pipeline API).

### `first_step_event_id` / `agent_step_number` — needs agent-step tracker (Medium)
For multi-step agent conversations. The session store has `max_tool_depth_seen` and `AnomalyFlag::AgentLoopPattern` exists, but no code assigns step numbers or tracks the originating event ID of a multi-step sequence.

**Current state**: `SessionSnapshot` tracks `request_count`, `models_used_this_session`, and `max_tool_depth_seen`. The anomaly stage detects `AgentLoopPattern` when rapid-fire + tools + multi-model conditions are met. What's missing is correlating individual events within an agent loop.

**Implementation plan**:
1. Add `current_step_number: u32` and `current_step_first_event_id: Option<Uuid>` to `SessionSnapshot`.
2. In the session manager (or session mutation path), detect a "new step" when `conversation_turn` resets or a tool-result message appears after a tool-call message. Increment `current_step_number` and capture the event ID of the first event in each step.
3. In stage 7 telemetry, read `snapshot.current_step_number` → `agent_step_number` and `snapshot.current_step_first_event_id` → `first_step_event_id`.
4. Reset step tracking when session key changes or a configurable idle timeout elapses.

**Key files**: `crates/soth-core/src/session.rs` (SessionSnapshot), `crates/soth-proxy/src/session.rs` (session mutations), `crates/soth-classify/src/stage7_telemetry.rs` (event assembly).

### `cache_level` — needs caching layer (Not planned)
`CacheLevel` enum (Exact, Semantic, Prefix) exists but no caching layer evaluates whether a request is a cache hit. Infrastructure for cache-hit determination doesn't exist. This is an intelligence-layer feature, not in scope for the edge proxy.

**If pursued later**: The classify pipeline already produces `semantic_hash` (stage 2) and `prefix_hash` (detect). A cache-hit evaluator would check these hashes against a recent-request LRU: exact match on `canonical_cache_key` → `CacheLevel::Exact`, cosine similarity above threshold on embedding → `CacheLevel::Semantic`, shared prefix hash → `CacheLevel::Prefix`. This would slot in as a new stage between cluster (stage 2) and usecase (stage 3), or as a post-pipeline enrichment. Estimated effort: ~2-3 days including LRU store and similarity threshold tuning.

## Practical Checklist for New Provider/Agent
1. Add/update provider + domain + detection rules in cloud bundle seed/compiler.
2. Ensure `detection_id` values are present and stable in compiled bundle/providers.
3. Validate local classification with edge registry tests and proxy integration tests.
4. Verify detection metadata appears in local DB rows, sync payloads, and heartbeat/runtime traces.
