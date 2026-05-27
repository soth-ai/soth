# AGENTS.md

Operational guide for Codex instances working in this repository.

## Scope
SOTH is an edge sensor for AI traffic with three capture paths:

- `soth start` / `soth up`: HTTP/HTTPS + WebSocket proxy capture.
- `soth wrap`: MCP stdio capture by wrapping MCP server processes.
- collector pipeline (config-driven): local session artifact ingestion.

Policy, budget, identity/crypto, and observability apply across all paths and normalize into Exchange V2 records.

## Workspace Map
- `crates/soth-cli`: CLI surface and runtime lifecycle (`start/up/down/stop/logs/on/off`, `wrap`, `runtime`, `dev`).
- `crates/soth-proxy`: MITM transport + bundle-driven gating/classification + exchange assembly.
- `crates/soth-sync`: cloud sync, exchange upload queue, registry bundle cache refresh.
- `crates/soth-telemetry`: local SQLite telemetry storage and query helpers.
- `crates/soth-collector`: local session collectors and incremental scans.
- `crates/soth-wrap`: MCP stdio runtime path (planned near-term expansion).
- `crates/soth-core`: shared config, event/exchange schemas, sqlite logger/storage primitives.
- `crates/soth-crypto`: key management, signatures, TLS helpers.
- `crates/soth-bundle`: bundle loader/cache/watcher for classify/policy/detect artifacts.
- `crates/soth-classify`: 7-stage classification pipeline and anomaly scoring.
- `crates/soth-detect`: deterministic detection helpers and host/domain attribution.
- `crates/soth-policy`: policy engine/wrappers.
- `crates/soth-sqlite-vec`: sqlite-vec lifecycle/loading adapter.

## Canonical Host Classes
Bundle classification splits traffic into:

1. `ai_inference`
2. `mcp`
3. `agent_apps`

Host lists can still be configured under `forward_proxy.hosts`, but runtime interception/classification is bundle-driven through the edge registry bundle.

## Detection Model
- Proxy: edge registry bundle rules are primary.
- Wrap: precedence is `--agent` override, MCP `initialize.clientInfo`, env/process hints, then unknown.
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
  - In `soth-mitm` (`mitm-sidecar/src/flow_intercept.rs`), when downstream negotiates h2 but upstream negotiates non-h2, the flow exits with `MitmHttpError` instead of protocol downgrading.
  Current guidance:
  - For gating corpus/debug traffic, force HTTP/1.1 for h2-incompatible hosts to avoid transport false negatives.
  - Fix direction: add host-level `disable_h2` override (or h2->h1 downgrade path) so downstream ALPN does not advertise/commit h2 for those hosts.

## Backlog — Metadata-Only Implementation Gaps

Gaps identified during plan audit (2026-03-06). Pick up when available.

### Phase 2 — Dedup & Fingerprinting
- [ ] `conversation_fingerprint.rs` module: `fingerprint_conversation`, `resolve_effective_capture_mode`, `normalize_message_content`, `novel_tail_slice`
- [ ] `DetectBundleSlice` threshold config fields: `force_metadata_only_above_bytes`, `min_dedup_payload_bytes`, `seen_code_hash_capacity`, `seen_prefix_hash_capacity`

### Phase 3 — Session/Pipeline
- [ ] `classify_slice()` function in soth-classify
- [ ] `reaper_loop()` background tokio task for session TTL cleanup
- [ ] `sqlite.upsert_code_blob()` implementation

### Phase 4 — Schema
- [ ] Schema version bump confirmation

### Phase 5 — Extensions
- [ ] Per-extension `SessionManager` (`HashMap<ExtensionType, SessionManager>`) in extension manager
- [ ] `build_extension_manager()` wired into soth-proxy main.rs
- [ ] `ExtensionManager` wired into `ProxyHandler` startup

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
