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

## Practical Checklist for New Provider/Agent
1. Add/update provider + domain + detection rules in cloud bundle seed/compiler.
2. Ensure `detection_id` values are present and stable in compiled bundle/providers.
3. Validate local classification with edge registry tests and proxy integration tests.
4. Verify detection metadata appears in local DB rows, sync payloads, and heartbeat/runtime traces.
