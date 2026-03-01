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
- `crates/soth-edge`: MITM transport + bundle-driven classification + exchange assembly.
- `crates/soth-sync`: cloud sync, exchange upload queue, registry bundle cache refresh.
- `crates/soth-dashboard`: API + WS backend for local dashboard/TUI data.
- `crates/soth-collector`: local session collectors and incremental scans.
- `crates/soth-core`: shared config, event/exchange schemas, sqlite logger/storage primitives.
- `crates/soth-crypto`: key management, signatures, TLS helpers.
- `crates/soth-policy`: policy engine/wrappers.
- `crates/soth-budget`: spend tracking and budget enforcement primitives.
- `crates/soth-observe`: enrichment/parsing helpers (PII, JSONL, storage adapters).
- `crates/soth-storage`: shared storage helpers.

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
- Cloud sync uploads Exchange V2 batches to `/api/v1/exchanges/batch`.
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

## Practical Checklist for New Provider/Agent
1. Add/update provider + domain + detection rules in cloud bundle seed/compiler.
2. Ensure `detection_id` values are present and stable in compiled bundle/providers.
3. Validate local classification with edge registry tests and proxy integration tests.
4. Verify detection metadata appears in local DB and dashboard/TUI views.
