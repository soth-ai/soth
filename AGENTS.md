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

## Practical Checklist for New Provider/Agent
1. Add/update provider + domain + detection rules in cloud bundle seed/compiler.
2. Ensure `detection_id` values are present and stable in compiled bundle/providers.
3. Validate local classification with edge registry tests and proxy integration tests.
4. Verify detection metadata appears in local DB and dashboard/TUI views.
