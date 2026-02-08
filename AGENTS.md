# AGENTS.md

This file is an operational guide for new Codex instances working in this repository.

## Scope
SOTH is an edge proxy + wrap system for AI agent traffic.

- `soth proxy` captures HTTP/HTTPS + WebSocket traffic.
- `soth wrap` captures MCP stdio traffic by wrapping MCP server processes.
- Identity/policy/budget/observe pipelines can be applied to both paths.

## Workspace Map
- `crates/soth-core`: shared config, core types (`WrapEvent`, `TrafficEnvelope`), domain filters.
- `crates/soth-proxy`: proxy transport, host/provider/agent fingerprinting, enforcement pipeline.
- `crates/soth-cli`: commands (`proxy`, `wrap`, `init`, `config`, etc.).
- `crates/soth-identity`, `crates/soth-policy`, `crates/soth-budget`, `crates/soth-observe`: enforcement subsystems.
- `crates/soth-dashboard`: dashboard backend.

## Canonical Domain Classes
Forward proxy interception is now explicitly split into 3 classes:

1. `ai_inference`: direct model API domains.
2. `mcp`: MCP transport/service domains.
3. `agent_apps`: end-user agent surfaces (ChatGPT/Claude/Gemini/web IDE agents).

Config lives under `forward_proxy.hosts`:

- inline lists: `ai_inference`, `mcp`, `agent_apps`
- optional external files: `forward_proxy.hosts.domain_files.{ai_inference,mcp,agent_apps}`

When a `domain_files.*` entry is set, that file replaces the corresponding inline list.

## Where the 3 Files Come From
`soth init` now scaffolds:

- `domains/ai_inference.yaml`
- `domains/mcp.yaml`
- `domains/agent_apps.yaml`

and wires them in `soth.yaml` via `forward_proxy.hosts.domain_files`.

## System Definitions (MCP vs AI Inference vs Agent)
- **MCP traffic**: JSON-RPC MCP methods (`tools/*`, `resources/*`, `prompts/*`, etc.) over stdio/HTTP/WS.
- **AI inference traffic**: direct provider inference endpoints (`api.openai.com`, `api.anthropic.com`, etc.).
- **Agent app traffic**: app surfaces that orchestrate user interactions (ChatGPT/Claude/Gemini/Cursor/Copilot/etc.).

Event-level encoding:

- `EventSource::Mcp` + `TrafficSource::McpStdio` for wrap stdio.
- `EventSource::Mcp` + `TrafficSource::McpHttp` for MCP over HTTP/WS.
- `EventSource::AiProxy` or `EventSource::AgentApp` + `TrafficSource::ProxyHudsucker` for proxy AI/agent traffic.

## Agent Detection: Current Behavior

### Proxy path (`crates/soth-proxy/src/transport/hudsucker_proxy.rs`)
Detection order:

1. User-Agent heuristic (`detect_agent_from_user_agent`).
2. Host/path/model fingerprint (`host_fingerprint`).
3. Provider fallback where applicable.

Important: host-driven inference is now **gated by configured agent domains**.

- Host/path fallback (including Codex host+path promotion) only applies when:
  - host matches configured `agent_apps`, or
  - host mode is `discovery`.
- Strong explicit signals still work without host fallback:
  - Codex model marker (`model` contains `codex`),
  - explicit User-Agent markers.

This prevents hardcoded domain fingerprints from silently overriding selective domain configuration.

### Wrap path (`crates/soth-cli/src/commands/wrap/agent_detect.rs`)
Detection precedence:

1. CLI override (`--agent`) [highest].
2. MCP `initialize.params.clientInfo`.
3. Environment variables.
4. Parent process tree.
5. Unknown.

## Codex / ChatGPT / Claude / Gemini Notes
- Codex can be detected by:
  - User-Agent markers (`openai-codex`, `codex/`),
  - model marker (`*codex*`),
  - ChatGPT host + Codex path markers (host-gated as above).
- ChatGPT/Claude/Gemini host fallbacks are present but now controlled by `agent_apps` host config.
- Claude API hosts (`api.claude.ai`, `api.anthropic.com`) are explicitly excluded from `agent_apps` classification.

## Known Gaps
1. Host/provider fingerprints are still hardcoded in code (`host_fingerprint.rs`), not fully declarative.
2. User-Agent/process/env detection signatures are hardcoded, not config-driven.
3. Proxy events do not yet carry a structured "detection reason" payload (which heuristic won).
4. Discovery mode intentionally bypasses selective host constraints; this can surprise users if enabled.
5. Wildcard matching in host filters is simple single-`*` pattern matching and not full glob/regex.

## Recommended Next Iteration
1. Add a declarative `forward_proxy.detection.rules_file` for UA/path/model/host signatures.
2. Share one detection engine between proxy and wrap (single rule source).
3. Emit structured `agent_detection_reason` in event metadata for debugging.
4. Add end-to-end tests proving per-agent detection behavior from config-only inputs.

## Practical Checklist When Adding a New Agent
1. Add/verify host domains in `domains/agent_apps.yaml` (and maybe `ai_inference.yaml` for direct APIs).
2. Add provider/agent fingerprints in `host_fingerprint.rs` if host heuristics are required.
3. Add wrap-side env/process/initialize normalization in `agent_detect.rs`.
4. Add tests in:
   - `crates/soth-proxy/src/transport/hudsucker_proxy.rs`
   - `crates/soth-cli/src/commands/wrap/agent_detect.rs`
   - `crates/soth-core/src/config/types.rs`
