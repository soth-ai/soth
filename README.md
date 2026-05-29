# Soth

**An edge proxy and observability layer for AI agent traffic.**

[![CI](https://github.com/soth-ai/soth/actions/workflows/ci.yml/badge.svg)](https://github.com/soth-ai/soth/actions/workflows/ci.yml)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://www.mozilla.org/en-US/MPL/2.0/)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

Soth sits between your AI agents and the rest of the world. It captures, classifies,
and governs MCP, HTTP, and AI provider traffic — so you can see what your agents are
doing, enforce policy, and stay within budget.

---

## What it does

- **MITM proxy** — selective TLS termination of AI provider domains (OpenAI, Anthropic,
  Google, etc.); transparent tunnel for everything else. Always-on without breaking
  unrelated traffic.
- **MCP wrap** — wraps any MCP server (`soth wrap -- <cmd>`) to capture stdio
  JSON-RPC traffic from Claude Desktop, Cursor, Windsurf, and other clients.
- **Policy & budget** — OPA-style rules to block, allow, or rate-limit by agent,
  model, endpoint, or cost.
- **Local-first observability** — events stream to a SQLite store and a local
  dashboard at `http://127.0.0.1:3002`. Nothing leaves the machine unless you
  enable cloud sync.

## Install

**macOS / Linux**

```bash
curl -fsSL https://soth.ai/install.sh | bash
```

**Windows (PowerShell 7.5+)**

```powershell
iwr -useb https://soth.ai/install.ps1 | iex
```

Or build from source:

```bash
git clone https://github.com/soth-ai/soth
cd soth
cargo build --release
./target/release/soth --version
```

## Quickstart (60 seconds)

```bash
# 1. Generate a local MITM CA (one-time)
soth proxy setup-ca

# 2. Start the proxy
soth start

# 3. Route system traffic through it
soth proxy on

# 4. Open any AI app or browse api.openai.com — then watch the feed
soth tail
```

Or wrap an MCP server directly:

```bash
soth wrap -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

A local dashboard is available at **http://127.0.0.1:3002** (enable via
`dashboard.enabled: true` in `soth.yaml`).

## Configuration

Copy `soth.example.yaml` to `~/.soth/soth.yaml` and edit. Key sections:

| Section | What it controls |
|---|---|
| `identity` | Per-agent crypto identity & trust store |
| `policy` | OPA Rego rules, enforcement mode, cache TTLs |
| `observe` | Local logging, PII redaction, retention |
| `budget` | Per-agent token & cost limits |
| `forward_proxy` | MITM listener, intercept domain list, CA paths |
| `dashboard` | Local UI listener (default `127.0.0.1:3001`) |

See [`docs/INSTALL.md`](docs/INSTALL.md) for installation internals and
[`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md) for operational
guidance.

## Architecture

```
       ┌──────────────┐
agents │  AI clients  │
       │ (Claude, GPT │
       │  MCP, curl)  │
       └──────┬───────┘
              │ HTTP(S) / stdio / WebSocket
              ▼
       ┌──────────────┐         ┌─────────────────┐
       │     soth     │ ──────► │  AI providers   │
       │  edge proxy  │         │ (api.openai...) │
       └──────┬───────┘         └─────────────────┘
              │ events
              ▼
       ┌──────────────┐         ┌─────────────────┐
       │  SQLite +    │ ──────► │ optional cloud  │
       │  dashboard   │         │ sync (opt-in)   │
       └──────────────┘         └─────────────────┘
```

Core crates:

- `soth-cli` — CLI surface and runtime lifecycle
- `soth-proxy` — MITM transport, gating, classification, exchange assembly
- `soth-policy` — policy engine (OPA Rego)
- `soth-classify` — 7-stage classification pipeline with optional ONNX models
- `soth-detect` — deterministic detection helpers
- `soth-telemetry` — local SQLite storage
- `soth-extensions` — extension manager (with `historian` and `code` ext bundled)

## Status

Soth is **alpha**. The proxy, wrap, and policy engine work today and are used in
production by the maintainers, but APIs may change before 1.0. See
[CHANGELOG.md](CHANGELOG.md) for what's shipped.

## Contributing

Bug reports, fixes, and ideas welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
for setup and the PR workflow. Security issues: [SECURITY.md](SECURITY.md).

## License

Soth is distributed under the **Mozilla Public License 2.0** —
see [LICENSE](LICENSE). Modifications to MPL-covered files must be
shared under the same license; everything else (downstream applications,
larger works that link to Soth) can be licensed however you like.
