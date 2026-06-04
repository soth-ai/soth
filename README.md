<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/logo-white.svg" />
    <source media="(prefers-color-scheme: light)" srcset=".github/assets/logo-black.svg" />
    <img src=".github/assets/logo-black.svg" alt="Soth" width="120" />
  </picture>
</p>

<h1 align="center">SOTH</h1>

<p align="center">
  <strong>An edge proxy and observability layer for AI agent traffic.</strong>
</p>

<p align="center">
  <em>Know your agents. Control what they do.</em>
</p>

<p align="center">
  <a href="https://github.com/soth-ai/soth/actions/workflows/ci.yml">
    <img src="https://github.com/soth-ai/soth/actions/workflows/ci.yml/badge.svg" alt="CI" />
  </a>
  <a href="https://www.mozilla.org/en-US/MPL/2.0/">
    <img src="https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg" alt="License: MPL 2.0" />
  </a>
  <a href="https://www.rust-lang.org">
    <img src="https://img.shields.io/badge/rust-1.75%2B-orange.svg" alt="Rust 1.75+" />
  </a>
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg" alt="Platform: macOS | Linux | Windows" />
</p>

<p align="center">
  <a href="#quick-start-60-seconds">Quick start</a> ·
  <a href="#install">Install</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#contributing">Contributing</a>
</p>

---

Soth sits between your AI agents and the rest of the world. It captures, classifies,
and governs MCP, HTTP, and AI-provider traffic — so you can see what your agents are
doing, enforce policy, and stay within budget.

## What it does

- **MITM proxy** — selective TLS termination of AI-provider domains (OpenAI, Anthropic,
  Google, …); transparent tunnel for everything else. Always-on without breaking
  unrelated traffic.
- **Policy & budget** — OPA-style rules to block, allow, or rate-limit by agent,
  model, endpoint, or cost.
- **Local-first observability** — events stream to a SQLite store. Nothing leaves the
  machine unless you opt into cloud sync.

## Quick start (60 seconds)

```bash
# 1. Generate a local MITM CA (one-time)
soth setup-ca

# 2. Start the proxy
soth start

# 3. Route system traffic through it
soth on

# 4. Open any AI app or browse api.openai.com — then watch the feed
soth events stream
```

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

## Configuration

Copy `soth.example.yaml` to `~/.soth/soth.yaml` and edit. Key sections:

| Section | What it controls |
|---|---|
| `identity` | Per-agent crypto identity & trust store |
| `policy` | OPA Rego rules, enforcement mode, cache TTLs |
| `observe` | Local logging, PII redaction, retention |
| `budget` | Per-agent token & cost limits |
| `forward_proxy` | MITM listener, intercept domain list, CA paths |

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
       │ SQLite store │ ──────► │ optional cloud  │
       │  (events)    │         │ sync (opt-in)   │
       └──────────────┘         └─────────────────┘
```

Core crates:

- `soth-cli` — CLI surface and runtime lifecycle
- `soth-proxy` — MITM transport, gating, classification, exchange assembly
- `soth-policy` — policy engine (OPA Rego)
- `soth-classify` — 7-stage classification pipeline with optional ONNX models
- `soth-detect` — deterministic detection helpers
- `soth-telemetry` — local SQLite storage
- `soth-extensions` — extension manager (bundles `historian` and `code`)

## Documentation

| Guide | What's inside |
|---|---|
| [Installation internals](docs/INSTALL.md) | Installer mechanics, paths, self-update |
| [Production readiness](docs/PRODUCTION_READINESS.md) | Operational guidance & known gaps |
| [Configuration reference](soth.example.yaml) | Every config key, annotated |
| [Contributing](CONTRIBUTING.md) | Dev setup and the PR workflow |
| [Security policy](SECURITY.md) | Reporting vulnerabilities |
| [Changelog](CHANGELOG.md) | What's shipped |

## Status

Soth is **alpha**. The proxy and policy engine work today and are used in production by
the maintainers, but APIs may change before 1.0. See [CHANGELOG.md](CHANGELOG.md) for
what's shipped.

## Contributing

Bug reports, fixes, and ideas welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup
and the PR workflow. Security issues: [SECURITY.md](SECURITY.md).

## License

Soth is distributed under the **Mozilla Public License 2.0** — see [LICENSE](LICENSE).
Modifications to MPL-covered files must be shared under the same license; everything else
(downstream applications, larger works that link to Soth) can be licensed however you like.
