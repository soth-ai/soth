<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/logo-white.svg" />
    <source media="(prefers-color-scheme: light)" srcset=".github/assets/logo-black.svg" />
    <img src=".github/assets/logo-black.svg" alt="Soth" width="120" />
  </picture>
</p>

<h1 align="center">SOTH</h1>

<p align="center">
  <strong>An edge proxy and observability platform for AI agent traffic.</strong>
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
  <a href="#quick-start">Quick start</a> ·
  <a href="#standalone-self-hosted">Self-hosted</a> ·
  <a href="#open-source-vs-soth-cloud">OSS vs Cloud</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#contributing">Contributing</a>
</p>

---

Soth sits between your AI agents and the rest of the world — capturing, classifying, and
governing MCP, HTTP, and AI-provider traffic. Connect your nodes to **[SOTH Cloud](https://dashboard.soth.ai)**
for a managed dashboard with live feeds, policy, and budget across your whole fleet — or
run the proxy fully standalone and headless. Either way: see what your agents are doing,
enforce policy, and stay within budget.

## What it does

- **MITM proxy** — selective TLS termination of AI-provider domains (OpenAI, Anthropic,
  Google, …); transparent tunnel for everything else. Always-on without breaking
  unrelated traffic.
- **Policy & budget** — OPA-style rules to block, allow, or rate-limit by agent,
  model, endpoint, or cost.
- **Fleet observability** — every event is captured locally (SQLite) and, with SOTH
  Cloud, streams to a managed dashboard with live feeds, policy and budget views, and
  multi-node management. No UI to build or host yourself.

## Quick start

Two ways to run Soth. Most teams start with **SOTH Cloud** — a managed backend and
dashboard, so there's no UI to build or host. The proxy is identical either way.

### SOTH Cloud (recommended)

1. Sign in at **[dashboard.soth.ai](https://dashboard.soth.ai)** and create an
   enrollment link for your team.
2. Run the one-liner it gives you on each machine:

```bash
curl -fsSL "https://dashboard.soth.ai/install?enroll_token=<token>" | bash -s --
```

This downloads the signature-verified proxy binary, enrolls the node with the backend,
and starts capturing. Live traffic, policy, and budget show up in your dashboard right
away — across every enrolled machine.

> Prefer an API key to a per-node token?
> `curl -fsSL "https://dashboard.soth.ai/install" | bash -s -- --api-key <key>`

### Standalone (self-hosted)

Soth also runs fully standalone — no account, no cloud, nothing leaves the machine.
Install the headless binary and drive it from the CLI:

```bash
# macOS / Linux
curl -fsSL https://soth.ai/install.sh | bash
# Windows (PowerShell 7.5+):  iwr -useb https://soth.ai/install.ps1 | iex

soth setup-ca        # one-time local MITM CA
soth start           # start the proxy
soth on              # route system traffic through it
soth events stream   # headless live feed (no GUI)
```

The standalone proxy is **headless** — inspect traffic with `soth events stream` or query
the SQLite store at `~/.soth/` directly. Build from source:

```bash
git clone https://github.com/soth-ai/soth
cd soth && cargo build --release
./target/release/soth --version
```

## Open source vs SOTH Cloud

| | Open source (this repo) | SOTH Cloud |
|---|---|---|
| Edge proxy, MCP / HTTP capture | ✅ | ✅ |
| Policy engine, budget, classification | ✅ | ✅ |
| Local SQLite store + `soth events stream` | ✅ | ✅ |
| Visual dashboard & live feeds | — | ✅ |
| Multi-node fleet management | — | ✅ |
| Managed policy / budget across teams | — | ✅ |

The proxy is fully functional standalone. SOTH Cloud is a managed backend + dashboard on
top — there's no UI to build or host yourself.

## Configuration

Copy `soth.example.yaml` to `~/.soth/soth.yaml` and edit. Key sections:

| Section | What it controls |
|---|---|
| `identity` | Per-agent crypto identity & trust store |
| `policy` | OPA Rego rules, enforcement mode, cache TTLs |
| `observe` | Local logging, PII redaction, retention |
| `budget` | Per-agent token & cost limits |
| `forward_proxy` | MITM listener, intercept domain list, CA paths |
| `cloud` | SOTH Cloud endpoints & enrollment credentials |

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
       ┌──────────────┐         ┌─────────────────────┐
       │ SQLite store │ ──────► │     SOTH Cloud      │
       │  (local)     │         │ dashboard · policy  │
       └──────────────┘         │ budget · fleet      │
                                └─────────────────────┘
```

Cloud sync is what powers the dashboard; the local SQLite store always works on its own,
so the proxy runs fully standalone if you skip enrollment.

Core crates:

- `soth-cli` — CLI surface and runtime lifecycle
- `soth-proxy` — MITM transport, gating, classification, exchange assembly
- `soth-policy` — policy engine (OPA Rego)
- `soth-classify` — 7-stage classification pipeline with optional ONNX models
- `soth-detect` — deterministic detection helpers
- `soth-telemetry` — local SQLite storage
- `soth-sync` — cloud enrollment and event sync
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
