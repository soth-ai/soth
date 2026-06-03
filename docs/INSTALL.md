# SOTH Install Paths — Canonical Reference

This is the authoritative spec for **where the `soth` binary lives** on each
supported platform. The self-update code (`crates/soth-cli/src/update/swap_*.rs`)
relies on these paths being stable. Treat changes here as breaking.

## Quick start

```bash
# macOS / Linux
curl -fsSL https://soth.ai/install.sh | bash

# Windows (PowerShell 7.5+)
iwr -useb https://soth.ai/install.ps1 | iex
```

Channel, version, and install-dir overrides:

```bash
# Bash
SOTH_CHANNEL=canary curl -fsSL https://soth.ai/install.sh | bash
SOTH_VERSION=0.1.0 curl -fsSL https://soth.ai/install.sh | bash
curl -fsSL https://soth.ai/install.sh | bash -s -- --install-dir /opt/soth/bin
curl -fsSL https://soth.ai/install.sh | bash -s -- --version 0.1.0

# PowerShell
$env:SOTH_CHANNEL = 'canary'; iwr -useb https://soth.ai/install.ps1 | iex
$env:SOTH_VERSION = '0.1.0'; iwr -useb https://soth.ai/install.ps1 | iex
```

Both scripts:
1. Fetch the manifest over HTTPS (channel-current pointer by default, frozen
   per-version snapshot when `--version` / `SOTH_VERSION` is set),
2. Verify the ed25519 signature against a public key embedded in the script,
3. Download the platform binary (and the soth-update.exe sidecar on Windows)
   from the per-version path the manifest points at,
4. Verify each artifact's sha256 against the manifest before installing,
5. Atomically swap into place, preserving the previous binary at `<install>.previous`.

## Storage layout (since 0.1.0 GA)

```
storage.soth.ai/release/
├── v0.1.0/                            # Per-version, frozen, immutable.
│   ├── soth-darwin-arm64              # Cache-Control: public, max-age=31536000, immutable
│   ├── soth-darwin-arm64.sha256
│   ├── soth-darwin-amd64{,.sha256}
│   ├── soth-linux-amd64{,.sha256}
│   ├── soth-linux-arm64{,.sha256}
│   ├── soth-windows-amd64.exe{,.sha256}
│   └── soth-update-windows-amd64.exe{,.sha256}
├── v0.1.1/ …                          # Each new release goes in its own prefix
├── v0.2.0/ …
└── manifest/
    ├── stable.json                    # Channel-current pointer (mutable, no-cache)
    ├── stable.json.sig
    ├── stable.v0.1.0.json              # Frozen per-version snapshot (immutable)
    ├── stable.v0.1.0.json.sig
    └── canary.json{,.sig} + per-version

# storage.staging.soth.xyz hosts the same shape (stable + canary
# manifests + per-version dirs) for internal release-candidate testing.
# Environment and channel are orthogonal — staging.soth.xyz is "where",
# stable/canary is "what trust tier."
```

**The manifest is the only routing layer.** Old (unversioned)
`storage.soth.ai/release/soth-darwin-arm64` URLs return 404 — they were
removed in the 0.1.0 GA cut. Consumers that hard-code the binary URL
must update to fetch through the channel manifest.

**`release_seq`** is monotonic per channel. Anti-rollback ships by default;
`--force-downgrade` or `--version <X>` are the explicit opt-outs.

## Why this exists

`soth update --apply` performs an atomic in-place binary swap. The swap
logic needs to know — without ambiguity — **the path of the running binary**
and **the path of the launchd/systemd unit that will restart it**. Letting
each install method choose its own path makes the update story untestable.

## Canonical paths

| Platform | User install (default) | Root install (optional) |
|----------|------------------------|-------------------------|
| **macOS** | `~/.local/bin/soth` | `/usr/local/bin/soth` |
| **Linux** | `~/.local/bin/soth` | `/usr/local/bin/soth` |
| **Windows** | `%LOCALAPPDATA%\soth\soth.exe` | `%PROGRAMFILES%\soth\soth.exe` |

The update flow always writes the new binary to a staging path first, then
swaps. Staging paths:

| Platform | Staging |
|----------|---------|
| macOS / Linux | `~/.soth/run/soth.new` |
| Windows | `%LOCALAPPDATA%\soth\soth.exe.new` |

After a successful swap, the previous binary is preserved at:

| Platform | Previous |
|----------|----------|
| macOS / Linux | `<install_path>.previous` (same dir as install) |
| Windows | `<install_path>.previous.exe` |

## Service / launch unit paths

| Platform | Method | Unit |
|----------|--------|------|
| macOS | launchd (user) | `~/Library/LaunchAgents/ai.soth.proxy.plist` |
| macOS | launchd (system) | `/Library/LaunchDaemons/ai.soth.proxy.plist` |
| Linux | systemd (user) | `~/.config/systemd/user/soth-proxy.service` |
| Linux | systemd (system) | `/etc/systemd/system/soth-proxy.service` |
| Linux | no systemd | pid file `~/.soth/run/proxy.pid` |
| Windows | Service Control Manager | service name `soth` |

## Windows sidecar updater (Phase 4b, 0.2.0+)

Windows holds an exclusive lock on the running `.exe`, so in-place
self-update needs a tiny helper binary that owns the lock-release-and-
replace sequence:

| Path | Purpose |
|------|---------|
| `%LOCALAPPDATA%\soth\soth.exe`         | main binary (gets replaced on update) |
| `%LOCALAPPDATA%\soth\soth-update.exe`  | sidecar updater (rarely changes) |

The sidecar is published as `soth-update-windows-amd64.exe` at the same
release URL as the main binaries. Install scripts download it once
during initial setup; subsequent `soth update --apply` calls reuse the
local copy and do NOT re-download per update.

When the sidecar is missing (pre-0.2.0 install or hand-deployed
binary), `soth update --apply` returns a clean error pointing at the
download URL — never attempts a doomed in-place rename.

## Detecting which install you have

The update flow detects in this order:

1. `which soth` — if it resolves to one of the canonical paths above, use it.
2. Else try `~/.local/bin/soth` (most likely user install).
3. Else try `/usr/local/bin/soth` (root install).
4. Else error: "soth is not installed at a canonical location; manual update required."

## Why not `/opt/soth/`, Homebrew, or apt?

We may add packaged distributions later. Until then:

- **Homebrew formula**: `brew` writes to `/opt/homebrew/bin/soth` (Apple Silicon)
  or `/usr/local/bin/soth` (Intel). The update flow refuses to swap a
  Homebrew-managed binary and prints `brew upgrade soth` instead — Homebrew
  owns that file, we don't.
- **`/opt/soth/`**: not used. Adds a layer with no benefit for a single binary.
- **apt / rpm / msi packages**: when these ship, they will defer to the
  package manager's update path. The update flow detects `dpkg-query`,
  `rpm`, or MSI install metadata and refuses to swap.

## Files SOTH manages under `~/.soth/`

These are NOT install paths but are referenced throughout the update flow:

```
~/.soth/
├── config.yaml          (user config — not touched by updates)
├── historian.db         (extension data — preserved across updates)
├── keys/release/        (operator-only; signing privates if this is a release host)
├── logs/events.jsonl    (preserved)
├── run/
│   ├── proxy.pid                  (Linux non-systemd only)
│   ├── soth.new                   (staging during update)
│   ├── update_pending.json        (Phase 2+ heartbeat-delivered offer)
│   └── update_cache.json          (Phase 1 last-check result)
└── tls/                 (CA + intermediates — preserved)
```

## Versioning contract

`soth --version` reports `env!("CARGO_PKG_VERSION")` which is sourced from
the workspace `Cargo.toml::workspace.package.version`. This must always
match the version published to the manifest. CI verifies this at release
time (`make release-cli` reads the version, builds, publishes a manifest
with that exact string).

## Related docs

- Architecture: [`docs/common/2026-05-09/hot-update-plan.md`](common/2026-05-09/hot-update-plan.md) (parent plan)
- Phase-by-phase implementation: `../../docs/common/2026-05-11/hot-update-0.1.1-impl-plan.md` (workspace-level)
- Signing keys: [`ops/keys/README.md`](../ops/keys/README.md)
