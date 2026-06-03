# Changelog

All notable changes to Soth are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once a `1.0` release is cut. Until then, expect occasional breaking changes
on minor version bumps.

## [Unreleased]

### Added
- Mozilla Public License 2.0 file at repository root.
- `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md` for the
  public open-source release.
- GitHub issue and pull-request templates under `.github/`.

### Changed
- Repository moved to `github.com/soth-ai/soth` (was internal).
- `AGENTS.md` (AI-assistant operational guide) relocated to `docs/agents/`.

### Removed
- Internal `TODO.md` audit document and development screenshots from the
  repository root.

## [0.1.1] — 2026-05-22

### Fixed
- Internet Properties dialog no longer pops up on Windows startup when the
  proxy enables the system proxy.
- macOS swap port-release wait after `launchctl bootout` during self-update.
- Code-extension hooks (Cursor) and provider attribution.
- Doctor diagnostics for the code extension.

### Added
- Embedded default policy rule pack as a built-in fallback when no policy
  bundle is loaded.

## [0.1.0] — 2026-05-10

Initial public release on the `stable` channel.

### Added
- Edge MITM proxy with selective TLS interception for AI provider domains.
- `soth wrap` MCP stdio capture for Claude Desktop, Cursor, Windsurf.
- OPA Rego policy engine with L1/L2 caching.
- 7-stage classification pipeline with optional ONNX models.
- Local SQLite event store and dashboard (Next.js).
- `historian` extension for ingesting AI tool history (Claude Code, Gemini
  CLI, Codex, Cursor, OpenClaw via JSON playbooks).
- `code` extension for capturing coding-agent traffic.
- Self-update via signed manifests (stable / canary channels).
- Cross-platform binaries: macOS arm64/amd64, Linux arm64/amd64, Windows amd64.

[Unreleased]: https://github.com/soth-ai/soth/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/soth-ai/soth/releases/tag/v0.1.1
[0.1.0]: https://github.com/soth-ai/soth/releases/tag/v0.1.0
