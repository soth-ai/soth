# @soth/sdk (soth-node)

Node.js binding for the SOTH SDK. Built with napi-rs; published to npm
as `@soth/sdk` with prebuilt binaries per platform/arch.

## Status

**Phase 1 scaffold.** The Rust extension exposes the `SothSdk` facade
through napi-rs; the JS shim in `index.js` wraps it with the `guard()`
helper, the `SothBlocked` exception class, and the contract negative
tests in `__test__/blocked-propagates.test.mjs`.

What v0 ships:
- `soth.init({ apiKey, orgId, hmacKeyEnv })` — module-level singleton
- `soth.guard(asyncFn, { call })` — wraps an LLM call with `pre_call` / `post_call`
- `soth.SothBlocked` — class extending `Error` (NOT `OpenAI.APIError`)
- `soth.SothFlagged` — surface for `Decision::Flag`

What's deferred to follow-up Phase 1 commits:
- Auto-instrumentation for `openai`, `@anthropic-ai/sdk`, `cohere-ai`,
  `@google/generative-ai`, `mistralai`
- undici dispatcher (`soth.fetch`)
- `soth.withContext({ userId, teamId }, async () => ...)` per-call overrides
- Streaming wrapper for `AsyncIterable`
- Per-arch binary loader (today: hardcoded for `darwin-arm64` for local
  smoke; production loader lands with the wheel matrix work)

## Building

```sh
cd bindings/soth-node
npm install
npm run build:debug   # local dev — produces soth-node.<arch>.node
```

The Rust extension is part of the workspace, so `cargo build -p soth-node`
also works for compile-checking. Note: `cargo build -p soth-node` requires
Node and the napi build tooling (`napi-build` build dep); CI installs
these automatically.

## Tests

```sh
npm install
npm run build:debug
npm test
```

The `__test__/blocked-propagates.test.mjs` suite is the contract gate:
`SothBlocked` MUST NOT be `instanceof OpenAI.APIError`. If that test
fails, the inheritance has drifted from the spec and bindings cannot
ship.

## Binary matrix (Phase-1 deliverable)

| Platform | Architecture |
|---|---|
| linux-x64 (gnu, musl) | x86_64 |
| linux-arm64 (gnu, musl) | aarch64 |
| darwin-arm64 | aarch64 |
| darwin-x64 | x86_64 |
| win32-x64-msvc | x86_64 |

Built via `@napi-rs/cli` in CI; postinstall picks the right binary for
the host platform.

Node 18+ required.

## Public API contract

Locked by:
- `docs/common/SDK_DECISION_API_SPEC.md` — Decision lifecycle, exception contract
- `docs/common/SDK_WASM_TRUST_BOUNDARY_SPEC.md` — bundle / classification mode

Read those before changing any public symbol in `index.js` / `index.d.ts`
or the napi-rs wrapper. `@soth/sdk` ships in customer dependencies and
breaking changes propagate downstream.
