# @soth/sdk-edge

SOTH SDK for edge runtimes — Cloudflare Workers, Vercel Edge,
Deno Deploy, Fastly Compute. WASM-backed.

## Status

**Phase 4 scaffold.** The shim's public API and the WASM build for
`soth-sdk-core` (`cargo build --target wasm32-unknown-unknown
--no-default-features`) both land in this commit. The wasm-bindgen
boundary that connects them is **the next PR's work** — today the
shim's `_invokeWasmStub` returns deterministic Allow decisions so
customers can wire the shim into their edge worker skeleton.

What this scaffold delivers:
- `npm install @soth/sdk-edge` resolves
- `init() / guard() / guardStream() / shutdown() / SothBlocked` API
  shape matches the native bindings
- `npm run build:wasm` builds the WASM artifact via cargo
- Tier matrix + reduced-mode capability docs live with the code

What this scaffold does **not** yet deliver:
- WASM function exports from `soth-sdk-core` (the
  `wasm_bindgen` annotations; PR following this one)
- Per-runtime loaders (Workers / Vercel / Deno / Fastly each have
  slightly different import paths for WASM modules)
- An end-to-end test that deploys to a real edge runtime and
  measures latency

## Tier matrix (locked by SDK_WASM_TRUST_BOUNDARY_SPEC.md §3)

| Runtime | Compressed budget | Mode | Notes |
|---|---|---|---|
| Cloudflare Workers (any plan) | 3–10 MB | **Reduced** | doesn't fit ONNX Web |
| Vercel Edge Functions | 1–4 MB | **Reduced** | tightest budget |
| Deno Deploy | ~10 MB script | Full WASM | monitor headroom |
| Fastly Compute | 100 MB | Full WASM | no constraint |

The shim defaults to **Reduced** mode so customers don't accidentally
ship a 25 MB worker. Full mode is opt-in per runtime via
`classificationMode: 'full'` (lands in the next PR).

## What Reduced mode delivers

- ✓ Sensitive-artifact redaction (regex-only)
- ✓ Counter-based anomaly flags (TokenBurst, CredentialBurst,
  ModelSwitch, RapidFireRequests, ToolCallDepthSpike)
- ✓ Artifact-based policy (block on credential, private_key)
- ✓ Session-level dedup
- ✓ Telemetry shipping (HTTPS POST to soth-cloud)
- ✗ Semantic clustering / `use_case_label`
- ✗ TopicDrift / AgentLoopPattern / UnusualSystemPromptChange anomalies

Telemetry events emitted in Reduced mode carry
`classification_mode: "reduced"` and a canonical `missing_fields`
list so cloud analytics filters cleanly rather than treating the
sentinel values as missing data.

## Cloudflare Workers usage

```typescript
import wasmModule from './soth_sdk_core.wasm'; // requires wasm-loader plugin
import { init, guard } from '@soth/sdk-edge';

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (!_inited) {
      await init({
        apiKey: env.SOTH_API_KEY,
        orgId: env.SOTH_ORG_ID,
        hmacKeyStatic: env.SOTH_HMAC_KEY,  // bound from secrets store
        telemetryEndpoint: 'https://api.soth.cloud/v1/edge/telemetry/batch',
        wasmModule,
      });
      _inited = true;
    }

    const response = await guard(
      () => fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { /* ... */ },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          messages: [{ role: 'user', content: 'hello' }],
        }),
      }),
      {
        call: {
          provider: 'openai',
          model: 'gpt-4o-mini',
          messages: [{ role: 'user', content: 'hello' }],
        },
      },
    );

    return new Response(await response.text());
  }
};
```

## Vercel Edge usage

```typescript
import wasmModule from './soth_sdk_core.wasm';
import { init, guard } from '@soth/sdk-edge';

export const config = { runtime: 'edge' };

await init({
  apiKey: process.env.SOTH_API_KEY!,
  orgId: process.env.SOTH_ORG_ID!,
  hmacKeyEnv: 'SOTH_HMAC_KEY',
  telemetryEndpoint: 'https://api.soth.cloud/v1/edge/telemetry/batch',
  wasmModule,
});

export default async function handler(req: Request) {
  const response = await guard(/* ... */);
  return new Response(await response.text());
}
```

## Building the WASM artifact

```sh
cd bindings/soth-edge
npm run build:wasm
# outputs wasm/soth_sdk_core.wasm
```

This invokes:
```
cargo build -p soth-sdk-core --target wasm32-unknown-unknown --release --no-default-features
```

The release binary is what production deploys; debug binaries
have ~5x the bundle size and won't fit Workers/Vercel.

## Why this can't just be `@soth/sdk` with a different feature flag

`@soth/sdk` (the napi-rs binding) ships native binaries per platform —
they won't load in V8 isolates, which is what edge runtimes use.
`@soth/sdk-edge` ships WASM, which V8 can load but native runtimes
shouldn't pay the WASM overhead for. Two packages, one source of
truth (`soth-sdk-core` in Rust).

## Phase 4 follow-ups

1. wasm-bindgen exports on `soth-sdk-core` (the `__soth_init`,
   `__soth_pre_call`, etc. functions called by `_invokeWasmStub`)
2. Per-runtime loader test suites (wrangler-based for CF Workers;
   Vercel deploy preview for Edge)
3. Bundle-size CI gate so the WASM stays under per-runtime limits
4. CDN signature verification path (Ed25519 — same as native
   bindings; reuse `soth-bundle::verify` compiled to WASM)
