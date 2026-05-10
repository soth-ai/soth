// @soth/sdk-edge — SOTH SDK for edge runtimes.
//
// **Status: Phase 4 scaffold.** The runtime API surface mirrors the
// native bindings (init / guard / guardStream / SothBlocked); the
// classification mode is locked to `Reduced` per the
// SDK_WASM_TRUST_BOUNDARY_SPEC.md tier matrix:
//
//   - Cloudflare Workers (any plan)  →  Reduced
//   - Vercel Edge Functions          →  Reduced
//   - Deno Deploy                    →  Full WASM (when bundle fits)
//   - Fastly Compute                 →  Full WASM (no bundle limit)
//
// In Reduced mode the SDK delivers:
//   ✓ sensitive-artifact redaction (regex-only, no model)
//   ✓ counter-based anomaly flags (5/8 of AnomalyFlag)
//   ✓ artifact-based policy (block on credential / private_key)
//   ✓ session-level dedup
//   ✓ telemetry shipping (HTTPS POST to soth-cloud)
//   ✗ semantic clustering / use_case_label (no ONNX in this build)
//   ✗ topic-drift / agent-loop / system-prompt-change anomalies
//
// **What this scaffold ships:** the JS shim + import path + tier-matrix
// docs. The actual WASM-runtime call boundary (Decision marshalling,
// telemetry queue serialization across the wasm-bindgen boundary) is
// **the next-PR's work**. See the section "What still needs to be wired"
// in README.md and the placeholder `_invokeWasm` calls below.

const PACKAGE_VERSION = '0.1.0-alpha.1';

class SothBlocked extends Error {
  constructor(decisionId, reason) {
    super(`SOTH policy blocked call: ${reason?.kind ?? 'unknown'}`);
    this.name = 'SothBlocked';
    this.decisionId = decisionId;
    this.reason = reason;
  }
}

let _wasmModule = null;
let _config = null;

/**
 * Load the WASM artifact and initialize the SDK.
 *
 * `wasmModule` is a `WebAssembly.Module` (or compiled instance) the
 * caller has loaded via the runtime's preferred mechanism:
 *
 *   - Cloudflare Workers: `import wasmModule from './soth_sdk_core.wasm';`
 *     (bundlers expose the WASM as a Module via a wasm-loader plugin)
 *   - Vercel Edge:        same import pattern works
 *   - Deno:               `await WebAssembly.compileStreaming(fetch(...))`
 *   - Fastly Compute:     `compute-js` provides the binary at runtime
 *
 * The shim does not bundle the WASM itself — that's left to the
 * customer's deploy pipeline so the artifact source + signing path
 * is auditable.
 *
 * @param {Object} options
 * @param {string} options.apiKey
 * @param {string} options.orgId
 * @param {string} [options.hmacKeyEnv]
 * @param {Uint8Array} [options.hmacKeyStatic]
 * @param {string} [options.telemetryEndpoint]
 * @param {WebAssembly.Module|WebAssembly.Instance} options.wasmModule
 */
async function init({
  apiKey,
  orgId,
  hmacKeyEnv,
  hmacKeyStatic,
  telemetryEndpoint,
  wasmModule,
}) {
  if (!apiKey) throw new Error('init: apiKey required');
  if (!orgId) throw new Error('init: orgId required');
  if (!wasmModule) {
    throw new Error('init: wasmModule required (load soth-sdk-core.wasm via your runtime\'s wasm import)');
  }

  // Resolve HMAC key. Edge runtimes don't expose process.env directly
  // (Workers uses `env`, Vercel uses `process.env`, Deno uses
  // `Deno.env.get`); customers SHOULD pass `hmacKeyStatic` populated
  // from their runtime's secret-manager binding.
  let hmacBytes;
  if (hmacKeyStatic) {
    hmacBytes = hmacKeyStatic;
  } else if (hmacKeyEnv && typeof process !== 'undefined' && process.env) {
    const raw = process.env[hmacKeyEnv];
    if (!raw) throw new Error(`init: ${hmacKeyEnv} not set in environment`);
    hmacBytes = new TextEncoder().encode(raw);
  } else {
    throw new Error('init: hmacKeyStatic or hmacKeyEnv (with process.env support) required');
  }
  if (hmacBytes.byteLength < 32) {
    throw new Error(`init: HMAC key too short (got ${hmacBytes.byteLength} bytes, need >=32)`);
  }

  _wasmModule = wasmModule;
  _config = {
    apiKey,
    orgId,
    hmacBytes,
    telemetryEndpoint,
    classificationMode: 'reduced',
  };

  // Phase-4 follow-up: instantiate the WASM module with the runtime's
  // imports and call `__soth_init` exported by soth-sdk-core. The
  // wasm-bindgen plumbing for that lives in the next PR.
  await _invokeWasmStub('__soth_init', {
    apiKey,
    orgId,
    classificationMode: 'reduced',
  });
}

/**
 * Wrap an LLM call with SOTH's pre/post lifecycle.
 * Same semantics as @soth/sdk's `guard`.
 */
async function guard(callFn, { call }) {
  if (!_wasmModule) throw new Error('soth-edge: init() must be called first');

  const decision = await _invokeWasmStub('__soth_pre_call', { call });
  if (decision.kind === 'block') {
    await _invokeWasmStub('__soth_post_call', { token: decision.token });
    throw new SothBlocked(decision.token, decision.reason);
  }

  let result;
  try {
    result = await callFn();
  } finally {
    await _invokeWasmStub('__soth_post_call', { token: decision.token });
  }
  return result;
}

async function* guardStream(iterFactory, { call, chunkExtractor }) {
  if (!_wasmModule) throw new Error('soth-edge: init() must be called first');

  const decision = await _invokeWasmStub('__soth_stream_begin', { call });
  if (decision.kind === 'block') {
    await _invokeWasmStub('__soth_stream_end', { token: decision.token });
    throw new SothBlocked(decision.token, decision.reason);
  }

  let sequence = 0;
  const extractor = chunkExtractor ?? defaultOpenAIChunkExtractor;
  try {
    let provIter = iterFactory();
    if (provIter && typeof provIter.then === 'function') provIter = await provIter;
    for await (const chunk of provIter) {
      const { deltaContent, finishReason } = extractor(chunk);
      await _invokeWasmStub('__soth_stream_chunk', {
        token: decision.token,
        sequence,
        deltaContent: deltaContent ?? null,
        finishReason: finishReason ?? null,
      });
      sequence += 1;
      yield chunk;
    }
  } finally {
    await _invokeWasmStub('__soth_stream_end', { token: decision.token });
  }
}

function defaultOpenAIChunkExtractor(chunk) {
  try {
    const choice = chunk?.choices?.[0];
    return {
      deltaContent: choice?.delta?.content ?? null,
      finishReason: choice?.finish_reason ?? null,
    };
  } catch (_) {
    return { deltaContent: null, finishReason: null };
  }
}

async function shutdown() {
  if (!_wasmModule) return;
  await _invokeWasmStub('__soth_shutdown', {});
  _wasmModule = null;
  _config = null;
}

/**
 * Phase-4 placeholder. The real implementation calls wasm-bindgen-
 * exported functions on `_wasmModule`. Until that lands, the stub
 * returns a deterministic Allow decision so customers can wire the
 * shim into their app skeleton and exercise the runtime path.
 *
 * The stub MUST emit the same telemetry event shape the production
 * impl will, so customers' downstream consumers (dashboard, logs)
 * see consistent data when the real WASM path arrives.
 */
async function _invokeWasmStub(funcName, payload) {
  if (funcName === '__soth_pre_call' || funcName === '__soth_stream_begin') {
    return {
      kind: 'allow',
      token: `stub-${funcName}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    };
  }
  // post_call / stream_chunk / stream_end / shutdown are no-ops.
  return null;
}

module.exports = {
  init,
  guard,
  guardStream,
  shutdown,
  SothBlocked,
  // Surfaced for documentation; consumers don't need to set this manually.
  PACKAGE_VERSION,
};
