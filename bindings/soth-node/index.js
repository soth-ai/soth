// soth-node — JS shim layered on top of the napi-rs extension.
//
// The native extension exposes a low-level `SothSdk` class that returns
// typed `JsDecision` objects. This shim:
//   1. Exposes `init`, `guard`, `withContext` as the user-facing API
//   2. Translates `Decision::Block` into a thrown `SothBlocked`
//      (extends `Error`, NOT `OpenAI.APIError` / etc.)
//   3. Surfaces `Decision::Flag` via the `console.warn` channel and
//      a `SothFlagged` instance attached to the result for inspection
//
// Decision API contract: `docs/common/SDK_DECISION_API_SPEC.md` §6.3.
// The exception inheritance MUST stay flat — `SothBlocked extends Error`.
// If anyone changes that, `__test__/blocked-propagates.test.mjs` fails.

const native = require('./soth-node.darwin-arm64.node'); /* eslint-disable-line global-require */
// Real builds ship per-arch binaries via @napi-rs/cli; the line above
// is a placeholder for local dev. Production loader logic lands in a
// follow-up commit.

class SothBlocked extends Error {
  constructor(decisionId, reason) {
    super(`SOTH policy blocked call: ${reason?.kind ?? 'unknown'}`);
    this.name = 'SothBlocked';
    this.decisionId = decisionId;
    this.reason = reason;
  }
}

class SothFlagged {
  constructor(severity) {
    this.severity = severity;
  }
}

let _singleton = null;

function init({ apiKey, orgId, hmacKeyEnv, hmacKeyStatic, telemetryEndpoint }) {
  if (!apiKey) throw new Error('init: apiKey required');
  if (!orgId) throw new Error('init: orgId required');
  _singleton = native.SothSdk.create(
    apiKey,
    orgId,
    hmacKeyEnv ?? null,
    hmacKeyStatic ?? null,
    telemetryEndpoint ?? null,
  );
}

/**
 * Stop the background telemetry shipper and flush pending events.
 * Customers SHOULD call this at process exit (e.g. on SIGINT / SIGTERM)
 * so the last batch window's events aren't lost. Idempotent.
 */
function shutdown() {
  if (_singleton) {
    _singleton.shutdown();
  }
}

function getSdk() {
  if (!_singleton) {
    throw new Error('soth.init({...}) must be called before any guard() / SDK call');
  }
  return _singleton;
}

async function guard(callFn, { call }) {
  const sdk = getSdk();
  const decision = sdk.preCall(call);
  const { kind, token } = decision;

  if (kind === 'block') {
    sdk.postCall(token, null);
    throw new SothBlocked(token, decision.reason);
  }

  // Allow / Flag / Redact (Redact treated as Allow for v0; Phase-1
  // wires actual message rewriting via per-provider adapters).
  let result;
  try {
    result = await callFn();
  } finally {
    sdk.postCall(token, null);
  }

  if (kind === 'flag') {
    console.warn(`soth flagged call: severity=${decision.severity}`);
  }

  return result;
}

// Default chunk extractor for OpenAI-shaped chat-completion streams.
// Returns `{ deltaContent, finishReason }` extracted from the chunk's
// `choices[0]` entry. Customers using non-OpenAI shapes pass their own
// extractor to `guardStream`.
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

/**
 * Wrap a streaming LLM call with SOTH's pre/post lifecycle.
 *
 * `iterFactory` returns the provider's async iterable (e.g. the result
 * of `client.chat.completions.create({stream: true, ...})`). The
 * `chunkExtractor` (defaults to OpenAI shape) pulls
 * `{deltaContent, finishReason}` from each chunk; the SDK records
 * those alongside chunk count.
 *
 * Yields each chunk back to the caller. Throws `SothBlocked` if the
 * decision is `Block`. Always finalizes the stream observation on
 * normal completion or thrown exception.
 */
async function* guardStream(iterFactory, { call, chunkExtractor } = {}) {
  if (!call) throw new Error('guardStream: call required');
  const extractor = chunkExtractor ?? defaultOpenAIChunkExtractor;
  const sdk = getSdk();
  const decision = sdk.streamBegin(call);
  const { kind, token } = decision;

  if (kind === 'block') {
    sdk.streamEnd(token);
    throw new SothBlocked(token, decision.reason);
  }

  let sequence = 0;
  try {
    let provIter = iterFactory();
    if (provIter && typeof provIter.then === 'function') {
      provIter = await provIter;
    }
    for await (const chunk of provIter) {
      const { deltaContent, finishReason } = extractor(chunk);
      sdk.streamChunk(token, sequence, deltaContent ?? null, finishReason ?? null);
      sequence += 1;
      yield chunk;
    }
  } finally {
    sdk.streamEnd(token);
  }
}

module.exports = {
  init,
  shutdown,
  guard,
  guardStream,
  getSdk,
  SothBlocked,
  SothFlagged,
};
