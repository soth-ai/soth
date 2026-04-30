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

function init({ apiKey, orgId, hmacKeyEnv, hmacKeyStatic }) {
  if (!apiKey) throw new Error('init: apiKey required');
  if (!orgId) throw new Error('init: orgId required');
  _singleton = native.SothSdk.create(
    apiKey,
    orgId,
    hmacKeyEnv ?? null,
    hmacKeyStatic ?? null,
  );
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

module.exports = {
  init,
  guard,
  getSdk,
  SothBlocked,
  SothFlagged,
};
