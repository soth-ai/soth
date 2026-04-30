// Auto-instrumentation for provider SDKs.
//
// Public entry points (re-exported from the top-level `index.js`):
//     soth.instrument({ providers })
//     soth.uninstrument({ providers })
//     soth.isInstrumented(provider)
//
// Robustness contract — same as the Python adapter
// (`python/soth/instrumentation/__init__.py`):
//
//   1. Idempotent. Calling instrument() twice returns the same state
//      without re-wrapping. Subsequent calls return "skipped:already-…".
//   2. Reversible. uninstrument() restores the originals captured at
//      apply time; if another tool wrapped over us, we leave that
//      wrapper in place and log.
//   3. Provider-conditional. Missing packages don't throw — the entry
//      returns "skipped:not-installed".
//   4. Fail open. Extractor exceptions fall back to the original SDK
//      call uninstrumented; SOTH never breaks the customer's API call.
//   5. Sync + async aware. Provider methods that return Promises are
//      handled the same way as those that return values directly,
//      because the JS guard()/guardStream() helpers already detect.

const openai = require('./openai.js');

const REGISTRY = Object.freeze({
  openai,
});

const _state = Object.fromEntries(Object.keys(REGISTRY).map((k) => [k, false]));

function _selectedProviders(requested) {
  if (!requested) return new Set(Object.keys(REGISTRY));
  if (Array.isArray(requested)) return new Set(requested);
  return new Set(Object.keys(REGISTRY)); // unknown shape → instrument all
}

function instrument({ providers } = {}) {
  const selected = _selectedProviders(providers);
  const results = {};

  for (const [name, adapter] of Object.entries(REGISTRY)) {
    if (!selected.has(name)) {
      results[name] = 'skipped:disabled';
      continue;
    }
    if (_state[name]) {
      results[name] = 'skipped:already-instrumented';
      continue;
    }

    let applied;
    try {
      applied = adapter.apply();
    } catch (e) {
      console.warn(`soth.instrument(${name}) failed:`, e?.message ?? e);
      results[name] = `error:${e?.constructor?.name ?? 'Error'}`;
      continue;
    }

    if (applied) {
      _state[name] = true;
      results[name] = 'instrumented';
    } else {
      results[name] = 'skipped:not-installed';
    }
  }

  return results;
}

function uninstrument({ providers } = {}) {
  const selected = _selectedProviders(providers);
  const results = {};

  for (const [name, adapter] of Object.entries(REGISTRY)) {
    if (!selected.has(name)) {
      results[name] = 'skipped:disabled';
      continue;
    }
    if (!_state[name]) {
      results[name] = 'skipped:not-instrumented';
      continue;
    }

    try {
      adapter.revert();
    } catch (e) {
      console.warn(`soth.uninstrument(${name}) failed:`, e?.message ?? e);
      results[name] = `error:${e?.constructor?.name ?? 'Error'}`;
      continue;
    }

    _state[name] = false;
    results[name] = 'uninstrumented';
  }

  return results;
}

function isInstrumented(provider) {
  return _state[provider] === true;
}

module.exports = {
  instrument,
  uninstrument,
  isInstrumented,
};
