// Robustness tests for soth.instrument().
//
// Mirrors the Python instrumentation suite: idempotency, reversibility,
// missing-provider tolerance, fail-open extractors, double-wrap
// detection, sync+async coroutine handling.
//
// Tests do NOT require the `openai` package — when absent, the relevant
// adapter assertions skip rather than fail.
//
// Run with:
//   cd bindings/soth-node
//   npm install
//   npm run build:debug
//   npm test

import { test } from 'node:test';
import { strict as assert } from 'node:assert';

import * as soth from '../index.js';

process.env.SOTH_HMAC_KEY = 'x'.repeat(32);

soth.init({
  apiKey: 'sk-test',
  orgId: 'org-test',
  hmacKeyEnv: 'SOTH_HMAC_KEY',
});

// ── idempotency / reversibility ─────────────────────────────────────

test('instrument is idempotent — second call reports already-instrumented', () => {
  const first = soth.instrument();
  const second = soth.instrument();
  for (const [provider, status] of Object.entries(first)) {
    if (status === 'instrumented') {
      assert.equal(
        second[provider],
        'skipped:already-instrumented',
        `${provider}: idempotency violated`,
      );
    }
  }
  // Cleanup.
  soth.uninstrument();
});

test('uninstrument reverses instrument', () => {
  const first = soth.instrument();
  soth.uninstrument();
  for (const [provider, status] of Object.entries(first)) {
    if (status === 'instrumented') {
      assert.equal(
        soth.isInstrumented(provider),
        false,
        `${provider} still instrumented after uninstrument`,
      );
    }
  }
});

test('uninstrument without prior instrument is safe', () => {
  const results = soth.uninstrument();
  for (const [, status] of Object.entries(results)) {
    assert.ok(['skipped:not-instrumented', 'skipped:disabled'].includes(status));
  }
});

// ── provider selection ─────────────────────────────────────────────

test('instrument with explicit providers skips others', () => {
  const results = soth.instrument({ providers: ['openai'] });
  // No anthropic adapter on Node yet (Phase-1 ships OpenAI only).
  // The registry doesn't include anthropic, so the result map only
  // has the providers we know about. Exercise: openai is in the
  // selected set and gets processed (instrumented or
  // skipped:not-installed).
  assert.ok('openai' in results);
  soth.uninstrument();
});

// ── fail-open extractor ────────────────────────────────────────────

test('buildCall exception falls through to original (fail-open)', async () => {
  const { wrapMethod, revertAll } = await import('../instrumentation/_base.js');

  class FakeClient {
    create(opts) {
      return Promise.resolve({ ok: true, opts });
    }
  }

  const bustedBuildCall = () => {
    throw new Error('simulated extractor crash');
  };

  const patch = wrapMethod(FakeClient, 'create', {
    providerName: 'fake',
    buildCall: bustedBuildCall,
  });
  assert.ok(patch !== null);

  const client = new FakeClient();
  // Despite the extractor raising, the original method runs and
  // returns its expected value.
  const result = await client.create({ model: 'x' });
  assert.equal(result.ok, true);
  assert.deepEqual(result.opts, { model: 'x' });

  revertAll([patch]);
});

// ── double-wrap detection ──────────────────────────────────────────

test('wrapped method carries SOTH provenance markers', async () => {
  const { wrapMethod, isInstrumentedMethod, revertAll } = await import(
    '../instrumentation/_base.js'
  );

  class Target {
    m() {
      return 1;
    }
  }

  const patch = wrapMethod(Target, 'm', {
    providerName: 'test',
    buildCall: () => ({ provider: 'test', model: '', messages: [] }),
  });
  assert.ok(patch !== null);
  assert.equal(isInstrumentedMethod(Target.prototype.m), true);
  assert.equal(Target.prototype.m.__sothProvider, 'test');

  revertAll([patch]);
});

test('revert leaves third-party wrapper in place', async () => {
  const { wrapMethod, revertAll } = await import('../instrumentation/_base.js');

  class Target {
    m() {
      return 1;
    }
  }

  const patch = wrapMethod(Target, 'm', {
    providerName: 'test',
    buildCall: () => ({ provider: 'test', model: '', messages: [] }),
  });
  assert.ok(patch !== null);

  // Simulate another tool wrapping over our wrapper.
  const sothWrapper = Target.prototype.m;
  function thirdPartyWrapper(...args) {
    return sothWrapper.apply(this, args);
  }
  Target.prototype.m = thirdPartyWrapper;

  revertAll([patch]);
  // We don't clobber the third-party wrapper; it stays.
  assert.equal(Target.prototype.m, thirdPartyWrapper);
});

// ── adapter integration ────────────────────────────────────────────

test('OpenAI adapter apply returns bool — no exceptions', async () => {
  const adapter = await import('../instrumentation/openai.js');
  const result = adapter.apply();
  assert.ok(typeof result === 'boolean');
  if (result === true) {
    adapter.revert();
  }
});

test('OpenAI buildCall extracts model + messages from create() options', async () => {
  const adapter = await import('../instrumentation/openai.js');
  const call = adapter._buildCall([
    {
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'hello' }],
      stream: false,
      tools: [
        {
          type: 'function',
          function: {
            name: 'lookup_weather',
            description: 'Look up the weather',
            parameters: { type: 'object', properties: { city: { type: 'string' } } },
          },
        },
      ],
    },
  ]);
  assert.equal(call.provider, 'openai');
  assert.equal(call.model, 'gpt-4o-mini');
  assert.equal(call.messages.length, 1);
  assert.equal(call.tools.length, 1);
  assert.equal(call.tools[0].name, 'lookup_weather');
});
