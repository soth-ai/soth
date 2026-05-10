// Streaming round-trip tests for @soth/sdk. Mirrors the streaming
// integration test in `crates/soth-sdk-core/tests/round_trip.rs`.
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

async function* fakeOpenAIStream(deltas) {
  for (let i = 0; i < deltas.length; i += 1) {
    const finishReason = i === deltas.length - 1 ? 'stop' : null;
    yield {
      choices: [
        {
          delta: { content: deltas[i] },
          finish_reason: finishReason,
        },
      ],
    };
    // Yield to the event loop so this looks like a real network stream.
    await new Promise((r) => setImmediate(r));
  }
}

test('stream round trip consumes token once', async () => {
  const received = [];
  for await (const chunk of soth.guardStream(
    () => fakeOpenAIStream(['hello ', 'world', '!']),
    {
      call: {
        provider: 'openai',
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: 'say hi' }],
        stream: true,
      },
    },
  )) {
    received.push(chunk);
  }
  assert.equal(received.length, 3);
  const sdk = soth.getSdk();
  assert.equal(sdk.inFlightDecisions(), 0);
  const events = sdk.drainTelemetryForTest();
  assert.equal(events.length, 1);
  assert.equal(events[0].provider, 'openai');
});

test('stream blocks on credential in user message', async () => {
  await assert.rejects(
    () => (async () => {
      for await (const _ of soth.guardStream(
        () => fakeOpenAIStream(['should ', 'not ', 'stream']),
        {
          call: {
            provider: 'openai',
            model: 'gpt-4o-mini',
            messages: [
              {
                role: 'user',
                content: 'leaked sk-abcdefghijklmnopqrstuvwxyzABCD1234567890 here',
              },
            ],
            stream: true,
          },
        },
      )) {
        // unreachable — Block raises before iteration
      }
    })(),
    (err) => {
      assert.ok(err instanceof soth.SothBlocked);
      assert.equal(err.reason.kind, 'sensitive_artifact');
      return true;
    },
  );
  const sdk = soth.getSdk();
  assert.equal(sdk.inFlightDecisions(), 0);
});

test('stream end is idempotent (double-end safe)', async () => {
  const sdk = soth.getSdk();
  const decision = sdk.streamBegin({
    provider: 'openai',
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: 'hi' }],
    stream: true,
  });
  assert.equal(decision.kind, 'allow');
  sdk.streamChunk(decision.token, 0, 'a', null);
  sdk.streamChunk(decision.token, 1, 'b', 'stop');
  sdk.streamEnd(decision.token);
  // Second end is documented no-op (no exception).
  sdk.streamEnd(decision.token);
  assert.equal(sdk.inFlightDecisions(), 0);
});
