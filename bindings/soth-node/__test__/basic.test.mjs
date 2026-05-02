// Smoke test for @soth/sdk. Mirrors the round-trip tests in
// `crates/soth-sdk-core/tests/round_trip.rs`.
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

test('pre/post round trip emits telemetry and balances slab', async () => {
  let called = false;
  const result = await soth.guard(
    async () => {
      called = true;
      return 'ok';
    },
    {
      call: {
        provider: 'openai',
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: 'hello' }],
      },
    },
  );
  assert.equal(result, 'ok');
  assert.ok(called);
  const sdk = soth.getSdk();
  assert.equal(sdk.inFlightDecisions(), 0);
  const events = sdk.drainTelemetryForTest();
  assert.equal(events.length, 1);
  assert.equal(events[0].provider, 'openai');
});

test('credential in user message blocks', async () => {
  await assert.rejects(
    () => soth.guard(
      async () => 'should not be called',
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
        },
      },
    ),
    (err) => {
      assert.ok(err instanceof soth.SothBlocked);
      assert.equal(err.reason.kind, 'sensitive_artifact');
      return true;
    },
  );
  const sdk = soth.getSdk();
  assert.equal(sdk.inFlightDecisions(), 0);
});
