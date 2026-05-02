// Negative tests for the SothBlocked propagation contract.
//
// SDK_DECISION_API_SPEC.md §6.3 commits that SothBlocked extends Error
// (not any provider exception class) and propagates past existing
// `try { ... } catch (e) { if (e instanceof OpenAI.APIError) ... }` blocks.
// Customers' retry logic catches OpenAI.APIError to retry on rate
// limits / 5xx; a policy block must NOT be silently retried.
//
// If any future change makes SothBlocked extend OpenAI.APIError or any
// provider's class, these tests fail immediately.
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

let openai;
try {
  openai = await import('openai');
} catch (_) {
  console.warn('skipping propagation tests — openai package not installed');
}

soth.init({
  apiKey: 'sk-test',
  orgId: 'org-test',
  hmacKeyEnv: 'SOTH_HMAC_KEY',
});

async function makeBlockingCall() {
  return soth.guard(
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
  );
}

test('SothBlocked does not extend openai.APIError', { skip: !openai }, () => {
  // Static check on the prototype chain. If SothBlocked were to extend
  // OpenAI.APIError, this would be true and the spec is violated.
  const blocked = new soth.SothBlocked('0', { kind: 'test' });
  assert.equal(
    blocked instanceof openai.OpenAI.APIError,
    false,
    'SothBlocked must NOT inherit from OpenAI.APIError. See SDK_DECISION_API_SPEC.md §6.3.',
  );
});

test(
  'SothBlocked propagates past try { ... } catch (OpenAI.APIError) handlers',
  { skip: !openai },
  async () => {
    let caughtAPIError = false;
    let caughtSoth = false;

    try {
      try {
        await makeBlockingCall();
      } catch (e) {
        if (e instanceof openai.OpenAI.APIError) {
          caughtAPIError = true;
        } else {
          throw e;
        }
      }
    } catch (e) {
      if (e instanceof soth.SothBlocked) {
        caughtSoth = true;
      } else {
        throw e;
      }
    }

    assert.equal(caughtAPIError, false, 'SothBlocked was caught by OpenAI.APIError — spec violation');
    assert.equal(caughtSoth, true, 'SothBlocked must propagate past OpenAI.APIError');
  },
);

test('SothBlocked extends Error directly', () => {
  const blocked = new soth.SothBlocked('0', { kind: 'test' });
  assert.ok(blocked instanceof Error, 'SothBlocked must extend Error');
  assert.equal(blocked.name, 'SothBlocked');
});
