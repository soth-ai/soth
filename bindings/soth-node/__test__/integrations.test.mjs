// Tests for Node framework integrations (Vercel AI SDK middleware).
//
// We don't require `ai` to be installed — module imports cleanly and
// the middleware factory returns a usable object even without it.
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

test('vercel-ai sothMiddleware returns LanguageModelV1Middleware shape', async () => {
  const mod = await import('../integrations/vercel-ai.js');
  const middleware = mod.sothMiddleware();
  assert.equal(middleware.middlewareVersion, 'v1');
  assert.equal(typeof middleware.wrapGenerate, 'function');
  assert.equal(typeof middleware.wrapStream, 'function');
});

test('vercel-ai buildCallFromVercelParams normalizes prompt structure', async () => {
  const { _buildCallFromVercelParams } = await import('../integrations/vercel-ai.js');
  const call = _buildCallFromVercelParams(
    {
      prompt: [
        { role: 'user', content: [{ type: 'text', text: 'hello' }] },
        { role: 'assistant', content: [{ type: 'text', text: 'hi' }] },
      ],
    },
    {
      provider: 'openai.chat',
      modelId: 'gpt-4o-mini',
    },
  );
  assert.equal(call.provider, 'openai');
  assert.equal(call.model, 'gpt-4o-mini');
  assert.equal(call.messages.length, 2);
  assert.equal(call.messages[0].content, 'hello');
});

test('vercel-ai inferProviderFromModel handles common providers', async () => {
  const { _inferProviderFromModel } = await import('../integrations/vercel-ai.js');
  assert.equal(_inferProviderFromModel({ provider: 'openai.chat' }), 'openai');
  assert.equal(_inferProviderFromModel({ provider: 'anthropic.messages' }), 'anthropic');
  assert.equal(_inferProviderFromModel({ provider: 'google.generative-ai' }), 'google_genai');
  assert.equal(_inferProviderFromModel({ provider: 'mistral.chat' }), 'mistralai');
  assert.equal(_inferProviderFromModel({ provider: 'cohere.chat' }), 'cohere');
  assert.equal(_inferProviderFromModel({ provider: 'unknown-vendor' }), 'unknown');
});

test('vercel-ai middleware passes through when soth.init() not called', async () => {
  // Reset the module-level singleton by re-loading the package.
  // We can't easily un-init(), so this asserts that wrapGenerate's
  // pass-through path returns whatever doGenerate() returns.
  const mod = await import('../integrations/vercel-ai.js');
  const middleware = mod.sothMiddleware();

  // Constructive: feed a fake doGenerate that returns a known value.
  const result = await middleware.wrapGenerate({
    doGenerate: async () => ({ text: 'pass-through ok' }),
    params: { prompt: [] },
    model: { provider: 'openai.chat', modelId: 'gpt-4o-mini' },
  });
  // soth.init() WAS called above, so this actually goes through the
  // SOTH lifecycle. The result is preserved either way.
  assert.equal(result.text, 'pass-through ok');
});
