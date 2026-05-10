// Vercel AI SDK middleware integration.
//
// The `ai` npm package (Vercel AI SDK) supports a middleware pattern
// via `wrapLanguageModel({ model, middleware })`. Each middleware is a
// `LanguageModelV1Middleware` object with optional `wrapGenerate`,
// `wrapStream`, and `transformParams` hooks. The middleware sits
// between the customer's `streamText` / `generateText` call and the
// underlying model adapter.
//
// Customer usage:
//
//   const { wrapLanguageModel } = require('ai');
//   const { sothMiddleware } = require('@soth/sdk/integrations/vercel-ai');
//   const { openai } = require('@ai-sdk/openai');
//
//   const wrappedModel = wrapLanguageModel({
//     model: openai('gpt-4o'),
//     middleware: [sothMiddleware()],
//   });
//
//   const result = await generateText({ model: wrappedModel, ... });
//
// Robustness contract: missing-`ai`-package tolerance, fail-open
// extraction, no-op when soth.init() hasn't been called yet
// (logs warning, lets the call through).

const soth = require('../index.js');

/**
 * Construct a Vercel AI SDK middleware that routes generate/stream
 * calls through SOTH's pre/post lifecycle.
 *
 * Returns an object compatible with `LanguageModelV1Middleware`. If
 * the customer hasn't called `soth.init(...)` yet, the middleware
 * logs a warning and acts as a pass-through — a no-op.
 */
function sothMiddleware() {
  return {
    middlewareVersion: 'v1',
    wrapGenerate,
    wrapStream,
  };
}

async function wrapGenerate({ doGenerate, params, model }) {
  let sdk;
  try {
    sdk = soth.getSdk();
  } catch (e) {
    console.warn('soth-vercel-ai: middleware used before soth.init(); pass-through');
    return doGenerate();
  }

  let call;
  try {
    call = buildCallFromVercelParams(params, model);
  } catch (e) {
    console.warn('soth-vercel-ai: buildCall failed:', e?.message ?? e);
    return doGenerate();
  }

  const decision = sdk.preCall(call, _currentVercelContext());
  const { kind, token } = decision;

  if (kind === 'block') {
    sdk.postCall(token, null);
    throw new soth.SothBlocked(token, decision.reason);
  }

  try {
    const result = await doGenerate();
    return result;
  } finally {
    sdk.postCall(token, null);
  }
}

async function wrapStream({ doStream, params, model }) {
  let sdk;
  try {
    sdk = soth.getSdk();
  } catch (e) {
    console.warn('soth-vercel-ai: middleware used before soth.init(); pass-through');
    return doStream();
  }

  let call;
  try {
    call = buildCallFromVercelParams(params, model, /* stream= */ true);
  } catch (e) {
    console.warn('soth-vercel-ai: buildCall failed:', e?.message ?? e);
    return doStream();
  }

  const decision = sdk.streamBegin(call, _currentVercelContext());
  const { kind, token } = decision;

  if (kind === 'block') {
    sdk.streamEnd(token);
    throw new soth.SothBlocked(token, decision.reason);
  }

  // Vercel returns a `{ stream, ... }` object from doStream. We tap
  // the stream by intercepting it and forwarding chunks while feeding
  // SOTH's observation. The original stream contract (ReadableStream
  // of language-model parts) is preserved.
  const upstream = await doStream();
  const tappedStream = tapStreamForSoth({
    stream: upstream.stream,
    sdk,
    token,
  });
  return { ...upstream, stream: tappedStream };
}

function tapStreamForSoth({ stream, sdk, token }) {
  let sequence = 0;
  // Vercel's stream is a Web ReadableStream<LanguageModelV1StreamPart>.
  // We use TransformStream to peek at each part and forward it.
  const transform = new TransformStream({
    transform(part, controller) {
      try {
        if (part?.type === 'text-delta' && typeof part.textDelta === 'string') {
          sdk.streamChunk(token, sequence, part.textDelta, null);
          sequence += 1;
        } else if (part?.type === 'finish') {
          sdk.streamChunk(token, sequence, null, part.finishReason ?? 'stop');
          sequence += 1;
        }
      } catch (_) {
        // Fail-open: never break the customer's stream because of
        // SOTH-side failures.
      }
      controller.enqueue(part);
    },
    flush() {
      try {
        sdk.streamEnd(token);
      } catch (_) { /* fall through */ }
    },
  });
  return stream.pipeThrough(transform);
}

function buildCallFromVercelParams(params, model, stream = false) {
  // Vercel V1 params shape:
  //   {
  //     mode: { type: 'regular' | 'object-json' | ... },
  //     prompt: [{ role, content }, ...],   // content is a structured
  //                                         // array, not a string
  //     temperature, maxTokens, ...
  //   }

  const provider = inferProviderFromModel(model);
  const modelId = String(model?.modelId ?? model?.specificationVersion ?? '');

  const rawPrompt = Array.isArray(params?.prompt) ? params.prompt : [];
  const messages = rawPrompt.map((m) => {
    const role = typeof m?.role === 'string' ? m.role : 'user';
    let content = m?.content ?? '';
    if (Array.isArray(content)) {
      content = content
        .map((p) => (p && typeof p === 'object' ? p.text ?? '' : ''))
        .filter(Boolean)
        .join(' ');
    }
    return { role, content: String(content) };
  });

  return {
    provider,
    model: modelId,
    messages,
    stream,
  };
}

function inferProviderFromModel(model) {
  // Vercel AI SDK models carry a `.provider` string like
  // 'openai.chat', 'anthropic.messages', 'google.generative-ai',
  // 'mistral.chat'.
  const providerStr = String(model?.provider ?? '').toLowerCase();
  if (providerStr.startsWith('openai')) return 'openai';
  if (providerStr.startsWith('anthropic')) return 'anthropic';
  if (providerStr.startsWith('cohere')) return 'cohere';
  if (providerStr.startsWith('google')) return 'google_genai';
  if (providerStr.startsWith('mistral')) return 'mistralai';
  return 'unknown';
}

function _currentVercelContext() {
  // The middleware sits inside Node, so the existing AsyncLocalStorage
  // from the top-level shim provides the context. Pull it via the
  // exported helper rather than reaching into private state.
  try {
    const sdk = soth.getSdk();
    // No public accessor today; use the same path guard()/guardStream()
    // already use internally.
    return null; // Phase-1.5 keeps this simple; Phase-2 wires.
  } catch (_) {
    return null;
  }
}

module.exports = {
  sothMiddleware,
  // Test surface
  _buildCallFromVercelParams: buildCallFromVercelParams,
  _inferProviderFromModel: inferProviderFromModel,
};
