// Anthropic Node SDK auto-instrumentation.
//
// Patches `Messages.create` on the typed messages module of
// `@anthropic-ai/sdk`. Anthropic's Node API is OpenAI-shaped except
// for the `system` parameter (separate field, not a system message)
// and tools (using `input_schema` rather than `parameters`).
//
//   client.messages.create({
//     model: 'claude-3-5-sonnet-latest',
//     messages: [{ role: 'user', content: '...' }],
//     system: '...',
//     stream: true|false,
//     tools: [{ name, description, input_schema }],
//     max_tokens: 1024,
//   })

const { wrapMethod, revertAll } = require('./_base.js');

const PROVIDER = 'anthropic';
const _patches = [];

function apply() {
  let anthropic;
  try {
    anthropic = require('@anthropic-ai/sdk');
  } catch (_) {
    return false;
  }

  // Anthropic's npm SDK has rotated typed-resource paths a few times
  // in its 0.x series. Try multiple candidates for version tolerance.
  const candidates = [
    () => require('@anthropic-ai/sdk/resources/messages'),
    () => require('@anthropic-ai/sdk/resources/messages/messages'),
  ];

  let messagesModule = null;
  for (const loader of candidates) {
    try {
      messagesModule = loader();
      break;
    } catch (_) {
      continue;
    }
  }
  if (!messagesModule) return false;

  const targets = [];
  const Messages = messagesModule.Messages;
  if (Messages && typeof Messages.prototype?.create === 'function') {
    targets.push([Messages, 'create']);
  }
  // Anthropic's beta module exports `MessagesBeta` with the same
  // `create` shape; patch when present.
  for (const exportName of Object.keys(messagesModule)) {
    const cls = messagesModule[exportName];
    if (
      typeof cls === 'function'
      && cls?.prototype
      && typeof cls.prototype.create === 'function'
      && !targets.some(([t]) => t === cls)
    ) {
      targets.push([cls, 'create']);
    }
  }

  for (const [target, methodName] of targets) {
    const patch = wrapMethod(target, methodName, {
      providerName: PROVIDER,
      buildCall,
      chunkExtractor,
    });
    if (patch) _patches.push(patch);
  }

  return _patches.length > 0;
}

function revert() {
  revertAll(_patches);
  _patches.length = 0;
}

function buildCall(args) {
  const opts = args?.[0] ?? {};
  const model = opts.model ?? '';
  const rawMessages = Array.isArray(opts.messages) ? opts.messages : [];

  const messages = rawMessages.map((m) => {
    const role = typeof m?.role === 'string' ? m.role : 'user';
    let content = m?.content ?? '';
    if (Array.isArray(content)) {
      // Multi-modal / tool-use content blocks: flatten text parts.
      content = content
        .map((p) => (p && typeof p === 'object' ? p.text ?? '' : ''))
        .filter(Boolean)
        .join(' ');
    } else if (content == null) {
      content = '';
    }
    return { role, content: String(content) };
  });

  const tools = [];
  if (Array.isArray(opts.tools)) {
    for (const t of opts.tools) {
      if (!t || typeof t !== 'object' || typeof t.name !== 'string') continue;
      tools.push({
        name: t.name,
        description: t.description ?? null,
        // Anthropic uses `input_schema` rather than OpenAI's `parameters`.
        parametersJson: stableStringify(t.input_schema ?? {}),
      });
    }
  }

  const call = {
    provider: PROVIDER,
    model: String(model),
    messages,
    stream: Boolean(opts.stream),
  };
  if (tools.length) call.tools = tools;
  if (opts.system) call.system = String(opts.system);
  return call;
}

function chunkExtractor(chunk) {
  // Anthropic streaming: events of type `content_block_delta`,
  // `message_delta`, `message_stop`. Text deltas live on
  // `chunk.delta.text`.
  try {
    const eventType = chunk?.type;
    if (eventType === 'content_block_delta') {
      const delta = chunk?.delta;
      const text = delta?.text ?? delta?.partial_json ?? null;
      return { deltaContent: text, finishReason: null };
    }
    if (eventType === 'message_delta') {
      const stop = chunk?.delta?.stop_reason ?? null;
      return { deltaContent: null, finishReason: stop };
    }
    if (eventType === 'message_stop') {
      return { deltaContent: null, finishReason: 'stop' };
    }
  } catch (_) { /* fall through */ }
  return { deltaContent: null, finishReason: null };
}

function stableStringify(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(stableStringify).join(',')}]`;
  const keys = Object.keys(obj).sort();
  const pairs = keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`);
  return `{${pairs.join(',')}}`;
}

module.exports = {
  apply,
  revert,
  _buildCall: buildCall,
  _chunkExtractor: chunkExtractor,
};
