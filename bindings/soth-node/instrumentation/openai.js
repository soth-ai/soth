// OpenAI Node SDK auto-instrumentation.
//
// The npm `openai` package exposes:
//   - OpenAI         (sync-API client; methods return Promises in JS)
//   - AzureOpenAI    (subclass; same method shapes)
//
// Methods of interest:
//   client.chat.completions.create({ model, messages, stream, tools, ... })
//
// In recent versions (4.x) `chat.completions` is a property that
// returns a `Completions` instance whose `create` method we patch
// on its prototype.

const { wrapMethod, revertAll } = require('./_base.js');

const PROVIDER = 'openai';
const _patches = [];

function apply() {
  let openai;
  try {
    openai = require('openai');
  } catch (_) {
    return false;
  }

  // Walk into the typed completions module. Path differs slightly
  // across 4.x versions; defensive lookup keeps us version-tolerant.
  const completionsCandidates = [
    () => require('openai/resources/chat/completions'),
    () => require('openai/resources/chat/completions/completions'),
  ];

  let completionsModule = null;
  for (const loader of completionsCandidates) {
    try {
      completionsModule = loader();
      break;
    } catch (_) {
      continue;
    }
  }

  if (!completionsModule) {
    // Fallback: try via the runtime client. Newer SDKs sometimes hide
    // class names; in that case we instantiate-then-patch on the
    // prototype.
    if (openai?.OpenAI) {
      // Best-effort: grab a Chat → Completions chain off the class
      // prototype. If it's not a method we can patch, return false.
      const chatProto = openai.OpenAI.prototype?.chat;
      if (chatProto && typeof chatProto === 'object') {
        // chat is typically a getter returning a Chat instance; we
        // can't patch through here without instantiating. Phase-2
        // adds an instance-level patcher; for now mark as
        // not-installed so the harness reports honestly.
      }
    }
    return false;
  }

  const targets = [];
  if (completionsModule.Completions) {
    targets.push([completionsModule.Completions, 'create']);
  }
  // Some 4.x versions expose `CompletionsBase` or split sync/async.
  // We patch any class that exposes a `create` prototype method.
  for (const exportName of Object.keys(completionsModule)) {
    const cls = completionsModule[exportName];
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
  // OpenAI's create() takes a single options object as the first arg.
  const opts = args?.[0] ?? {};
  const model = opts.model ?? '';
  const rawMessages = Array.isArray(opts.messages) ? opts.messages : [];

  const messages = rawMessages.map((m) => {
    const role = typeof m?.role === 'string' ? m.role : 'user';
    let content = m?.content ?? '';
    if (Array.isArray(content)) {
      // Multi-modal: flatten text parts.
      content = content
        .map((p) => (p && typeof p === 'object' ? p.text ?? p.input_text ?? '' : ''))
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
      if (!t || typeof t !== 'object') continue;
      if (t.type === 'function' && t.function && typeof t.function.name === 'string') {
        tools.push({
          name: t.function.name,
          description: t.function.description ?? null,
          parametersJson: stableStringify(t.function.parameters ?? {}),
        });
      }
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

function stableStringify(obj) {
  // Deterministic JSON for tool-parameter hashing — sorts keys at
  // every depth so logically-equivalent schemas produce the same hash.
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(stableStringify).join(',')}]`;
  const keys = Object.keys(obj).sort();
  const pairs = keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`);
  return `{${pairs.join(',')}}`;
}

module.exports = {
  apply,
  revert,
  // Test surface
  _buildCall: buildCall,
  _chunkExtractor: chunkExtractor,
};
