// Shared instrumentation helpers for Node provider adapters.
//
// `wrapMethod(target, methodName, { providerName, buildCall, chunkExtractor })`
// replaces a method on a class prototype with a SOTH-wrapped version
// that:
//   - calls buildCall(args) to derive the LlmCall dict
//   - on extractor failure: logs and falls through to the original
//   - on streaming (`stream: true` in args[0]): routes through
//     guardStream
//   - on non-streaming: routes through guard
//
// Returns a Patch object so revert() can restore the original.

const soth = require('../index.js'); // for guard / guardStream

function wrapMethod(target, methodName, { providerName, buildCall, chunkExtractor }) {
  if (!target?.prototype) {
    return null;
  }
  const original = target.prototype[methodName];
  if (typeof original !== 'function') {
    return null;
  }

  const wrapper = function wrappedSdkMethod(...args) {
    let callDict;
    try {
      callDict = buildCall(args);
    } catch (e) {
      console.warn(`soth: buildCall failed for ${providerName}.${methodName}:`, e?.message ?? e);
      return original.apply(this, args);
    }

    const isStreaming = Boolean(args?.[0]?.stream);
    const self = this;

    if (isStreaming) {
      // guardStream is an async generator. The SDK consumer uses
      // `for await (const chunk of result)`; the original method
      // typically returns an `AsyncIterable` already. We hand the
      // factory through so guardStream can lazy-call the underlying
      // method and wire chunks.
      return soth.guardStream(
        () => original.apply(self, args),
        {
          call: callDict,
          chunkExtractor,
        },
      );
    }

    // Non-streaming: original may return a Promise OR a value. soth.guard
    // accepts an async fn and awaits if needed; here we wrap the call
    // so guard sees the same shape.
    return soth.guard(
      async () => {
        const ret = original.apply(self, args);
        return ret && typeof ret.then === 'function' ? await ret : ret;
      },
      { call: callDict },
    );
  };

  // SOTH provenance markers — let revert() and any future
  // re-instrument check whether the method is already wrapped.
  Object.defineProperty(wrapper, '__sothWrapped', { value: true, enumerable: false });
  Object.defineProperty(wrapper, '__sothProvider', { value: providerName, enumerable: false });
  Object.defineProperty(wrapper, '__sothOriginal', { value: original, enumerable: false });
  wrapper.displayName = `soth(${providerName}.${methodName})`;

  target.prototype[methodName] = wrapper;
  return { target, methodName, original };
}

function isInstrumentedMethod(fn) {
  return Boolean(fn && fn.__sothWrapped);
}

function revertAll(patches) {
  for (const patch of patches) {
    const current = patch.target.prototype[patch.methodName];
    if (!current) continue;
    if (!isInstrumentedMethod(current)) {
      console.warn(
        `soth: ${patch.target.name}.${patch.methodName} was rewrapped by another tool; leaving in place`,
      );
      continue;
    }
    patch.target.prototype[patch.methodName] = patch.original;
  }
}

module.exports = {
  wrapMethod,
  isInstrumentedMethod,
  revertAll,
};
