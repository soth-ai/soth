"""OpenAI auto-instrumentation.

Patches `openai.resources.chat.completions.Completions.create` and
`openai.resources.chat.completions.AsyncCompletions.create` (and
`responses.Responses` if available — newer SDK paths).

The OpenAI Python SDK structures requests as:

    client.chat.completions.create(
        model="...",
        messages=[...],
        stream=True/False,
        tools=[...],          # function-calling
        ...
    )

The SDK's typed argument shape is largely stable across 1.x. This
adapter uses defensive `kwargs.get` access so minor-version field
additions don't break the wrapper.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from ._base import Patch, revert_all, wrap_method

logger = logging.getLogger("soth.instrumentation.openai")

PROVIDER = "openai"
_patches: list[Patch] = []


def apply() -> bool:
    """Patch OpenAI's chat.completions classes. Returns True on
    success, False if the openai package isn't importable."""
    try:
        from openai.resources.chat import completions as chat_completions
    except ImportError:
        return False

    targets: list[tuple[type, str]] = []

    sync_cls = getattr(chat_completions, "Completions", None)
    if sync_cls is not None:
        targets.append((sync_cls, "create"))

    async_cls = getattr(chat_completions, "AsyncCompletions", None)
    if async_cls is not None:
        targets.append((async_cls, "create"))

    # Newer SDKs expose `responses.Responses` (text-completion-style
    # API). Patch defensively if available.
    try:
        from openai.resources import responses as resp_module

        sync_resp = getattr(resp_module, "Responses", None)
        if sync_resp is not None:
            targets.append((sync_resp, "create"))
        async_resp = getattr(resp_module, "AsyncResponses", None)
        if async_resp is not None:
            targets.append((async_resp, "create"))
    except ImportError:
        pass

    for target, method_name in targets:
        patch = wrap_method(
            target,
            method_name,
            provider_name=PROVIDER,
            build_call=_build_call,
            chunk_extractor=_chunk_extractor,
        )
        if patch is not None:
            _patches.append(patch)

    if not _patches:
        # `openai` is installed but neither Completions nor Responses
        # is available — likely a very old or stripped install. Treat
        # as not installed so customers see "skipped:not-installed".
        return False
    return True


def revert() -> None:
    """Restore originals patched in `apply`."""
    revert_all(_patches)
    _patches.clear()


def _build_call(args: tuple, kwargs: dict) -> dict[str, Any]:
    """Extract an LlmCall dict from OpenAI's `create(...)` arguments.

    Most fields come from kwargs since the SDK's create() is
    keyword-only for everything except `self` and (rarely) the model.
    Defensive about unknown fields — anything we don't recognize
    is ignored, not propagated.
    """
    model = kwargs.get("model")
    if model is None and args:
        # Some SDK signatures accept (self, model) positionally.
        # Skip the bound-self position and check the rest.
        for arg in args[1:]:
            if isinstance(arg, str):
                model = arg
                break

    raw_messages = kwargs.get("messages") or []
    messages: list[dict[str, str]] = []
    for m in raw_messages:
        # Each message is typically `{"role": ..., "content": ...}`,
        # but content may be a list of content parts (vision / multi-
        # modal). Flatten lists into a string for hashing purposes.
        role = m.get("role", "user") if isinstance(m, dict) else "user"
        content = m.get("content", "") if isinstance(m, dict) else ""
        if isinstance(content, list):
            parts = []
            for p in content:
                if isinstance(p, dict):
                    text = p.get("text") or p.get("input_text") or ""
                    if text:
                        parts.append(text)
            content = " ".join(parts)
        elif content is None:
            content = ""
        messages.append({"role": str(role), "content": str(content)})

    tools_kwarg = kwargs.get("tools") or []
    tools: list[dict[str, Any]] = []
    for t in tools_kwarg:
        if not isinstance(t, dict):
            continue
        # OpenAI tools shape: {"type": "function", "function": {...}}
        if t.get("type") == "function":
            fn = t.get("function") or {}
            name = fn.get("name")
            if not name:
                continue
            tools.append(
                {
                    "name": str(name),
                    "description": fn.get("description"),
                    "parameters_json": _stable_json_dumps(fn.get("parameters", {})),
                }
            )

    call: dict[str, Any] = {
        "provider": PROVIDER,
        "model": str(model) if model else "",
        "messages": messages,
        "stream": bool(kwargs.get("stream", False)),
    }
    if tools:
        call["tools"] = tools
    if "system" in kwargs:
        call["system"] = kwargs["system"]
    return call


def _chunk_extractor(chunk: Any) -> tuple[Optional[str], Optional[str]]:
    """Default chunk extractor for OpenAI streams.

    OpenAI's streaming response yields ChatCompletionChunk objects with
    `choices[0].delta.content` and `choices[0].finish_reason`. Returns
    `(None, None)` for chunks that don't fit (e.g. tool-call deltas).
    """
    try:
        choice = chunk.choices[0]
        delta = getattr(choice, "delta", None)
        delta_content = getattr(delta, "content", None) if delta else None
        finish_reason = getattr(choice, "finish_reason", None)
        return delta_content, finish_reason
    except (AttributeError, IndexError, TypeError):
        return None, None


def _stable_json_dumps(obj: Any) -> str:
    """Stable JSON serialization for tool parameter hashing.

    `sort_keys=True` so the same logical schema produces the same
    hash across Python dict ordering changes. Falls back to repr()
    if the object isn't JSON-serializable.
    """
    import json

    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(obj)
