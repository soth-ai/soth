"""Mistral auto-instrumentation.

Patches `mistralai.chat.Chat.complete`,
`mistralai.chat.Chat.complete_async`, `Chat.stream`, `Chat.stream_async`
on the Mistral SDK (mistralai 1.x).

The Mistral request shape is OpenAI-equivalent:

    client.chat.complete(
        model="mistral-large-latest",
        messages=[{"role": "user", "content": "..."}],
        stream=True/False,
        tools=[...],
    )
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from ._base import Patch, revert_all, wrap_method

logger = logging.getLogger("soth.instrumentation.mistral")

PROVIDER = "mistralai"
_patches: list[Patch] = []


def apply() -> bool:
    try:
        from mistralai import chat as chat_module  # type: ignore
    except ImportError:
        return False

    chat_cls = getattr(chat_module, "Chat", None)
    if chat_cls is None:
        return False

    methods = []
    for name in ("complete", "complete_async", "stream", "stream_async"):
        if callable(getattr(chat_cls, name, None)):
            methods.append(name)

    for method_name in methods:
        patch = wrap_method(
            chat_cls,
            method_name,
            provider_name=PROVIDER,
            build_call=_build_call,
            chunk_extractor=_chunk_extractor,
        )
        if patch is not None:
            _patches.append(patch)

    return bool(_patches)


def revert() -> None:
    revert_all(_patches)
    _patches.clear()


def _build_call(args: tuple, kwargs: dict) -> dict[str, Any]:
    model = kwargs.get("model")
    raw_messages = kwargs.get("messages") or []
    messages: list[dict[str, str]] = []
    for m in raw_messages:
        # mistralai uses pydantic models OR dicts depending on shape.
        if isinstance(m, dict):
            role = m.get("role", "user")
            content = m.get("content", "")
        else:
            role = getattr(m, "role", "user")
            content = getattr(m, "content", "")
        if isinstance(content, list):
            # Multi-modal: flatten text parts.
            parts = []
            for p in content:
                if isinstance(p, dict):
                    text = p.get("text") or ""
                    if text:
                        parts.append(text)
                else:
                    text = getattr(p, "text", None)
                    if text:
                        parts.append(text)
            content = " ".join(parts)
        elif content is None:
            content = ""
        messages.append({"role": str(role), "content": str(content)})

    tools = []
    raw_tools = kwargs.get("tools") or []
    for t in raw_tools:
        # mistralai tools follow OpenAI's `{type: function, function: {...}}` shape.
        if not isinstance(t, dict):
            continue
        if t.get("type") == "function":
            fn = t.get("function") or {}
            name = fn.get("name")
            if not name:
                continue
            tools.append(
                {
                    "name": str(name),
                    "description": fn.get("description"),
                    "parameters_json": _stable_json(fn.get("parameters", {})),
                }
            )

    # Mistral's `stream` and `stream_async` are dedicated methods —
    # always streaming. `complete` / `complete_async` are not. The
    # base wrapper detects via kwargs.get('stream') so we surface that
    # explicitly here based on the call site.
    is_stream = bool(kwargs.get("stream", False))

    call: dict[str, Any] = {
        "provider": PROVIDER,
        "model": str(model) if model else "",
        "messages": messages,
        "stream": is_stream,
    }
    if tools:
        call["tools"] = tools
    return call


def _chunk_extractor(chunk: Any) -> tuple[Optional[str], Optional[str]]:
    """Mistral streaming chunks have a `.data.choices[0].delta.content` /
    `.data.choices[0].finish_reason` shape (mistralai wraps OpenAI-style
    chunks in a `data` envelope)."""
    try:
        # Mistral's CompletionEvent shape: {data: {choices: [{delta: {content}, finish_reason}]}}
        data = getattr(chunk, "data", None) or chunk
        choices = getattr(data, "choices", None)
        if not choices:
            return (None, None)
        choice = choices[0]
        delta = getattr(choice, "delta", None)
        content = getattr(delta, "content", None) if delta else None
        finish = getattr(choice, "finish_reason", None)
        return (content if content else None, finish)
    except (AttributeError, IndexError, TypeError):
        return (None, None)


def _stable_json(obj: Any) -> str:
    import json

    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(obj)
