"""Anthropic auto-instrumentation.

Patches `anthropic.resources.messages.Messages.create` and
`anthropic.resources.messages.AsyncMessages.create`.

Anthropic's request shape:

    client.messages.create(
        model="claude-...",
        messages=[{"role": "user", "content": "..."}],
        system="...",       # SEPARATE FIELD — not in messages
        stream=True/False,
        tools=[{"name": ..., "description": ..., "input_schema": {...}}],
        max_tokens=...,
    )

Differs from OpenAI in:
- `system` is a separate parameter (not a message with role=system)
- Tools use `{name, description, input_schema}` shape (vs OpenAI's nested)
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from ._base import Patch, revert_all, wrap_method

logger = logging.getLogger("soth.instrumentation.anthropic")

PROVIDER = "anthropic"
_patches: list[Patch] = []


def apply() -> bool:
    """Patch Anthropic's messages classes. Returns True on success,
    False if the anthropic package isn't importable."""
    try:
        from anthropic.resources import messages as msg_module
    except ImportError:
        return False

    targets: list[tuple[type, str]] = []

    sync_cls = getattr(msg_module, "Messages", None)
    if sync_cls is not None:
        targets.append((sync_cls, "create"))

    async_cls = getattr(msg_module, "AsyncMessages", None)
    if async_cls is not None:
        targets.append((async_cls, "create"))

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

    return bool(_patches)


def revert() -> None:
    revert_all(_patches)
    _patches.clear()


def _build_call(args: tuple, kwargs: dict) -> dict[str, Any]:
    """Extract an LlmCall dict from Anthropic's `create(...)` args."""
    model = kwargs.get("model")
    raw_messages = kwargs.get("messages") or []
    messages: list[dict[str, str]] = []
    for m in raw_messages:
        role = m.get("role", "user") if isinstance(m, dict) else "user"
        content = m.get("content", "") if isinstance(m, dict) else ""
        # Anthropic content may be a string OR a list of ContentBlock
        # objects (`{"type": "text", "text": "..."}`). Flatten.
        if isinstance(content, list):
            parts = []
            for p in content:
                if isinstance(p, dict):
                    text = p.get("text", "")
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
        name = t.get("name")
        if not name:
            continue
        tools.append(
            {
                "name": str(name),
                "description": t.get("description"),
                "parameters_json": _stable_json_dumps(t.get("input_schema", {})),
            }
        )

    call: dict[str, Any] = {
        "provider": PROVIDER,
        "model": str(model) if model else "",
        "messages": messages,
        "stream": bool(kwargs.get("stream", False)),
    }
    if "system" in kwargs and kwargs["system"]:
        call["system"] = kwargs["system"]
    if tools:
        call["tools"] = tools
    return call


def _chunk_extractor(chunk: Any) -> tuple[Optional[str], Optional[str]]:
    """Anthropic streaming yields a sequence of MessageStreamEvent
    objects (`MessageStartEvent`, `ContentBlockDeltaEvent`,
    `MessageStopEvent`, ...). The text deltas live on
    `ContentBlockDeltaEvent.delta.text`.

    Returns `(text, finish_reason)` where `finish_reason` is set on
    the terminal `MessageDeltaEvent` when present.
    """
    try:
        event_type = getattr(chunk, "type", None)
        if event_type == "content_block_delta":
            delta = getattr(chunk, "delta", None)
            if delta is not None:
                text = getattr(delta, "text", None) or getattr(delta, "partial_json", None)
                return (text, None) if text else (None, None)
        if event_type == "message_delta":
            delta = getattr(chunk, "delta", None)
            stop = getattr(delta, "stop_reason", None) if delta else None
            return (None, stop)
        if event_type == "message_stop":
            return (None, "stop")
    except (AttributeError, TypeError):
        pass
    return (None, None)


def _stable_json_dumps(obj: Any) -> str:
    import json

    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(obj)
