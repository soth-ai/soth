"""Cohere auto-instrumentation.

Patches `cohere.client_v2.ClientV2.chat` and
`cohere.client_v2.AsyncClientV2.chat` (Cohere v5+ uses an
OpenAI-shaped `messages=[{role, content}]` API on `ClientV2`).

Falls back to the v4 `cohere.Client.chat(message=, chat_history=)`
shape when only the legacy client is present — a pragmatic
compatibility layer for customers still on the older release.

The robustness contract from `_base.py` applies: missing-package
tolerance, fail-open extraction, idempotent re-instrument.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from ._base import Patch, revert_all, wrap_method

logger = logging.getLogger("soth.instrumentation.cohere")

PROVIDER = "cohere"
_patches: list[Patch] = []


def apply() -> bool:
    try:
        import cohere  # noqa: F401
    except ImportError:
        return False

    targets: list[tuple[type, str, Any]] = []  # (class, method, build_call_fn)

    # v5+ ClientV2 — OpenAI-shaped messages.
    try:
        from cohere import client_v2 as v2_module

        sync_v2 = getattr(v2_module, "ClientV2", None)
        if sync_v2 is not None:
            targets.append((sync_v2, "chat", _build_call_v2))
            targets.append((sync_v2, "chat_stream", _build_call_v2))
        async_v2 = getattr(v2_module, "AsyncClientV2", None)
        if async_v2 is not None:
            targets.append((async_v2, "chat", _build_call_v2))
            targets.append((async_v2, "chat_stream", _build_call_v2))
    except ImportError:
        pass

    # v4 fallback Client / AsyncClient — distinct `message` + `chat_history` shape.
    try:
        from cohere.client import Client as v4_sync, AsyncClient as v4_async

        if v4_sync is not None:
            targets.append((v4_sync, "chat", _build_call_v4))
        if v4_async is not None:
            targets.append((v4_async, "chat", _build_call_v4))
    except ImportError:
        pass

    for target, method_name, build_fn in targets:
        patch = wrap_method(
            target,
            method_name,
            provider_name=PROVIDER,
            build_call=build_fn,
            chunk_extractor=_chunk_extractor,
        )
        if patch is not None:
            _patches.append(patch)

    return bool(_patches)


def revert() -> None:
    revert_all(_patches)
    _patches.clear()


def _build_call_v2(args: tuple, kwargs: dict) -> dict[str, Any]:
    """v5+ ClientV2.chat(messages=[...], model=..., stream=...)."""
    model = kwargs.get("model")
    raw_messages = kwargs.get("messages") or []
    messages: list[dict[str, str]] = []
    for m in raw_messages:
        role = m.get("role", "user") if isinstance(m, dict) else "user"
        content = m.get("content", "") if isinstance(m, dict) else ""
        if isinstance(content, list):
            parts = [p.get("text", "") for p in content if isinstance(p, dict)]
            content = " ".join(p for p in parts if p)
        elif content is None:
            content = ""
        messages.append({"role": str(role), "content": str(content)})

    tools = []
    raw_tools = kwargs.get("tools") or []
    for t in raw_tools:
        if not isinstance(t, dict):
            continue
        # v2 tools shape: {"type": "function", "function": {name, description, parameters}}
        fn = t.get("function") if t.get("type") == "function" else t
        if not isinstance(fn, dict):
            continue
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

    call: dict[str, Any] = {
        "provider": PROVIDER,
        "model": str(model) if model else "",
        "messages": messages,
        "stream": bool(kwargs.get("stream", False)),
    }
    if tools:
        call["tools"] = tools
    return call


def _build_call_v4(args: tuple, kwargs: dict) -> dict[str, Any]:
    """v4 Client.chat(message=, chat_history=, model=)."""
    model = kwargs.get("model")
    message = kwargs.get("message", "") or ""
    chat_history = kwargs.get("chat_history") or []

    messages: list[dict[str, str]] = []
    for h in chat_history:
        if not isinstance(h, dict):
            continue
        # v4 history: {"role": "USER" | "CHATBOT" | "SYSTEM", "message": "..."}
        role = h.get("role", "USER")
        # Normalize Cohere uppercase roles to OpenAI-style lowercase so
        # the SDK's hashing is consistent with other providers.
        if role == "CHATBOT":
            role = "assistant"
        else:
            role = role.lower()
        content = h.get("message") or h.get("text") or ""
        messages.append({"role": str(role), "content": str(content)})
    if message:
        messages.append({"role": "user", "content": str(message)})

    call: dict[str, Any] = {
        "provider": PROVIDER,
        "model": str(model) if model else "",
        "messages": messages,
        "stream": bool(kwargs.get("stream", False)),
    }
    return call


def _chunk_extractor(chunk: Any) -> tuple[Optional[str], Optional[str]]:
    """Cohere v5 streaming events: `chunk.type` is one of
    `content-delta`, `content-end`, `message-start`, `message-end`,
    etc. Text deltas live on `chunk.delta.message.content.text`.
    """
    try:
        event_type = getattr(chunk, "type", None)
        if event_type == "content-delta":
            delta = getattr(chunk, "delta", None)
            msg = getattr(delta, "message", None) if delta else None
            content = getattr(msg, "content", None) if msg else None
            text = getattr(content, "text", None) if content else None
            return (text, None) if text else (None, None)
        if event_type in ("message-end", "message-stop", "stream-end"):
            return (None, "stop")
    except (AttributeError, TypeError):
        pass
    return (None, None)


def _stable_json(obj: Any) -> str:
    import json

    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(obj)
