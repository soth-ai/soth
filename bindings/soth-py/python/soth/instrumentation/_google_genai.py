"""Google GenAI auto-instrumentation.

Patches `google.genai.models.Models.generate_content`,
`generate_content_stream`, and their async counterparts on
`google.genai.models.AsyncModels`.

Google's request shape diverges meaningfully from OpenAI:

    client.models.generate_content(
        model="gemini-2.0-flash",
        contents="Tell me about Rust",      # str | list | dict
        config={"system_instruction": "..."},
    )

`contents` can be:
- a single string (the user prompt)
- a list of strings (multiple prompts; multimodal)
- a list of `Content` objects with role + parts
- a dict-shaped `Content`

The adapter normalizes all four into the SDK's `messages: [{role, content}]`
shape; defensive on unknown structures.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from ._base import Patch, revert_all, wrap_method

logger = logging.getLogger("soth.instrumentation.google_genai")

PROVIDER = "google_genai"
_patches: list[Patch] = []


def apply() -> bool:
    try:
        from google.genai import models as models_module  # type: ignore
    except ImportError:
        return False

    targets: list[tuple[type, str]] = []
    sync_cls = getattr(models_module, "Models", None)
    if sync_cls is not None:
        for name in ("generate_content", "generate_content_stream"):
            if callable(getattr(sync_cls, name, None)):
                targets.append((sync_cls, name))
    async_cls = getattr(models_module, "AsyncModels", None)
    if async_cls is not None:
        for name in ("generate_content", "generate_content_stream"):
            if callable(getattr(async_cls, name, None)):
                targets.append((async_cls, name))

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
    model = kwargs.get("model")
    contents = kwargs.get("contents")
    config = kwargs.get("config") or {}

    messages = _normalize_contents(contents)

    # `system_instruction` lives on the config object in newer
    # google-genai releases; fall back to the kwarg for older shapes.
    system = None
    if isinstance(config, dict):
        system = config.get("system_instruction")
    else:
        system = getattr(config, "system_instruction", None)
    if not system:
        system = kwargs.get("system_instruction")

    is_streaming = "_stream" in (
        kwargs.get("__call_method") or ""
    ) or bool(kwargs.get("stream", False))
    # Streaming is detected at the wrapper level via
    # `kwargs.get('stream')`; google-genai uses a separate
    # `generate_content_stream` method, so we always set
    # stream=True for that target. The wrapper also overrides this
    # via the call shape.
    method_name = kwargs.get("__call_method", "")
    if method_name.endswith("stream"):
        is_streaming = True

    call: dict[str, Any] = {
        "provider": PROVIDER,
        "model": str(model) if model else "",
        "messages": messages,
        "stream": is_streaming,
    }
    if system:
        call["system"] = str(system)
    return call


def _normalize_contents(contents: Any) -> list[dict[str, str]]:
    """Convert google-genai's flexible `contents` into a
    `[{role, content}]` list. Returns `[]` for unrecognized shapes
    (the wrapper still operates; just no message content)."""
    if contents is None:
        return []
    # Single string → single user message.
    if isinstance(contents, str):
        return [{"role": "user", "content": contents}]
    # List handling — heterogeneous.
    if isinstance(contents, list):
        out: list[dict[str, str]] = []
        for item in contents:
            if isinstance(item, str):
                out.append({"role": "user", "content": item})
            elif isinstance(item, dict):
                out.append(_normalize_content_dict(item))
            else:
                # Content object with .role and .parts attributes.
                role = getattr(item, "role", "user") or "user"
                parts = getattr(item, "parts", None) or []
                texts = []
                for p in parts:
                    text = getattr(p, "text", None)
                    if not text and isinstance(p, dict):
                        text = p.get("text")
                    if text:
                        texts.append(str(text))
                out.append({"role": str(role), "content": " ".join(texts)})
        return out
    # Single dict → treat as Content.
    if isinstance(contents, dict):
        return [_normalize_content_dict(contents)]
    return []


def _normalize_content_dict(d: dict) -> dict[str, str]:
    role = d.get("role", "user")
    parts = d.get("parts") or []
    texts: list[str] = []
    if isinstance(parts, list):
        for p in parts:
            if isinstance(p, dict):
                text = p.get("text")
                if text:
                    texts.append(str(text))
            elif isinstance(p, str):
                texts.append(p)
    elif isinstance(parts, str):
        texts.append(parts)
    return {"role": str(role), "content": " ".join(texts)}


def _chunk_extractor(chunk: Any) -> tuple[Optional[str], Optional[str]]:
    """google-genai streaming yields `GenerateContentResponse` objects
    where each has `.text` (the delta) and `.candidates[].finish_reason`.
    """
    try:
        text = getattr(chunk, "text", None)
        finish = None
        candidates = getattr(chunk, "candidates", None)
        if candidates:
            cand = candidates[0]
            finish_reason = getattr(cand, "finish_reason", None)
            if finish_reason:
                finish = str(finish_reason)
        return text if text else None, finish
    except (AttributeError, IndexError, TypeError):
        return (None, None)
