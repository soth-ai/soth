"""Shared instrumentation infrastructure.

Each provider adapter (`_openai.py`, `_anthropic.py`, ...) imports from
this module to get:

- `wrap_method`: replaces a method on a class with a SOTH-wrapped version
  that handles sync/async, streaming/non-streaming, and fails open.
- `Patch`: bookkeeping struct so `revert()` can restore the original.

Adapters track their patches in module-level `_patches: list[Patch]`
and call `revert_all(_patches)` when uninstrumenting.
"""

from __future__ import annotations

import functools
import inspect
import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

logger = logging.getLogger("soth.instrumentation")


@dataclass
class Patch:
    """Captures one instrumentation site so `revert()` can undo it."""

    target: type
    method_name: str
    original: Any
    """The method object that was replaced. May itself be a wrapper
    from a prior instrumentation tool — we restore it verbatim."""


def wrap_method(
    target: type,
    method_name: str,
    *,
    provider_name: str,
    build_call: Callable[[tuple, dict], dict],
    chunk_extractor: Optional[
        Callable[[Any], tuple[Optional[str], Optional[str]]]
    ] = None,
) -> Optional[Patch]:
    """Replace `target.method_name` with a SOTH-wrapped version.

    `build_call(args, kwargs) -> dict` extracts the LlmCall dict from
    the SDK call's positional + keyword arguments. Errors during
    extraction trigger fail-open (the original SDK is invoked,
    SOTH bypassed for that call only).

    `chunk_extractor` is the per-provider streaming extractor passed
    to `guard_stream` / `guard_stream_sync`.

    Returns a Patch on success, or `None` if the method is missing
    on the target (silently skipped — version tolerance).
    """
    original = getattr(target, method_name, None)
    if original is None:
        logger.debug(
            "instrument(%s): %s.%s not found; skipping",
            provider_name,
            target.__name__,
            method_name,
        )
        return None

    is_async = inspect.iscoroutinefunction(original) or inspect.isasyncgenfunction(
        original
    )

    if is_async:
        wrapper = _make_async_wrapper(
            original,
            provider_name=provider_name,
            build_call=build_call,
            chunk_extractor=chunk_extractor,
        )
    else:
        wrapper = _make_sync_wrapper(
            original,
            provider_name=provider_name,
            build_call=build_call,
            chunk_extractor=chunk_extractor,
        )

    # Record SOTH provenance so `is_instrumented_method` can detect it
    # and so a future re-instrument doesn't double-wrap.
    setattr(wrapper, "__soth_wrapped__", True)
    setattr(wrapper, "__soth_provider__", provider_name)
    setattr(wrapper, "__soth_original__", original)

    setattr(target, method_name, wrapper)
    return Patch(target=target, method_name=method_name, original=original)


def _make_sync_wrapper(
    original: Callable,
    *,
    provider_name: str,
    build_call: Callable[[tuple, dict], dict],
    chunk_extractor: Optional[Callable[[Any], tuple[Optional[str], Optional[str]]]],
) -> Callable:
    """Wrap a sync method. Handles both streaming and non-streaming
    based on `kwargs.get('stream', False)` at call time."""
    from .. import guard, guard_stream_sync  # avoid circular at import time

    @functools.wraps(original)
    def wrapper(*args, **kwargs):
        # Fail-open extraction: any exception in build_call falls back
        # to the original SDK call uninstrumented.
        try:
            call_dict = build_call(args, kwargs)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "soth: build_call failed for %s.%s: %s; bypassed",
                provider_name,
                getattr(original, "__qualname__", "?"),
                e,
            )
            return original(*args, **kwargs)

        is_streaming = bool(kwargs.get("stream", False))
        if is_streaming:
            return guard_stream_sync(
                lambda: original(*args, **kwargs),
                call=call_dict,
                chunk_extractor=chunk_extractor,
            )
        return guard(
            lambda: original(*args, **kwargs),
            call=call_dict,
        )

    return wrapper


def _make_async_wrapper(
    original: Callable,
    *,
    provider_name: str,
    build_call: Callable[[tuple, dict], dict],
    chunk_extractor: Optional[Callable[[Any], tuple[Optional[str], Optional[str]]]],
) -> Callable:
    """Wrap an async method. Routes streaming through `guard_stream`
    (async generator) and non-streaming through `guard` (which now
    returns a coroutine when `call_fn` returns one)."""
    from .. import guard, guard_stream

    @functools.wraps(original)
    async def wrapper(*args, **kwargs):
        try:
            call_dict = build_call(args, kwargs)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "soth: build_call failed for %s.%s: %s; bypassed",
                provider_name,
                getattr(original, "__qualname__", "?"),
                e,
            )
            return await original(*args, **kwargs)

        is_streaming = bool(kwargs.get("stream", False))
        if is_streaming:
            # Return the async generator directly; the customer iterates
            # over it with `async for`.
            return guard_stream(
                lambda: original(*args, **kwargs),
                call=call_dict,
                chunk_extractor=chunk_extractor,
            )

        return await guard(
            lambda: original(*args, **kwargs),
            call=call_dict,
        )

    return wrapper


def is_instrumented_method(method: Any) -> bool:
    """Return whether `method` carries the SOTH provenance marker.

    Used to detect double-instrumentation and to warn when another
    tool has wrapped over our wrapper after we patched.
    """
    return bool(getattr(method, "__soth_wrapped__", False))


def revert_all(patches: list[Patch]) -> None:
    """Restore originals captured in `patches`. Best-effort: if
    another tool wrapped over our wrapper after we applied, that
    wrapper persists and we log a warning rather than silently
    overwriting it."""
    for patch in patches:
        current = getattr(patch.target, patch.method_name, None)
        if current is None:
            continue
        if not is_instrumented_method(current):
            logger.warning(
                "soth: %s.%s was rewrapped by another tool; leaving in place",
                patch.target.__name__,
                patch.method_name,
            )
            continue
        setattr(patch.target, patch.method_name, patch.original)
