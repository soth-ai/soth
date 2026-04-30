"""SOTH SDK for Python.

Public API:
    init(...)                  -> SothSdk
    SothBlocked                -> exception (does NOT inherit from any
                                  provider SDK exception type; propagates
                                  past `try/except openai.APIError`)
    BlockReason                -> typed reason carried on SothBlocked

The Decision API contract is locked by `docs/common/SDK_DECISION_API_SPEC.md`.

Quick start:

    import soth, openai

    soth.init(
        api_key="sk-...",
        org_id="org-123",
        hmac_key_env="SOTH_HMAC_KEY",
    )
    client = openai.OpenAI()
    try:
        response = soth.guard(
            lambda: client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "hello"}],
            ),
            call={
                "provider": "openai",
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
    except soth.SothBlocked as e:
        print("blocked:", e.reason)
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional, TypeVar

from . import _soth_native  # type: ignore[attr-defined]
from .exceptions import (
    BlockReason,
    SothBlocked,
    SothFlagged,
    block_reason_from_dict,
)

__version__ = _soth_native.__version__

__all__ = [
    "init",
    "shutdown",
    "guard",
    "guard_stream",
    "context",
    "SothBlocked",
    "SothFlagged",
    "BlockReason",
]


# Per-call context lives in a contextvars.ContextVar so it survives
# `asyncio` task switches naturally — async code that awaits inside a
# `with soth.context(...)` block sees the same context after the await.
_current_context: contextvars.ContextVar[dict[str, str]] = contextvars.ContextVar(
    "soth_current_context", default={}
)


@contextmanager
def context(
    *,
    user_id_hmac: Optional[str] = None,
    team_id: Optional[str] = None,
    device_id_hash: Optional[str] = None,
    session_id: Optional[str] = None,
    request_id: Optional[str] = None,
) -> Iterator[None]:
    """Override identity fields for any `guard()` / `guard_stream()`
    calls inside this block.

    Uses `contextvars` so async tasks awaited inside the block see the
    same context. Nested `with soth.context(...)` blocks merge — fields
    not set in the inner block fall through to the outer block.

    `user_id_hmac` MUST be the HMAC of the customer's user ID,
    computed by the customer's code using their `SOTH_HMAC_KEY`.
    The SDK never sees plaintext user IDs.
    """
    current = dict(_current_context.get())
    if user_id_hmac is not None:
        current["user_id_hmac"] = user_id_hmac
    if team_id is not None:
        current["team_id"] = team_id
    if device_id_hash is not None:
        current["device_id_hash"] = device_id_hash
    if session_id is not None:
        current["session_id"] = session_id
    if request_id is not None:
        current["request_id"] = request_id
    token = _current_context.set(current)
    try:
        yield
    finally:
        _current_context.reset(token)

# Module-level singleton. Bindings keep one SothSdk per process; per-call
# context (org/user/team override) is layered on top via `with_context`.
_singleton: Optional[_soth_native.SothSdk] = None

T = TypeVar("T")


def init(
    *,
    api_key: str,
    org_id: str,
    hmac_key_env: Optional[str] = None,
    hmac_key_static: Optional[bytes] = None,
    telemetry_endpoint: Optional[str] = None,
) -> None:
    """Initialize the SOTH SDK module-level singleton.

    Specify exactly one of `hmac_key_env` (read from environment) or
    `hmac_key_static` (raw bytes). Production usage SHOULD prefer
    `hmac_key_env` so the key never sits in source-controlled config.

    `telemetry_endpoint` (e.g.
    `"https://api.soth.cloud/v1/edge/telemetry/batch"`) enables the
    background HTTPS shipper. When omitted, telemetry events accumulate
    in an in-memory queue with no transport — useful for tests.
    """
    global _singleton
    _singleton = _soth_native.SothSdk(
        api_key=api_key,
        org_id=org_id,
        hmac_key_env=hmac_key_env,
        hmac_key_static=hmac_key_static,
        telemetry_endpoint=telemetry_endpoint,
    )


def shutdown() -> None:
    """Stop the background telemetry shipper and flush pending events.

    Customers SHOULD call this at process exit (e.g. in a `finally`
    block at the top of `main`) so the last batch window's events
    aren't lost. Idempotent.
    """
    global _singleton
    if _singleton is not None:
        _singleton.shutdown()


def get_sdk() -> _soth_native.SothSdk:
    """Return the initialized SDK or raise if `init` hasn't run."""
    if _singleton is None:
        raise RuntimeError(
            "soth.init(...) must be called before any guard() / SDK call"
        )
    return _singleton


def guard(
    call_fn: Callable[[], T],
    *,
    call: dict[str, Any],
    response_extractor: Optional[Callable[[T], dict[str, Any]]] = None,
) -> T:
    """Wrap an LLM call with SOTH's pre/post decision lifecycle.

    Translates `Decision::Block` into a raised `SothBlocked` and
    `Decision::Flag` into a logged `SothFlagged` warning. `Allow` and
    `Redact` proceed to invoke `call_fn` (Redact handling is a Phase-1
    deliverable; v0 treats Redact as Allow with the redactions logged).

    `call_fn` is the customer's existing call (e.g.
    `client.chat.completions.create(...)`); the wrapper is intentionally
    narrow so it can be applied per-call with minimal disruption.
    """
    sdk = get_sdk()
    ctx = _current_context.get() or None
    decision = sdk.pre_call(call, ctx)
    kind = decision["kind"]
    token = decision["token"]

    if kind == _soth_native.DECISION_KIND_BLOCK:
        # Consume the token so the slab balances even on block.
        sdk.post_call(token, None)
        raise SothBlocked(
            decision_id=str(token),
            reason=block_reason_from_dict(decision.get("reason", {})),
        )

    # Allow / Flag / Redact (Redact is Phase-1; treat as Allow + log)
    try:
        result = call_fn()
    finally:
        # Always consume the token, even on host-level failure.
        response_dict = (
            response_extractor(result)  # type: ignore[name-defined]
            if response_extractor and "result" in dir()
            else None
        )
        sdk.post_call(token, response_dict)

    if kind == _soth_native.DECISION_KIND_FLAG:
        # Surface the flag through a logger; customers can install
        # handlers to act on it. Does NOT raise.
        import logging

        logging.getLogger("soth").warning(
            "soth flagged call: severity=%s", decision.get("severity")
        )

    return result


async def guard_stream(
    iter_factory: Callable[[], Any],
    *,
    call: dict[str, Any],
    chunk_extractor: Callable[[Any], tuple[Optional[str], Optional[str]]] | None = None,
):
    """Wrap a streaming LLM call with SOTH's pre/post lifecycle.

    `iter_factory` returns an async iterator (typically the awaited
    result of e.g. ``client.chat.completions.create(stream=True, ...)``).
    `chunk_extractor(chunk) -> (delta_content, finish_reason)` pulls the
    fields the SDK records from each provider chunk; defaults to OpenAI's
    `chunk.choices[0].delta.content` shape.

    Yields each chunk back to the caller. Raises `SothBlocked` if the
    decision is `Block`. Always finalizes the stream observation on
    completion or exception.
    """
    sdk = get_sdk()
    ctx = _current_context.get() or None
    decision, observation = sdk.stream_begin(call, ctx)
    kind = decision["kind"]

    if kind == _soth_native.DECISION_KIND_BLOCK:
        observation.end()  # Consume token even on block.
        raise SothBlocked(
            decision_id=str(decision["token"]),
            reason=block_reason_from_dict(decision.get("reason", {})),
        )

    if chunk_extractor is None:
        chunk_extractor = _default_openai_chunk_extractor

    sequence = 0
    try:
        provider_iter = iter_factory()
        # Provider may return a sync iterator (e.g. anthropic non-async)
        # OR a coroutine that resolves to an async iterator. Handle both.
        if hasattr(provider_iter, "__await__"):
            provider_iter = await provider_iter
        async for chunk in provider_iter:
            delta_content, finish_reason = chunk_extractor(chunk)
            observation.chunk(sequence, delta_content, finish_reason)
            sequence += 1
            yield chunk
    finally:
        observation.end()


def _default_openai_chunk_extractor(chunk: Any) -> tuple[Optional[str], Optional[str]]:
    """Default chunk extractor for OpenAI-shaped streams.

    Looks for `chunk.choices[0].delta.content` and
    `chunk.choices[0].finish_reason`. Falls back to `(None, None)` for
    chunks that don't fit (the SDK still sees the chunk count, just no
    content sample).
    """
    try:
        choice = chunk.choices[0]
        delta = getattr(choice, "delta", None)
        delta_content = getattr(delta, "content", None) if delta else None
        finish_reason = getattr(choice, "finish_reason", None)
        return delta_content, finish_reason
    except (AttributeError, IndexError, TypeError):
        return None, None


# Test-only re-exports (used by `tests/test_smoke.py` etc.)
def _drain_telemetry_for_test() -> list[dict[str, Any]]:
    return get_sdk().drain_telemetry_for_test()


def _in_flight_decisions() -> int:
    return get_sdk().in_flight_decisions()
