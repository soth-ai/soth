"""LangChain integration.

Provides `SothCallbackHandler`, a `BaseCallbackHandler` that hooks
into LangChain's per-invocation lifecycle. Customers register it on
their chain / agent / runnable:

    from soth.integrations.langchain import SothCallbackHandler

    chain.invoke({...}, config={"callbacks": [SothCallbackHandler()]})

OR globally via `langchain.callbacks.set_handler(...)`.

The handler maps LangChain's `on_llm_start` / `on_llm_end` /
`on_llm_new_token` / `on_llm_error` events onto SOTH's pre/post
decision lifecycle:

  on_llm_start   → SothSdk.pre_call (block raises SothBlocked)
  on_llm_new_token → StreamObservation.chunk
  on_llm_end     → SothSdk.post_call
  on_llm_error   → SothSdk.post_call (lifecycle balanced even on error)

Robustness contract is the same as the direct provider adapters
(`instrumentation/_base.py`):

  - Idempotent: registering the same handler instance twice is safe
  - Fail-open: extractor exceptions don't break the customer's chain
  - Version-tolerant: defensive `getattr` on LangChain types
  - Async-aware: also implements `AsyncCallbackHandler` methods
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Optional
from uuid import UUID

logger = logging.getLogger("soth.integrations.langchain")

try:
    from langchain_core.callbacks import (  # type: ignore
        AsyncCallbackHandler,
        BaseCallbackHandler,
    )
    _LC_AVAILABLE = True
except ImportError:
    _LC_AVAILABLE = False

    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Stub used when langchain isn't installed; instantiating
        SothCallbackHandler raises with a helpful pip-install hint."""

        pass

    class AsyncCallbackHandler:  # type: ignore[no-redef]
        pass


def _ensure_langchain() -> None:
    if not _LC_AVAILABLE:
        raise ImportError(
            "langchain-core is required for soth.integrations.langchain. "
            "Install with: pip install soth[langchain] or pip install langchain-core"
        )


class SothCallbackHandler(BaseCallbackHandler, AsyncCallbackHandler):
    """LangChain callback handler that routes LLM calls through SOTH.

    Synchronous and async chains both work — this class implements
    both `BaseCallbackHandler` and `AsyncCallbackHandler`. LangChain's
    callback dispatcher invokes the right method based on the
    chain's execution mode.

    Block decisions surface as `SothBlocked` raised from `on_llm_start`,
    which propagates up through LangChain's invoke() and aborts the
    chain — same semantic as direct instrumentation.
    """

    raise_error: bool = True
    """LangChain's BaseCallbackHandler reads `raise_error` to decide
    whether exceptions in the handler should propagate. We MUST raise
    so SothBlocked surfaces to the customer."""

    run_inline: bool = True
    """LangChain runs callbacks asynchronously by default; we need
    them inline so pre_call's decision arrives before LangChain
    forwards to the provider."""

    def __init__(self) -> None:
        _ensure_langchain()
        # Per-run state keyed by LangChain's `run_id` so concurrent
        # invocations don't collide. The lock guards the dict.
        self._runs: dict[UUID, dict[str, Any]] = {}
        self._lock = threading.Lock()

    # ── sync handlers ───────────────────────────────────────────────

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        invocation_params: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        self._handle_start(
            serialized=serialized,
            messages=[{"role": "user", "content": p} for p in prompts],
            invocation_params=invocation_params,
            run_id=run_id,
            **kwargs,
        )

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        invocation_params: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        # `messages` is `list[list[BaseMessage]]` (one inner list per
        # generation). Use the first generation's messages for the
        # call shape — most chains have generation_count=1.
        first_gen = messages[0] if messages else []
        norm_messages = [_normalize_lc_message(m) for m in first_gen]
        self._handle_start(
            serialized=serialized,
            messages=norm_messages,
            invocation_params=invocation_params,
            run_id=run_id,
            **kwargs,
        )

    def on_llm_new_token(self, token: str, *, run_id: UUID, **kwargs: Any) -> None:
        with self._lock:
            state = self._runs.get(run_id)
        if state is None:
            return
        observation = state.get("observation")
        if observation is None:
            return
        try:
            sequence = state["sequence"]
            observation.chunk(sequence, token, None)
            state["sequence"] = sequence + 1
        except Exception as e:  # noqa: BLE001
            logger.warning("soth: chunk emit failed for run %s: %s", run_id, e)

    def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
        self._finalize(run_id)

    def on_llm_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        # Always balance the slab — even if the provider call failed.
        self._finalize(run_id)

    # ── async handlers (mirror of the sync ones) ───────────────────

    async def on_llm_start_async(self, *args: Any, **kwargs: Any) -> None:
        self.on_llm_start(*args, **kwargs)

    async def on_chat_model_start_async(self, *args: Any, **kwargs: Any) -> None:
        self.on_chat_model_start(*args, **kwargs)

    async def on_llm_new_token_async(self, token: str, **kwargs: Any) -> None:
        self.on_llm_new_token(token, **kwargs)

    async def on_llm_end_async(self, response: Any, **kwargs: Any) -> None:
        self.on_llm_end(response, **kwargs)

    async def on_llm_error_async(self, error: BaseException, **kwargs: Any) -> None:
        self.on_llm_error(error, **kwargs)

    # ── shared logic ────────────────────────────────────────────────

    def _handle_start(
        self,
        *,
        serialized: dict[str, Any],
        messages: list[dict[str, str]],
        invocation_params: Optional[dict[str, Any]],
        run_id: UUID,
        **_: Any,
    ) -> None:
        from .. import SothBlocked, _current_context, _soth_native, get_sdk
        from ..exceptions import block_reason_from_dict

        try:
            call = _build_call_from_lc(serialized, messages, invocation_params)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "soth: build_call failed for langchain run %s: %s; bypassed",
                run_id,
                e,
            )
            return

        try:
            sdk = get_sdk()
        except RuntimeError:
            logger.warning(
                "soth: SothCallbackHandler used before soth.init(); bypassed"
            )
            return

        ctx = _current_context.get() or None
        is_streaming = bool(call.get("stream"))
        try:
            if is_streaming:
                decision, observation = sdk.stream_begin(call, ctx)
            else:
                decision = sdk.pre_call(call, ctx)
                observation = None
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "soth: pre_call/stream_begin failed for langchain run %s: %s; bypassed",
                run_id,
                e,
            )
            return

        token = decision["token"]
        kind = decision["kind"]

        with self._lock:
            self._runs[run_id] = {
                "token": token,
                "observation": observation,
                "sequence": 0,
                "is_streaming": is_streaming,
            }

        if kind == _soth_native.DECISION_KIND_BLOCK:
            # Balance the slab before raising so the run cleans up.
            self._finalize(run_id)
            raise SothBlocked(
                decision_id=str(token),
                reason=block_reason_from_dict(decision.get("reason", {})),
            )

    def _finalize(self, run_id: UUID) -> None:
        from .. import get_sdk

        with self._lock:
            state = self._runs.pop(run_id, None)
        if state is None:
            return
        try:
            sdk = get_sdk()
        except RuntimeError:
            return
        try:
            if state.get("is_streaming") and state.get("observation") is not None:
                state["observation"].end()
            else:
                sdk.post_call(state["token"], None)
        except Exception as e:  # noqa: BLE001
            logger.warning("soth: finalize failed for langchain run %s: %s", run_id, e)


# ── helpers ─────────────────────────────────────────────────────────


def _normalize_lc_message(message: Any) -> dict[str, str]:
    """Flatten a LangChain BaseMessage into `{role, content}`."""
    msg_type = getattr(message, "type", None) or "user"
    # LangChain's `.type` is `human` / `ai` / `system` / `tool`;
    # normalize to OpenAI-style roles for consistent hashing.
    role_map = {"human": "user", "ai": "assistant", "system": "system", "tool": "tool"}
    role = role_map.get(msg_type, msg_type)
    content = getattr(message, "content", "")
    if isinstance(content, list):
        # Multi-modal content blocks; flatten text parts.
        parts = []
        for p in content:
            if isinstance(p, dict):
                text = p.get("text", "")
            else:
                text = getattr(p, "text", "")
            if text:
                parts.append(str(text))
        content = " ".join(parts)
    return {"role": str(role), "content": str(content) if content else ""}


def _build_call_from_lc(
    serialized: dict[str, Any],
    messages: list[dict[str, str]],
    invocation_params: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Derive a SOTH LlmCall dict from LangChain's start-event args."""
    invocation_params = invocation_params or {}

    # `serialized` describes the model class. Walk a few common paths
    # to extract a provider hint and the configured model name.
    provider, model = _extract_provider_and_model(serialized, invocation_params)

    is_streaming = bool(invocation_params.get("stream", False))

    return {
        "provider": provider,
        "model": model,
        "messages": messages,
        "stream": is_streaming,
    }


def _extract_provider_and_model(
    serialized: dict[str, Any], params: dict[str, Any]
) -> tuple[str, str]:
    """Pull `(provider, model)` from LangChain's serialized model info.

    The `serialized` shape is roughly:
        {"id": ["langchain_openai", "ChatOpenAI"], "kwargs": {"model": "gpt-4o"}}

    Provider is inferred from the import path; model from kwargs or
    the invocation params. Defaults to `("unknown", "")` if extraction
    fails — the SDK still operates, just with degraded attribution.
    """
    id_path = serialized.get("id") if isinstance(serialized, dict) else None
    provider = "unknown"
    if isinstance(id_path, list) and id_path:
        first = str(id_path[0]).lower()
        if "openai" in first:
            provider = "openai"
        elif "anthropic" in first:
            provider = "anthropic"
        elif "cohere" in first:
            provider = "cohere"
        elif "google" in first or "vertex" in first or "gemini" in first:
            provider = "google_genai"
        elif "mistral" in first:
            provider = "mistralai"

    serialized_kwargs = (
        serialized.get("kwargs", {}) if isinstance(serialized, dict) else {}
    )
    model = (
        params.get("model")
        or params.get("model_name")
        or serialized_kwargs.get("model")
        or serialized_kwargs.get("model_name")
        or ""
    )
    return provider, str(model)


__all__ = ["SothCallbackHandler"]
