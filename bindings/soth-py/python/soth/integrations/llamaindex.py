"""LlamaIndex integration.

LlamaIndex's callback system uses `BaseEventHandler` + an event
dispatcher. We hook the LLM lifecycle events:
  - LLMChatStartEvent / LLMCompletionStartEvent → SothSdk.pre_call
  - LLMChatEndEvent / LLMCompletionEndEvent → SothSdk.post_call

The integration is intentionally narrow — only LLM events are
hooked, not retrieval / embedding events (those don't go through
SOTH's classify pipeline).

Usage:
    from llama_index.core.instrumentation import get_dispatcher
    from soth.integrations.llamaindex import SothEventHandler

    get_dispatcher().add_event_handler(SothEventHandler())
"""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger("soth.integrations.llamaindex")

try:
    from llama_index.core.instrumentation.event_handlers.base import (  # type: ignore
        BaseEventHandler,
    )
    from llama_index.core.instrumentation.events.llm import (  # type: ignore
        LLMChatEndEvent,
        LLMChatStartEvent,
        LLMCompletionEndEvent,
        LLMCompletionStartEvent,
    )
    _LI_AVAILABLE = True
except ImportError:
    _LI_AVAILABLE = False

    class BaseEventHandler:  # type: ignore[no-redef]
        pass

    LLMChatStartEvent = LLMChatEndEvent = None  # type: ignore[assignment]
    LLMCompletionStartEvent = LLMCompletionEndEvent = None  # type: ignore[assignment]


def _ensure_llamaindex() -> None:
    if not _LI_AVAILABLE:
        raise ImportError(
            "llama-index-core is required for soth.integrations.llamaindex. "
            "Install with: pip install soth[llamaindex] or pip install llama-index-core"
        )


class SothEventHandler(BaseEventHandler):  # type: ignore[misc]
    """LlamaIndex event handler that routes LLM events through SOTH.

    Block decisions raise `SothBlocked` from the start-event handler,
    which propagates up through LlamaIndex's call stack — same
    semantic as direct instrumentation.
    """

    @classmethod
    def class_name(cls) -> str:
        return "SothEventHandler"

    def __init__(self) -> None:
        _ensure_llamaindex()
        # Per-event-id state. LlamaIndex's events have a `.id_` UUID
        # that pairs Start with End.
        self._events: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def handle(self, event: Any, **kwargs: Any) -> None:
        """Single-method dispatcher per BaseEventHandler API."""
        if LLMChatStartEvent is not None and isinstance(event, LLMChatStartEvent):
            self._on_start(event, kind="chat")
        elif LLMCompletionStartEvent is not None and isinstance(
            event, LLMCompletionStartEvent
        ):
            self._on_start(event, kind="completion")
        elif LLMChatEndEvent is not None and isinstance(event, LLMChatEndEvent):
            self._on_end(event)
        elif LLMCompletionEndEvent is not None and isinstance(
            event, LLMCompletionEndEvent
        ):
            self._on_end(event)

    def _on_start(self, event: Any, *, kind: str) -> None:
        from .. import SothBlocked, _current_context, _soth_native, get_sdk
        from ..exceptions import block_reason_from_dict

        try:
            call = _build_call_from_li(event, kind=kind)
        except Exception as e:  # noqa: BLE001
            logger.warning("soth: build_call failed for llamaindex event: %s", e)
            return

        try:
            sdk = get_sdk()
        except RuntimeError:
            logger.warning(
                "soth: SothEventHandler used before soth.init(); bypassed"
            )
            return

        ctx = _current_context.get() or None
        try:
            decision = sdk.pre_call(call, ctx)
        except Exception as e:  # noqa: BLE001
            logger.warning("soth: pre_call failed for llamaindex event: %s", e)
            return

        event_id = str(getattr(event, "id_", ""))
        with self._lock:
            self._events[event_id] = {"token": decision["token"]}

        if decision["kind"] == _soth_native.DECISION_KIND_BLOCK:
            self._end_one(event_id)
            raise SothBlocked(
                decision_id=str(decision["token"]),
                reason=block_reason_from_dict(decision.get("reason", {})),
            )

    def _on_end(self, event: Any) -> None:
        event_id = str(getattr(event, "id_", ""))
        self._end_one(event_id)

    def _end_one(self, event_id: str) -> None:
        from .. import get_sdk

        with self._lock:
            state = self._events.pop(event_id, None)
        if state is None:
            return
        try:
            get_sdk().post_call(state["token"], None)
        except Exception as e:  # noqa: BLE001
            logger.warning("soth: finalize failed for llamaindex event %s: %s", event_id, e)


def _build_call_from_li(event: Any, *, kind: str) -> dict[str, Any]:
    """Extract LlmCall fields from a LlamaIndex Start event."""
    # LlamaIndex events expose `model_dict` or `model_kwargs` — try both.
    model_info = getattr(event, "model_dict", None) or {}
    model_name = (
        getattr(event, "model", None)
        or model_info.get("model")
        or model_info.get("model_name")
        or ""
    )

    # Provider isn't directly on the event; infer from class path.
    provider = "unknown"
    cls_path = type(event).__module__.lower()
    if "openai" in cls_path:
        provider = "openai"
    elif "anthropic" in cls_path:
        provider = "anthropic"
    elif "cohere" in cls_path:
        provider = "cohere"
    elif "gemini" in cls_path or "vertex" in cls_path:
        provider = "google_genai"
    elif "mistral" in cls_path:
        provider = "mistralai"

    if kind == "chat":
        raw_messages = getattr(event, "messages", None) or []
        messages = []
        for m in raw_messages:
            role = getattr(m, "role", None) or "user"
            content = getattr(m, "content", "") or ""
            messages.append({"role": str(role), "content": str(content)})
    else:
        prompt = getattr(event, "prompt", "") or ""
        messages = [{"role": "user", "content": str(prompt)}]

    return {
        "provider": provider,
        "model": str(model_name),
        "messages": messages,
        "stream": False,  # LlamaIndex doesn't expose stream-vs-not on the event
    }


__all__ = ["SothEventHandler"]
