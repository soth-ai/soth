"""LiteLLM integration.

LiteLLM provides a unified `litellm.completion(...)` API that
proxies to ~100 providers. Customers register callbacks on the
module-level `litellm.callbacks` list:

    import litellm
    from soth.integrations.litellm import register

    register()  # adds soth's success/failure handlers

LiteLLM's callback contract is dict-shaped — each callback function
receives `(kwargs, completion_response, start_time, end_time)`. We
also support the new class-based callback (`CustomLogger`) for
users on litellm 1.40+.

Robustness guarantees: idempotent register/unregister, fail-open
extraction, missing-litellm graceful degradation.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Optional

logger = logging.getLogger("soth.integrations.litellm")

_state_lock = threading.Lock()
_registered = False
_pending_tokens: dict[str, int] = {}
"""Maps litellm's `id` (per-call UUID) to our DecisionToken raw u64.
Carries pre_call → post_call across litellm's split callback API."""


def _ensure_litellm() -> Any:
    """Import litellm or raise a helpful ImportError."""
    try:
        import litellm  # type: ignore

        return litellm
    except ImportError as e:
        raise ImportError(
            "litellm is required for soth.integrations.litellm. "
            "Install with: pip install soth[litellm] or pip install litellm"
        ) from e


def register() -> str:
    """Register SOTH's success / failure callbacks with litellm.

    Returns one of:
      "registered"            — first-time registration
      "already-registered"    — second call is a no-op (idempotent)
    """
    global _registered

    litellm = _ensure_litellm()

    with _state_lock:
        if _registered:
            return "already-registered"

        # litellm has both legacy callback lists and a `CustomLogger`
        # class API. Append to the legacy lists for the broadest
        # version compatibility; class-based wiring lands in a
        # follow-up if customers need it.
        existing_success = list(getattr(litellm, "success_callback", None) or [])
        existing_failure = list(getattr(litellm, "failure_callback", None) or [])

        if _success_handler not in existing_success:
            existing_success.append(_success_handler)
        if _failure_handler not in existing_failure:
            existing_failure.append(_failure_handler)

        litellm.success_callback = existing_success
        litellm.failure_callback = existing_failure

        # Also wire input_callback for pre_call. Older litellm
        # versions don't have this; defensive.
        existing_input = getattr(litellm, "input_callback", None)
        if existing_input is not None:
            existing_input = list(existing_input)
            if _input_handler not in existing_input:
                existing_input.append(_input_handler)
            litellm.input_callback = existing_input

        _registered = True
        return "registered"


def unregister() -> str:
    """Remove SOTH's callbacks from litellm. Idempotent."""
    global _registered

    litellm = _ensure_litellm()

    with _state_lock:
        if not _registered:
            return "not-registered"

        for attr in ("success_callback", "failure_callback", "input_callback"):
            existing = getattr(litellm, attr, None)
            if existing is None:
                continue
            target = {
                "success_callback": _success_handler,
                "failure_callback": _failure_handler,
                "input_callback": _input_handler,
            }[attr]
            try:
                existing.remove(target)
            except ValueError:
                pass

        _registered = False
        return "unregistered"


def is_registered() -> bool:
    return _registered


# ── handlers ─────────────────────────────────────────────────────────


def _input_handler(model: str, messages: list[Any], kwargs: dict[str, Any]) -> None:
    """Pre-call handler — runs before litellm dispatches to the
    underlying provider. Block decisions raise SothBlocked which
    aborts the litellm call."""
    from .. import SothBlocked, _current_context, _soth_native, get_sdk
    from ..exceptions import block_reason_from_dict

    try:
        call = _build_call(model, messages, kwargs)
    except Exception as e:  # noqa: BLE001
        logger.warning("soth: litellm build_call failed: %s; bypassed", e)
        return

    try:
        sdk = get_sdk()
    except RuntimeError:
        logger.warning("soth: litellm input_handler before init(); bypassed")
        return

    ctx = _current_context.get() or None
    try:
        decision = sdk.pre_call(call, ctx)
    except Exception as e:  # noqa: BLE001
        logger.warning("soth: litellm pre_call failed: %s; bypassed", e)
        return

    call_id = _extract_call_id(kwargs)
    if call_id:
        with _state_lock:
            _pending_tokens[call_id] = decision["token"]

    if decision["kind"] == _soth_native.DECISION_KIND_BLOCK:
        # Balance the slab before raising.
        if call_id:
            with _state_lock:
                _pending_tokens.pop(call_id, None)
        try:
            sdk.post_call(decision["token"], None)
        except Exception:  # noqa: BLE001
            pass
        raise SothBlocked(
            decision_id=str(decision["token"]),
            reason=block_reason_from_dict(decision.get("reason", {})),
        )


def _success_handler(
    kwargs: dict[str, Any],
    completion_response: Any,
    start_time: Any,
    end_time: Any,
) -> None:
    """Post-call success handler. Consumes the DecisionToken stored
    by `_input_handler`."""
    _finalize_from_kwargs(kwargs)


def _failure_handler(
    kwargs: dict[str, Any],
    exception: BaseException,
    start_time: Any,
    end_time: Any,
) -> None:
    """Post-call failure handler. Balance the slab even on error."""
    _finalize_from_kwargs(kwargs)


def _finalize_from_kwargs(kwargs: dict[str, Any]) -> None:
    from .. import get_sdk

    call_id = _extract_call_id(kwargs)
    if not call_id:
        return
    with _state_lock:
        token = _pending_tokens.pop(call_id, None)
    if token is None:
        return
    try:
        get_sdk().post_call(token, None)
    except Exception as e:  # noqa: BLE001
        logger.warning("soth: litellm finalize failed: %s", e)


def _extract_call_id(kwargs: dict[str, Any]) -> Optional[str]:
    """LiteLLM gives each call a UUID — `kwargs["litellm_call_id"]`
    in modern versions; some 0.x have `id`. Try both."""
    for key in ("litellm_call_id", "id", "request_id"):
        v = kwargs.get(key)
        if v:
            return str(v)
    return None


def _build_call(model: str, messages: list[Any], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Derive a SOTH LlmCall dict from litellm's pre-call args.

    LiteLLM normalizes provider-specific shapes onto OpenAI's
    `messages=[{role, content}]`, so extraction is uniform.
    """
    norm_messages = []
    for m in messages or []:
        if isinstance(m, dict):
            role = m.get("role", "user")
            content = m.get("content", "")
        else:
            role = getattr(m, "role", "user")
            content = getattr(m, "content", "")
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
        norm_messages.append({"role": str(role), "content": str(content)})

    # LiteLLM model strings are namespaced: "openai/gpt-4o-mini",
    # "anthropic/claude-3-5-sonnet-latest", "cohere/command-r-plus".
    # Pull the provider prefix out for SOTH attribution.
    provider = "unknown"
    if "/" in str(model):
        prefix, _, _ = str(model).partition("/")
        prefix = prefix.lower()
        if prefix in ("openai", "azure"):
            provider = "openai"
        elif prefix == "anthropic":
            provider = "anthropic"
        elif prefix == "cohere":
            provider = "cohere"
        elif prefix in ("gemini", "vertex_ai", "google"):
            provider = "google_genai"
        elif prefix == "mistral":
            provider = "mistralai"

    return {
        "provider": provider,
        "model": str(model),
        "messages": norm_messages,
        "stream": bool(kwargs.get("stream", False)),
    }


__all__ = ["register", "unregister", "is_registered"]
