"""Robustness tests for `soth.instrument()`.

Each test asserts one of the contract guarantees in
`python/soth/instrumentation/__init__.py`:

  - idempotent: instrument() called twice returns "skipped:already-…"
  - reversible: uninstrument() restores originals
  - missing-provider tolerant: not-installed providers don't raise
  - fail-open extractor: build_call exceptions fall through
  - double-wrap detection: __soth_wrapped__ marker survives revert
  - sync coroutine handling: guard() handles awaitable returns

The tests do NOT require openai / anthropic to be installed; they
either skip when the package is absent (so CI without optional deps
still passes) or use mock classes / objects.

Run with:
    cd bindings/soth-py
    pip install -e ".[test]"
    maturin develop
    pytest tests/test_instrumentation.py
"""

import os
from typing import Any
from unittest import mock

import pytest

import soth
from soth.instrumentation import _base, _reset_state_for_test


@pytest.fixture(autouse=True)
def _init_sdk():
    os.environ["SOTH_HMAC_KEY"] = "x" * 32
    soth.init(
        api_key="sk-test",
        org_id="org-test",
        hmac_key_env="SOTH_HMAC_KEY",
    )
    # Reset instrumentation state before each test so they don't bleed.
    _reset_state_for_test()
    yield
    _reset_state_for_test()


# ── idempotency / reversibility ─────────────────────────────────────


def test_instrument_idempotent_second_call_returns_already_instrumented():
    """Calling instrument() twice must NOT double-wrap. The second
    call returns 'skipped:already-instrumented' for any provider the
    first call patched."""
    first = soth.instrument()
    second = soth.instrument()

    # Whatever first instrumented, second must report as already-done.
    for provider, status in first.items():
        if status == "instrumented":
            assert second[provider] == "skipped:already-instrumented", (
                f"{provider}: idempotency violated. first={status}, second={second[provider]}"
            )


def test_uninstrument_reverses_instrument():
    """After uninstrument(), state.is_instrumented(p) is False for
    every previously-instrumented provider."""
    first = soth.instrument()
    soth.uninstrument()

    for provider, status in first.items():
        if status == "instrumented":
            assert soth.is_instrumented(provider) is False, (
                f"{provider} still reports as instrumented after uninstrument()"
            )


def test_uninstrument_without_prior_instrument_is_safe():
    """uninstrument() before any instrument() returns
    'skipped:not-instrumented' rather than raising."""
    results = soth.uninstrument()
    for provider, status in results.items():
        assert status in ("skipped:not-instrumented", "skipped:disabled")


# ── provider selection ─────────────────────────────────────────────


def test_instrument_with_explicit_providers_skips_others():
    """Passing providers=['openai'] leaves anthropic at
    'skipped:disabled' regardless of whether anthropic is installed."""
    results = soth.instrument(providers=["openai"])
    assert results.get("anthropic") == "skipped:disabled"


def test_instrument_unknown_provider_is_silently_skipped():
    """Listing an unknown provider in the explicit set doesn't error;
    known providers still process normally."""
    results = soth.instrument(providers=["openai", "definitely-not-a-provider"])
    # Known provider gets processed (instrumented or skipped).
    assert "openai" in results
    # Unknown provider isn't in the registry, so it's not in results.
    assert "definitely-not-a-provider" not in results


# ── missing-provider tolerance ─────────────────────────────────────


def test_missing_provider_returns_skipped_not_installed(monkeypatch):
    """If the provider package isn't importable, the entry returns
    'skipped:not-installed' rather than raising ImportError."""
    # Force the openai adapter's apply() to behave as if openai is
    # uninstalled by monkey-patching its import.
    from soth.instrumentation import _openai

    def _apply_returns_false():
        return False

    monkeypatch.setattr(_openai, "apply", _apply_returns_false)
    results = soth.instrument(providers=["openai"])
    assert results["openai"] == "skipped:not-installed"


# ── fail-open extractor ────────────────────────────────────────────


def test_build_call_exception_falls_through_to_original(monkeypatch):
    """If the buildCall extractor raises, the wrapper invokes the
    original method without going through SOTH's lifecycle. The
    customer's call must complete unaffected."""
    # Mock the wrap_method machinery against a hand-rolled class.
    class FakeClient:
        def create(self, **kwargs):
            return {"ok": True, "kwargs": kwargs}

    def busted_build_call(args, kwargs):
        raise RuntimeError("simulated extractor crash")

    patch = _base.wrap_method(
        FakeClient,
        "create",
        provider_name="fake",
        build_call=busted_build_call,
    )
    assert patch is not None

    client = FakeClient()
    # The original behavior must be preserved despite the extractor
    # raising — fail-open.
    result = client.create(model="x", messages=[])
    assert result == {"ok": True, "kwargs": {"model": "x", "messages": []}}

    # Restore so other tests aren't polluted.
    _base.revert_all([patch])


# ── double-wrap detection ──────────────────────────────────────────


def test_wrapped_method_carries_soth_provenance_marker():
    """The wrapper records `__soth_wrapped__` and `__soth_provider__`
    so `revert_all` can detect whether another tool has overwritten
    our wrapper after we patched."""
    class Target:
        def m(self):
            return 1

    patch = _base.wrap_method(
        Target,
        "m",
        provider_name="test",
        build_call=lambda args, kwargs: {"provider": "test", "model": "", "messages": []},
    )
    assert patch is not None
    assert _base.is_instrumented_method(Target.m) is True
    assert getattr(Target.m, "__soth_provider__", None) == "test"
    _base.revert_all([patch])


def test_revert_leaves_third_party_wrapper_in_place():
    """If another tool wraps over our wrapper after we patch, revert
    must NOT clobber it. Our wrapper is gone-but-not-replaced — the
    third-party wrapper persists."""
    class Target:
        def m(self):
            return 1

    patch = _base.wrap_method(
        Target,
        "m",
        provider_name="test",
        build_call=lambda args, kwargs: {"provider": "test", "model": "", "messages": []},
    )
    assert patch is not None

    # Simulate another tool wrapping over our wrapper.
    soth_wrapper = Target.m
    def third_party_wrapper(self, *args, **kwargs):
        return soth_wrapper(self, *args, **kwargs)
    Target.m = third_party_wrapper  # type: ignore[method-assign]

    _base.revert_all([patch])
    # The third-party wrapper should still be there — we don't
    # overwrite a non-soth wrapper.
    assert Target.m is third_party_wrapper


# ── coroutine handling for guard() ─────────────────────────────────


@pytest.mark.asyncio
async def test_guard_returns_coroutine_when_inner_returns_coroutine():
    """When the wrapped call_fn returns a coroutine, guard() must
    return a coroutine that, when awaited, finalizes the lifecycle.
    This makes one guard() entry-point work for both sync (OpenAI)
    and async (AsyncOpenAI) clients."""
    async def inner():
        return "async-result"

    result_coro = soth.guard(
        inner,
        call={
            "provider": "openai",
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hi"}],
        },
    )
    # guard() returned the coroutine; nothing has run yet.
    assert result_coro is not None
    # Awaiting finalizes the lifecycle.
    result = await result_coro
    assert result == "async-result"
    assert soth._in_flight_decisions() == 0


def test_guard_runs_synchronously_when_inner_returns_value():
    """Sync providers return a plain value from call_fn. guard()
    finalizes inline and returns the value — no coroutine wrapping."""
    result = soth.guard(
        lambda: "sync-result",
        call={
            "provider": "openai",
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hi"}],
        },
    )
    assert result == "sync-result"
    assert soth._in_flight_decisions() == 0


# ── adapter integration (only when SDKs installed) ─────────────────


def test_openai_adapter_apply_returns_bool():
    """The adapter's apply() must return True/False — never raise.
    On systems without openai installed, it returns False; with
    openai installed, returns True. Either way, no exception."""
    from soth.instrumentation import _openai

    result = _openai.apply()
    assert result in (True, False)
    if result is True:
        # Restore so other tests aren't polluted.
        _openai.revert()


def test_anthropic_adapter_apply_returns_bool():
    from soth.instrumentation import _anthropic

    result = _anthropic.apply()
    assert result in (True, False)
    if result is True:
        _anthropic.revert()


def test_cohere_adapter_apply_returns_bool():
    from soth.instrumentation import _cohere

    result = _cohere.apply()
    assert result in (True, False)
    if result is True:
        _cohere.revert()


def test_google_genai_adapter_apply_returns_bool():
    from soth.instrumentation import _google_genai

    result = _google_genai.apply()
    assert result in (True, False)
    if result is True:
        _google_genai.revert()


def test_mistral_adapter_apply_returns_bool():
    from soth.instrumentation import _mistral

    result = _mistral.apply()
    assert result in (True, False)
    if result is True:
        _mistral.revert()


# ── extractor unit tests (no provider SDK install required) ────────


def test_cohere_v2_extractor_normalizes_messages():
    from soth.instrumentation._cohere import _build_call_v2

    call = _build_call_v2(
        (),
        {
            "model": "command-r-plus",
            "messages": [
                {"role": "user", "content": "hello"},
                {
                    "role": "assistant",
                    "content": [{"text": "hi"}, {"text": "there"}],
                },
            ],
            "stream": False,
        },
    )
    assert call["provider"] == "cohere"
    assert call["model"] == "command-r-plus"
    assert call["messages"][0] == {"role": "user", "content": "hello"}
    assert call["messages"][1]["content"] == "hi there"


def test_cohere_v4_extractor_promotes_message_to_messages():
    from soth.instrumentation._cohere import _build_call_v4

    call = _build_call_v4(
        (),
        {
            "model": "command-r-plus",
            "message": "current question",
            "chat_history": [
                {"role": "USER", "message": "earlier"},
                {"role": "CHATBOT", "message": "earlier reply"},
            ],
        },
    )
    assert call["messages"][-1] == {"role": "user", "content": "current question"}
    assert call["messages"][1] == {"role": "assistant", "content": "earlier reply"}


def test_google_genai_extractor_handles_string_contents():
    from soth.instrumentation._google_genai import _build_call

    call = _build_call(
        (),
        {"model": "gemini-2.0-flash", "contents": "explain rust"},
    )
    assert call["provider"] == "google_genai"
    assert call["messages"] == [{"role": "user", "content": "explain rust"}]


def test_google_genai_extractor_handles_list_of_content_dicts():
    from soth.instrumentation._google_genai import _build_call

    call = _build_call(
        (),
        {
            "model": "gemini-2.0-flash",
            "contents": [
                {"role": "user", "parts": [{"text": "first"}]},
                {"role": "model", "parts": [{"text": "answer"}]},
                {"role": "user", "parts": [{"text": "follow-up"}]},
            ],
        },
    )
    assert len(call["messages"]) == 3
    assert call["messages"][0]["content"] == "first"
    assert call["messages"][1]["role"] == "model"


def test_mistral_extractor_normalizes_messages():
    from soth.instrumentation._mistral import _build_call

    call = _build_call(
        (),
        {
            "model": "mistral-large-latest",
            "messages": [{"role": "user", "content": "hi"}],
        },
    )
    assert call["provider"] == "mistralai"
    assert call["messages"][0] == {"role": "user", "content": "hi"}
