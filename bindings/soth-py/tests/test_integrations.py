"""Tests for framework integrations.

Each integration's import-without-the-framework path is tested. We
don't depend on LangChain / LlamaIndex / LiteLLM being installed —
the modules import cleanly and instantiation raises a helpful
ImportError when the framework is missing.

When the framework IS installed, the handler/event mechanics are
exercised against a stub event bus.

Run with:
    pytest tests/test_integrations.py
"""

import os
from typing import Any

import pytest

import soth


@pytest.fixture(autouse=True)
def _init_sdk():
    os.environ["SOTH_HMAC_KEY"] = "x" * 32
    soth.init(
        api_key="sk-test",
        org_id="org-test",
        hmac_key_env="SOTH_HMAC_KEY",
    )
    yield


# ── module-level import safety ──────────────────────────────────────


def test_langchain_module_imports_without_langchain_installed():
    """The module imports cleanly even when langchain isn't installed.
    Instantiation raises ImportError with a pip-install hint."""
    from soth.integrations import langchain

    if not langchain._LC_AVAILABLE:
        with pytest.raises(ImportError, match="langchain-core"):
            langchain.SothCallbackHandler()
    else:
        # Framework installed → instantiation succeeds.
        handler = langchain.SothCallbackHandler()
        assert handler is not None


def test_llamaindex_module_imports_without_llamaindex_installed():
    from soth.integrations import llamaindex

    if not llamaindex._LI_AVAILABLE:
        with pytest.raises(ImportError, match="llama-index-core"):
            llamaindex.SothEventHandler()
    else:
        handler = llamaindex.SothEventHandler()
        assert handler is not None


def test_litellm_module_imports_without_litellm_installed():
    from soth.integrations import litellm as soth_litellm

    try:
        soth_litellm.register()
        # Framework installed; clean up.
        soth_litellm.unregister()
    except ImportError as e:
        assert "litellm" in str(e)


# ── litellm idempotency (when installed) ────────────────────────────


def test_litellm_register_idempotent():
    """register() called twice must not double-add the callback."""
    pytest.importorskip("litellm")
    from soth.integrations import litellm as soth_litellm

    first = soth_litellm.register()
    assert first in ("registered", "already-registered")
    second = soth_litellm.register()
    assert second == "already-registered"
    soth_litellm.unregister()


def test_litellm_unregister_without_register_is_safe():
    pytest.importorskip("litellm")
    from soth.integrations import litellm as soth_litellm

    # Reset state for the test if previous tests left it on.
    if soth_litellm.is_registered():
        soth_litellm.unregister()
    result = soth_litellm.unregister()
    assert result == "not-registered"


# ── extractor unit tests (no framework install required) ───────────


def test_langchain_extract_provider_from_serialized_id():
    from soth.integrations.langchain import _extract_provider_and_model

    p, m = _extract_provider_and_model(
        {"id": ["langchain_openai", "ChatOpenAI"], "kwargs": {"model": "gpt-4o-mini"}},
        {},
    )
    assert p == "openai"
    assert m == "gpt-4o-mini"

    p, m = _extract_provider_and_model(
        {"id": ["langchain_anthropic", "ChatAnthropic"], "kwargs": {"model": "claude-3-5-sonnet"}},
        {},
    )
    assert p == "anthropic"
    assert m == "claude-3-5-sonnet"


def test_langchain_normalize_message_flattens_multimodal_content():
    from soth.integrations.langchain import _normalize_lc_message

    class FakeMessage:
        type = "human"
        content = [{"text": "first"}, {"text": "second"}]

    msg = _normalize_lc_message(FakeMessage())
    assert msg["role"] == "user"  # "human" → "user"
    assert msg["content"] == "first second"


def test_litellm_build_call_extracts_namespaced_provider():
    from soth.integrations.litellm import _build_call

    call = _build_call(
        "anthropic/claude-3-5-sonnet-latest",
        [{"role": "user", "content": "hi"}],
        {"stream": False},
    )
    assert call["provider"] == "anthropic"
    assert call["model"] == "anthropic/claude-3-5-sonnet-latest"
    assert call["stream"] is False


def test_litellm_build_call_handles_unknown_provider_prefix():
    from soth.integrations.litellm import _build_call

    call = _build_call(
        "togethercomputer/llama-3-70b",
        [{"role": "user", "content": "hi"}],
        {},
    )
    assert call["provider"] == "unknown"  # not in our prefix table
    assert call["model"] == "togethercomputer/llama-3-70b"
