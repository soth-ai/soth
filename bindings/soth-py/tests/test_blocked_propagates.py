"""Negative tests for the `SothBlocked` propagation contract.

`SDK_DECISION_API_SPEC.md` §6 commits that `SothBlocked` does NOT
inherit from any provider SDK exception type and MUST propagate past
existing `try/except openai.APIError` handlers. Customers' retry
logic catches `openai.APIError` to retry on rate limits / 5xx; a
policy block must NOT be silently retried.

If any future change to `SothBlocked` makes it inherit from
`openai.APIError` (or any provider's hierarchy), one of these tests
fails immediately.

Run with:
    cd bindings/soth-py
    pip install ".[test]"
    maturin develop
    pytest tests/test_blocked_propagates.py
"""

import os

import pytest

import soth

# Some test environments don't have openai installed. Skip the negative
# tests rather than failing — but DO emit a clear message so CI catches
# the missing dep.
openai = pytest.importorskip(
    "openai",
    reason="openai is required for the SothBlocked propagation contract test "
    "(install via `pip install soth[test]` or `pip install openai`)",
)


def _make_blocking_call():
    return soth.guard(
        lambda: "should not be called",
        call={
            "provider": "openai",
            "model": "gpt-4o-mini",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "leaked sk-abcdefghijklmnopqrstuvwxyzABCD1234567890 here"
                    ),
                }
            ],
        },
    )


@pytest.fixture(autouse=True)
def _init_sdk():
    os.environ["SOTH_HMAC_KEY"] = "x" * 32
    soth.init(
        api_key="sk-test",
        org_id="org-test",
        hmac_key_env="SOTH_HMAC_KEY",
    )
    yield


def test_soth_blocked_does_not_inherit_from_openai_apierror():
    """Static check — if this fails the inheritance hierarchy is wrong."""
    assert not issubclass(soth.SothBlocked, openai.APIError), (
        "SothBlocked must NOT inherit from openai.APIError. See "
        "SDK_DECISION_API_SPEC.md §6.1."
    )


def test_soth_blocked_propagates_past_openai_apierror_handler():
    """Customer code with `try/except openai.APIError` MUST NOT swallow
    SothBlocked. The block propagates past the API-error handler."""
    caught_apierror = False
    caught_soth = False

    try:
        try:
            _make_blocking_call()
        except openai.APIError:
            caught_apierror = True
    except soth.SothBlocked:
        caught_soth = True

    assert not caught_apierror, (
        "SothBlocked was caught by `except openai.APIError` — that's a "
        "spec violation. See SDK_DECISION_API_SPEC.md §6.1."
    )
    assert caught_soth, "SothBlocked must propagate past openai.APIError"


def test_soth_blocked_inherits_from_base_exception_directly():
    """SothBlocked extends Exception, not BaseException, so KeyboardInterrupt
    handling isn't accidentally trapped."""
    # Exception in MRO; BaseException at the top.
    mro_names = [cls.__name__ for cls in soth.SothBlocked.__mro__]
    assert "Exception" in mro_names
    # Should not be a BaseException-only inheritor (which would be a
    # subclass of GeneratorExit / KeyboardInterrupt etc.).
    assert mro_names[1] == "Exception", (
        "SothBlocked must inherit directly from Exception. Spec §6.1."
    )
