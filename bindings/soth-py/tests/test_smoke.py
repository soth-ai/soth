"""Smoke tests for soth-py.

Mirror the round-trip tests in `crates/soth-sdk-core/tests/round_trip.rs`,
asserting the FFI layer doesn't introduce drift.

Run with:
    cd bindings/soth-py
    maturin develop
    pytest tests/
"""

import os

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


def test_init_creates_singleton():
    sdk = soth.get_sdk()
    assert sdk.in_flight_decisions() == 0


def test_pre_post_call_round_trip_emits_telemetry():
    captured = {}

    def fake_call():
        captured["called"] = True
        return "ok"

    result = soth.guard(
        fake_call,
        call={
            "provider": "openai",
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello"}],
        },
    )
    assert result == "ok"
    assert captured.get("called") is True
    assert soth._in_flight_decisions() == 0
    events = soth._drain_telemetry_for_test()
    assert len(events) == 1
    assert events[0]["provider"] == "openai"


def test_credential_in_user_message_blocks():
    def fake_call():
        return "should not be called"

    with pytest.raises(soth.SothBlocked) as excinfo:
        soth.guard(
            fake_call,
            call={
                "provider": "openai",
                "model": "gpt-4o-mini",
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "review this key sk-abcdefghijklmnopqrstuvwxyzABCD1234567890"
                            " for me"
                        ),
                    }
                ],
            },
        )

    assert excinfo.value.reason.kind == "sensitive_artifact"
    assert soth._in_flight_decisions() == 0
