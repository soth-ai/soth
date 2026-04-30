"""Streaming round-trip tests for soth-py.

Mirrors the streaming smoke test in `crates/soth-sdk-core/tests/round_trip.rs`,
asserting the FFI streaming surface (`stream_begin` + chunk/end) doesn't
introduce drift.

Run with:
    cd bindings/soth-py
    maturin develop
    pytest tests/test_streaming.py
"""

import asyncio
import os
from typing import Any

import pytest

import soth


class FakeChoice:
    def __init__(self, content: str, finish_reason: str | None = None):
        self.delta = type("Delta", (), {"content": content})()
        self.finish_reason = finish_reason


class FakeChunk:
    def __init__(self, content: str, finish_reason: str | None = None):
        self.choices = [FakeChoice(content, finish_reason)]


async def fake_openai_stream(deltas: list[str]):
    """Mimics openai's async stream — yields chunks shaped like the
    real ChatCompletionChunk objects. Last chunk carries finish_reason."""
    for i, delta in enumerate(deltas):
        finish = "stop" if i == len(deltas) - 1 else None
        yield FakeChunk(delta, finish)
        # Yield to the event loop so this looks like a real network stream.
        await asyncio.sleep(0)


@pytest.fixture(autouse=True)
def _init_sdk():
    os.environ["SOTH_HMAC_KEY"] = "x" * 32
    soth.init(
        api_key="sk-test",
        org_id="org-test",
        hmac_key_env="SOTH_HMAC_KEY",
    )
    yield


@pytest.mark.asyncio
async def test_stream_round_trip_consumes_token_once():
    deltas = ["hello ", "world", "!"]
    received: list[Any] = []

    async for chunk in soth.guard_stream(
        lambda: fake_openai_stream(deltas),
        call={
            "provider": "openai",
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "say hi"}],
            "stream": True,
        },
    ):
        received.append(chunk)

    assert len(received) == 3
    assert soth._in_flight_decisions() == 0
    events = soth._drain_telemetry_for_test()
    assert len(events) == 1
    assert events[0]["provider"] == "openai"


@pytest.mark.asyncio
async def test_stream_blocks_on_credential_in_user_message():
    async def _consume():
        async for _ in soth.guard_stream(
            lambda: fake_openai_stream(["should ", "not ", "stream"]),
            call={
                "provider": "openai",
                "model": "gpt-4o-mini",
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "review key sk-abcdefghijklmnopqrstuvwxyzABCD1234567890"
                        ),
                    }
                ],
                "stream": True,
            },
        ):
            pass

    with pytest.raises(soth.SothBlocked):
        await _consume()
    assert soth._in_flight_decisions() == 0


@pytest.mark.asyncio
async def test_stream_observation_double_end_is_idempotent():
    deltas = ["a", "b"]
    sdk = soth.get_sdk()
    decision, obs = sdk.stream_begin(
        {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": True,
        }
    )
    assert decision["kind"] == "allow"
    obs.chunk(0, "a", None)
    obs.chunk(1, "b", "stop")
    obs.end()
    # Second end is a documented no-op (logged warning, no exception).
    obs.end()
    assert sdk.in_flight_decisions() == 0


# pytest-asyncio configuration — keeps this self-contained so the suite
# doesn't require a project-level conftest.
def pytest_collection_modifyitems(config, items):
    # No-op; pytest-asyncio's `asyncio_mode = "auto"` would normally be
    # set in pyproject.toml. The `@pytest.mark.asyncio` decorator is
    # explicit here to make the dependency visible.
    pass
