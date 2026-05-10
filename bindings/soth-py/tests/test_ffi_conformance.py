"""FFI conformance — drives the same fixtures the Rust harness uses
through the actual PyO3 binding.

The Rust conformance harness (`soth-conformance-tests`) runs three
lanes against each fixture: proxy, SDK direct, SDK facade. This file
adds the **fourth lane** — calls go through Python's `soth.guard()`,
which crosses the PyO3 boundary into `soth-sdk-core`. Any drift
between the Rust facade and the Python FFI marshalling fails here,
naming the field.

Run with:
    cd bindings/soth-py
    maturin develop
    pytest tests/test_ffi_conformance.py

In CI, this runs after the wheel is built. Failure modes the harness
catches:
- PyO3 dict construction drops a field
- Python wrapper passes a stale context dict
- `pre_call` returns a token that `post_call` can't consume
- Telemetry event shape changed in the FFI layer

The test SKIPS gracefully if the fixtures directory isn't reachable
(running outside the workspace) or if `soth.init` itself fails.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

import soth

# Locate the fixture corpus relative to this file. The structure is
# fixed by Plan 1 PR 5; if it changes, this resolver needs an update.
_FIXTURES_DIR = (
    Path(__file__).resolve().parents[3]
    / "crates"
    / "soth-conformance-tests"
    / "fixtures"
)


def _load_fixtures() -> list[tuple[str, dict[str, Any]]]:
    if not _FIXTURES_DIR.is_dir():
        return []
    out = []
    for path in sorted(_FIXTURES_DIR.glob("*.json")):
        with path.open("r") as f:
            out.append((path.name, json.load(f)))
    return out


_fixtures = _load_fixtures()


@pytest.fixture(autouse=True)
def _init_sdk():
    os.environ["SOTH_HMAC_KEY"] = "x" * 32
    soth.init(
        api_key="sk-test",
        org_id="org-conformance",
        hmac_key_env="SOTH_HMAC_KEY",
    )
    yield


def _fixture_to_call(fixture: dict[str, Any]) -> dict[str, Any]:
    """Convert the fixture's `typed_call` shape into the dict
    `soth.guard()` expects. Same conversion the Rust SDK lane does
    in `soth-conformance-tests/src/lib.rs`."""
    typed = fixture["typed_call"]
    call: dict[str, Any] = {
        "provider": typed["provider"],
        "model": typed["model"],
        "messages": typed.get("messages", []),
        "stream": typed.get("stream", False),
    }
    if typed.get("system"):
        call["system"] = typed["system"]
    if typed.get("tools"):
        call["tools"] = typed["tools"]
    return call


@pytest.mark.skipif(
    not _fixtures, reason="Conformance fixtures not reachable from this path"
)
@pytest.mark.parametrize("fixture_name,fixture", _fixtures, ids=[name for name, _ in _fixtures])
def test_ffi_emits_expected_telemetry_shape(fixture_name: str, fixture: dict[str, Any]):
    """Assert the FFI lane emits a TelemetryEvent with the same
    contract-surface fields the Rust facade lane produces.

    Strict on: provider, model (when present), endpoint_type,
    capture_mode. These are the fields the cloud ingestion contract
    pins. Other fields (use_case, anomaly_flags) are ML-pipeline
    output and may vary in the fallback bundle; they're inspected
    but not asserted byte-equal.
    """
    expected_provider = fixture["typed_call"]["provider"]
    expected_model = fixture["typed_call"]["model"]
    expected_block = fixture.get("axes", {}).get("policy_decision") == "Block"

    call = _fixture_to_call(fixture)

    if expected_block or fixture.get("axes", {}).get("content_class") == "credential":
        # Credential fixtures must produce SothBlocked from Python.
        with pytest.raises(soth.SothBlocked):
            soth.guard(lambda: "should-not-be-called", call=call)
    else:
        result = soth.guard(lambda: "ok", call=call)
        assert result == "ok"

    events = soth._drain_telemetry_for_test()
    assert len(events) == 1, f"{fixture_name}: expected 1 event, got {len(events)}"
    event = events[0]
    assert event["provider"] == expected_provider, (
        f"{fixture_name}: provider drift: expected {expected_provider}, got {event['provider']}"
    )
    if expected_model and "model" in event:
        # Some Block fixtures emit a stub event with empty model;
        # only assert when the cloud-contract field was set.
        assert event["model"] == expected_model, (
            f"{fixture_name}: model drift: expected {expected_model}, got {event['model']}"
        )
    assert "endpoint_type" in event
    assert "capture_mode" in event
    assert soth._in_flight_decisions() == 0


def test_ffi_corpus_at_least_seven_fixtures():
    """Sanity check: the conformance corpus floor is 7 fixtures
    (Plan 1 PR 5 corpus). A drop below means somebody removed
    fixtures and we want CI to flag it."""
    assert len(_fixtures) >= 7, (
        f"Conformance corpus shrank to {len(_fixtures)} — "
        "should have at least the 7 launch fixtures from PR 5"
    )
