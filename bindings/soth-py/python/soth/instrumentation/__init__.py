"""Auto-instrumentation for provider SDKs.

Public entry points:
    soth.instrument(providers=None) — patch installed provider SDKs
    soth.uninstrument(providers=None) — restore originals
    soth.is_instrumented(provider) — query state

Robustness contract (per `SDK_DECISION_API_SPEC.md` §6 + Phase-1 design):

1. **Idempotent.** `instrument()` called twice returns the same state
   without re-wrapping. Calling `instrument()` after another
   instrumentation tool (LangSmith, OTel, dd-trace) preserves the
   prior wrapper — SOTH chains rather than replaces.
2. **Reversible.** `uninstrument()` restores the originals captured
   at apply time. Restoration is best-effort; if another tool wrapped
   AFTER SOTH, that wrapper persists and SOTH logs a warning.
3. **Provider-conditional.** Missing provider packages don't raise —
   the entry returns `"skipped:not-installed"` and instrumentation
   continues with the rest.
4. **Fail open.** Any exception during call extraction or wrapper
   setup falls back to the original SDK call uninstrumented. The
   customer's API call MUST complete unaffected if SOTH itself fails.
5. **Version tolerant.** Adapters use defensive `getattr` access so
   minor-version SDK changes don't break the wrapper.
6. **Sync + async aware.** Each adapter wraps both sync and async
   client classes; streaming and non-streaming paths are detected
   per-call from `kwargs.get('stream')`.
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from . import _anthropic, _openai

logger = logging.getLogger("soth.instrumentation")

# Registry: provider name → adapter module. Adding a provider is a
# new entry here + a corresponding `_<provider>.py` adapter module.
_REGISTRY = {
    "openai": _openai,
    "anthropic": _anthropic,
}

# State tracking for idempotency. Maps provider name → bool.
_state: dict[str, bool] = {name: False for name in _REGISTRY}


def instrument(providers: Optional[Iterable[str]] = None) -> dict[str, str]:
    """Patch each importable provider's client classes so calls
    automatically run through SOTH's pre/post lifecycle.

    Returns a status dict mapping each provider name to one of:
        "instrumented"                  — patched successfully
        "skipped:not-installed"         — provider package not importable
        "skipped:already-instrumented"  — patched in a previous call
        "skipped:disabled"              — not in the requested providers list
        "error:<exception class>"       — apply() raised; SDK is unchanged

    Customers SHOULD call this once at app startup. Subsequent calls
    are safe (idempotent) but produce only the "skipped:*" outcomes.
    """
    selected = set(providers) if providers else set(_REGISTRY)
    results: dict[str, str] = {}

    for name, adapter in _REGISTRY.items():
        if name not in selected:
            results[name] = "skipped:disabled"
            continue
        if _state.get(name, False):
            results[name] = "skipped:already-instrumented"
            continue
        try:
            applied = adapter.apply()
        except Exception as e:  # noqa: BLE001 — fail open is the contract
            logger.warning(
                "instrument(%s) failed: %s; provider SDK is unchanged",
                name,
                e,
            )
            results[name] = f"error:{type(e).__name__}"
            continue

        if applied:
            _state[name] = True
            results[name] = "instrumented"
        else:
            results[name] = "skipped:not-installed"

    return results


def uninstrument(providers: Optional[Iterable[str]] = None) -> dict[str, str]:
    """Restore each provider's original client methods.

    Returns a status dict mapping each provider name to one of:
        "uninstrumented"                — restored
        "skipped:not-instrumented"      — never patched
        "skipped:disabled"              — not in the requested providers list
        "error:<exception class>"       — revert() raised; state may be inconsistent

    Use sparingly — typical workflows leave instrumentation on for the
    process lifetime.
    """
    selected = set(providers) if providers else set(_REGISTRY)
    results: dict[str, str] = {}

    for name, adapter in _REGISTRY.items():
        if name not in selected:
            results[name] = "skipped:disabled"
            continue
        if not _state.get(name, False):
            results[name] = "skipped:not-instrumented"
            continue
        try:
            adapter.revert()
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "uninstrument(%s) failed: %s; state may be inconsistent",
                name,
                e,
            )
            results[name] = f"error:{type(e).__name__}"
            continue

        _state[name] = False
        results[name] = "uninstrumented"

    return results


def is_instrumented(provider: str) -> bool:
    """Return whether `provider` is currently patched."""
    return _state.get(provider, False)


def _reset_state_for_test() -> None:
    """Test-only helper. Resets the state map without touching the
    underlying provider SDKs — used by tests that mock the adapters."""
    for name in _state:
        _state[name] = False
