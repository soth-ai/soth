"""SOTH exceptions and reason types.

The exception hierarchy is locked by `SDK_DECISION_API_SPEC.md` §6.2:

- `SothBlocked` extends Python's built-in `Exception` directly. It does
  NOT inherit from any provider SDK exception type (`openai.APIError`,
  `anthropic.APIError`, `cohere.CohereError`, ...).
- `SothBlocked` therefore propagates past `try/except openai.APIError`
  handlers — this is intentional. A policy block is not an upstream API
  error and must not be retried by retry-on-API-error logic.

If a future change makes `SothBlocked` inherit from any provider type,
the `tests/test_blocked_propagates.py` negative tests will fail. That's
the intended forcing function — read the spec section before touching
this file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class BlockReason:
    """Typed reason carried on `SothBlocked`. The `kind` field is the
    discriminator; the rest of the fields populate based on it."""

    kind: str  # "sensitive_artifact" | "budget_exceeded" | "policy_rule" | "use_alternative"
    artifact: Optional[str] = None
    severity: Optional[str] = None
    budget_kind: Optional[str] = None
    observed: Optional[int] = None
    limit: Optional[int] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    suggested_provider: Optional[str] = None
    suggested_model: Optional[str] = None


def block_reason_from_dict(d: dict[str, Any]) -> BlockReason:
    return BlockReason(
        kind=str(d.get("kind", "unknown")),
        artifact=d.get("artifact"),
        severity=d.get("severity"),
        budget_kind=d.get("budget_kind"),
        observed=d.get("observed"),
        limit=d.get("limit"),
        rule_id=d.get("rule_id"),
        rule_name=d.get("rule_name"),
        suggested_provider=d.get("suggested_provider"),
        suggested_model=d.get("suggested_model"),
    )


class SothBlocked(Exception):
    """Raised when SOTH policy blocks an LLM call.

    Inherits from Exception, NOT from any provider SDK exception type.
    Will propagate past `try/except openai.APIError` handlers — this is
    intentional. A policy block is not an upstream API error and must
    not be retried by retry-on-API-error logic.

    See `SDK_DECISION_API_SPEC.md` §6 for the full contract.
    """

    decision_id: str
    reason: BlockReason

    def __init__(self, decision_id: str, reason: BlockReason):
        self.decision_id = decision_id
        self.reason = reason
        super().__init__(f"SOTH policy blocked call: {reason.kind}")


class SothFlagged(Warning):
    """Surfaces a `Decision::Flag` to anyone listening on warnings.

    Does NOT inherit from any provider exception type either. Customers
    that want to act on flags install a `warnings.simplefilter` or
    capture the `soth` logger output.
    """

    severity: str

    def __init__(self, severity: str):
        self.severity = severity
        super().__init__(f"SOTH flagged call: severity={severity}")
