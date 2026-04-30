"""Type stubs for the compiled `_soth_native` extension.

Generated manually; the public Python surface is in `soth/__init__.py`.
"""

from __future__ import annotations

from typing import Any, Optional

__version__: str

DECISION_KIND_ALLOW: str
DECISION_KIND_BLOCK: str
DECISION_KIND_REDACT: str
DECISION_KIND_FLAG: str


class SothSdk:
    def __init__(
        self,
        *,
        api_key: str,
        org_id: str,
        hmac_key_env: Optional[str] = None,
        hmac_key_static: Optional[bytes] = None,
    ) -> None: ...

    def pre_call(self, call: dict[str, Any]) -> dict[str, Any]: ...
    def post_call(self, token: int, response: Optional[dict[str, Any]] = None) -> None: ...
    def in_flight_decisions(self) -> int: ...
    def drain_telemetry_for_test(self) -> list[dict[str, Any]]: ...
