# soth-py

Python binding for the SOTH SDK. Built with PyO3 + maturin; abi3-py310
wheels publishable to PyPI as `soth`.

## Status

**Phase 1 scaffold.** The Rust extension exposes the `SothSdk` facade
through PyO3; the user-facing Python API in `python/soth/__init__.py`
wraps it with the `guard()` helper, the `SothBlocked` exception, and
the contract negative tests.

What v0 ships:
- `soth.init(api_key, org_id, hmac_key_env=...)` — module-level singleton
- `soth.guard(fn, call=...)` — wraps an LLM call with `pre_call` / `post_call`
- `soth.SothBlocked` — exception (does NOT inherit from any provider hierarchy)
- `soth.SothFlagged` — warning surface for `Decision::Flag`
- `soth.BlockReason` — typed reason carried on `SothBlocked`

## HMAC key handling

`hmac_key_env` / `hmac_key_static` on `soth.init(...)` are **optional
in v1**.

- **With HMAC key:** customers pre-compute `user_id_hmac` themselves
  using their stored secret (`hmac.new(secret, user_id, "sha256")
  .hexdigest()`) and pass it via `with soth.context(user_id_hmac=...)`.
  The Phase-2.5 SDK adds a `soth.hash_user_id()` helper that uses the
  configured key for SDK-side hashing.
- **Without HMAC key:** anything passed via `user_id_hmac` reaches
  soth-cloud as-is. Regulated workloads (HIPAA / heavy-PII) SHOULD
  configure a key. Non-regulated workloads can defer.

See `docs/common/SDK_WASM_TRUST_BOUNDARY_SPEC.md` §6.6 for the full
key-lifecycle contract.

What's deferred to follow-up Phase 1 commits:
- Auto-instrumentation (`soth.instrument()`) for openai / anthropic / cohere /
  google-genai / mistralai
- httpx middleware (`soth.httpx_client()`)
- `with soth.context(user_id=..., team_id=...)` per-call overrides
- Streaming wrapper for native `AsyncIterator`s
- `Redact` decision handling (v0 treats Redact as Allow with logging)
- Auto-instrument on import

## Building

```sh
# Once. Per-target wheels via cibuildwheel in CI.
pip install maturin
cd bindings/soth-py
maturin develop  # builds + installs into the active venv
```

The Rust extension is part of the workspace, so `cargo build -p soth-py`
also works for compile-checking.

## Tests

```sh
pip install -e ".[test]"
maturin develop
pytest tests/
```

The `test_blocked_propagates.py` suite is the contract gate:
`SothBlocked` MUST NOT be caught by `try/except openai.APIError`. If
that test fails, the inheritance hierarchy has drifted from the spec
and bindings cannot ship.

## Wheel matrix (Phase-1 deliverable)

| Platform | Architecture | Python |
|---|---|---|
| manylinux2014 | x86_64 | abi3-py310 |
| manylinux2014 | aarch64 | abi3-py310 |
| macOS | x86_64 | abi3-py310 |
| macOS | arm64 | abi3-py310 |
| Windows | x86_64 | abi3-py310 |

Built via `cibuildwheel` in CI; abi3 means one wheel per platform×arch
covers Python 3.10+.

Python 3.9 reached EOL in October 2025 — explicitly NOT supported.

## Public API contract

Locked by:
- `docs/common/SDK_DECISION_API_SPEC.md` — Decision lifecycle, exception contract
- `docs/common/SDK_WASM_TRUST_BOUNDARY_SPEC.md` — bundle / classification mode

Read those before changing any public symbol in `python/soth/__init__.py`
or the PyO3 wrapper. Public-API stability matters here — `soth` ships in
customer dependencies and breaking changes propagate.
