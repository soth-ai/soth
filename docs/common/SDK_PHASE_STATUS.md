# SDK Build Phase Status

**Branch:** `sdk-build`
**Last updated:** 2026-04-30

This doc tracks what's been delivered against the original Plan 2
phasing so reviewers can scan the state without diffing 20+ commits.

---

## Plan 1 — Refactor (DONE)

5 PRs landed on `sdk-refactor`, merged here:

| PR | Scope | Commit |
|---|---|---|
| 1 | Feature-gate native deps for SDK/WASM | `57fbf48` |
| 2 | Split `ProxyContext` into Identity/Transport/Attribution | `e66a6bd` |
| 3 | Pre-parsed entry point in soth-detect | `2abf879` |
| 4 | Send + Sync audit + concurrent stress tests | `3e09910` |
| 5 | Conformance harness for cross-lane parity | `a739494` |

**Status: Done. Verified by 654 lib tests + conformance harness.**

---

## Pre-flight specs (DONE)

Both locked the public-API contracts before any SDK code shipped:

- `docs/common/SDK_DECISION_API_SPEC.md` (`d68fb20`)
- `docs/common/SDK_WASM_TRUST_BOUNDARY_SPEC.md` (`d68fb20`)

---

## Phase 0 — soth-sdk-core facade (DONE)

| Item | Status | Commit |
|---|---|---|
| `crates/soth-sdk-core` workspace member | done | `b5c6f6d` |
| Public types per Decision API spec | done | `b5c6f6d` |
| `DecisionToken` slab (4096 slots) | done | `b5c6f6d` |
| In-memory telemetry queue | done | `b5c6f6d` |
| `SothSdk::for_test` ctor | done | `ba5d83b` |
| Conformance facade lane | done | `ba5d83b` |

Verified by 15 unit + 5 integration tests.

---

## Phase 1 — Tier-1 bindings (DONE)

| Item | Status | Commit |
|---|---|---|
| soth-py PyO3 binding scaffold | done | `088b950` |
| soth-node napi-rs binding scaffold | done | `026fa11` |
| Streaming wrapper (both bindings) | done | `c084831` |
| Background HTTPS telemetry shipper | done | `76f336b` |
| Per-call CallContext (contextvars / AsyncLocalStorage) | done | `da72b10` |
| Auto-instrumentation for OpenAI + Anthropic | done | `32e52ff` |

`SothBlocked` propagation contract gated by negative tests on both
sides.

---

## Phase 1.5 — Long-tail providers + framework integrations (DONE)

| Item | Status | Commit |
|---|---|---|
| Cohere Python adapter | done | `0589288` |
| Google GenAI Python adapter | done | `0589288` |
| Mistral Python adapter | done | `0589288` |
| Anthropic Node adapter | done | `0589288` |
| LangChain Python `SothCallbackHandler` | done | `6a1cb29` |
| LlamaIndex Python `SothEventHandler` | done | `6a1cb29` |
| LiteLLM Python callbacks | done | `6a1cb29` |
| Vercel AI SDK Node middleware | done | `6a1cb29` |

5 Python provider adapters + 2 Node provider adapters + 4 framework
integrations. All gate the same six robustness contracts.

---

## Phase 2 — CI matrix + FFI conformance (DONE)

| Item | Status | Commit |
|---|---|---|
| `ci.yml` extended with WASM + conformance + bindings-build-check | done | `1f6d79d` |
| `python-wheels.yml` (5 platform/arch jobs via maturin-action) | done | `1f6d79d` |
| `node-binaries.yml` (7 napi-rs triples) | done | `1f6d79d` |
| Python FFI conformance suite | done | `d498d1e` |
| Node FFI conformance suite | done | `d498d1e` |
| `ffi-conformance.yml` workflow | done | `d498d1e` |

Every PR touching detect / classify / sdk-core / bindings now runs
through the four-lane conformance harness.

---

## Phase 3 — Framework adapters (DONE)

Folded into Phase 1.5 since the framework integrations and long-tail
provider adapters were close enough in scope to deliver together.
LangChain / LlamaIndex / LiteLLM / Vercel AI SDK shipped in `6a1cb29`.

---

## Phase 4 — Go SDK + edge runtimes (SCAFFOLD ONLY)

This is the only phase that's intentionally **not production-ready**
in this branch. Per the original Plan 2 effort estimate, Phase 4 is
4–6 weeks of work; what's been delivered:

| Item | Status | Notes |
|---|---|---|
| WASM target builds for soth-sdk-core | done | `cargo build -p soth-sdk-core --target wasm32-unknown-unknown --no-default-features` is clean |
| `bindings/soth-edge` JS shim scaffold | scaffold | API surface frozen; `_invokeWasmStub` returns Allow until extern "C" exports land |
| `sdks/soth-go` Go SDK scaffold | scaffold | wazero dep + API surface; bridge methods stubbed |
| wasm-bindgen / extern "C" exports on soth-sdk-core | **not started** | the single biggest gap |
| Per-runtime CF Workers / Vercel deploy templates | not started | |
| Conformance harness Go lane | not started | |

**Scaffold meaning:** the public API surfaces are stable and the
package boundaries are committed. Customer code that integrates
against `@soth/sdk-edge` or `soth-go` today will continue to compile
and run when the real WASM bridge lands — only the call results
change (from stubbed Allow → actual decisions).

The follow-up PR for Phase 4 is decoupled enough that it can land
post-Tier-1 GA without blocking native SDK customers.

---

## Tier 1 readiness summary

**Native bindings (Python + Node, OpenAI/Anthropic/Cohere/Google/Mistral):**
✅ functionally shippable. Customers can `pip install soth` /
`npm i @soth/sdk` once the wheel/binary CI runs and the publish
workflow lands.

**Edge runtimes (CF Workers, Vercel Edge, Deno, Fastly):**
🟡 scaffold. API frozen; WASM bridge is the next-PR work.

**Go SDK:** 🟡 scaffold. Same status as edge runtimes — same WASM
artifact will unblock both.

**What's strictly remaining for paying-customer Tier-1 pilot:**
1. PyPI publish workflow (release-engineering, ~2 days)
2. npm publish workflow (release-engineering, ~2 days)
3. A friendly customer to integrate against
