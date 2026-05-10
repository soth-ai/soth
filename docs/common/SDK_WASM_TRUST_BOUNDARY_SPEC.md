# SDK WASM Trust-Boundary Specification

**Status:** Drafted — 2026-04-30
**Scope:** `soth-sdk-core` WASM target and the runtime tiers it serves
**Blocks:** Plan 2 Phase 0 — public types in `soth-sdk-core` depend on
which classification mode is the default per runtime.
**Companion spec:** `SDK_DECISION_API_SPEC.md`

---

## 1. Why this spec exists

The original Plan 2 draft positioned cloud-classify as a "graceful
fallback" for WASM targets where local ONNX won't fit. The Plan 1 review
correctly flagged this as a violation of the architectural trust anchor:
**content never leaves the customer's environment**. Routing prompt text
to soth-cloud for embedding breaks the first paragraph of the master
trust model, regardless of how fast or cheap it is.

This spec replaces the fallback model with a tiered model:

- **Native bindings** (Python / Node) — full local ONNX, content stays
  local, default everywhere.
- **WASM where size permits** (browser, Bun, Deno, Lambda) — full local
  via ONNX Runtime Web, content stays local, default.
- **WASM where size doesn't permit** (Cloudflare Workers, Vercel Edge) —
  reduced mode, no semantic classification, content stays local, default.
- **Cloud-classify** — opt-in privacy-tier with separate DPA,
  explicitly enabled per-customer, telemetry-tagged. **Never the
  default.** **Never a fallback.**

The phrasing "graceful fallback to cloud-classify" must not appear in
any customer-facing surface. If a customer ends up using cloud-classify,
it's because they signed a DPA that authorizes it.

---

## 2. ORT-Web compressed-size spike result

Pre-flight measurement before the tier matrix was committed:

| Component | Uncompressed | Brotli compressed |
|---|---|---|
| ORT Web (wasm-simd-threaded build) | ~10–15 MB | ~3–5 MB |
| all-MiniLM-L6-v2 INT8 ONNX model | ~23 MB | ~18–20 MB *(weights compress poorly)* |
| HuggingFace `tokenizers` to WASM | ~1–2 MB | ~1 MB |
| **Total realistic full-mode payload** | **~34–40 MB** | **~22–27 MB** |

**Original target ≤8 MB compressed: not feasible** with the current
embedding model. Confirmed via direct measurement against
`onnxruntime-web@1.17` and the model HuggingFace publishes. The
conclusion below stands; only the threshold numbers are corrected.

A future workstream may distill or quantize the embedding model to
fit the smaller-runtime targets — tracked in §6 as deferred.

---

## 3. Tier matrix

### 3.1 Targets and modes

| Target | Compressed budget | Classification mode | Notes |
|---|---|---|---|
| Python (PyO3, native) | unbounded | **Full (local ONNX)** | Default; primary Tier-1 surface. |
| Node.js / Bun (napi-rs, native) | unbounded | **Full (local ONNX)** | Default; primary Tier-1 surface. |
| Browser (WASM) | ~30 MB practical | **Full (ONNX Web)** | Default; full mode loadable. |
| Bun (WASM, where applicable) | unbounded | **Full (ONNX Web)** | Default. |
| Node.js (WASM, edge-style) | unbounded | **Full (ONNX Web)** | Default. |
| Deno Deploy | ~10 MB script | **Full (ONNX Web)**, monitor | Tight; revisit if compressed bundle > 8 MB. |
| AWS Lambda | unbounded (50 MB unzipped) | **Full** (native via cdylib preferred, ONNX Web acceptable) | Cold-start cost is the real constraint, not bundle size. |
| Fastly Compute | 100 MB | **Full (ONNX Web)** | Default. |
| Cloudflare Workers (free / paid) | 1–10 MB | **Reduced** | Doesn't fit ONNX Web. |
| Vercel Edge Functions | 1–4 MB | **Reduced** | Doesn't fit ONNX Web. |
| CloudFront Functions | < 1 MB | **Reduced** (lite) | Tightest; may not fit even reduced mode without further work. |

### 3.2 Selection logic

`SdkConfig.local_classification` is the customer-facing dial:

```rust
pub enum ClassificationMode {
    /// Local embedding via ONNX (native or ONNX Web). Content never
    /// leaves the customer's environment. Default for all targets
    /// where it fits.
    Full,

    /// No local embedding. Heuristic detect + counter-based anomaly +
    /// artifact-based policy. Telemetry events emit with
    /// `use_case_label: Unknown`. Default for size-constrained edge
    /// runtimes.
    Reduced,

    /// Customer has explicitly opted in to send normalized request
    /// data to soth-cloud for classification. Requires a separate DPA
    /// covering content egress. Telemetry events tagged
    /// `classification_location: "cloud"`.
    CloudOptIn,
}
```

The SDK does **not** auto-promote `Reduced` to `CloudOptIn` based on
runtime detection. Promotion is a deliberate customer config change
backed by a DPA.

### 3.3 What `Full` actually does on each target

Native: links `ort` directly via `cdylib`. ONNX runtime executes in-process,
bundle's ONNX model loaded from memory bytes (no disk required for the
model itself; bundle cache is opt-in via `bundle_cache_dir`).

WASM: links `ort` compiled to `wasm32-unknown-unknown`, loaded by the
host runtime (browser via `WebAssembly.instantiate`, Node via
`WebAssembly` global, Bun similar, Deno similar). The host runtime
provides the threading + SIMD primitives.

Workers AI alternative — explicitly NOT used: the trust anchor requires
embeddings to be computed locally. Workers AI runs ONNX on Cloudflare's
edge GPUs; that's still off-customer-infrastructure egress. Reduced
mode is the honest answer for Workers, not "delegate embedding to
Cloudflare's GPUs."

---

## 4. Reduced-mode capability statement

When `local_classification: Reduced`, the SDK delivers:

### 4.1 Available

- **Sensitive-artifact redaction** — full credential / PII / private-key
  detection via the existing regex pipeline. No model needed.
- **Counter-based anomaly flags** — `TokenBurst`, `CredentialBurst`,
  `ModelSwitch`, `RapidFireRequests`, `ToolCallDepthSpike`. All driven
  by session-state counters; no embedding required.
- **Artifact-based policy** — block on credential leak, block on
  private-key, redact on PII match. Doesn't need classified labels.
- **Session-level dedup** — `is_prefix_repeat`, `prefix_hash` flow
  through unchanged from `process_normalized`'s session phase.
- **Telemetry shipping** — full telemetry events emit; only the
  semantic fields are sentinels.

### 4.2 Unavailable (telemetry sentinel values)

- `use_case_label: UseCaseLabel::Unknown` (never one of the 16 trained
  labels)
- `volatility_class: VolatilityClass::Unknown` (degraded)
- `topic_cluster_id: 0` (sentinel; the cloud knows 0 means "no cluster
  computed")
- `semantic_hash: ""` (empty)
- `embedding_norm: 0.0`
- `anomaly_flags`: missing the 3 semantic ones —
  `TopicDrift`, `AgentLoopPattern`, `UnusualSystemPromptChange`
- Org policy rules conditioned on `use_case_label` or `topic_cluster_id`
  do not fire (the rule short-circuits to a no-op with a tagged
  telemetry event)

### 4.3 Capability disclosure

Every telemetry event emitted in reduced mode carries:

```json
{
  "classification_mode": "reduced",
  "classification_location": "local",
  "missing_fields": ["use_case_label", "volatility_class", "topic_cluster_id",
                     "semantic_hash", "embedding_norm"]
}
```

The `missing_fields` list is canonical: cloud-side analytics filters
on it explicitly rather than treating empty/sentinel values as
"missing data" (which would be ambiguous with full-mode failures).

### 4.4 Customer documentation requirement

The reduced-mode capability statement appears verbatim in:
- The SDK README for every binding
- The customer dashboard's "SDK runtime modes" page
- The deploy-to-edge quickstart guides

Customers picking edge-runtime targets must see this list before they
deploy. No silent feature regression.

---

## 5. Cloud-classify (opt-in only)

### 5.1 Activation

Single explicit config flag:

```rust
pub enum ClassificationMode {
    // ...
    /// Customer has explicitly opted in. Requires a DPA covering
    /// content egress to soth-cloud's classify endpoint.
    CloudOptIn,
}
```

There is no auto-promotion, no environment-variable shortcut, no
"if local is unavailable, fall back to cloud" path. The customer sets
`ClassificationMode::CloudOptIn` after their legal team has signed the
DPA addendum.

### 5.2 Wire format

Cloud-classify request (`POST /v1/edge/classify`):

```json
{
  "request_id": "uuid-v4",
  "org_id": "org-123",
  "normalized": {
    "provider": "openai",
    "model": "gpt-4o",
    "user_content": "<the actual prompt text>",
    "system_prompt": "<system prompt or null>",
    "tool_definitions_json": "<serialized tools or null>",
    "endpoint_type": "ChatCompletion",
    "is_streaming": false
  },
  "session_snapshot": { /* abbreviated SessionSnapshot */ }
}
```

Response:

```json
{
  "request_id": "uuid-v4",
  "use_case_label": "CodeGeneration",
  "use_case_confidence": 0.87,
  "volatility_class": "LowVolatile",
  "topic_cluster_id": 142,
  "semantic_hash": "...",
  "embedding_norm": 1.42,
  "anomaly_flags": ["TopicDrift"],
  "anomaly_score": 0.31,
  "classification_location": "cloud"
}
```

Authentication: org-level bearer token (the same `api_key` used for
telemetry).

Transport: HTTPS only, TLS 1.3, certificate pinned to soth-cloud's
public key, retry budget identical to telemetry sink (5 attempts with
exponential backoff, then dead-letter).

Latency target: p99 < 50 ms round-trip from the customer's region.

### 5.3 Telemetry tagging

Every telemetry event from a `CloudOptIn` SothSdk instance carries:

```json
{
  "classification_mode": "cloud_opt_in",
  "classification_location": "cloud",
  "cloud_classify_request_id": "uuid-v4"
}
```

The `cloud_classify_request_id` lets the cloud correlate the
classification request with the telemetry event for audit.

### 5.4 DPA placeholder language

The DPA addendum (legal team to finalize) covers:

- Definition of "Customer Content" — prompt text, system prompts,
  tool definitions
- soth-cloud's processing scope — classification only, no model
  training, no third-party sharing, retention ≤ 90 days
- Customer's right to revoke at any time by reverting to
  `ClassificationMode::Full` or `Reduced`
- Subprocessor list — the cloud-side classify infrastructure is run
  by SOTH or its named subprocessors; updates require 30-day notice

The actual DPA template is finalized by legal and not part of this
spec. This spec only commits that **CloudOptIn requires a DPA** and
defines the technical contract.

### 5.5 What CloudOptIn does NOT change

- Sensitive-artifact detection still runs locally on the SDK side.
  Credentials, PII, private keys are detected and redacted before any
  cloud round-trip happens. The cloud never receives detected
  artifacts.
- Policy evaluation for artifact-conditioned rules runs locally.
  The cloud only contributes classified labels.
- Telemetry event structure is identical to `Full` mode (cloud just
  fills in the semantic fields the local pipeline can't).

---

## 6. Bundle CDN trust path

### 6.1 Bundle source

`SdkConfig.bundle_url` (default: SOTH-hosted CDN endpoint). Bundle is
fetched at SDK init via HTTPS:

```
GET {bundle_url}/manifest.json
GET {bundle_url}/<asset_path>           # for each asset in manifest
```

### 6.2 Verification

Reuse `soth-bundle::verify`:

- Manifest signature (Ed25519, vendor public key embedded in SDK)
- Asset SHA256 + size match per manifest entry
- Manifest `expires_at` not in the past
- Optional: org approval signature when `require_org_approval: true`
  in `SdkConfig`

Verification failure → init returns `SdkError::BundleVerification`,
SDK enters no-op mode (logs warning; host calls proceed with
no-op `Decision::Allow`). The customer's observability picks up the
init error.

### 6.3 Caching

`SdkConfig.bundle_cache_dir`:
- `Some(path)` — verified bundle cached on disk; subsequent process
  starts use the cache if `expires_at` not exceeded.
- `None` — no on-disk cache. Bundle pulled from CDN on every init.
  Required for serverless / read-only-filesystem targets (Lambda,
  Workers, edge functions).

### 6.4 Refresh path

Customer schedules `SothSdk::refresh_bundle()` (cron, background task,
dashboard webhook). The SDK does not spawn its own refresher.

Refresh flow:
1. Fetch new manifest
2. If `version` matches current and `etag` matches, no-op (304-style)
3. Otherwise fetch + verify new assets
4. Hot-swap via `ArcSwap<Bundle>` — no allocations on the call path
5. Old bundle dropped after the swap completes (no in-flight calls
   reference it)

Refresh failure leaves the running bundle in place; logs at WARN.

### 6.5 What lives in the bundle (recap from Plan 1)

- `manifest.json` — version, sigs, expiry, scope (~1 KB)
- `classify/` — embedding ONNX, tokenizer, centroids, LSH projection,
  use-case head (~30 MB)
- `policy/` — rule set (small)
- `redact/` — artifact patterns (small)
- `anomaly/` — thresholds + signal weights (tiny)
- `taxonomy/` — `UseCaseLabel` set + version (tiny)

Two-tier shipping for SDKs:
- **Lite bundle (~200 KB)** embedded in the wheel/npm package —
  patterns, policy, thresholds, taxonomy. Always available offline.
- **ML bundle (~30 MB)** pulled from CDN at first init, cached at
  `bundle_cache_dir`. Customers in `ClassificationMode::Reduced` or
  `CloudOptIn` never pull the ML bundle.

### 6.6 No key fetching

soth-cloud never possesses the customer's HMAC key. There is no
endpoint that returns it. The DPA, the SDK, and the CDN are explicit
on this point. Anyone proposing a key-fetch endpoint is breaking the
trust model — point them at this paragraph.

---

## 7. Conformance assertions

The conformance harness gains two new lanes for the SDK build:

### 7.1 SDK-via-PyO3 lane

Same fixture corpus as the existing SDK lane, but driven through the
Python binding's `pre_call` API (running the Rust core via PyO3 FFI).
Asserts that the Python wrapper does not introduce drift vs. the Rust
core directly.

### 7.2 SDK-via-WASM-reduced lane

Subset of fixtures that don't require semantic classification (use_case
or anomaly). Run through the WASM artifact in reduced mode. Asserts
that reduced mode produces the same artifact detection, capture mode,
policy decision, and telemetry shape as full mode for the fixtures it
can handle.

### 7.3 SDK-via-WASM-cloud-optin lane

Run against a stubbed local classify endpoint (a tiny test server) so
CI stays hermetic. Asserts that `CloudOptIn` mode produces a
`ClassifiedResult` with the same shape as full local mode, and that
the telemetry event correctly tags `classification_location: "cloud"`.

### 7.4 Mode transitions

Test that mode is honored:
- `ClassificationMode::Full` on a runtime that doesn't fit ONNX: SDK
  init returns `SdkError::OnnxUnavailable`. Customer must explicitly
  pick Reduced or CloudOptIn.
- `ClassificationMode::Reduced`: telemetry events carry the canonical
  `missing_fields` list.
- `ClassificationMode::CloudOptIn` without `bundle_url` configured:
  SDK init returns `SdkError::CloudClassifyEndpointMissing`.

---

## 8. Open questions / deferred

- **Smaller embedding model for size-constrained WASM** — distillation
  or int4 quantization to fit ~5–10 MB compressed. Would let
  Cloudflare Workers paid tier run full mode. Tracked as a follow-up
  ML workstream; doesn't block SDK launch.
- **Per-call mode override** — should `pre_call` accept a `force_mode`
  parameter for canary rollouts (e.g., 1% of traffic uses full, 99%
  reduced)? Useful but not Tier-1; deferred until customer demand.
- **Bundle pull from a customer-controlled CDN** — `bundle_url` is
  already configurable, but signature verification still uses the
  vendor public key. Allowing org-signed bundles (org-approved
  override) is in `soth-bundle::verify` but the SDK doesn't expose
  the toggle yet. Deferred.

---

## 9. If this needs to change

Adding a new `ClassificationMode` variant: minor bump (variants are
`#[non_exhaustive]`).

Changing the cloud-classify wire format: requires versioning the
endpoint (`/v2/edge/classify`) and a deprecation window. The SDK pins
its endpoint version explicitly in the request URL.

Changing the trust anchor (e.g., allowing default content egress):
requires architectural review, customer notice, DPA revision. **Don't.**

Reduced-mode capability changes: any new field that becomes available
in reduced mode graduates from the `missing_fields` list. Any new
field that becomes available only in full mode joins the list. The
customer dashboard's runtime-modes page must update synchronously.
