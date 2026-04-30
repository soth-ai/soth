# soth-sdk-core

Public-API facade consumed by every SOTH SDK binding (PyO3, napi-rs,
WASM). Bindings depend ONLY on this crate; the internal `soth-detect` /
`soth-classify` / `soth-telemetry` crates are not re-exported, so
swapping their internals does not ripple downstream.

This crate is **public-API stable** by contract — every type re-exported
from `lib.rs` is part of the SDK's customer-facing surface. Changes
require a major version bump.

The two pre-flight specs lock the surface:

- `docs/common/SDK_DECISION_API_SPEC.md` — Decision / DecisionToken /
  wrapper exception contract / sync-vs-async budget
- `docs/common/SDK_WASM_TRUST_BOUNDARY_SPEC.md` — tier matrix /
  reduced-mode capabilities / cloud-classify opt-in

## Public surface

```rust
use soth_sdk_core::{
    SothSdk, SdkConfigBuilder, HmacKey, ClassificationMode,
    LlmCall, LlmResponse, LlmChunk, Message, Tool,
    Decision, DecisionToken, BlockReason, FlagSeverity,
    MessageRedactions, MessageRedaction, RedactReason,
    Observation, StreamObservation,
    SdkError,
};

let sdk = SothSdk::init(
    SdkConfigBuilder::new()
        .api_key("sk-...")
        .org_id("org-123")
        .hmac_key(HmacKey::from_env("SOTH_HMAC_KEY"))
        .local_classification(ClassificationMode::Full)
        .build()?
)?;

// Synchronous decision path (≤5 ms p99 budget)
let decision = sdk.pre_call(&call);
match decision {
    Decision::Allow { token } => {
        // forward to provider, then:
        sdk.post_call(token, &response);
    }
    Decision::Block { token, reason } => {
        // bindings translate this into SothBlocked
        sdk.post_call(token, &empty_response);
    }
    // Redact / Flag handled similarly
    _ => {}
}

// Streaming
let (decision, mut obs) = sdk.stream_begin(&call);
// ... iterate provider stream, call sdk.stream_chunk(&mut obs, &chunk) ...
sdk.stream_end(obs);
```

## What v0 does (Phase 0)

- ✅ `init` validates config (HMAC key optional in v1; resolved when
     present), builds an empty detect bundle and the deterministic
     fallback classify bundle.
- ✅ `pre_call` runs `process_normalized` for artifact detection +
     session dedup. Sync block path fires on credential / private-key
     artifacts. Returns a real `DecisionToken` allocated from a fixed
     4096-slot slab.
- ✅ `post_call` consumes the token, runs the full classify pipeline
     (with fallback bundle, so `use_case_label` is heuristic), pushes
     a `TelemetryEvent` onto the in-memory queue.
- ✅ Streaming round-trip: `stream_begin` / `stream_chunk` /
     `stream_end` consume the token exactly once.
- ✅ `DecisionToken` lifecycle per spec §5: panic-on-reuse in debug,
     log+ignore in release, `SLAB_FULL` sentinel under pressure,
     `SENTINEL_FAIL_OPEN` for FFI-boundary fail-open.
- ✅ Compile-time `Send + Sync` assertions for `SothSdk` and
     `Observation`.
- ✅ HMAC key never logged: `Debug` redacts plaintext bytes; resolved
     bytes held in `Zeroizing<Vec<u8>>` and dropped on init.

## What's deferred to Phase 1

- ❌ Real bundle CDN pull + Ed25519 verification (stubbed; uses the
     fallback bundle today). Spec'd in WASM trust-boundary §6.
- ❌ Background telemetry shipper (HTTPS POST to soth-cloud). Events
     accumulate in the in-memory queue; tests drain them via
     `drain_telemetry_for_test`.
- ❌ Cloud-classify wire transport (the `CloudOptIn` path stops at
     init validation in v0). Spec'd in WASM trust-boundary §5.
- ❌ Orphan sweeper for never-consumed tokens. Slab grows up to
     `SLAB_FULL` threshold and then returns sentinels; sweeper is a
     Phase-1 background task per spec §5.4.
- ❌ Full org-rule evaluation (artifact-conditioned + label-conditioned).
     Today's sync block is hard-coded on credential / private-key
     artifacts; full policy eval lands in Phase 1.
- ❌ OTel span emission (feature-gated; stub).
- ❌ Conformance harness lane through this facade. The fixture corpus
     in `soth-conformance-tests` already runs both proxy and SDK lanes
     through the lower-level crates; adding a `via-facade` lane goes
     into Phase 1's binding-validation work.

## Send + Sync

The crate has compile-time assertions that `SothSdk` and `Observation`
remain `Send + Sync`. Any future change that introduces a non-`Send`
field fails the build. Bindings stash an `Arc<SothSdk>` and call from
arbitrary host worker threads.

## Feature flags

| Feature | Default | Purpose |
|---|---|---|
| `onnx-models` | on | Transitively enables local ONNX classification in `soth-classify`. Bindings flip this off for WASM/edge targets that ship reduced mode. |
| `otel` | off | Emits OpenTelemetry spans for every observed call. Bindings opt in when the host already has an OTel pipeline. |

## Running the tests

```sh
cargo test -p soth-sdk-core
```

15 unit tests + 5 integration round-trip tests. The integration tests
exercise:
- `init` with minimal config
- `pre_call` → `post_call` slab balance + telemetry emission
- credential-in-user-message sync block path
- streaming round-trip token-consumed-once invariant
- slab pressure under 6K allocations without `post_call`
