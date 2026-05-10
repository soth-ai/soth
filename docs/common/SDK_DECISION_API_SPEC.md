# SDK Decision API Specification

**Status:** Drafted — 2026-04-30
**Scope:** Public API contract for `soth-sdk-core` and every language binding
(`soth-py`, `soth-node`, `soth-go`, `soth-wasm`)
**Blocks:** Plan 2 Phase 0 — `soth-sdk-core` cannot lock public types until
this spec is signed off.

---

## 1. Why this spec exists

The SDK's job is half observation, half enforcement. The original Plan 2
draft specified an observation-only API (`observe_request → Observation`,
`observe_response`); the Plan 1 review correctly pointed out that without a
synchronous decision-return, customers integrating the SDK get telemetry
and audit but lose enforcement, which is half the product. A credential
detected in a request must never reach the upstream provider — that's the
contract, regardless of whether the proxy or the SDK is the integration
point.

This spec locks the public types, the lifecycle, the per-language wrapper
contract, and the conformance assertions that prove parity with the proxy.
It is the API the SDK ships in customer dependencies — once committed,
every change is a breaking change for downstream code.

---

## 2. Scope decisions

### 2.1 Reroute is out of the SDK Decision enum

**Decision:** The SDK does not return `Decision::Reroute`. Reroute remains
a proxy/sidecar capability.

**Rationale:** In the proxy, `Reroute` means "I'm intercepting this request
and forwarding it to a different upstream — your code doesn't see the
swap." In the SDK, the customer's code constructed a typed client pointing
at OpenAI; the SDK can't redirect the underlying connection without
substituting the entire client object, which would be a deeply intrusive,
provider-specific operation that breaks the customer's typing.

**What the SDK does instead:** Reroute-shaped policies surface as
`Decision::Block { reason: BlockReason::UseAlternative { suggested_model,
suggested_provider } }`. The customer's app implements
retry-with-alternative if it wants. The proxy continues to do real reroute.
Same policy in the bundle, different runtime behavior depending on
enforcement location, documented as such.

**Conformance impact:** Fixtures that exercise reroute policies are tagged
`proxy_only: true` in the conformance corpus and are not asserted on the
SDK lane.

### 2.2 Redact is scoped to message-level replacement

**Decision:** `Decision::Redact` returns a list of message-index →
replacement-content edits. The SDK does not perform within-message
surgical edits.

**Rationale:** Within-message redaction (e.g. scrub a credential from the
middle of a paragraph) requires per-provider schema knowledge that grows
linearly with provider count and breaks every time a provider SDK updates
its content type. Message-level replacement only depends on the existence
of a `messages` array and is uniformly implementable across providers.

**What the SDK does:** `MessageRedactions` carries a `Vec<(MessageIdx,
RedactedContent)>`. The wrapper applies these via a per-provider adapter
that calls `provider.replace_messages(typed_call, redacted_messages)`.
Each provider adapter is <100 LOC.

**Documented limitation:** Customers wanting fine-grained within-message
redaction use the proxy. The SDK README states this explicitly.

**Conformance impact:** Fixtures that require within-message redaction
are tagged `proxy_only: true`.

---

## 3. Public types

These types live in `soth-sdk-core` and are re-exported through every
language binding. **Once committed, changes are breaking.**

### 3.1 `Decision`

```rust
pub enum Decision {
    Allow {
        token: DecisionToken,
    },
    Block {
        token: DecisionToken,
        reason: BlockReason,
    },
    Redact {
        token: DecisionToken,
        redactions: MessageRedactions,
    },
    Flag {
        token: DecisionToken,
        severity: FlagSeverity,
    },
}
```

`#[non_exhaustive]` on `Decision`, `BlockReason`, `FlagSeverity` so
future variants can be added without a major bump.

### 3.2 `BlockReason`

```rust
#[non_exhaustive]
pub enum BlockReason {
    /// Sensitive artifact detected (credential, private key, PII).
    SensitiveArtifact {
        kind: ArtifactKind,
        severity: ArtifactSeverity,
    },
    /// Org-level budget exhausted (token / cost / request count).
    BudgetExceeded {
        budget_kind: BudgetKind,
        observed: u64,
        limit: u64,
    },
    /// Org policy rule fired.
    PolicyRule {
        rule_id: String,
        rule_name: Option<String>,
    },
    /// Reroute-shaped policy surfaced as a block with an alternative.
    /// Customer apps that implement retry-with-alternative use this.
    UseAlternative {
        suggested_provider: Option<String>,
        suggested_model: Option<String>,
        rule_id: String,
    },
}
```

### 3.3 `MessageRedactions`

```rust
pub struct MessageRedactions {
    pub replacements: Vec<MessageRedaction>,
}

pub struct MessageRedaction {
    /// Index into `LlmCall.messages`. The wrapper's provider adapter
    /// uses this to locate the message in the typed call object.
    pub message_idx: usize,
    /// Content that replaces the original message. Always set; the
    /// SDK never returns "delete this message" — it returns a
    /// placeholder so conversation turn structure is preserved.
    pub redacted_content: String,
    /// Reason surface — telemetry tags so the cloud can correlate
    /// what triggered the redaction.
    pub reason: RedactReason,
}

#[non_exhaustive]
pub enum RedactReason {
    SensitiveArtifact { kind: ArtifactKind },
    PolicyRule { rule_id: String },
}
```

### 3.4 `DecisionToken`

```rust
pub struct DecisionToken {
    /// Opaque identifier — bindings must not interpret this. Carried
    /// from `pre_call` to `post_call` so the SDK can correlate the
    /// decision with the response.
    inner: u64,
}
```

`DecisionToken` is `Copy` and lock-free. The `inner` field is private;
the SDK uses it as a key into a slab of pending decisions.

### 3.5 `FlagSeverity`

```rust
#[non_exhaustive]
pub enum FlagSeverity {
    Info,
    Warning,
    Critical,
}
```

`Flag` is enforcement-cooperative: the wrapper does not raise an
exception; it logs a structured event and the call proceeds. The
customer's observability stack picks the flag up via OTel spans.

---

## 4. `SothSdk` API

### 4.1 Synchronous decision path

```rust
impl SothSdk {
    /// Returns within 5 ms p99 budget. Runs:
    ///   1. Per-org budget check (atomic counter, no I/O)
    ///   2. System rules conditioned on artifacts only
    ///   3. Heuristic credential scan (regex pass)
    ///   4. Org rules conditioned on artifacts (NOT classified labels)
    /// Does NOT run: embedding, cluster, use_case, semantic anomaly,
    /// org rules conditioned on classified labels.
    pub fn pre_call(&self, call: &LlmCall) -> Decision;

    /// Async enrichment + telemetry emission. Must NOT be called on
    /// the host's critical path. Bindings spawn this on a worker thread
    /// or async task. Runs:
    ///   - Embedding (ONNX or cloud, depending on tier)
    ///   - Cluster, use_case, semantic anomaly
    ///   - Org rules conditioned on classified labels
    ///   - Final telemetry emission (enriched event)
    pub fn post_call(&self, token: DecisionToken, resp: &LlmResponse);
}
```

### 4.2 Streaming variants

```rust
impl SothSdk {
    /// Streaming counterpart to `pre_call`. Returns a Decision on the
    /// initial call and an observation handle for the chunk stream.
    /// If Decision is Block, `chunk` and `end` are never called.
    pub fn stream_begin(&self, call: &LlmCall) -> (Decision, StreamObservation);

    /// Per-chunk update. Cheap; no I/O. Bindings call this once per
    /// chunk emitted by the provider stream.
    pub fn stream_chunk(&self, obs: &mut StreamObservation, chunk: &LlmChunk);

    /// Stream end. Equivalent to `post_call` for streaming responses.
    /// Telemetry emission happens here.
    pub fn stream_end(&self, obs: StreamObservation);
}
```

### 4.3 Bundle refresh

```rust
impl SothSdk {
    /// Pull a new bundle from the configured CDN URL, verify signature,
    /// hot-swap via ArcSwap. Customer schedules this (cron, background
    /// task, dashboard webhook). The SDK does NOT spawn its own
    /// refresher.
    pub fn refresh_bundle(&self) -> Result<(), SdkError>;
}
```

---

## 5. `DecisionToken` lifecycle

### 5.1 Creation

`DecisionToken` is allocated by `pre_call` / `stream_begin`. Internally it
indexes into a fixed-size slab (default 4096 slots) holding the pending
decision context (artifacts, anomaly signals, partial classification
state, redaction list).

### 5.2 Consumption

A token is consumed exactly once by `post_call` / `stream_end`. Consumption:
- Marks the slab slot free
- Triggers async classify enrichment using the partial state
- Emits the final telemetry event

### 5.3 Token reuse

**Debug builds:** panic with a clear message identifying the offending
binding.

**Release builds:** log the reuse at WARN level with the token ID and
counter value, then ignore the reuse silently. The host call continues
unaffected.

Rationale: token reuse is a binding bug, not a customer bug. We want to
catch it loudly during binding development (panic in debug); we do not
want to crash a customer's prod app if a binding bug slips through. The
log line is the trigger for the binding team to fix the leak.

### 5.4 Never consumed (orphaned)

A timeout-driven sweeper checks slab slots older than a configurable
threshold (default 60s). Orphaned slots:
- Emit a telemetry event tagged `decision_orphaned: true` with the
  partial state available
- Free the slab slot

Rationale: customers using cancellation, retries, or framework wrappers
that drop the response can leave tokens orphaned. The 60s window is
generous enough to cover even slow provider streams; the telemetry tag
lets the cloud distinguish orphans from completed calls.

### 5.5 Slab pressure

When the slab is at 95% capacity, `pre_call` switches to a degraded
mode: it still returns a `Decision`, but the embedded token is the
sentinel `DecisionToken::SLAB_FULL`. The wrapper treats this token
identically; `post_call(SLAB_FULL, ...)` is a no-op and emits a
telemetry event tagged `slab_full_no_enrichment: true`.

This guarantees `pre_call` never blocks or fails on slab pressure. The
slab-full event is the signal to size up.

---

## 6. Wrapper exception contract

### 6.1 The contract

For every language binding:

1. `Decision::Block` is translated into a host-language exception
   named `SothBlocked` (Python) / `SothBlocked` (TypeScript) / etc.
2. `SothBlocked` inherits from the language's **base exception type**
   (`Exception` in Python, `Error` in TypeScript), NOT from the
   provider SDK's exception hierarchy (`openai.APIError`,
   `anthropic.APIError`, etc.).
3. `SothBlocked` propagates past existing
   `try/except openai.APIError` blocks. **This is intentional behavior.**
4. Wrappers MUST NOT catch `SothBlocked` and re-raise it as a
   provider-specific exception type.
5. Wrappers MUST NOT wrap `SothBlocked` inside a provider exception.

### 6.2 Python contract

```python
class SothBlocked(Exception):
    """Raised when SOTH policy blocks an LLM call.

    Inherits from Exception, NOT from any provider SDK exception type.
    Will propagate past `try/except openai.APIError` handlers — this is
    intentional. A policy block is not an upstream API error and must
    not be retried by retry-on-API-error logic.
    """
    decision_id: str
    reason: BlockReason
    policy_rule_id: Optional[str]
```

### 6.3 TypeScript contract

```typescript
export class SothBlocked extends Error {
  constructor(
    public readonly decisionId: string,
    public readonly reason: BlockReason,
    public readonly policyRuleId?: string,
  ) {
    super(`SOTH policy blocked call: ${reason.kind}`);
    this.name = 'SothBlocked';
  }
}
```

`extends Error` — does NOT extend `OpenAI.APIError` or any provider's
error type.

### 6.4 Per-binding test invariants

Each binding ships negative tests that prove:

```python
# Python — must pass
import openai
try:
    client.chat.completions.create(...)  # blocked
except openai.APIError:
    assert False, "SothBlocked must not be caught by openai.APIError"
except SothBlocked:
    pass  # correct
```

```typescript
// TypeScript — must pass
try {
  await client.chat.completions.create({ ... });  // blocked
} catch (e) {
  if (e instanceof OpenAI.APIError) {
    throw new Error("SothBlocked must not be caught by OpenAI.APIError");
  }
  if (e instanceof SothBlocked) {
    // correct
  }
}
```

These tests are gating: a binding cannot ship without them passing.

### 6.5 Rationale

A policy block is a SOTH decision, not an upstream API error. Customers
with retry-on-API-error logic (almost everyone) would silently retry
blocked calls if `SothBlocked` inherited from the provider's exception
hierarchy, which would defeat the purpose of enforcement. The
propagate-past behavior is the correct semantic; the docs explain it
clearly so customers add explicit `except SothBlocked` handlers when
they want graceful degradation.

---

## 7. Sync vs async budget

### 7.1 `pre_call` budget — synchronous, ≤5 ms p99

Allowed work:
- **Budget check** — atomic counter read + compare. ~1 µs.
- **System rules** — fixed set of artifact-conditioned rules
  (private_key, aws_access_key, openai_secret, etc.). All regex; no
  ML. ~10–500 µs depending on body size.
- **Heuristic credential scan** — same regex pass as the proxy's
  `credential_scan_str`. Already optimized; ~100 µs–1 ms.
- **Org rules — artifact branch only** — rules that match on
  `artifacts[].kind`, NOT on classified labels. ~50 µs per rule.

Forbidden work:
- ONNX inference (not in budget)
- LSH cluster lookup (depends on embedding)
- Any I/O — telemetry, network, disk
- Any allocation > 1 KB

### 7.2 `post_call` / `stream_end` budget — async, ≤300 ms p99

Allowed work:
- **Embedding** — ONNX inference (full mode) or cloud round-trip
  (cloud-classify mode). Dominant cost.
- **Cluster, use_case, volatility, semantic anomaly** — pure CPU,
  ~5–20 ms total.
- **Org rules — full branch** — rules conditioned on classified labels.
  ~50 µs per rule.
- **Telemetry emission** — serialize event, push to in-memory queue.
  Cloud transport is its own background task.

Allowed I/O:
- HTTPS POST to soth-cloud telemetry endpoint (background task)
- HTTPS GET to cloud-classify endpoint (cloud-classify mode only)

### 7.3 Budget enforcement

Bindings instrument both paths with histograms. CI gating:
- `pre_call` p99 < 5 ms over 10 K synthetic calls
- `post_call` p99 < 300 ms over 1 K synthetic calls (with mocked
  cloud endpoints to keep CI hermetic)

Any binding PR that regresses these gates fails CI.

### 7.4 Failure modes

`pre_call` panic → caught at FFI boundary, return
`Decision::Allow { token: SENTINEL_TOKEN }`, log at ERROR. The host
call proceeds.

`post_call` panic → caught at FFI boundary, log at ERROR, drop the
slab slot. No host-visible effect.

Cloud-classify failure → log at WARN, emit telemetry event tagged
`cloud_classify_failed: true` with whatever local state is available
(Unknown use_case_label, partial anomaly flags).

---

## 8. Conformance harness assertions

The `soth-conformance-tests` corpus from Plan 1 PR 5 is extended for the
SDK lane.

### 8.1 Strict-parity Decision assertions

For every fixture not tagged `proxy_only: true`, the harness asserts
`Decision` equality between the proxy lane and the SDK lane:

- **Variant equality** — `Decision::Allow / Block / Redact / Flag`
  must match.
- **`BlockReason` equality** — when both are `Block`, the inner
  `BlockReason` must match (same `kind`, same `rule_id` for
  `PolicyRule`, etc.).
- **`MessageRedactions` parity** — when both are `Redact`, the set of
  `message_idx` values must match. The replacement content does NOT
  need to be byte-identical (proxy may use a different placeholder
  string); only the set of redacted indices is asserted.
- **`FlagSeverity` equality** — when both are `Flag`, severity must
  match.

### 8.2 Excluded from strict comparison

- `DecisionToken` (per-call ephemeral, never compared)
- `RedactReason` (telemetry tag; harness asserts presence but not exact
  match across lanes)
- `BlockReason::PolicyRule.rule_name` (cosmetic; only `rule_id` is
  asserted)

### 8.3 Proxy-only fixtures

Fixtures tagged `proxy_only: true` skip the SDK-lane assertion entirely.
Today's tags:

- Reroute-policy fixtures (SDK doesn't return Reroute)
- Within-message-redaction fixtures (SDK is message-level only)
- gRPC fixtures (until SDK ships gRPC support)

### 8.4 Asymmetric fixtures

The harness's `compare()` must not fail when the SDK Decision contains
a richer `BlockReason` than the proxy provides (e.g. SDK adds
`UseAlternative` while proxy returns plain Reroute). This is normal
graduation; the proxy will catch up over time.

### 8.5 Conformance harness extension

`crates/soth-conformance-tests/src/lib.rs` adds:

```rust
pub fn compare_decisions(
    proxy_decision: &Decision,
    sdk_decision: &Decision,
) -> Vec<DecisionDiff>;
```

A new dimension in the existing `Diff` output: `decision.variant`,
`decision.block_reason.kind`, `decision.redact.message_indices`.

---

## 9. Open questions / deferred

- **Async runtime in `post_call`**: bindings need to spawn `post_call`
  off-thread. Python uses `concurrent.futures.ThreadPoolExecutor`;
  Node uses `napi-rs`'s threadpool; Go uses a goroutine. The Rust core
  exposes `post_call` as a blocking function; bindings own the
  threading. **Confirmed.**
- **Nested calls** (an LLM tool call that itself triggers another LLM
  call): each call gets its own `DecisionToken`. The `LlmCall.context`
  carries a `parent_decision_id` so the cloud can reconstruct the
  call tree. Spec'd separately in a follow-up.
- **Bidirectional streaming** (e.g. realtime audio): treated as a
  long-lived stream. `stream_chunk` runs per audio frame; `stream_end`
  is the session terminator. Latency budget for `stream_chunk` is
  even tighter (≤500 µs p99). Spec'd separately if the realtime API
  becomes a target.

---

## 10. If this needs to change

Any change to `Decision`, `BlockReason`, `MessageRedactions`,
`DecisionToken` lifecycle, or the wrapper exception contract is a
**breaking change** for every binding and every customer downstream.
Roll forward with semver: bump major on `soth-sdk-core`, bump major
on every binding, document migration in CHANGELOG.

The conformance harness is the safety net: any divergence from this
spec that affects strict-parity fixtures fails CI, naming the
diverging field. Use that signal — don't override it.
