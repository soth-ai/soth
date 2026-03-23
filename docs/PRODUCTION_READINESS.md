# SOTH Production Readiness Assessment

**Date:** 2026-03-23
**Scope:** Enterprise deployment as an AI governance & enforcement proxy across 1000+ organizations
**Status:** Pre-production — critical gaps identified

---

## Executive Summary

SOTH is an edge MITM proxy that intercepts AI provider traffic (OpenAI, Anthropic, Google, etc.) to provide organizational governance: policy enforcement, cost tracking, credential detection, and audit logging. It runs as a per-device agent on macOS, Linux, and Windows.

The core architecture is sound — the parsing pipeline, streaming extraction, bundle hot-reload, and telemetry durability are well-engineered. However, the system was built as an **observability tool** and has not yet been hardened for **enforcement**. The default configuration is observe-only, meaning policy block decisions are logged but not acted upon.

For enterprise deployment as a governance tool, four areas require attention:
1. Policy enforcement must actually enforce (not just observe)
2. Compliance with data protection regulations (GDPR, SOC2)
3. Operational infrastructure for fleet management at scale
4. Reliability hardening for always-on production use

---

## 1. Policy Enforcement

### 1.1 Default Configuration Is Observe-Only

**Current state:** The proxy's default `intercept_mode` is `Monitor`, which tees the request body and forwards it to the AI provider simultaneously. Even if the classify pipeline produces a `Block` decision, the request has already been delivered to the provider. The proxy can suppress the response, but the prompt has already been processed by the AI model.

Additionally, `block_signal_timeout_ms` defaults to `0`, meaning the handler does a non-blocking check for the classify result and immediately returns `Allow` if classify hasn't finished yet. Since classify runs asynchronously (embedding + policy evaluation), it almost never finishes in zero milliseconds.

**Why this matters:** An organization deploys SOTH to prevent employees from sending proprietary source code to AI providers. Under the default configuration, the source code reaches the provider before the policy evaluation completes. The proxy logs that the request *should have been blocked* (`policy_enforced: false`), but the data has already left the organization.

**What needs to change:**
- Governance deployments must use `intercept_mode: enforce` with `buffer_request_bodies: true`
- `block_signal_timeout_ms` should default to 250-500ms in enforce mode, giving the classify pipeline time to evaluate before the request is forwarded
- A deployment profile or config template for governance use cases should ship with the product
- Documentation must clearly distinguish "audit mode" from "enforce mode" and their guarantees

### 1.2 Fast Block Decision Skips Org-Specific Rules

**Current state:** The synchronous fast-block evaluation path (`fast_block_decision` in classify_task.rs) sets `skip_org_rules: true`. This means only system-level rules (budget limits, credential blocks) are evaluated synchronously. Organization-specific custom rules are only evaluated in the asynchronous path, which completes after the timeout window.

**Why this matters:** An organization creates a policy rule "block all requests to AI providers containing the keyword 'CONFIDENTIAL'". This rule is an org-level rule. Under the current architecture, it is never evaluated within the block timeout window, so it can never be enforced — only logged after the fact.

**What needs to change:**
- The fast-block path should evaluate org rules when `block_signal_timeout_ms > 0`
- If full org-rule evaluation is too expensive for the synchronous path, the most critical org rules should be extractable into a "fast rules" set

### 1.3 WebSocket Upgrades Cannot Be Revoked

**Current state:** WebSocket upgrade requests always return `Allow`. Policy evaluation is deferred to the first WebSocket frame. If the deferred evaluation produces a `Block` decision, the block signal receiver is intentionally discarded — the connection remains open.

**Why this matters:** AI providers are increasingly using WebSocket for real-time streaming (OpenAI Responses API, Codex). An organization that blocks certain models or usage patterns has no enforcement mechanism for WebSocket-based interactions. The proxy observes but cannot intervene.

**What needs to change:**
- When deferred classify produces a `Block`, the proxy should send a WebSocket close frame (RFC 6455 status code 1008: Policy Violation) and terminate the connection
- This requires the streaming layer to accept a "kill" signal from the classify task

### 1.4 Fail-Open Default Posture

**Current state:** Every gating stage defaults to fail-open:
- `unknown_app_action: Skip` — unknown applications are allowed through
- `non_cataloged_host_action: Skip` — traffic to hosts not in the bundle catalog passes without inspection
- Stage 3 (blacklist) returns `Skip`, not `Block` — blacklisted content is skipped from capture, not actively blocked
- HTTP/3 QUIC traffic is passthroughed without inspection (`http3_passthrough: true`)

**Why this matters:** A governance tool that defaults to allowing everything it doesn't recognize provides a false sense of security. Unknown AI providers, self-hosted LLM endpoints, or providers that adopt QUIC transport will bypass all policy enforcement silently.

**What needs to change:**
- Governance deployments should default to `non_cataloged_host_action: intercept` (inspect unknown hosts) or at minimum `passthrough` (forward but log)
- The blacklist stage should support a `Block` action in addition to `Skip`
- HTTP/3 interception or at minimum blocking should be on the roadmap
- Documentation should explain the security implications of each default

### 1.5 Classify Overload Silently Bypasses Policy

**Current state:** The classify pipeline has 8 concurrent slots (configurable). When all slots are occupied, new requests are silently dropped from classification. The `classify_overload_drop` counter is incremented, but the request is forwarded without policy evaluation.

**Why this matters:** Under sustained load (many concurrent AI requests), the most important requests — those that should be evaluated for policy compliance — may be the ones dropped. There is no priority queue, no backpressure to the client, and no differentiation between high-risk and low-risk requests.

**What needs to change:**
- In enforce mode, classify overload should either queue the request (with a timeout) or return a configurable fallback decision (default: `Block` for governance, `Allow` for monitoring)
- The overload condition should be exposed as a heartbeat alert, not just a counter

---

## 2. Compliance & Data Governance

### 2.1 No Employee Notification of Interception

**Current state:** The proxy operates as a transparent MITM. Employees whose AI traffic is intercepted receive no notification — no HTTP header, no system tray icon, no browser banner, no login-time consent dialog.

**Why this matters:** In the EU/EEA, intercepting employee communications without notification is likely illegal under GDPR Articles 13-14 (right to be informed) and Article 6 (lawful basis for processing). Even in jurisdictions with more permissive employer monitoring laws (US, UK), SOC2 and ISO 27001 require documented security policies and employee awareness.

Enterprise customers will be asked by their legal teams: "Do employees know their AI usage is being monitored?" Without a built-in notification mechanism, the answer is "the product doesn't support that."

**What needs to change:**
- At minimum: inject an `X-Soth-Intercepted: true` HTTP header into proxied requests (allows browser extensions or AI tools to display a notification)
- Recommended: provide a system tray agent that displays interception status
- Required: ship privacy notice templates, employee notification templates, and DPIA (Data Protection Impact Assessment) guidance
- The CA certificate installation process should include employee communication templates

### 2.2 No Data Retention Enforcement

**Current state:** The `intercept_records` table in SQLite grows unboundedly. The config file defines retention periods (`ai_proxy_days: 7`, `agent_app_days: 1`), but no code reads or enforces these values. Embeddings are expired after 90 days, but the primary audit records have no lifecycle.

**Why this matters:** GDPR Article 5(1)(e) requires that personal data is "kept in a form which permits identification of data subjects for no longer than is necessary." An AI governance proxy that retains usage records indefinitely violates this principle. SOC2 also requires documented data retention policies with enforcement.

From a practical standpoint, a proxy generating 1,000 records per day will accumulate 365,000 records per year. The SQLite database will grow to gigabytes, eventually filling the disk and causing the proxy to malfunction.

**What needs to change:**
- Implement a periodic retention enforcement job (in the existing maintenance tick) that deletes records older than the configured threshold
- Default retention should be 30 days (configurable per capture tier)
- The retention job should log how many records were purged (for audit trail)
- A startup check should warn when the DB exceeds a configurable size threshold

### 2.3 No Right to Erasure Mechanism

**Current state:** There is no way to delete all records for a specific individual. The `user_id_hmac` field is a one-way HMAC, which is good for privacy (pseudonymization) but means you cannot query "delete all records for employee john@company.com" without first computing their HMAC from the original identifier.

**Why this matters:** GDPR Article 17 gives data subjects the right to request erasure of their personal data. An enterprise deploying SOTH must be able to fulfill these requests. Without a mechanism in the product, the enterprise must build custom tooling or manually manipulate the SQLite database.

**What needs to change:**
- Provide a CLI command: `soth data erase --user-identifier "john@company.com"` that computes the HMAC, finds all matching records, and deletes them
- The cloud backend must also support erasure requests for transmitted telemetry
- Document the pseudonymization scheme so enterprises understand the data flow

### 2.4 No Built-In PII Detection for GDPR Categories

**Current state:** The credential scanner detects API keys, tokens, and private keys (12+ types). However, there are no built-in detectors for personal data categories relevant to GDPR: email addresses, phone numbers, social security numbers, postal addresses, dates of birth, or national ID numbers.

The `pii_detected` and `pii_types` fields exist in the API types, and the org-pattern system allows enterprises to configure custom regex patterns. But no patterns ship out of the box.

**Why this matters:** An employee asks an AI model to "summarize this customer record" and pastes a customer's name, email, phone number, and address into the prompt. SOTH detects no PII because it only looks for API keys and credentials. The organization's DPO (Data Protection Officer) has no visibility into personal data flowing to AI providers.

**What needs to change:**
- Ship built-in PII detectors for: email addresses, phone numbers (international formats), common national ID patterns (US SSN, UK NI, EU VAT), credit card numbers
- These should be configurable (enable/disable per category) and documented with false-positive guidance
- PII detection results should populate the `pii_detected` and `pii_types` fields in telemetry

### 2.5 No Encryption at Rest for Local Data

**Current state:** The local SQLite database (`~/.soth/logs/events.db`) stores intercept records, telemetry JSON, embeddings, and sync state as plaintext. Standard `rusqlite::Connection::open` is used with no encryption.

**Why this matters:** If the device is lost, stolen, or compromised, the SQLite database exposes a complete history of the employee's AI usage including hashed content, detected credentials (with 4-character hints), policy decisions, and cost data. While the data is pseudonymized and credentials are hashed, the metadata alone reveals sensitive patterns.

SOC2 requires encryption of data at rest for sensitive information. ISO 27001 Annex A.10 requires cryptographic controls.

**What needs to change:**
- Support SQLCipher or application-level encryption for the SQLite database
- The encryption key should be derived from the device identity and protected by the OS keychain (macOS Keychain, Windows DPAPI, Linux Secret Service)
- At minimum, document that filesystem-level encryption (FileVault, BitLocker, LUKS) is a prerequisite for deployment

### 2.6 No Customer-Managed Encryption Keys

**Current state:** Telemetry batches can be encrypted with ECIES (X25519 + ChaCha20-Poly1305). The encryption key is a static vendor public key configured in the proxy. The SOTH vendor holds the corresponding private key and can decrypt all telemetry.

**Why this matters:** Enterprise customers in regulated industries (healthcare, finance, government) require that the vendor cannot access their data. The current architecture requires trusting the vendor with the decryption key.

**What needs to change:**
- Support customer-managed encryption keys: the organization provides their own X25519 public key, and only they can decrypt the telemetry
- The vendor can provide infrastructure (storage, transport) without being able to read the content
- This is a prerequisite for deployment in industries with data sovereignty requirements

---

## 3. Operational Readiness

### 3.1 No Health or Metrics Endpoint

**Current state:** The proxy has no HTTP endpoint for health checks or metrics export. Health is inferred externally by `soth start`'s TCP connect check. The 17 heartbeat counters are shipped to the cloud backend via the sync agent but not exposed locally.

The config file declares `production.health.metrics_path: "/metrics"` but this is aspirational — no code implements it.

**Why this matters:** Fleet operators use Prometheus, Datadog, Grafana, or similar tools to monitor thousands of instances. Without a standard `/metrics` endpoint, SOTH cannot be integrated into existing monitoring infrastructure. Operators are blind to proxy health between heartbeat cycles.

Kubernetes liveness/readiness probes require an HTTP endpoint. Without `/healthz` and `/readyz`, container orchestration cannot manage the proxy lifecycle.

**What needs to change:**
- Implement a lightweight HTTP server (separate port from the MITM proxy) exposing:
  - `GET /healthz` — returns 200 if the proxy is accepting connections
  - `GET /readyz` — returns 200 if bundle is loaded AND sync agent is connected
  - `GET /metrics` — Prometheus-format exposition of all heartbeat counters plus latency histograms
- The heartbeat counters already exist; they just need an HTTP exposition layer

### 3.2 Circuit Breaker Not Implemented

**Current state:** The config file defines circuit breaker parameters (`failure_threshold: 5`, `open_duration: 30s`, `success_threshold: 3`), but no code reads or implements these values. The sync agent and telemetry sender retry failed requests with exponential backoff but no circuit breaking.

**Why this matters:** When the cloud backend is down, the sync agent makes a failed heartbeat request every 30 seconds, the telemetry replay worker retries failed batches on a 15-second scan interval, and the config puller makes failed config requests on each heartbeat cycle. This generates sustained failed-request load against a potentially recovering backend.

With 1,000+ instances all retrying against a recovering backend, the thundering herd effect can prevent recovery. Circuit breakers are a standard pattern for preventing this.

**What needs to change:**
- Implement circuit breaker logic for the sync agent's heartbeat, telemetry sender, and config puller
- When the circuit is open, skip the request entirely and return a cached/default response
- The config parameters already exist; they just need backing implementation

### 3.3 No Canary/Staged Bundle Rollout

**Current state:** All proxy instances poll the same cloud endpoint for bundles. When a new bundle is published, every instance downloads and applies it within one sync cycle. There is no mechanism for staged rollout, version pinning, or canary deployment.

**Why this matters:** A bundle contains format descriptors, matching rules, entity definitions, and policy rules. A malformed bundle (wrong regex, missing entity, incorrect path pattern) deployed to the entire fleet simultaneously could:
- Break detection for a specific AI provider (miss all traffic to that provider)
- Incorrectly block legitimate traffic (false positive in a policy rule)
- Cause parse failures that degrade proxy performance

At 1,000+ organizations, the blast radius of a bad bundle is the entire customer base.

**What needs to change:**
- Support bundle version pinning per organization or device group
- Implement percentage-based rollout (deploy to 1% of instances, then 10%, then 100%)
- Add a rollback command (`soth bundle rollback`) that reverts to the last-known-good version
- The cloud backend should track which version each device is running and alert on rollout failures

### 3.4 No Data Retention or Disk Management

**Current state:** The SQLite database grows without bound. There is no retention policy enforcement, no disk space monitoring, and no graceful degradation when disk is full.

**Why this matters:** A device generating 1,000 intercept records per day with average record size of 2KB produces ~700MB per year of DB growth. The WAL file adds overhead. With embeddings (384-dimensional float32 vectors = 1.5KB each), a busy device can generate gigabytes within months.

When the disk fills, SQLite writes fail. The proxy continues forwarding traffic (fail-open), but audit records are silently lost. The telemetry outbox also fails to enqueue, creating a data loss gap. The operator receives no warning until `soth status` reports degraded health.

**What needs to change:**
- Implement configurable retention with enforcement (delete records older than N days)
- Add disk space monitoring in the maintenance tick (warn at 90% capacity, degrade at 95%)
- When disk is critically low: skip non-essential writes (embeddings, body captures), continue forwarding traffic, emit heartbeat alert
- Add `PRAGMA wal_checkpoint(TRUNCATE)` to prevent WAL file unbounded growth

---

## 4. Scalability & Reliability

### 4.1 Long-Lived WebSocket Sessions Killed by Stale Eviction

**Current state:** The `StreamingStore.evict_stale` method evicts streams older than 300 seconds (5 minutes) based on `started_at` timestamp. It does not consider whether the stream is still actively receiving chunks.

**Why this matters:** AI coding assistants (Codex, Cursor, Claude Code) maintain long-lived WebSocket connections for real-time streaming. A coding session can last hours. After 5 minutes, the proxy's stale eviction kills the streaming state, meaning the proxy loses track of the session — no more turn counting, no usage extraction, no artifact scanning for the remainder of the connection.

**What needs to change:**
- Track `last_chunk_at` in `StreamAccumulator` (updated on each chunk)
- Change `evict_stale` to check `last_chunk_at` instead of `started_at`
- A stream that received a chunk within the last 5 minutes is not stale, regardless of when it started

### 4.2 CI Does Not Cover Primary Platforms

**Current state:** The CI pipeline (`.github/workflows/ci.yml`) runs only on `ubuntu-latest`. It checks formatting, runs clippy, and executes lib+bin tests. Integration tests (`--tests`) are not run. macOS and Windows are not tested.

**Why this matters:** SOTH's primary deployment target is macOS (developer workstations). Platform-specific code exists for system proxy configuration (`networksetup` on macOS, registry on Windows), CA certificate trust installation, process attribution, and daemon management. None of this is tested in CI.

A regression in macOS-specific code (e.g., system proxy enable/disable) would not be caught until manual testing or customer reports.

**What needs to change:**
- Add macOS runner to CI (GitHub Actions supports `macos-latest`)
- Run integration tests (`cargo test --workspace`) in CI, not just lib tests
- Add Windows runner for the platform-specific code paths
- Consider nightly CI jobs for load testing and integration tests against provider sandboxes

### 4.3 No Fuzzing Infrastructure

**Current state:** No `cargo-fuzz` targets, no `proptest` usage, no AFL integration. One test function named `phase4_fuzz_no_panic` is a hand-written property test, not actual fuzzing.

**Why this matters:** The proxy parses arbitrary JSON, HTTP, GraphQL, gRPC, protobuf, and SSE payloads from potentially adversarial sources. A malformed payload that causes a panic, infinite loop, or excessive memory allocation in the parse or detect pipeline is a denial-of-service vulnerability.

For a security-critical proxy deployed across thousands of organizations, fuzz testing is not optional — it is an industry standard expectation (see: Google's OSS-Fuzz, Microsoft's OneFuzz).

**What needs to change:**
- Add `cargo-fuzz` targets for: JSON body parsing (soth-parse), SSE chunk extraction (soth-detect streaming), credential regex matching (soth-detect sensitive), policy CEL evaluation (soth-policy)
- Integrate fuzz testing into nightly CI
- Run initial fuzzing campaigns to establish baseline coverage

---

## Appendix: Current Architecture Strengths

These areas are production-ready and well-engineered:

| Area | Details |
|------|---------|
| **Credential Detection** | 12+ types with hashed storage, 4-char hints, policy-driven redaction |
| **Bundle Hot-Reload** | Atomic ArcSwap swap, last-known-good fallback, signature verification |
| **Telemetry Durability** | SQLite outbox with retry, exponential backoff, dead-letter, signed batches |
| **Transit Encryption** | ECIES with ephemeral keys, ChaCha20-Poly1305, HKDF with salt, zeroized secrets |
| **Resource Bounding** | All stores have capacity limits with eviction, FD budget management, panic recovery |
| **Streaming Extraction** | SSE, NDJSON, WebSocket, length-prefixed, protobuf, Socket.IO support |
| **Parser DSL** | Data-driven format descriptors with rules engine, preprocess pipeline, accumulation |
| **Commitment Hashes** | SHA3-256 with random nonce — cryptographic proof of content observation |

---

## Appendix: Recommended Deployment Profiles

### Profile: Audit Mode (current default)

For organizations that want visibility into AI usage without blocking any traffic.

```yaml
pipeline:
  unknown_app_action: intercept
forward_proxy:
  intercept_mode: monitor
  buffer_request_bodies: false
```

### Profile: Governance Mode (recommended for enterprise)

For organizations that need to enforce AI usage policies.

```yaml
pipeline:
  unknown_app_action: intercept
  non_cataloged_host_action: intercept
forward_proxy:
  intercept_mode: enforce
  buffer_request_bodies: true
classify:
  block_signal_timeout_ms: 500
```

### Profile: Strict Mode (regulated industries)

For organizations with zero-tolerance data loss prevention requirements.

```yaml
pipeline:
  unknown_app_action: block
  non_cataloged_host_action: block
forward_proxy:
  intercept_mode: enforce
  buffer_request_bodies: true
  http3_passthrough: false
classify:
  block_signal_timeout_ms: 1000
```
