# P2 Implementation Task List

Date: 2026-02-07  
Branch: `feature/p2-implementation`  
Source plans: `docs/P1_EXECUTION_CHECKLIST.md`, `docs/PROPOSED_ARCHITECTURE_10X.md`, `docs/ARCHITECTURE_IMPROVEMENT_PLAN.md`

## 1. P2 Scope

P2 focuses on high-leverage architecture work that remains after P1:

1. Backend materialized projections for fast reads (`event_pairs`, `event_clusters`, `rollups_*`)
2. Frontend state/store rewrite for high-volume smoothness
3. Optional scale extensions behind explicit adoption gates
4. Full 10x benchmark certification and release hardening

Current status: Workstreams A and C are implemented in code; Workstreams B/D/E are partially complete and still need benchmark-grade validation.

## 2. Workstream A: Materialized Read Model

## Goal
Eliminate expensive runtime/UI recomputation by maintaining incremental projection tables.

## Tasks

- [x] Define projection schemas and migrations:
  - `event_pairs`
  - `event_clusters`
  - `rollups_1m`, `rollups_5m`, `rollups_1h` (or equivalent)
- [x] Implement projection worker(s) consuming committed event seq ranges.
- [x] Make projection updates idempotent and restart-safe.
- [x] Add projection watermark state (`last_projected_seq`) for recovery.
- [x] Add APIs that read projections directly (no full-scan fallback in hot path):
  - `/api/clusters`
  - `/api/rollups`
  - paired-response lookup via `event_pairs`

## Acceptance

- [x] Projection rebuild from empty DB succeeds and is deterministic.
- [x] Cluster and rollup endpoints avoid full event-table scans.
- [x] Replay/restart produces no duplicate or missing projection rows.

## 3. Workstream B: Frontend Store/Data-Plane Rewrite

## Goal
Keep UI responsive under heavy ingest by separating ingest entities from view windows.

## Tasks

- [x] Split state into:
  - stream cursor/connection state
  - entity map (`event_id -> summary`)
  - ordered ids/window cache
  - view/filter/selection state
- [x] Replace per-event append/update with batched apply.
- [x] Ensure id-upsert semantics preserve selection and row stability.
- [x] Move expensive decode/derive operations out of render hot path.
- [x] Keep payload hydration lazy and cache by `(event_id, part)`.

## Acceptance

- [ ] Fast scroll stays smooth while live ingest continues.
- [x] Reconnect replay does not duplicate rows.
- [x] Placeholder -> final payload replacement is deterministic.

## 4. Workstream C: Stream Protocol Hardening

## Goal
Make stream transport cursor-driven and lossless by protocol, not by best effort.

## Tasks

- [x] Standardize WS messages as seq-batched deltas.
- [x] Add explicit client ack/high-water semantics.
- [x] Add automatic backfill from DB when client lags.
- [x] Add stream lag observability (`latest_seq - acked_seq`).

## Acceptance

- [x] Reconnect from stale seq replays correctly.
- [x] No seq gaps in client-visible stream under burst load.
- [x] Lag metrics visible and alertable.

## 5. Workstream D: Optional Scale Extensions (Gate-Controlled)

## Goal
Prepare >10x headroom extensions without forcing operational complexity early.

## Tasks

- [ ] Define feature flags and activation thresholds for:
  - durable event bus mirror
  - analytics mirror (columnar)
- [ ] Keep SQLite-first as default authoritative path.
- [ ] Add compatibility adapters so extensions are non-breaking.

## Acceptance

- [ ] Extensions remain disabled by default.
- [ ] Enabling extension does not change enforcement correctness.
- [ ] Rollback to SQLite-only mode is straightforward.

## 6. Workstream E: 10x Benchmark and Release Certification

## Goal
Prove architecture gains with repeatable benchmarks and correctness invariants.

## Tasks

- [ ] Define baseline vs P2 benchmark suite:
  - sustained 200-500 events/sec
  - burst 1,500-3,000 events/sec
- [ ] Capture p50/p95/p99 for:
  - ingest commit latency
  - stream catch-up latency
  - UI interaction/frame smoothness
- [ ] Add invariant checks:
  - no seq gaps
  - no duplicate `event_id`
  - correct request/response pairing
- [ ] Produce benchmark report doc and release checklist.

## Acceptance

- [ ] Demonstrated >=10x throughput headroom vs baseline scenario.
- [ ] No data-loss regressions in stress tests.
- [ ] Release checklist signed off.

## 7. Execution Order

1. Workstream A (materialized read model)
2. Workstream C (stream hardening)
3. Workstream B (frontend store rewrite)
4. Workstream E (benchmark certification)
5. Workstream D (optional extensions)

Rationale: backend read/stream determinism first, then frontend scaling, then formal certification.

## 8. Test Gates

- [ ] `cargo check --workspace --all-targets`
- [ ] `cargo test --workspace --all-targets`
- [x] `npm --prefix dashboard run lint`
- [x] `npm --prefix dashboard run build`

Targeted gates:

- [x] projection rebuild/recovery tests
- [ ] seq replay and lag tests
- [ ] UI live-ingest + fast-scroll regression tests
- [ ] 10x benchmark script and result artifact

## 9. Definition of P2 Done

P2 is complete when:

- [ ] materialized projections are authoritative for heavy observability views
- [ ] frontend data plane remains responsive under high ingest
- [ ] stream protocol is cursor-driven with reliable replay
- [ ] benchmark suite and invariants demonstrate 10x target readiness
