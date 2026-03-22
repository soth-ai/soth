---
name: type_unification_complete
description: B1-B6 type unification between soth-parse and soth-core is DONE — ~200 line conversion layer eliminated, all types re-exported from soth-core
type: project
---

B1-B6 type unification is complete. The ~200-line conversion layer in `soth-detect/src/engine.rs` (lines 1014-1212) has been reduced to ~30 lines with 1 trivial mapping function.

**What was done:**
- `Provider` string wrapper deleted → bare `String` on NormalizedRequest.provider (bundle-driven, no hardcoded enum)
- soth-parse `EndpointType`, `ParseWarning`, `FormatMetadata`, `GraphQlOperationType`, `ParseSource`, `NormalizedRequest` all deleted — re-exported from soth-core
- soth-parse `SensitiveArtifact`, `ArtifactKind`, `ArtifactSeverity`, `ArtifactLocation`, `ImportCategory` all deleted — re-exported from soth-core
- Core `NormalizedRequest.provider` changed from `DetectedProvider` enum to `String` (Option B — bundle-driven)
- Core `NormalizedRequest` gained `user_prompt: Option<String>` field
- Core `TelemetryEvent.provider`, `PreEmitResult.provider`, `GovernableEvent.provider` all changed to `String`
- 10 mapping functions deleted: `map_provider`, `map_endpoint_type`, `map_parse_warning`, `map_format_metadata`, `map_parse_source`, `to_core_normalized`, `map_artifact`, `map_artifact_kind`, `map_artifact_severity`, `map_artifact_location`, `map_import_category`

**Why:** Eliminate duplicated type definitions and the error-prone conversion layer between soth-parse and soth-core. Single source of truth for all shared types.

**How to apply:** When adding new fields to NormalizedRequest or artifact types, only soth-core needs to change. Parse-side construction sites use the core types directly.

**Remaining residue (intentionally kept):**
- `to_core_detect_result()` — structural copy needed because soth-parse `DetectResult` has `raw_body_bytes: Option<Bytes>` and `warnings: Vec<DetectWarning>` (different from core's `Vec<ParseWarning>`)
- `map_detect_warning()` — 4 lines converting `DetectWarning { code, detail }` → `ParseWarning::PartialBodyParse`
- Type aliases kept for brevity: `FormatMeta = FormatMetadata`, `GqlOpType = GraphQlOperationType`, `ArtifactType = ArtifactKind`, `Severity = ArtifactSeverity`, `DetectedImportCategory = ImportCategory`

**Baseline:** 271 tests, 0 failures maintained throughout.
