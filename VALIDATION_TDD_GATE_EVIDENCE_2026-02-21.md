# Validation/TDD Gate Evidence (2026-02-21)

## Scope

This records execution evidence for item `3` in the edge/cloud final plan:
`Run and record the full Validation Matrix and TDD gating assertions as release evidence`.

## Compile-Time Assertions (`C001`-`C009`)

Fixture: `docs/TDD_GOLDEN_FINAL_BUNDLE.json`  
Assertions: `docs/TDD_GOLDEN_BUNDLE_ASSERTIONS.json`

Executed machine checks (`jq`) for `C001`-`C008`:

- `C001` `required_top_level_keys`: PASS
- `C002` `no_legacy_detection_identity_keys`: PASS
- `C003` `formats_non_empty`: PASS
- `C004` `providers_api_format_resolves`: PASS
- `C005` `decision_rules_have_detection_id`: PASS
- `C006` `collector_sources_have_detection_and_parser`: PASS
- `C007` `wildcard_preservation`: PASS
- `C008` `sensor_source_sections_present`: PASS

`C009` is a description-only assertion in the JSON (manual evidence required).  
Manual host parity extraction result (after fixture parity update):

- Unmatched whitelist host patterns vs `decision_rules.rules[].host_pattern`: none (`[]`)

## Runtime Assertions (`R001`-`R105`)

Added executable runtime gate test:

- `crates/soth-oisp/tests/tdd_golden_runtime_assertions.rs`

Command:

- `cargo test -p soth-oisp --test tdd_golden_runtime_assertions`

Result:

- `2 passed, 0 failed`
- Covers connect assertions `R001`-`R003` and request assertions `R101`-`R105`.

Note: Runtime test keeps a defensive in-memory normalizer, but fixture parity was also corrected directly so `C009` now passes on raw artifact checks.

## Collector Assertions (`L001`-`L003`)

Contract checks against fixture (`jq` + glob matching in shell):

- `L001` openclaw deleted-session path matches source glob and skip pattern: PASS
- `L002` codex path matches collector glob, `read_mode=incremental`, `detection_id=agent.codex.app`: PASS
- `L003` antigravity has binary collector entry and upload endpoint `/api/v1/ingest/local-sessions`: PASS

Runtime behavior tests:

- `cargo test -p soth-collector`
- Result: `15 passed, 0 failed`
- Includes skip/glob collector behavior tests (`source_path_matches_skip_patterns_*`, `resolve_collector_sources_for_scan_*`).

## Ingest Assertions (`I001`-`I003`)

Cloud-side targeted tests:

- `cargo test --manifest-path ../soth-cloud/Cargo.toml -p soth-cloud-api normalize_exchange_v1_requires_detection_fields_for_non_collector`
- `cargo test --manifest-path ../soth-cloud/Cargo.toml -p soth-cloud-api normalize_exchange_v1_requires_client_device_id`
- `cargo test --manifest-path ../soth-cloud/Cargo.toml -p soth-cloud-api bundle_contract_validation_accepts_canonical_sections`
- `cargo test --manifest-path ../soth-cloud/Cargo.toml -p soth-cloud-api bundle_contract_validation_rejects_legacy_detection_identity_keys`
- `cargo test --manifest-path ../soth-cloud/Cargo.toml -p soth-cloud-api bundle_contract_validation_rejects_v3_provider_api_format_without_matching_format_key`

Result:

- All above tests passed.
- Additional ingest SQLx test `ingest_batch_keeps_valid_rows_when_some_rows_fail` is present but was ignored in this environment because `DATABASE_URL` is not set.

## Throughput Assertions (`T001`-`T002`)

Edge sync/throughput evidence:

- `cargo test -p soth-sync`
- Result: `47 unit tests passed`, `6 contract tests passed`, `0 failed`

Targeted coverage includes:

- frontload mode behavior (`exchange_sync_mode_frontload_tag_*`)
- frontload/live separation (`contract_frontload_and_live_batches_are_separated`)
- retry behavior (`contract_retry_queue_on_body_upload_failure`)
- rejection retry/drop classification (`classify_exchange_rejection_classifies_terminal_and_retryable_reasons`)

## Summary

- Assertion groups with executable evidence: compile-time (`C001`-`C008`), runtime (`R001`-`R105`), collector (`L001`-`L003`), ingest (required-field normalization + contract checks), throughput (frontload/retry behavior).
- Remaining explicit follow-up from this run:
  - SQLx ingest integration test requiring `DATABASE_URL` could not be executed in this environment.
