//! End-to-end latency benchmark for the synchronous hook pipeline.
//!
//! Measures `soth_code::run_hook` from stdin-bytes-in to queue-row-on-disk.
//! That covers: adapter parse → credential detect → classify (fallback
//! bundle) → policy decide → enqueue (atomic JSONL append).
//!
//! Targets (docs/gryph/plan.md §10.10):
//! - p99 ≤ 50ms cached
//! - p99 ≤ 100ms cold
//!
//! Cached/cold here distinguishes: the *first* invocation in this
//! process pays the bundle-load cost; subsequent invocations reuse the
//! cached bundle from `OnceLock`. The benchmark warms the cache before
//! measuring so reported timings reflect the steady-state cached path.
//!
//! Run with `cargo bench -p soth-code` for an interactive HTML report,
//! or `cargo bench -p soth-code -- --save-baseline ci` for a CI gate
//! that compares against a stored baseline.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use soth_code::paths::CodePaths;

/// Three input shapes covering the hot paths the dashboard cares about:
/// clean tool action (Allow), credential-bearing command (Block),
/// MCP tool response with a non-trivial array shape (the gryph PR #32
/// stress case).
fn inputs() -> Vec<(&'static str, &'static [u8])> {
    vec![
        (
            "clean_read",
            br#"{"session_id":"bench","tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}}"#,
        ),
        (
            "block_aws_key",
            br#"{"session_id":"bench","tool_name":"Bash","tool_input":{"command":"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE aws s3 ls"}}"#,
        ),
        (
            "mcp_array_response",
            br#"{"session_id":"bench","tool_name":"mcp__weather__forecast","tool_input":{"city":"SF"},"tool_response":[{"day":1,"temp":60},{"day":2,"temp":65},{"day":3,"temp":62},{"day":4,"temp":58}]}"#,
        ),
    ]
}

fn bench_hook_pipeline(c: &mut Criterion) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let paths = CodePaths::from_root(tmp.path());

    // Warm the classify bundle cache before measuring. Otherwise the
    // first sample in the benchmark would absorb the bundle-load cost
    // and skew the reported p99 upward.
    let _ = soth_code::run_hook("claude_code", "pre_tool_use", inputs()[0].1, &paths);

    let mut group = c.benchmark_group("hook_pipeline");
    // Hook subprocess invocations are short-lived; sample a lot for
    // tight confidence intervals at the p99 tail.
    group.sample_size(200);

    for (label, payload) in inputs() {
        group.bench_with_input(BenchmarkId::from_parameter(label), &payload, |b, payload| {
            b.iter(|| {
                let outcome = soth_code::run_hook(
                    black_box("claude_code"),
                    black_box("pre_tool_use"),
                    black_box(payload),
                    black_box(&paths),
                )
                .expect("hook ok");
                black_box(outcome.event_id)
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_hook_pipeline);
criterion_main!(benches);
