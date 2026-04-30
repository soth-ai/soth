//! Cross-lane parity test.
//!
//! Discovers every `*.json` fixture under `crates/soth-conformance-tests/fixtures/`,
//! runs both the proxy and SDK lanes against it, and asserts the
//! contract-surface fields agree. On failure, every diverging field is
//! reported by name so the regression doesn't require local replay.

use soth_conformance_tests::{load_fixtures, CoverageReport, ParityRunner};

#[test]
fn proxy_and_sdk_lanes_agree_on_contract_surface() {
    let fixtures = load_fixtures();
    assert!(
        !fixtures.is_empty(),
        "no fixtures found — corpus directory is empty"
    );

    let runner = ParityRunner::new();
    let mut coverage = CoverageReport::default();
    let mut failures: Vec<(String, Vec<soth_conformance_tests::Diff>)> = Vec::new();

    let mut advisory: Vec<(String, Vec<soth_conformance_tests::Diff>)> = Vec::new();

    for (path, fixture) in &fixtures {
        coverage.record(fixture);
        let proxy = soth_conformance_tests::run_proxy_lane(
            fixture,
            &runner.detect_bundle,
            &runner.classify_bundle,
            &runner.config,
        );
        let sdk = soth_conformance_tests::run_sdk_lane(
            fixture,
            &runner.detect_bundle,
            &runner.classify_bundle,
            &runner.config,
        );

        let diffs = soth_conformance_tests::compare(&proxy, &sdk);
        if !diffs.is_empty() {
            failures.push((format!("{} ({})", fixture.name, path.display()), diffs));
        }

        let advisory_diffs = soth_conformance_tests::compare_advisory(&proxy, &sdk);
        if !advisory_diffs.is_empty() {
            advisory.push((fixture.name.clone(), advisory_diffs));
        }
    }

    println!("\n=== Conformance corpus coverage ===");
    println!("{}", coverage.render(fixtures.len()));

    if !advisory.is_empty() {
        println!("=== Advisory parity divergences (known follow-up work) ===");
        for (name, diffs) in &advisory {
            println!("  fixture: {name}");
            for diff in diffs {
                println!("    {}: proxy={} sdk={}", diff.field, diff.proxy, diff.sdk);
            }
        }
    }

    if !failures.is_empty() {
        let mut report = String::new();
        report.push_str("\n=== Conformance parity failures ===\n");
        for (name, diffs) in &failures {
            report.push_str(&format!("\nfixture: {name}\n"));
            for diff in diffs {
                report.push_str(&format!(
                    "  {}\n    proxy: {}\n    sdk:   {}\n",
                    diff.field, diff.proxy, diff.sdk
                ));
            }
        }
        panic!("{report}");
    }
}
