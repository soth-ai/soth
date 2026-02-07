//! Test command - Run tests with CI-friendly output
//!
//! Provides JSON, JUnit, and TAP output formats for CI/CD integration.

use crate::style;
use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::Args;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// Arguments for the test command
#[derive(Args, Debug)]
pub struct TestArgs {
    /// Output format (json, junit, tap, text)
    #[arg(short, long, default_value = "text")]
    pub format: String,

    /// Output file (stdout if not specified)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Run benchmarks instead of tests
    #[arg(long)]
    pub bench: bool,

    /// Filter tests by pattern
    #[arg(short = 'F', long)]
    pub filter: Option<String>,

    /// Only run tests matching this crate/package
    #[arg(short, long)]
    pub package: Option<String>,

    /// Run with release optimizations (for benchmarks)
    #[arg(long)]
    pub release: bool,

    /// Show per-layer timing breakdown
    #[arg(long)]
    pub timing: bool,

    /// Run integration tests only
    #[arg(long)]
    pub integration: bool,

    /// Number of parallel test threads
    #[arg(long)]
    pub jobs: Option<usize>,
}

/// Test result status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestStatus {
    Passed,
    Failed,
    Skipped,
    Ignored,
}

/// A single test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub name: String,
    pub status: TestStatus,
    pub duration_ms: u64,
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

/// Test suite summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuite {
    pub name: String,
    pub timestamp: DateTime<Utc>,
    pub duration_ms: u64,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub ignored: usize,
    pub tests: Vec<TestResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<TimingBreakdown>,
}

/// Per-layer timing breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingBreakdown {
    pub identity_us: Option<f64>,
    pub policy_us: Option<f64>,
    pub observe_us: Option<f64>,
    pub budget_us: Option<f64>,
    pub total_us: f64,
}

/// Full test report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestReport {
    pub version: String,
    pub generated_at: DateTime<Utc>,
    pub suites: Vec<TestSuite>,
    pub summary: TestSummary,
}

/// Overall test summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSummary {
    pub total_suites: usize,
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub ignored: usize,
    pub duration_ms: u64,
    pub success: bool,
}

/// Run the test command
pub async fn run(args: TestArgs) -> Result<()> {
    style::header("SOTH Test Runner");

    let start = Instant::now();

    // Build cargo test command
    let mut cmd = Command::new("cargo");

    if args.bench {
        cmd.arg("bench");
    } else {
        cmd.arg("test");
    }

    cmd.arg("--workspace");

    if let Some(ref package) = args.package {
        cmd.args(["--package", package]);
    }

    if args.release {
        cmd.arg("--release");
    }

    if args.integration {
        cmd.arg("--test").arg("*");
    }

    // Add test filter
    cmd.arg("--")
        .arg("--format=json")
        .arg("-Z")
        .arg("unstable-options");

    if let Some(ref filter) = args.filter {
        cmd.arg(filter);
    }

    if let Some(jobs) = args.jobs {
        cmd.args(["--test-threads", &jobs.to_string()]);
    }

    // Capture output
    println!("{} Running tests...", style::CIRCLE_FILLED.cyan());

    let output = cmd.output()?;
    let total_duration = start.elapsed();

    // Parse test output
    let report = parse_cargo_test_output(&output.stdout, &output.stderr, total_duration)?;

    // Output in requested format
    let formatted = match args.format.as_str() {
        "json" => format_json(&report)?,
        "junit" => format_junit(&report),
        "tap" => format_tap(&report),
        _ => format_text(&report),
    };

    // Write output
    if let Some(ref path) = args.output {
        tokio::fs::write(path, &formatted).await?;
        println!();
        style::success(&format!("Results written to {}", path.display()));
    } else if args.format != "text" {
        println!("{}", formatted);
    }

    // Print summary for text format or when writing to file
    if args.format == "text" || args.output.is_some() {
        print_summary(&report);
    }

    // Exit with appropriate code
    if report.summary.success {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn parse_cargo_test_output(stdout: &[u8], stderr: &[u8], duration: Duration) -> Result<TestReport> {
    let stdout_str = String::from_utf8_lossy(stdout);
    let _stderr_str = String::from_utf8_lossy(stderr);

    let mut tests: Vec<TestResult> = Vec::new();
    let mut current_suite = "default".to_string();

    // Parse JSON lines from cargo test output
    for line in stdout_str.lines() {
        if !line.starts_with('{') {
            continue;
        }

        if let Ok(event) = serde_json::from_str::<CargoTestEvent>(line) {
            match event.event_type.as_str() {
                "test" => {
                    if let Some(name) = event.name {
                        let status = match event.result.as_deref() {
                            Some("ok") => TestStatus::Passed,
                            Some("failed") => TestStatus::Failed,
                            Some("ignored") => TestStatus::Ignored,
                            _ => TestStatus::Skipped,
                        };

                        tests.push(TestResult {
                            name,
                            status,
                            duration_ms: event.exec_time.map(|t| (t * 1000.0) as u64).unwrap_or(0),
                            message: event.stdout.clone(),
                            stdout: event.stdout,
                            stderr: None,
                        });
                    }
                }
                "suite" => {
                    if let Some(name) = event.name {
                        current_suite = name;
                    }
                }
                _ => {}
            }
        }
    }

    // If we didn't parse any JSON (older cargo), parse plain text
    if tests.is_empty() {
        tests = parse_plain_text_output(&stdout_str);
    }

    // Calculate summary
    let passed = tests
        .iter()
        .filter(|t| t.status == TestStatus::Passed)
        .count();
    let failed = tests
        .iter()
        .filter(|t| t.status == TestStatus::Failed)
        .count();
    let skipped = tests
        .iter()
        .filter(|t| t.status == TestStatus::Skipped)
        .count();
    let ignored = tests
        .iter()
        .filter(|t| t.status == TestStatus::Ignored)
        .count();

    let suite = TestSuite {
        name: current_suite,
        timestamp: Utc::now(),
        duration_ms: duration.as_millis() as u64,
        total: tests.len(),
        passed,
        failed,
        skipped,
        ignored,
        tests,
        timing: None,
    };

    Ok(TestReport {
        version: "1.0.0".to_string(),
        generated_at: Utc::now(),
        suites: vec![suite],
        summary: TestSummary {
            total_suites: 1,
            total_tests: passed + failed + skipped + ignored,
            passed,
            failed,
            skipped,
            ignored,
            duration_ms: duration.as_millis() as u64,
            success: failed == 0,
        },
    })
}

fn parse_plain_text_output(output: &str) -> Vec<TestResult> {
    let mut tests = Vec::new();

    for line in output.lines() {
        if line.starts_with("test ")
            && (line.contains(" ... ok")
                || line.contains(" ... FAILED")
                || line.contains(" ... ignored"))
        {
            let parts: Vec<&str> = line.split(" ... ").collect();
            if parts.len() >= 2 {
                let name = parts[0].trim_start_matches("test ").to_string();
                let status = if parts[1].contains("ok") {
                    TestStatus::Passed
                } else if parts[1].contains("FAILED") {
                    TestStatus::Failed
                } else if parts[1].contains("ignored") {
                    TestStatus::Ignored
                } else {
                    TestStatus::Skipped
                };

                tests.push(TestResult {
                    name,
                    status,
                    duration_ms: 0,
                    message: None,
                    stdout: None,
                    stderr: None,
                });
            }
        }
    }

    tests
}

#[derive(Debug, Deserialize)]
struct CargoTestEvent {
    #[serde(rename = "type")]
    event_type: String,
    name: Option<String>,
    #[serde(rename = "event")]
    _event: Option<String>,
    #[serde(rename = "exec_time")]
    exec_time: Option<f64>,
    result: Option<String>,
    stdout: Option<String>,
}

fn format_json(report: &TestReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

fn format_junit(report: &TestReport) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");

    xml.push_str(&format!(
        "<testsuites name=\"soth\" tests=\"{}\" failures=\"{}\" errors=\"0\" time=\"{:.3}\">\n",
        report.summary.total_tests,
        report.summary.failed,
        report.summary.duration_ms as f64 / 1000.0
    ));

    for suite in &report.suites {
        xml.push_str(&format!(
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"0\" time=\"{:.3}\" timestamp=\"{}\">\n",
            escape_xml(&suite.name),
            suite.total,
            suite.failed,
            suite.duration_ms as f64 / 1000.0,
            suite.timestamp.to_rfc3339()
        ));

        for test in &suite.tests {
            xml.push_str(&format!(
                "    <testcase name=\"{}\" time=\"{:.3}\"",
                escape_xml(&test.name),
                test.duration_ms as f64 / 1000.0
            ));

            match test.status {
                TestStatus::Passed => {
                    xml.push_str(" />\n");
                }
                TestStatus::Failed => {
                    xml.push_str(">\n");
                    xml.push_str(&format!(
                        "      <failure message=\"{}\">{}</failure>\n",
                        escape_xml(test.message.as_deref().unwrap_or("Test failed")),
                        escape_xml(test.stdout.as_deref().unwrap_or(""))
                    ));
                    xml.push_str("    </testcase>\n");
                }
                TestStatus::Skipped | TestStatus::Ignored => {
                    xml.push_str(">\n");
                    xml.push_str("      <skipped />\n");
                    xml.push_str("    </testcase>\n");
                }
            }
        }

        xml.push_str("  </testsuite>\n");
    }

    xml.push_str("</testsuites>\n");
    xml
}

fn format_tap(report: &TestReport) -> String {
    let mut tap = String::new();
    tap.push_str(&format!(
        "TAP version 13\n1..{}\n",
        report.summary.total_tests
    ));

    let mut test_num = 1;
    for suite in &report.suites {
        for test in &suite.tests {
            let status = match test.status {
                TestStatus::Passed => "ok",
                TestStatus::Failed => "not ok",
                TestStatus::Skipped | TestStatus::Ignored => "ok # SKIP",
            };

            tap.push_str(&format!("{} {} - {}\n", status, test_num, test.name));

            if test.status == TestStatus::Failed {
                if let Some(ref msg) = test.message {
                    for line in msg.lines() {
                        tap.push_str(&format!("  # {}\n", line));
                    }
                }
            }

            test_num += 1;
        }
    }

    tap
}

fn format_text(report: &TestReport) -> String {
    let mut text = String::new();

    for suite in &report.suites {
        for test in &suite.tests {
            let status = match test.status {
                TestStatus::Passed => format!("{}", "ok".green()),
                TestStatus::Failed => format!("{}", "FAILED".red()),
                TestStatus::Skipped => format!("{}", "skipped".yellow()),
                TestStatus::Ignored => format!("{}", "ignored".dimmed()),
            };

            text.push_str(&format!(
                "test {} ... {} ({:.3}s)\n",
                test.name,
                status,
                test.duration_ms as f64 / 1000.0
            ));

            if test.status == TestStatus::Failed {
                if let Some(ref msg) = test.message {
                    text.push_str(&format!("  {}\n", msg));
                }
            }
        }
    }

    text
}

fn print_summary(report: &TestReport) {
    println!();
    println!("{}", "\u{2500}".repeat(60).dimmed());
    println!();

    let status_icon = if report.summary.success {
        style::CHECK.green().to_string()
    } else {
        style::CROSS.red().to_string()
    };

    let failed_str = if report.summary.failed > 0 {
        format!("{}", report.summary.failed.to_string().red())
    } else {
        format!("{}", report.summary.failed.to_string().dimmed())
    };

    println!(
        "{} Test Results: {} passed, {} failed, {} ignored ({:.2}s)",
        status_icon,
        report.summary.passed.to_string().green(),
        failed_str,
        report.summary.ignored.to_string().dimmed(),
        report.summary.duration_ms as f64 / 1000.0
    );

    if report.summary.failed > 0 {
        println!();
        println!("{}", "Failed tests:".red().bold());
        for suite in &report.suites {
            for test in &suite.tests {
                if test.status == TestStatus::Failed {
                    println!("  {} {}", style::CROSS.red(), test.name);
                }
            }
        }
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_plain_text() {
        let output = r#"
running 3 tests
test foo::bar ... ok
test baz::qux ... FAILED
test skip::me ... ignored

test result: FAILED. 1 passed; 1 failed; 1 ignored
"#;

        let tests = parse_plain_text_output(output);
        assert_eq!(tests.len(), 3);
        assert_eq!(tests[0].status, TestStatus::Passed);
        assert_eq!(tests[1].status, TestStatus::Failed);
        assert_eq!(tests[2].status, TestStatus::Ignored);
    }

    #[test]
    fn test_format_junit() {
        let report = TestReport {
            version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            suites: vec![TestSuite {
                name: "test".to_string(),
                timestamp: Utc::now(),
                duration_ms: 100,
                total: 2,
                passed: 1,
                failed: 1,
                skipped: 0,
                ignored: 0,
                tests: vec![
                    TestResult {
                        name: "test_pass".to_string(),
                        status: TestStatus::Passed,
                        duration_ms: 50,
                        message: None,
                        stdout: None,
                        stderr: None,
                    },
                    TestResult {
                        name: "test_fail".to_string(),
                        status: TestStatus::Failed,
                        duration_ms: 50,
                        message: Some("assertion failed".to_string()),
                        stdout: None,
                        stderr: None,
                    },
                ],
                timing: None,
            }],
            summary: TestSummary {
                total_suites: 1,
                total_tests: 2,
                passed: 1,
                failed: 1,
                skipped: 0,
                ignored: 0,
                duration_ms: 100,
                success: false,
            },
        };

        let junit = format_junit(&report);
        assert!(junit.contains("<?xml version"));
        assert!(junit.contains("<testsuites"));
        assert!(junit.contains("test_pass"));
        assert!(junit.contains("<failure"));
    }

    #[test]
    fn test_format_tap() {
        let report = TestReport {
            version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            suites: vec![TestSuite {
                name: "test".to_string(),
                timestamp: Utc::now(),
                duration_ms: 100,
                total: 2,
                passed: 1,
                failed: 1,
                skipped: 0,
                ignored: 0,
                tests: vec![
                    TestResult {
                        name: "test_pass".to_string(),
                        status: TestStatus::Passed,
                        duration_ms: 50,
                        message: None,
                        stdout: None,
                        stderr: None,
                    },
                    TestResult {
                        name: "test_fail".to_string(),
                        status: TestStatus::Failed,
                        duration_ms: 50,
                        message: None,
                        stdout: None,
                        stderr: None,
                    },
                ],
                timing: None,
            }],
            summary: TestSummary {
                total_suites: 1,
                total_tests: 2,
                passed: 1,
                failed: 1,
                skipped: 0,
                ignored: 0,
                duration_ms: 100,
                success: false,
            },
        };

        let tap = format_tap(&report);
        assert!(tap.contains("TAP version 13"));
        assert!(tap.contains("1..2"));
        assert!(tap.contains("ok 1 - test_pass"));
        assert!(tap.contains("not ok 2 - test_fail"));
    }
}
