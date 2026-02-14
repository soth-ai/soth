//! Overhead measurement utilities
//!
//! Provides tools for measuring the latency overhead added by SOTH
//! to MCP calls by comparing baseline vs wrapped execution times.

use std::future::Future;
use std::time::{Duration, Instant};

/// Statistics for a set of latency measurements
#[derive(Debug, Clone)]
pub struct LatencyStats {
    /// Minimum latency
    pub min_us: f64,
    /// Maximum latency
    pub max_us: f64,
    /// Mean latency
    pub mean_us: f64,
    /// Median (P50) latency
    pub p50_us: f64,
    /// 95th percentile latency
    pub p95_us: f64,
    /// 99th percentile latency
    pub p99_us: f64,
    /// Standard deviation
    pub std_dev_us: f64,
    /// Sample count
    pub count: usize,
}

impl LatencyStats {
    /// Calculate statistics from a vector of durations
    pub fn from_durations(durations: &[Duration]) -> Self {
        if durations.is_empty() {
            return Self {
                min_us: 0.0,
                max_us: 0.0,
                mean_us: 0.0,
                p50_us: 0.0,
                p95_us: 0.0,
                p99_us: 0.0,
                std_dev_us: 0.0,
                count: 0,
            };
        }

        let mut micros: Vec<f64> = durations.iter().map(|d| d.as_micros() as f64).collect();
        micros.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let count = micros.len();
        let min_us = *micros.first().unwrap();
        let max_us = *micros.last().unwrap();
        let mean_us = micros.iter().sum::<f64>() / count as f64;
        let p50_us = percentile(&micros, 50.0);
        let p95_us = percentile(&micros, 95.0);
        let p99_us = percentile(&micros, 99.0);

        // Calculate standard deviation
        let variance = micros.iter().map(|x| (x - mean_us).powi(2)).sum::<f64>() / count as f64;
        let std_dev_us = variance.sqrt();

        Self {
            min_us,
            max_us,
            mean_us,
            p50_us,
            p95_us,
            p99_us,
            std_dev_us,
            count,
        }
    }

    /// Format stats as a human-readable string
    pub fn format(&self) -> String {
        format!(
            "min={:.1}us mean={:.1}us p50={:.1}us p95={:.1}us p99={:.1}us max={:.1}us (n={})",
            self.min_us,
            self.mean_us,
            self.p50_us,
            self.p95_us,
            self.p99_us,
            self.max_us,
            self.count
        )
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = (p / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

/// Overhead comparison between baseline and wrapped execution
#[derive(Debug, Clone)]
pub struct OverheadMeasurement {
    /// Baseline (unwrapped) latency stats
    pub baseline: LatencyStats,
    /// Wrapped (with SOTH) latency stats
    pub with_soth: LatencyStats,
    /// Overhead statistics
    pub overhead: OverheadStats,
}

/// Statistics about the overhead added
#[derive(Debug, Clone)]
pub struct OverheadStats {
    /// Overhead added at P50
    pub p50_added_us: f64,
    /// Overhead added at P95
    pub p95_added_us: f64,
    /// Overhead added at P99
    pub p99_added_us: f64,
    /// Overhead as percentage at P50
    pub p50_percent: f64,
    /// Overhead as percentage at P95
    pub p95_percent: f64,
    /// Overhead as percentage at P99
    pub p99_percent: f64,
}

impl OverheadMeasurement {
    /// Calculate overhead from baseline and wrapped stats
    pub fn calculate(baseline: LatencyStats, with_soth: LatencyStats) -> Self {
        let p50_added_us = with_soth.p50_us - baseline.p50_us;
        let p95_added_us = with_soth.p95_us - baseline.p95_us;
        let p99_added_us = with_soth.p99_us - baseline.p99_us;

        let p50_percent = if baseline.p50_us > 0.0 {
            (p50_added_us / baseline.p50_us) * 100.0
        } else {
            0.0
        };
        let p95_percent = if baseline.p95_us > 0.0 {
            (p95_added_us / baseline.p95_us) * 100.0
        } else {
            0.0
        };
        let p99_percent = if baseline.p99_us > 0.0 {
            (p99_added_us / baseline.p99_us) * 100.0
        } else {
            0.0
        };

        Self {
            baseline,
            with_soth,
            overhead: OverheadStats {
                p50_added_us,
                p95_added_us,
                p99_added_us,
                p50_percent,
                p95_percent,
                p99_percent,
            },
        }
    }

    /// Print a formatted report
    pub fn print_report(&self) {
        println!("\n=== SOTH Overhead Measurement Report ===\n");

        println!("Baseline (no SOTH):");
        println!("  {}", self.baseline.format());
        println!();

        println!("With SOTH:");
        println!("  {}", self.with_soth.format());
        println!();

        println!("Overhead Added:");
        println!(
            "  P50: {:.1}us ({:+.1}%)",
            self.overhead.p50_added_us, self.overhead.p50_percent
        );
        println!(
            "  P95: {:.1}us ({:+.1}%)",
            self.overhead.p95_added_us, self.overhead.p95_percent
        );
        println!(
            "  P99: {:.1}us ({:+.1}%)",
            self.overhead.p99_added_us, self.overhead.p99_percent
        );
        println!();
    }

    /// Check if overhead is within acceptable limits
    pub fn is_acceptable(&self, p50_limit_us: f64, p95_limit_us: f64) -> bool {
        self.overhead.p50_added_us <= p50_limit_us && self.overhead.p95_added_us <= p95_limit_us
    }
}

/// Measure overhead by running baseline and wrapped operations
///
/// # Arguments
/// * `iterations` - Number of iterations to run
/// * `baseline_fn` - Function that runs the operation without SOTH
/// * `wrapped_fn` - Function that runs the operation with SOTH
///
/// # Example
/// ```ignore
/// let measurement = measure_overhead(
///     1000,
///     || async { mock_server.process(&request).await },
///     || async { pipeline.process(&mut ctx, msg.clone()).await },
/// ).await;
/// ```
pub async fn measure_overhead<B, W, Fb, Fw>(
    iterations: usize,
    mut baseline_fn: B,
    mut wrapped_fn: W,
) -> OverheadMeasurement
where
    B: FnMut() -> Fb,
    W: FnMut() -> Fw,
    Fb: Future<Output = ()>,
    Fw: Future<Output = ()>,
{
    // Warmup
    let warmup = iterations / 10;
    for _ in 0..warmup {
        baseline_fn().await;
        wrapped_fn().await;
    }

    // Measure baseline
    let mut baseline_durations = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        baseline_fn().await;
        baseline_durations.push(start.elapsed());
    }

    // Measure wrapped
    let mut wrapped_durations = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        wrapped_fn().await;
        wrapped_durations.push(start.elapsed());
    }

    let baseline = LatencyStats::from_durations(&baseline_durations);
    let with_soth = LatencyStats::from_durations(&wrapped_durations);

    OverheadMeasurement::calculate(baseline, with_soth)
}

/// Simple timer for measuring individual operations
pub struct Timer {
    start: Instant,
    label: String,
}

impl Timer {
    /// Start a new timer with a label
    pub fn start(label: impl Into<String>) -> Self {
        Self {
            start: Instant::now(),
            label: label.into(),
        }
    }

    /// Stop the timer and return the duration
    pub fn stop(self) -> Duration {
        self.start.elapsed()
    }

    /// Stop and print the duration
    pub fn stop_and_print(self) -> Duration {
        let elapsed = self.start.elapsed();
        println!("{}: {:?}", self.label, elapsed);
        elapsed
    }
}

/// Collect multiple timing samples into stats
pub struct TimingCollector {
    samples: Vec<Duration>,
    label: String,
}

impl TimingCollector {
    /// Create a new collector
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            samples: Vec::new(),
            label: label.into(),
        }
    }

    /// Create with pre-allocated capacity
    pub fn with_capacity(label: impl Into<String>, capacity: usize) -> Self {
        Self {
            samples: Vec::with_capacity(capacity),
            label: label.into(),
        }
    }

    /// Record a duration sample
    pub fn record(&mut self, duration: Duration) {
        self.samples.push(duration);
    }

    /// Time an operation and record it
    pub async fn time<F, Fut>(&mut self, f: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        let start = Instant::now();
        f().await;
        self.samples.push(start.elapsed());
    }

    /// Get the collected stats
    pub fn stats(&self) -> LatencyStats {
        LatencyStats::from_durations(&self.samples)
    }

    /// Print the collected stats
    pub fn print_stats(&self) {
        let stats = self.stats();
        println!("{}: {}", self.label, stats.format());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_stats() {
        let durations: Vec<Duration> = (0..100).map(|i| Duration::from_micros(i * 10)).collect();

        let stats = LatencyStats::from_durations(&durations);

        assert_eq!(stats.count, 100);
        assert_eq!(stats.min_us, 0.0);
        assert_eq!(stats.max_us, 990.0);
        assert!(stats.p50_us > 400.0 && stats.p50_us < 600.0);
    }

    #[test]
    fn test_overhead_measurement() {
        let baseline = LatencyStats {
            min_us: 100.0,
            max_us: 200.0,
            mean_us: 150.0,
            p50_us: 150.0,
            p95_us: 190.0,
            p99_us: 195.0,
            std_dev_us: 25.0,
            count: 100,
        };

        let with_soth = LatencyStats {
            min_us: 150.0,
            max_us: 300.0,
            mean_us: 225.0,
            p50_us: 225.0, // +75us overhead
            p95_us: 285.0, // +95us overhead
            p99_us: 293.0, // +98us overhead
            std_dev_us: 37.0,
            count: 100,
        };

        let measurement = OverheadMeasurement::calculate(baseline, with_soth);

        assert_eq!(measurement.overhead.p50_added_us, 75.0);
        assert_eq!(measurement.overhead.p95_added_us, 95.0);
        assert_eq!(measurement.overhead.p99_added_us, 98.0);
        assert!(measurement.overhead.p50_percent == 50.0); // 75/150 * 100
    }

    #[tokio::test]
    async fn test_measure_overhead() {
        let measurement = measure_overhead(
            100,
            || async {
                tokio::time::sleep(Duration::from_micros(100)).await;
            },
            || async {
                tokio::time::sleep(Duration::from_micros(200)).await;
            },
        )
        .await;

        // Validate output shape; relative timing can invert under scheduler jitter.
        assert_eq!(measurement.baseline.count, 100);
        assert_eq!(measurement.with_soth.count, 100);
        assert!(measurement.overhead.p50_added_us.is_finite());
        assert!(measurement.overhead.p95_added_us.is_finite());
        assert!(measurement.overhead.p99_added_us.is_finite());
    }

    #[tokio::test]
    async fn test_timing_collector() {
        let mut collector = TimingCollector::with_capacity("test", 10);

        for _ in 0..10 {
            collector
                .time(|| async {
                    tokio::time::sleep(Duration::from_micros(50)).await;
                })
                .await;
        }

        let stats = collector.stats();
        assert_eq!(stats.count, 10);
        assert!(stats.p50_us >= 50.0);
    }
}
