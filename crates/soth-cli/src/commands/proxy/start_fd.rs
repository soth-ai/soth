//! FD budget and monitor helpers for proxy start command.

use soth_helper::metrics;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tracing::{info, warn};

const MIN_NOFILE_SOFT_LIMIT: u64 = 8192;
const WARN_NOFILE_SOFT_LIMIT: u64 = 2048;
const FD_MONITOR_INTERVAL: Duration = Duration::from_secs(2);
const FD_MONITOR_WARN_INTERVAL: Duration = Duration::from_secs(30);

#[cfg(unix)]
pub(crate) fn ensure_fd_budget() {
    unsafe {
        let mut limits = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) != 0 {
            warn!("Failed to read RLIMIT_NOFILE");
            return;
        }

        let initial_soft = limits.rlim_cur as u64;
        let hard = limits.rlim_max as u64;

        if initial_soft < MIN_NOFILE_SOFT_LIMIT {
            let target = std::cmp::min(hard, MIN_NOFILE_SOFT_LIMIT) as libc::rlim_t;
            if target > limits.rlim_cur {
                limits.rlim_cur = target;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limits) == 0 {
                    info!(
                        previous_soft = initial_soft,
                        new_soft = target as u64,
                        hard_limit = hard,
                        "Raised RLIMIT_NOFILE soft limit"
                    );
                } else {
                    warn!(
                        soft_limit = initial_soft,
                        hard_limit = hard,
                        "Failed to raise RLIMIT_NOFILE soft limit"
                    );
                }
            }
        }

        let mut verify = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut verify) == 0 {
            let effective_soft = verify.rlim_cur as u64;
            let effective_hard = verify.rlim_max as u64;
            if effective_soft < WARN_NOFILE_SOFT_LIMIT {
                warn!(
                    soft_limit = effective_soft,
                    hard_limit = effective_hard,
                    "Low RLIMIT_NOFILE soft limit may cause EMFILE under bursty traffic"
                );
            }
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn ensure_fd_budget() {}

pub(crate) struct FdMonitorRuntime {
    pub(crate) shutdown_tx: tokio::sync::oneshot::Sender<()>,
    pub(crate) task: JoinHandle<()>,
}

#[cfg(unix)]
pub(crate) fn spawn_fd_monitor_runtime() -> Option<FdMonitorRuntime> {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(FD_MONITOR_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_warn_at: Option<Instant> = None;

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = interval.tick() => {
                    if let Some((open_fds, soft_limit, hard_limit)) = current_fd_snapshot() {
                        metrics::set_runtime_fd_snapshot(open_fds, soft_limit, hard_limit);
                        if soft_limit > 0 {
                            let utilization = (open_fds as f64) / (soft_limit as f64);
                            if utilization >= 0.9 {
                                let should_warn = last_warn_at
                                    .map(|last| last.elapsed() >= FD_MONITOR_WARN_INTERVAL)
                                    .unwrap_or(true);
                                if should_warn {
                                    last_warn_at = Some(Instant::now());
                                    warn!(
                                        open_fds = open_fds,
                                        soft_limit = soft_limit,
                                        hard_limit = hard_limit,
                                        utilization_pct = format!("{:.1}", utilization * 100.0),
                                        "High file-descriptor utilization detected"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    Some(FdMonitorRuntime { shutdown_tx, task })
}

#[cfg(not(unix))]
pub(crate) fn spawn_fd_monitor_runtime() -> Option<FdMonitorRuntime> {
    None
}

#[cfg(unix)]
fn current_fd_snapshot() -> Option<(u64, u64, u64)> {
    let (soft_limit, hard_limit) = current_nofile_limits()?;
    let open_fds = current_open_fd_count()?;
    Some((open_fds, soft_limit, hard_limit))
}

#[cfg(unix)]
fn current_nofile_limits() -> Option<(u64, u64)> {
    unsafe {
        let mut limits = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) != 0 {
            return None;
        }
        Some((limits.rlim_cur as u64, limits.rlim_max as u64))
    }
}

#[cfg(unix)]
fn current_open_fd_count() -> Option<u64> {
    for path in ["/proc/self/fd", "/dev/fd"] {
        if let Ok(entries) = std::fs::read_dir(path) {
            let count = entries.filter_map(Result::ok).count() as u64;
            if count > 0 {
                return Some(count);
            }
        }
    }
    None
}
