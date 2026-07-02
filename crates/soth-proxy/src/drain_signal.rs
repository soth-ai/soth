//! Cross-platform graceful-drain signal for the proxy worker.
//!
//! Unix: SIGUSR1, sent by the supervisor during graceful child rotation.
//! Windows: a named kernel event `Local\soth-worker-drain-{pid}` that the
//! supervisor opens and sets. `GenerateConsoleCtrlEvent` is not usable here —
//! the worker is spawned with `CREATE_NO_WINDOW` so it does not share a
//! console with the supervisor, and console ctrl events cannot cross that
//! boundary. A named event has no such restriction.
//!
//! Without this, Windows rotation had no drain path at all: the supervisor
//! hard-killed the worker (`TerminateProcess`), resetting every in-flight
//! connection on each network change.

use tracing::info;

/// The name of the drain event for a worker process id. Kept in sync with
/// the supervisor side (`soth-cli/src/commands/proxy/start.rs`).
#[cfg(windows)]
pub fn drain_event_name(pid: u32) -> String {
    format!("Local\\soth-worker-drain-{pid}")
}

/// Wait until a shutdown is requested: Ctrl+C on all platforms, plus
/// SIGUSR1 (Unix) or the named drain event (Windows).
pub(crate) async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut usr1 = signal(SignalKind::user_defined1()).expect("listen for SIGUSR1");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown requested (Ctrl+C)");
            }
            _ = usr1.recv() => {
                info!("graceful drain requested (SIGUSR1)");
            }
        }
    }
    #[cfg(windows)]
    {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        // A plain std thread (not spawn_blocking): the tokio runtime waits
        // for blocking tasks on drop, and this thread parks forever when
        // shutdown comes via Ctrl+C instead of the event.
        let spawned = std::thread::Builder::new()
            .name("soth-drain-event".to_string())
            .spawn(move || {
                if wait_for_drain_event(std::process::id()) {
                    let _ = tx.send(());
                }
                // On failure the sender drops; the receiver arm below
                // falls back to Ctrl+C-only.
            })
            .is_ok();
        if !spawned {
            tracing::warn!("failed to spawn drain-event thread; Ctrl+C only");
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown requested (Ctrl+C)");
            }
            result = rx => match result {
                Ok(()) => {
                    info!("graceful drain requested (drain event)");
                }
                Err(_) => {
                    tracing::warn!(
                        "drain-event listener unavailable; waiting on Ctrl+C only"
                    );
                    let _ = tokio::signal::ctrl_c().await;
                    info!("shutdown requested (Ctrl+C)");
                }
            },
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutdown requested (Ctrl+C)");
    }
}

/// Create the named drain event and block until the supervisor sets it.
/// Returns `true` when the event fired, `false` on any setup/wait failure.
#[cfg(windows)]
fn wait_for_drain_event(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};

    let name: Vec<u16> = drain_event_name(pid)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // Manual-reset, initially unsignaled. Created by the worker (not the
    // supervisor) so it exists for the worker's whole lifetime; the
    // supervisor opens it by name only when it wants to drain.
    let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, name.as_ptr()) };
    if handle.is_null() {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            "failed to create drain event; graceful drain unavailable"
        );
        return false;
    }
    let wait_result = unsafe { WaitForSingleObject(handle, INFINITE) };
    unsafe { CloseHandle(handle) };
    wait_result == WAIT_OBJECT_0
}
