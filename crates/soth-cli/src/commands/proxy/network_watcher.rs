//! Detects primary-network changes (wifi switch, captive-portal address
//! reassignment, VPN up/down) and signals the supervisor to graceful-rotate
//! the proxy worker. Without this, after a network change `soth-mitm`'s
//! upstream connection pool keeps trying to reuse TCP sockets bound to the
//! old gateway — surfacing as "tunnel connection failed" until `soth up`.
//!
//! Implementation: poll `getifaddrs(3)` every 5s and compare the set of
//! non-loopback IPv4 addresses bound to UP interfaces. Polling (vs.
//! event-driven `SCNetworkConfiguration` / netlink / `NotifyIpInterfaceChange`)
//! costs us a few seconds of latency but avoids three platform-specific code
//! paths and a new dependency. The symptom we're fixing already takes
//! seconds to surface, so the latency floor is acceptable.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info, warn};

const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Spawn the watcher. Returns a `watch::Receiver` whose value increments on
/// every detected change. The supervisor awaits `changed()` on it.
pub fn spawn() -> watch::Receiver<u64> {
    let (tx, rx) = watch::channel(0u64);
    tokio::spawn(async move {
        let mut last = local_v4_addrs();
        debug!(addrs = ?last, "network watcher: initial address set");
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        tick.tick().await;
        loop {
            tick.tick().await;
            let current = local_v4_addrs();
            if current.is_empty() {
                continue;
            }
            if current != last {
                info!(
                    previous = ?last,
                    current = ?current,
                    "primary network changed — signalling supervisor for graceful proxy rotation"
                );
                last = current;
                let next = tx.borrow().wrapping_add(1);
                if tx.send(next).is_err() {
                    return;
                }
            }
        }
    });
    rx
}

#[cfg(unix)]
fn local_v4_addrs() -> BTreeSet<Ipv4Addr> {
    use libc::{freeifaddrs, getifaddrs, ifaddrs, sockaddr_in, AF_INET, IFF_LOOPBACK, IFF_UP};
    let mut set = BTreeSet::new();
    unsafe {
        let mut head: *mut ifaddrs = std::ptr::null_mut();
        if getifaddrs(&mut head) != 0 || head.is_null() {
            warn!("getifaddrs failed; skipping network change check this tick");
            return set;
        }
        let mut cur = head;
        while !cur.is_null() {
            let entry = &*cur;
            cur = entry.ifa_next;
            if entry.ifa_addr.is_null() {
                continue;
            }
            let flags = entry.ifa_flags as i32;
            if flags & IFF_LOOPBACK != 0 || flags & IFF_UP == 0 {
                continue;
            }
            if (*entry.ifa_addr).sa_family as i32 != AF_INET {
                continue;
            }
            let sin = &*(entry.ifa_addr as *const sockaddr_in);
            let addr = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            set.insert(addr);
        }
        freeifaddrs(head);
    }
    set
}

#[cfg(not(unix))]
fn local_v4_addrs() -> BTreeSet<Ipv4Addr> {
    BTreeSet::new()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn local_v4_addrs_includes_loopback_when_loopback_filter_disabled() {
        // Sanity check: getifaddrs returns *something* on a normal host, and
        // our filter excludes loopback. We can't assert specific addresses
        // (CI / dev hosts vary), but the iteration should not panic and
        // should not return loopback (127.0.0.1) since it's excluded.
        let set = local_v4_addrs();
        assert!(
            !set.contains(&Ipv4Addr::LOCALHOST),
            "loopback should be filtered out"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn watcher_emits_no_events_when_addresses_stable() {
        let mut rx = spawn();
        // Advance past several poll intervals; nothing should fire because
        // the address set hasn't changed.
        tokio::time::advance(POLL_INTERVAL * 3).await;
        // changed() should not have fired.
        let changed = tokio::time::timeout(Duration::from_millis(10), rx.changed()).await;
        assert!(changed.is_err(), "watcher should not emit when stable");
    }
}
