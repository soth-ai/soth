//! Detects primary-network changes (wifi switch, captive-portal address
//! reassignment, VPN up/down, hotspot toggles) and signals the supervisor to
//! graceful-rotate the proxy worker. Without this, after a network change
//! `soth-mitm`'s DNS resolver and upstream sockets keep pointing at the old
//! gateway — surfacing as "tunnel connection failed" until `soth up`.
//!
//! Implementation: poll a [`NetworkSignature`] every 5s and compare. The
//! signature covers what actually changes across hotspot/AP transitions:
//!
//! - non-loopback IPv4 **and** IPv6 addresses on UP interfaces (v6-only and
//!   v6-primary tethering used to be invisible),
//! - the system DNS server list (a same-subnet network switch can change
//!   resolvers without changing our addresses),
//! - an offline marker, so *drop → recover on the same address* (hotspot
//!   toggled off/on, AP roam) fires a rotation even though the signature is
//!   unchanged — previously the empty set was skipped and the recovery was
//!   silent.
//!
//! Fires are debounced: at most one signal per [`DEBOUNCE`] window, with the
//! trailing change delivered on the first tick after the window closes, so a
//! flapping hotspot causes one rotation per window instead of a storm.
//!
//! Polling (vs. event-driven `SCNetworkConfiguration` / netlink /
//! `NotifyIpInterfaceChange`) costs a few seconds of latency but avoids
//! three platform-specific code paths. The symptom we're fixing already
//! takes seconds to surface, so the latency floor is acceptable.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info};

const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Minimum spacing between emitted change signals. Rotation itself takes a
/// few seconds; anything faster just kills connections repeatedly.
const DEBOUNCE: Duration = Duration::from_secs(10);

/// Point-in-time view of the network facts the proxy worker depends on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct NetworkSignature {
    v4: BTreeSet<Ipv4Addr>,
    /// Global + ULA only. Link-local (fe80::/10) churns on every interface
    /// event without affecting routing and is excluded.
    v6: BTreeSet<Ipv6Addr>,
    /// Ordered system DNS server list.
    dns: Vec<IpAddr>,
}

impl NetworkSignature {
    /// No usable addresses — treat as offline regardless of DNS remnants.
    fn is_addrless(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// Spawn the watcher. Returns a `watch::Receiver` whose value increments on
/// every detected change. The supervisor awaits `changed()` on it.
pub fn spawn() -> watch::Receiver<u64> {
    spawn_with_source(read_network_signature)
}

/// Watcher core with an injectable signature source (tests script network
/// transitions through it; production passes [`read_network_signature`]).
fn spawn_with_source(
    mut source: impl FnMut() -> NetworkSignature + Send + 'static,
) -> watch::Receiver<u64> {
    let (tx, rx) = watch::channel(0u64);
    tokio::spawn(async move {
        let mut last = source();
        debug!(signature = ?last, "network watcher: initial signature");
        let mut was_offline = false;
        let mut pending_signal = false;
        let mut last_fire: Option<tokio::time::Instant> = None;
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        tick.tick().await;
        loop {
            tick.tick().await;
            let current = source();
            if current.is_addrless() {
                // Offline. Remember it so recovery fires even when the
                // network comes back with an identical signature.
                if !was_offline {
                    debug!("network watcher: all addresses gone (offline)");
                }
                was_offline = true;
                continue;
            }
            if current != last || was_offline {
                info!(
                    previous = ?last,
                    current = ?current,
                    recovered_from_offline = was_offline,
                    "primary network changed — scheduling supervisor signal for graceful proxy rotation"
                );
                last = current;
                was_offline = false;
                pending_signal = true;
            }
            let debounce_open = last_fire
                .map(|fired| fired.elapsed() >= DEBOUNCE)
                .unwrap_or(true);
            if pending_signal && debounce_open {
                pending_signal = false;
                last_fire = Some(tokio::time::Instant::now());
                let next = tx.borrow().wrapping_add(1);
                if tx.send(next).is_err() {
                    return;
                }
            }
        }
    });
    rx
}

fn read_network_signature() -> NetworkSignature {
    let (v4, v6) = local_addrs();
    NetworkSignature {
        v4,
        v6,
        dns: system_dns_servers(),
    }
}

/// True for IPv6 addresses that identify a network rather than interface
/// noise: global unicast and ULA, excluding loopback/link-local/unspecified.
fn is_meaningful_v6(addr: &Ipv6Addr) -> bool {
    if addr.is_loopback() || addr.is_unspecified() {
        return false;
    }
    // Link-local fe80::/10.
    (addr.segments()[0] & 0xffc0) != 0xfe80
}

#[cfg(unix)]
fn local_addrs() -> (BTreeSet<Ipv4Addr>, BTreeSet<Ipv6Addr>) {
    use libc::{
        freeifaddrs, getifaddrs, ifaddrs, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6,
        IFF_LOOPBACK, IFF_UP,
    };
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    unsafe {
        let mut head: *mut ifaddrs = std::ptr::null_mut();
        if getifaddrs(&mut head) != 0 || head.is_null() {
            tracing::warn!("getifaddrs failed; skipping network change check this tick");
            return (v4, v6);
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
            match (*entry.ifa_addr).sa_family as i32 {
                family if family == AF_INET => {
                    let sin = &*(entry.ifa_addr as *const sockaddr_in);
                    v4.insert(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
                }
                family if family == AF_INET6 => {
                    let sin6 = &*(entry.ifa_addr as *const sockaddr_in6);
                    let addr = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    if is_meaningful_v6(&addr) {
                        v6.insert(addr);
                    }
                }
                _ => {}
            }
        }
        freeifaddrs(head);
    }
    (v4, v6)
}

/// Windows: enumerate adapters via `ipconfig` (the same crate
/// hickory-resolver uses for its Windows DNS discovery). This replaces the
/// old UDP-connect trick, which captured only the default-route IPv4 — it
/// missed secondary adapters, every IPv6 transition, and DNS-only changes.
#[cfg(windows)]
fn local_addrs() -> (BTreeSet<Ipv4Addr>, BTreeSet<Ipv6Addr>) {
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    let Ok(adapters) = ipconfig::get_adapters() else {
        tracing::warn!("ipconfig::get_adapters failed; skipping network change check this tick");
        return (v4, v6);
    };
    for adapter in adapters
        .iter()
        .filter(|adapter| adapter.oper_status() == ipconfig::OperStatus::IfOperStatusUp)
    {
        for addr in adapter.ip_addresses() {
            match addr {
                IpAddr::V4(value) => {
                    if !value.is_loopback() && !value.is_unspecified() {
                        v4.insert(*value);
                    }
                }
                IpAddr::V6(value) => {
                    if is_meaningful_v6(value) {
                        v6.insert(*value);
                    }
                }
            }
        }
    }
    (v4, v6)
}

/// Catch-all for non-Unix, non-Windows targets (BSDs we don't officially
/// ship to, WASM, etc.). Empty sets mean the watcher polls but never fires.
#[cfg(not(any(unix, windows)))]
fn local_addrs() -> (BTreeSet<Ipv4Addr>, BTreeSet<Ipv6Addr>) {
    (BTreeSet::new(), BTreeSet::new())
}

/// System DNS servers, best-effort. An empty list disables DNS-change
/// detection for the tick but never blocks address-based detection.
///
/// Unix: parse `/etc/resolv.conf` — written by `configd` on macOS and by
/// the resolver stack on Linux. (On systemd-resolved hosts this is the
/// constant 127.0.0.53 stub; DNS-change detection is then inert there,
/// which is harmless — address changes still fire.) Zone-scoped
/// nameservers (`fe80::1%en0`) don't parse as bare `IpAddr` and are
/// skipped.
#[cfg(unix)]
fn system_dns_servers() -> Vec<IpAddr> {
    let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    parse_resolv_conf_nameservers(&contents)
}

#[cfg(unix)]
fn parse_resolv_conf_nameservers(contents: &str) -> Vec<IpAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let value = trimmed.strip_prefix("nameserver")?.trim();
            value.split_whitespace().next()?.parse::<IpAddr>().ok()
        })
        .collect()
}

#[cfg(windows)]
fn system_dns_servers() -> Vec<IpAddr> {
    let Ok(adapters) = ipconfig::get_adapters() else {
        return Vec::new();
    };
    let mut servers = Vec::new();
    for adapter in adapters
        .iter()
        .filter(|adapter| adapter.oper_status() == ipconfig::OperStatus::IfOperStatusUp)
    {
        for server in adapter.dns_servers() {
            if !servers.contains(server) {
                servers.push(*server);
            }
        }
    }
    servers
}

#[cfg(not(any(unix, windows)))]
fn system_dns_servers() -> Vec<IpAddr> {
    Vec::new()
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;

    #[test]
    fn local_addrs_exclude_loopback() {
        let (v4, v6) = local_addrs();
        assert!(
            !v4.contains(&Ipv4Addr::LOCALHOST),
            "v4 loopback should be filtered out"
        );
        assert!(
            !v6.contains(&Ipv6Addr::LOCALHOST),
            "v6 loopback should be filtered out"
        );
    }

    #[test]
    fn meaningful_v6_excludes_link_local_and_loopback() {
        assert!(!is_meaningful_v6(&Ipv6Addr::LOCALHOST));
        assert!(!is_meaningful_v6(&Ipv6Addr::UNSPECIFIED));
        assert!(!is_meaningful_v6(&"fe80::1".parse().unwrap()));
        assert!(is_meaningful_v6(&"2001:db8::1".parse().unwrap()));
        // ULA stays in — it identifies the local network.
        assert!(is_meaningful_v6(&"fd00::1".parse().unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn resolv_conf_parser_extracts_nameservers() {
        let sample = "# comment\nnameserver 192.168.1.1\nnameserver 2606:4700::1111\nsearch example.com\nnameserver fe80::1%en0\nnameserver not-an-ip\n";
        let servers = parse_resolv_conf_nameservers(sample);
        assert_eq!(
            servers,
            vec![
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "2606:4700::1111".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn addrless_signature_reads_as_offline() {
        let empty = NetworkSignature::default();
        assert!(empty.is_addrless());
        let with_dns_only = NetworkSignature {
            dns: vec!["1.1.1.1".parse().unwrap()],
            ..NetworkSignature::default()
        };
        assert!(with_dns_only.is_addrless());
        let online = NetworkSignature {
            v4: [Ipv4Addr::new(192, 168, 1, 2)].into_iter().collect(),
            ..NetworkSignature::default()
        };
        assert!(!online.is_addrless());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn watcher_emits_no_events_when_addresses_stable() {
        let mut rx = spawn();
        // Advance past several poll intervals; nothing should fire because
        // the signature hasn't changed.
        tokio::time::advance(POLL_INTERVAL * 3).await;
        let changed = tokio::time::timeout(Duration::from_millis(10), rx.changed()).await;
        assert!(changed.is_err(), "watcher should not emit when stable");
    }

    fn sig_with_v4(last_octet: u8) -> NetworkSignature {
        NetworkSignature {
            v4: [Ipv4Addr::new(192, 168, 1, last_octet)]
                .into_iter()
                .collect(),
            ..NetworkSignature::default()
        }
    }

    /// Drive a scripted sequence of signatures through the watcher; the
    /// final entry repeats forever once the script is exhausted.
    fn spawn_scripted(script: Vec<NetworkSignature>) -> watch::Receiver<u64> {
        let mut queue = script.into_iter();
        let mut current = NetworkSignature::default();
        spawn_with_source(move || {
            if let Some(next) = queue.next() {
                current = next;
            }
            current.clone()
        })
    }

    /// Let the spawned watcher task run (paused-clock tests advance time
    /// manually; the task still needs scheduler turns to consume ticks).
    async fn drain_scheduler() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn watcher_fires_on_offline_recovery_with_same_signature() {
        // initial read, then: online → offline → online with the SAME
        // signature. The old watcher skipped empty sets entirely and never
        // fired on same-address recovery (hotspot toggled off/on).
        let rx = spawn_scripted(vec![
            sig_with_v4(2),              // initial read
            sig_with_v4(2),              // tick 1: stable
            NetworkSignature::default(), // tick 2: offline
            sig_with_v4(2),              // tick 3: recovered, same address
        ]);
        drain_scheduler().await;
        tokio::time::advance(POLL_INTERVAL * 3).await;
        drain_scheduler().await;
        assert!(
            rx.has_changed().expect("watcher alive"),
            "recovery with unchanged signature must fire a rotation signal"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn watcher_fires_on_dns_only_change() {
        let base = sig_with_v4(2);
        let mut with_new_dns = base.clone();
        with_new_dns.dns = vec!["9.9.9.9".parse().unwrap()];
        let rx = spawn_scripted(vec![base.clone(), base, with_new_dns]);
        drain_scheduler().await;
        tokio::time::advance(POLL_INTERVAL * 2).await;
        drain_scheduler().await;
        assert!(
            rx.has_changed().expect("watcher alive"),
            "DNS-only change must fire"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn watcher_debounces_rapid_flapping() {
        // Flap on every tick: the first change fires immediately, changes
        // inside the debounce window are deferred, and the trailing change
        // is delivered once the window closes.
        let mut rx = spawn_scripted(vec![
            sig_with_v4(2), // initial read
            sig_with_v4(3), // tick 1: change → fires
            sig_with_v4(2), // tick 2: change inside window → deferred
            sig_with_v4(3), // tick 3: change inside window → still deferred
        ]);
        drain_scheduler().await;

        tokio::time::advance(POLL_INTERVAL).await; // tick 1
        drain_scheduler().await;
        assert!(
            rx.has_changed().expect("watcher alive"),
            "first change must fire immediately"
        );
        rx.borrow_and_update();

        tokio::time::advance(POLL_INTERVAL).await; // tick 2, inside window
        drain_scheduler().await;
        assert!(
            !rx.has_changed().expect("watcher alive"),
            "change inside the debounce window must be deferred"
        );

        // Advance past the debounce window; the deferred change fires on the
        // next tick.
        tokio::time::advance(DEBOUNCE + POLL_INTERVAL).await;
        drain_scheduler().await;
        assert!(
            rx.has_changed().expect("watcher alive"),
            "deferred change must fire once the debounce window closes"
        );
    }
}
