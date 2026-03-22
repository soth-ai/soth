# `soth status --json` Schema

Stable public interface for machine health checks and MDM compliance scripts.

```json
{
  "proxy": {
    "running": true,
    "pid": 12345,
    "port": 8080,
    "bundle_runtime_source": "primary",
    "bundle_runtime_warning": null
  },
  "bundle": {
    "version": "bundle-v18",
    "sig_valid": true
  },
  "sync": {
    "last_heartbeat_secs": 120,
    "queued": 0,
    "failed": 0
  },
  "last_24h": {
    "total": 1204,
    "blocked": 4,
    "flagged": 2,
    "cost_usd": 3.42
  },
  "healthy": true
}
```

## Stability

- Existing fields are stable and must not be renamed or removed without a major version bump.
- Minor versions may add optional fields (for example `proxy.bundle_runtime_source` and `proxy.bundle_runtime_warning`).
- Exit code semantics:
  - `0`: healthy
  - `1`: degraded
