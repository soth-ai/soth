# SOTH Runtime Testing Tools

This folder documents practical runtime testing with the current SOTH CLI.

## Recommended Lifecycle Commands

Use the lifecycle pair for day-to-day operation:

```bash
# Bootstrap config/CA (if needed), start daemon, and enable system proxy
soth up

# Stop daemon and disable system proxy
soth down
```

Foreground mode (no daemonization):

```bash
soth up --foreground
```

Direct daemon controls:

```bash
soth start
soth stop
soth logs -f
```

## Quick Verification Flow

```bash
# 1) Start lifecycle
soth up

# 2) Export env in a second terminal
eval $(soth runtime env)

# 3) Send test request
curl https://api.openai.com/v1/models

# 4) Inspect logs
soth logs -f
```

## Runtime Commands

### `soth runtime setup-ca`

Generate CA certificate/key used for TLS interception.

```bash
soth runtime setup-ca
soth runtime setup-ca --output /path/to/ca
soth runtime setup-ca --no-trust
```

Generated files:

- `~/.soth/ca/ca.crt`
- `~/.soth/ca/ca.key`

### `soth runtime env`

Print shell exports for proxy routing.

```bash
eval $(soth runtime env)
eval (soth runtime env --shell fish)
soth runtime env --shell powershell
soth runtime env --ca-only
```

### `soth runtime status`

Show runtime status and CA readiness.

```bash
soth runtime status
```

### `soth runtime ca-info`

Show certificate metadata and validity.

```bash
soth runtime ca-info
```

## System Proxy Controls

```bash
soth on
soth off
```

These are useful when daemon is already running and you only want to toggle routing.

## API/UI Services for Local Dashboard

```bash
soth dev api start --port 3001
soth dev ui start --api-port 3001
```

## Advanced Diagnostics

```bash
soth dev advanced metrics
soth dev advanced metrics --raw
soth dev advanced connections
soth dev advanced circuit status
soth dev advanced circuit reset --host api.openai.com
soth dev advanced rate-limit
```

## Config Shape (Current)

```yaml
forward_proxy:
  enabled: true
  port: 8080
  hosts:
    mode: selective
    domain_files:
      ai_inference: "./domains/ai_inference.yaml"
      mcp: "./domains/mcp.yaml"
      agent_apps: "./domains/agent_apps.yaml"

production:
  rate_limit:
    enabled: true
  circuit_breaker:
    enabled: true
```

See `soth.example.yaml` for full options.

## SDK/CLI Usage Example

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
export SSL_CERT_FILE=~/.soth/ca/ca.crt
curl https://api.openai.com/v1/models
```

---

## MCP Proxy

SOTH also functions as an MCP (Model Context Protocol) proxy for wrapping local MCP servers.

### Quick Start

```bash
# Build everything first
cargo build --workspace

# Validate your config
./target/debug/soth config validate -f soth.yaml -v

# Run the load tests
cargo test -p soth-cli --test load_test -- --nocapture
```

---

## Testing Tools Overview

### 1. Config Validator (`soth config validate`)

Validates YAML configuration files before running SOTH.

```bash
# Validate a config file
./target/debug/soth config validate -f my-config.yaml

# Verbose output with summary
./target/debug/soth config validate -f my-config.yaml -v

# Show effective configuration (with defaults)
./target/debug/soth config show

# Generate example config
./target/debug/soth config example > my-config.yaml
```

**Checks performed:**
- YAML syntax validation
- Transport type validity (stdio, sse, http)
- Upstream configuration (command or url)
- Identity mode validity
- Policy mode validity
- Cache configuration
- Budget limits

### 2. Test Harness (`test_harness.sh`)

Interactive E2E testing tool for sending JSON-RPC requests.

```bash
# Run all tests
./tests/tools/test_harness.sh

# Use a custom config
./tests/tools/test_harness.sh my-config.yaml

# Interactive mode (send custom requests)
./tests/tools/test_harness.sh -i my-config.yaml
```

**Test scenarios:**
- Initialize request
- Tools list
- PII detection
- Policy enforcement
- Notification passthrough
- Invalid request handling

### 3. Mock MCP Server

A simple MCP server for isolated testing without external dependencies.

```bash
# Build the mock server
cd tests/tools/mock_mcp_server
cargo build

# Run standalone (for debugging)
cargo run
```

**Available tools:**
- `echo` - Echoes back input text
- `add` - Adds two numbers
- `get_time` - Returns current timestamp
- `slow_operation` - Simulates delays (for timeout testing)
- `fail` - Always returns error (for error handling testing)
- `blocked_tool` - Should be blocked by policy

### 4. Load Tests (`cargo test --test load_test`)

Measures throughput and latency under load.

```bash
# Run all load tests
cargo test -p soth-cli --test load_test -- --nocapture

# Run specific test
cargo test -p soth-cli --test load_test load_test_simple_requests -- --nocapture
```

**Test scenarios:**
- `load_test_simple_requests` - 1000 basic requests
- `load_test_pii_requests` - 1000 requests with PII content
- `load_test_cache_effectiveness` - Cold vs warm cache comparison
- `load_test_concurrent_sessions` - 10 concurrent sessions

### 5. Shell Load Test (`load_test.sh`)

Alternative load testing via shell (useful for end-to-end testing).

```bash
# Default: 10 concurrent, 100 requests
./tests/tools/load_test.sh

# Custom parameters
./tests/tools/load_test.sh -c 20 -n 500

# Environment variables
CONCURRENCY=50 REQUESTS=1000 ./tests/tools/load_test.sh
```

## Test Configurations

### `test_config.yaml`
Default test configuration using the mock MCP server.

### `test_pii_disabled.yaml`
Configuration with PII detection disabled for testing passthrough.

### `test_cache_config.yaml`
Configuration with custom cache TTLs for testing cache behavior.

## Performance Baselines

From load tests on a typical development machine:

| Scenario | Throughput | P95 Latency |
|----------|------------|-------------|
| Simple requests | >10,000 req/s | <1ms |
| PII requests | >5,000 req/s | <2ms |
| Concurrent sessions | >10,000 req/s | <1ms |
| Warm cache | 40-60% faster than cold |

## Troubleshooting

### Mock server won't start
```bash
# Rebuild the mock server
cd tests/tools/mock_mcp_server
cargo build --release
```

### Tests timeout
- Increase timeout in test harness
- Check if upstream command exists
- Verify config file path

### Low throughput in load tests
- Ensure release build: `cargo build --release`
- Check system resources
- Disable logging: set `observe.enabled: false`
