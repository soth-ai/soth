# SOTH Testing Tools

This directory contains tools for testing SOTH in practical settings.

---

## Forward Proxy

SOTH includes a TLS MITM forward proxy for intercepting and inspecting AI provider traffic (OpenAI, Anthropic, Google). This enables policy enforcement, cost tracking, and observability for all AI API calls.

### Quick Start

```bash
# 1. Generate CA certificate
soth proxy setup-ca

# 2. Start the proxy
soth proxy start

# 3. Configure your shell (in another terminal)
eval $(soth proxy env)

# 4. Test with curl
curl https://api.openai.com/v1/models
```

### CLI Commands

#### `soth proxy setup-ca`

Generate and optionally install the CA certificate for TLS interception.

```bash
# Generate CA (default location: ~/.soth/ca/)
soth proxy setup-ca

# Custom output directory
soth proxy setup-ca --output /path/to/ca

# Skip trust store instructions
soth proxy setup-ca --no-trust
```

The CA files are:
- `~/.soth/ca/ca.crt` - CA certificate (share this with clients)
- `~/.soth/ca/ca.key` - CA private key (keep this secret)

#### `soth proxy start`

Start the forward proxy server.

```bash
# Start with defaults (port 8080)
soth proxy start

# Custom port
soth proxy start --port 9090

# With config file
soth proxy start --config soth.yaml
```

The proxy will display:
- Listen address
- Allowed hosts
- Environment variable commands
- Rate limiting and circuit breaker status

#### `soth proxy env`

Output shell environment variables for configuring HTTP clients.

```bash
# Bash/Zsh (default)
eval $(soth proxy env)

# Fish shell
eval (soth proxy env --shell fish)

# PowerShell
soth proxy env --shell powershell

# Just the CA cert path
soth proxy env --ca-only
```

Environment variables set:
- `HTTP_PROXY` / `http_proxy` - Proxy URL
- `HTTPS_PROXY` / `https_proxy` - Proxy URL
- `SSL_CERT_FILE` - CA certificate path
- `REQUESTS_CA_BUNDLE` - For Python requests library
- `NODE_EXTRA_CA_CERTS` - For Node.js

#### `soth proxy status`

Show proxy status including CA certificate and connection state.

```bash
soth proxy status
```

#### `soth proxy ca-info`

Display detailed CA certificate information.

```bash
soth proxy ca-info
```

Shows:
- Subject/Issuer
- Validity dates
- Serial number
- Public key algorithm
- Days remaining

#### `soth proxy metrics`

Show Prometheus metrics from the running proxy.

```bash
# Human-readable summary
soth proxy metrics

# Raw Prometheus format
soth proxy metrics --raw

# With config file
soth proxy metrics --config soth.yaml
```

#### `soth proxy connections`

Show active connections and recent requests.

```bash
soth proxy connections
```

Shows:
- Active connection count
- Requests by provider
- Recent request history with latency and token counts

#### `soth proxy circuit status`

Show circuit breaker status for upstream providers.

```bash
soth proxy circuit status
```

States:
- **CLOSED** (green) - Normal operation
- **HALF-OPEN** (yellow) - Testing recovery
- **OPEN** (red) - Blocking requests

#### `soth proxy circuit reset`

Reset circuit breaker for a host.

```bash
# Reset specific host
soth proxy circuit reset --host api.openai.com

# Reset all hosts
soth proxy circuit reset
```

#### `soth proxy rate-limit`

Show rate limit status.

```bash
soth proxy rate-limit
```

### Configuration

Add to your `soth.yaml`:

```yaml
forward_proxy:
  enabled: true
  port: 8080
  address: "127.0.0.1"
  request_timeout: "5m"

  ca:
    cert_path: "~/.soth/ca/ca.crt"
    key_path: "~/.soth/ca/ca.key"

  hosts:
    allow:
      - "api.openai.com"
      - "api.anthropic.com"
      - "generativelanguage.googleapis.com"

production:
  rate_limit:
    enabled: true
    requests_per_second: 100
    burst_size: 200

  circuit_breaker:
    enabled: true
    failure_threshold: 5
    open_duration: "30s"
```

See `soth.example.yaml` for all configuration options.

### Platform-Specific CA Trust

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.soth/ca/ca.crt
```

**Linux (Ubuntu/Debian):**
```bash
sudo cp ~/.soth/ca/ca.crt /usr/local/share/ca-certificates/soth-ca.crt
sudo update-ca-certificates
```

**Linux (Fedora/RHEL):**
```bash
sudo cp ~/.soth/ca/ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

**Windows (Admin PowerShell):**
```powershell
Import-Certificate -FilePath "$HOME\.soth\ca\ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

### Using with AI SDKs

**Python (OpenAI):**
```bash
export HTTPS_PROXY=http://127.0.0.1:8080
export SSL_CERT_FILE=~/.soth/ca/ca.crt
python your_script.py
```

**Node.js (OpenAI):**
```bash
export HTTPS_PROXY=http://127.0.0.1:8080
export NODE_EXTRA_CA_CERTS=~/.soth/ca/ca.crt
node your_script.js
```

**curl:**
```bash
curl --proxy http://127.0.0.1:8080 \
     --cacert ~/.soth/ca/ca.crt \
     https://api.openai.com/v1/models
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
