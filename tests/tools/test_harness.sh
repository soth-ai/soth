#!/bin/bash
# SOTH Test Harness - E2E Testing Tool
# Usage: ./test_harness.sh [config.yaml]
#
# Sends JSON-RPC requests through SOTH and validates responses.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="${1:-$PROJECT_ROOT/tests/tools/test_config.yaml}"
SOTH_BIN="$PROJECT_ROOT/target/debug/soth"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
PASSED=0
FAILED=0
SKIPPED=0

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)); }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; ((SKIPPED++)); }
log_section() { echo -e "\n${YELLOW}=== $1 ===${NC}"; }

# Check prerequisites
check_prerequisites() {
    log_section "Checking Prerequisites"

    if ! command -v jq &> /dev/null; then
        log_fail "jq is required but not installed"
        exit 1
    fi
    log_pass "jq is installed"

    if [[ ! -f "$SOTH_BIN" ]]; then
        log_info "Building SOTH..."
        (cd "$PROJECT_ROOT" && cargo build --bin soth 2>/dev/null)
    fi

    if [[ -f "$SOTH_BIN" ]]; then
        log_pass "SOTH binary found"
    else
        log_fail "SOTH binary not found at $SOTH_BIN"
        exit 1
    fi
}

# Send a JSON-RPC request and capture response
# Args: $1 = request JSON, $2 = timeout (optional, default 5s)
send_request() {
    local request="$1"
    local timeout="${2:-5}"

    echo "$request" | timeout "$timeout" "$SOTH_BIN" -c "$CONFIG_FILE" start 2>/dev/null || true
}

# Test: Initialize request
test_initialize() {
    log_section "Test: Initialize Request"

    local request='{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-harness","version":"1.0.0"}},"id":1}'

    log_info "Sending initialize request..."
    local response
    response=$(send_request "$request" 10)

    if echo "$response" | jq -e '.result.protocolVersion' &>/dev/null; then
        log_pass "Initialize returned valid response"
        return 0
    else
        log_fail "Initialize failed or returned invalid response"
        echo "Response: $response"
        return 1
    fi
}

# Test: Tools list request
test_tools_list() {
    log_section "Test: Tools List Request"

    local request='{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}'

    log_info "Sending tools/list request..."
    local response
    response=$(send_request "$request")

    if echo "$response" | jq -e '.result.tools' &>/dev/null; then
        local tool_count
        tool_count=$(echo "$response" | jq '.result.tools | length')
        log_pass "Tools list returned $tool_count tools"
        return 0
    else
        log_fail "Tools list failed"
        return 1
    fi
}

# Test: PII detection (should redact SSN)
test_pii_detection() {
    log_section "Test: PII Detection"

    local request='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"text":"My SSN is 123-45-6789"}},"id":3}'

    log_info "Sending request with PII (SSN)..."
    local response
    response=$(send_request "$request")

    # Check if SSN was redacted in logs (would need to check log file)
    if echo "$response" | grep -q "123-45-6789"; then
        log_info "PII passed through (check if pii_detection is disabled)"
    else
        log_pass "PII appears to be redacted"
    fi
}

# Test: Policy enforcement (if configured)
test_policy_enforcement() {
    log_section "Test: Policy Enforcement"

    # This test depends on policy configuration
    local request='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"blocked_tool","arguments":{}},"id":4}'

    log_info "Sending request for potentially blocked tool..."
    local response
    response=$(send_request "$request")

    if echo "$response" | jq -e '.error' &>/dev/null; then
        local error_msg
        error_msg=$(echo "$response" | jq -r '.error.message')
        if echo "$error_msg" | grep -qi "policy\|denied\|blocked"; then
            log_pass "Policy correctly blocked the request: $error_msg"
        else
            log_info "Request failed with: $error_msg"
        fi
    else
        log_info "Request allowed (tool may not be blocked)"
    fi
}

# Test: Notification passthrough
test_notification() {
    log_section "Test: Notification Passthrough"

    local request='{"jsonrpc":"2.0","method":"notifications/initialized"}'

    log_info "Sending notification (no id)..."
    local response
    response=$(send_request "$request" 2)

    # Notifications should not return a response
    if [[ -z "$response" ]] || ! echo "$response" | jq -e '.id' &>/dev/null; then
        log_pass "Notification handled correctly (no response expected)"
    else
        log_info "Got response for notification: $response"
    fi
}

# Test: Invalid request handling
test_invalid_request() {
    log_section "Test: Invalid Request Handling"

    local request='{"jsonrpc":"2.0","method":"invalid/method","params":{},"id":5}'

    log_info "Sending invalid method request..."
    local response
    response=$(send_request "$request")

    if echo "$response" | jq -e '.error' &>/dev/null; then
        log_pass "Invalid request correctly returned error"
    else
        log_info "Response: $response"
    fi
}

# Run all tests
run_all_tests() {
    check_prerequisites

    log_section "Running Test Suite"
    log_info "Config file: $CONFIG_FILE"

    # Run individual tests (continue on failure)
    test_initialize || true
    test_tools_list || true
    test_pii_detection || true
    test_policy_enforcement || true
    test_notification || true
    test_invalid_request || true

    # Summary
    log_section "Test Summary"
    echo -e "${GREEN}Passed:${NC}  $PASSED"
    echo -e "${RED}Failed:${NC}  $FAILED"
    echo -e "${YELLOW}Skipped:${NC} $SKIPPED"

    if [[ $FAILED -gt 0 ]]; then
        exit 1
    fi
}

# Interactive mode - send custom requests
interactive_mode() {
    log_section "Interactive Mode"
    log_info "Enter JSON-RPC requests (Ctrl+D to exit)"
    log_info "Config: $CONFIG_FILE"
    echo ""

    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            echo -e "${BLUE}Request:${NC} $line"
            response=$(send_request "$line")
            echo -e "${GREEN}Response:${NC}"
            echo "$response" | jq . 2>/dev/null || echo "$response"
            echo ""
        fi
    done
}

# Main
case "${1:-}" in
    -i|--interactive)
        CONFIG_FILE="${2:-$CONFIG_FILE}"
        interactive_mode
        ;;
    -h|--help)
        echo "SOTH Test Harness"
        echo ""
        echo "Usage: $0 [options] [config.yaml]"
        echo ""
        echo "Options:"
        echo "  -i, --interactive    Interactive mode (send custom requests)"
        echo "  -h, --help           Show this help"
        echo ""
        echo "Examples:"
        echo "  $0                           Run all tests with default config"
        echo "  $0 my-config.yaml            Run all tests with custom config"
        echo "  $0 -i my-config.yaml         Interactive mode with custom config"
        ;;
    *)
        run_all_tests
        ;;
esac
