#!/bin/bash
# SOTH Load Testing Tool
# Usage: ./load_test.sh [options]
#
# Measures throughput and latency under load.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/test_config.yaml}"

# Default parameters
CONCURRENCY="${CONCURRENCY:-10}"
REQUESTS="${REQUESTS:-100}"
WARMUP="${WARMUP:-10}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_section() { echo -e "\n${YELLOW}=== $1 ===${NC}"; }

# Show help
show_help() {
    cat << EOF
SOTH Load Testing Tool

Usage: $0 [options]

Options:
    -c, --concurrency N    Number of concurrent workers (default: 10)
    -n, --requests N       Total number of requests (default: 100)
    -w, --warmup N         Warmup requests (default: 10)
    -C, --config FILE      Config file (default: test_config.yaml)
    -h, --help             Show this help

Environment Variables:
    CONCURRENCY           Same as -c
    REQUESTS              Same as -n
    WARMUP                Same as -w
    CONFIG_FILE           Same as -C

Examples:
    $0                              # Default: 10 concurrent, 100 requests
    $0 -c 20 -n 500                 # 20 concurrent, 500 requests
    CONCURRENCY=50 REQUESTS=1000 $0 # Using env vars
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--concurrency) CONCURRENCY="$2"; shift 2 ;;
        -n|--requests) REQUESTS="$2"; shift 2 ;;
        -w|--warmup) WARMUP="$2"; shift 2 ;;
        -C|--config) CONFIG_FILE="$2"; shift 2 ;;
        -h|--help) show_help; exit 0 ;;
        *) echo "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

log_section "SOTH Load Test"
log_info "Concurrency: $CONCURRENCY"
log_info "Total Requests: $REQUESTS"
log_info "Warmup: $WARMUP"
log_info "Config: $CONFIG_FILE"

# Build the load test binary
log_section "Building Load Test Tool"
cd "$PROJECT_ROOT"
cargo build --release --bin soth 2>/dev/null

# Create temp directory for results
RESULTS_DIR=$(mktemp -d)
log_info "Results directory: $RESULTS_DIR"

# Sample request
REQUEST='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"text":"load test"}},"id":1}'

# Run load test function
run_single_request() {
    local id=$1
    local start_time=$(python3 -c 'import time; print(int(time.time() * 1000000))')

    echo "$REQUEST" | timeout 30 "$PROJECT_ROOT/target/release/soth" start -c "$CONFIG_FILE" 2>/dev/null | head -1 >/dev/null

    local end_time=$(python3 -c 'import time; print(int(time.time() * 1000000))')
    local latency=$((end_time - start_time))

    echo "$latency" >> "$RESULTS_DIR/latencies.txt"
}

# Warmup phase
log_section "Warmup Phase"
for i in $(seq 1 $WARMUP); do
    run_single_request "warmup-$i" &
done
wait
rm -f "$RESULTS_DIR/latencies.txt"
log_info "Warmup complete"

# Main load test
log_section "Load Test Phase"
START_TIME=$(python3 -c 'import time; print(time.time())')

# Run requests with concurrency control
active_jobs=0
completed=0
for i in $(seq 1 $REQUESTS); do
    run_single_request "$i" &
    ((active_jobs++))

    if [[ $active_jobs -ge $CONCURRENCY ]]; then
        wait -n 2>/dev/null || true
        ((active_jobs--))
        ((completed++))

        # Progress indicator
        if [[ $((completed % 10)) -eq 0 ]]; then
            echo -ne "\rProgress: $completed/$REQUESTS"
        fi
    fi
done
wait
echo -ne "\rProgress: $REQUESTS/$REQUESTS\n"

END_TIME=$(python3 -c 'import time; print(time.time())')
DURATION=$(python3 -c "print(round($END_TIME - $START_TIME, 2))")

# Calculate statistics
log_section "Results"

if [[ -f "$RESULTS_DIR/latencies.txt" ]]; then
    TOTAL=$(wc -l < "$RESULTS_DIR/latencies.txt" | tr -d ' ')
    THROUGHPUT=$(python3 -c "print(round($TOTAL / $DURATION, 2))")

    # Sort latencies for percentile calculation
    sort -n "$RESULTS_DIR/latencies.txt" > "$RESULTS_DIR/sorted.txt"

    MIN=$(head -1 "$RESULTS_DIR/sorted.txt")
    MAX=$(tail -1 "$RESULTS_DIR/sorted.txt")
    AVG=$(awk '{sum+=$1} END {print int(sum/NR)}' "$RESULTS_DIR/sorted.txt")

    # Percentiles
    P50_LINE=$(python3 -c "print(int($TOTAL * 0.50))")
    P95_LINE=$(python3 -c "print(int($TOTAL * 0.95))")
    P99_LINE=$(python3 -c "print(int($TOTAL * 0.99))")

    P50=$(sed -n "${P50_LINE}p" "$RESULTS_DIR/sorted.txt")
    P95=$(sed -n "${P95_LINE}p" "$RESULTS_DIR/sorted.txt")
    P99=$(sed -n "${P99_LINE}p" "$RESULTS_DIR/sorted.txt")

    echo ""
    echo "Summary:"
    echo "  Total Requests:  $TOTAL"
    echo "  Duration:        ${DURATION}s"
    echo "  Throughput:      ${THROUGHPUT} req/s"
    echo ""
    echo "Latency (microseconds):"
    echo "  Min:             $MIN µs"
    echo "  Max:             $MAX µs"
    echo "  Avg:             $AVG µs"
    echo "  P50:             $P50 µs"
    echo "  P95:             $P95 µs"
    echo "  P99:             $P99 µs"
    echo ""

    # Convert to milliseconds for readability
    echo "Latency (milliseconds):"
    echo "  Min:             $(python3 -c "print(round($MIN/1000, 2))") ms"
    echo "  Avg:             $(python3 -c "print(round($AVG/1000, 2))") ms"
    echo "  P95:             $(python3 -c "print(round($P95/1000, 2))") ms"
    echo "  P99:             $(python3 -c "print(round($P99/1000, 2))") ms"
    echo "  Max:             $(python3 -c "print(round($MAX/1000, 2))") ms"
else
    echo -e "${RED}No results collected${NC}"
fi

# Cleanup
rm -rf "$RESULTS_DIR"

log_section "Load Test Complete"
