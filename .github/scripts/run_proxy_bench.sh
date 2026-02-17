#!/usr/bin/env bash
set -euo pipefail

# Reproducible benchmark runner for proxy pipeline/network hot paths.
# Usage:
#   .github/scripts/run_proxy_bench.sh quick
#   .github/scripts/run_proxy_bench.sh full

MODE="${1:-quick}"

export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=1

case "${MODE}" in
  quick)
    echo "Running quick proxy benchmark suite..."
    cargo bench-proxy-quick
    ;;
  full)
    echo "Running full proxy benchmark suite..."
    cargo bench-proxy-full
    ;;
  *)
    echo "Unknown mode: ${MODE}. Use: quick | full" >&2
    exit 2
    ;;
esac
