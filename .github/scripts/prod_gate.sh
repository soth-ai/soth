#!/usr/bin/env bash
set -euo pipefail

# Production gate for SOTH sensor/runtime path.
# Optional env toggles:
#   PERF_SMOKE=1     -> run criterion quick benchmark
#   STRICT_CLIPPY=1  -> enforce clippy -D warnings for soth-cli dependency graph

export CARGO_TERM_COLOR=always
export RUST_BACKTRACE=1

echo "==> fmt"
cargo fmt --all --check

echo "==> check (default members)"
cargo check

echo "==> check (local-debug)"
cargo check -p soth-cli --features local-debug

echo "==> check (release)"
cargo check -p soth-cli --release

echo "==> check (release + local-debug)"
cargo check -p soth-cli --release --features local-debug

echo "==> tests (critical crates)"
cargo test -p soth-proxy --lib
cargo test -p soth-sync --lib
cargo test -p soth-proxy usage_enrichment -- --nocapture

if [[ "${STRICT_CLIPPY:-0}" == "1" ]]; then
  echo "==> clippy (strict)"
  cargo clippy -p soth-cli -- -D warnings
fi

if [[ "${PERF_SMOKE:-0}" == "1" ]]; then
  echo "==> bench (quick)"
  cargo bench-proxy-quick
fi

echo "Production gate passed."
