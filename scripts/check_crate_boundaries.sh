#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is required" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 1
fi

edges="$(
  cargo metadata --format-version 1 --no-deps \
    | jq -r '
        .packages[]
        | select(.manifest_path | contains("/crates/"))
        | .name as $name
        | .dependencies[]
        | select(.path != null and (.path | contains("/crates/")))
        | "\($name)->\(.name)"
      ' \
    | sort -u
)"

has_edge() {
  local edge="$1"
  grep -Fxq "$edge" <<<"$edges"
}

blocked_edges=(
  "soth-core->soth-proxy"
  "soth-core->soth-dashboard"
  "soth-core->soth-cli"
  "soth-core->soth-collector"
  "soth-proxy->soth-cli"
  "soth-dashboard->soth-proxy"
  "soth-dashboard->soth-cli"
  "soth-collector->soth-proxy"
  "soth-collector->soth-dashboard"
  "soth-sync->soth-proxy"
  "soth-sync->soth-dashboard"
)

# Transitional exception tracked for P1:
# Remove this allow-list entry once API state emission is moved out of soth-proxy.
transitional_edges=(
  "soth-proxy->soth-dashboard"
)

echo "crate dependency edges:"
echo "$edges" | sed 's/^/  - /'
echo

failed=0
for edge in "${blocked_edges[@]}"; do
  if has_edge "$edge"; then
    echo "error: blocked dependency edge present: $edge" >&2
    failed=1
  fi
done

for edge in "${transitional_edges[@]}"; do
  if has_edge "$edge"; then
    echo "warn: transitional dependency edge still present: $edge" >&2
  fi
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "crate boundary check passed."
