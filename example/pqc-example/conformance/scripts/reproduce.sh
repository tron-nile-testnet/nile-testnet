#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"
# Do not overwrite the checked-in golden vectors while checking regeneration.
export CONFORMANCE_FIXTURE_DIR="$BUILD/regenerated-fixtures"
"$ROOT/scripts/prepare_all.sh"
for expected in "$ROOT"/fixtures/*; do
  cmp "$expected" "$CONFORMANCE_FIXTURE_DIR/$(basename "$expected")"
done
echo "fixture regeneration: PASS (matches checked-in bytes)"
