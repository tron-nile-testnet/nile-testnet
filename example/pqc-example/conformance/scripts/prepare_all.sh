#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

echo "[1/3] Preparing ML-DSA-44 / OpenSSL interoperability"
"$ROOT/scripts/prepare_mldsa.sh"

echo "[2/3] Building and validating Falcon reference interoperability"
"$ROOT/scripts/prepare_falcon.sh"

echo "[3/3] Checking Protobuf and fixture artifacts"
node "$ROOT/tools/fixture.mjs" check "$FIXTURES/ml-dsa-44.json" \
  "$FIXTURES/fn-dsa-512.json"

{
  echo "TIP-899 conformance preparation: PASS"
  echo "Implementation commit: c164973fffa4a7fa95ecfa9c0fe793f6761aeb78"
  echo "ML-DSA report: $BUILD/reports/ml-dsa-44.txt"
  echo "FN-DSA report: $BUILD/reports/fn-dsa-512.txt"
  echo "Fixtures: $FIXTURES"
  echo "ML-DSA fixture SHA-256: $(sha256_file "$FIXTURES/ml-dsa-44.json")"
  echo "FN-DSA fixture SHA-256: $(sha256_file "$FIXTURES/fn-dsa-512.json")"
} > "$BUILD/reports/summary.txt"

cat "$BUILD/reports/summary.txt"
