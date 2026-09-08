#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

for command in clang curl make shasum unzip; do
  require_command "$command"
done

mkdir -p "$CACHE/falcon-reference" "$BUILD/bin" "$BUILD/reports"
download_locked "$FALCON_URL" "$FALCON_ARCHIVE" "$FALCON_SHA256"
unzip -q -o "$FALCON_ARCHIVE" -d "$CACHE/falcon-reference"

jobs="$(sysctl -n hw.logicalcpu 2>/dev/null || echo 2)"
make -C "$FALCON_REF" -j"$jobs"

clang -std=c11 -Wall -Wextra -O2 -I"$FALCON_REF" \
  "$ROOT/tools/falcon_ref_cli.c" \
  "$FALCON_REF/codec.o" \
  "$FALCON_REF/common.o" \
  "$FALCON_REF/falcon.o" \
  "$FALCON_REF/fft.o" \
  "$FALCON_REF/fpr.o" \
  "$FALCON_REF/keygen.o" \
  "$FALCON_REF/rng.o" \
  "$FALCON_REF/shake.o" \
  "$FALCON_REF/sign.o" \
  "$FALCON_REF/vrfy.o" \
  -o "$BUILD/bin/falcon-ref-cli"

"$FALCON_REF/test_falcon" > "$BUILD/reports/falcon-reference-self-test.txt" 2>&1
grep -q 'Test external API:.*done\.' "$BUILD/reports/falcon-reference-self-test.txt"
grep -q 'Test NIST KAT (512):.*done\.' "$BUILD/reports/falcon-reference-self-test.txt"

echo "Falcon reference ready: $BUILD/bin/falcon-ref-cli"
