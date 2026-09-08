#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

"$ROOT/scripts/bootstrap_common.sh"
"$ROOT/scripts/build_falcon.sh"
node "$ROOT/tools/fixture.mjs" check \
  "$FIXTURES/ml-dsa-44.json" "$FIXTURES/fn-dsa-512.json" >/dev/null

EXTRACTED="$BUILD/fixture-check"
mkdir -p "$EXTRACTED/ml-dsa-44" "$EXTRACTED/fn-dsa-512" "$BUILD/reports"
python3 - "$FIXTURES" "$EXTRACTED" <<'PY'
from pathlib import Path
import json
import sys

fixtures = Path(sys.argv[1])
destination = Path(sys.argv[2])
for name, output_name in [
    ("ml-dsa-44.json", "ml-dsa-44"),
    ("fn-dsa-512.json", "fn-dsa-512"),
]:
    fixture = json.loads((fixtures / name).read_text())
    output = destination / output_name
    output.mkdir(parents=True, exist_ok=True)
    (output / "message.bin").write_bytes(bytes.fromhex(fixture["message"]["hex"]))
    (output / "public-key.bin").write_bytes(bytes.fromhex(fixture["publicKey"]["hex"]))
    (output / "signature.bin").write_bytes(bytes.fromhex(fixture["signature"]["hex"]))
PY

ML="$EXTRACTED/ml-dsa-44"
java_proto verify 2 "$ML/public-key.bin" "$ML/signature.bin" \
  "$FIXTURES/ml-dsa-44.pq-auth-sig.bin" \
  "$FIXTURES/ml-dsa-44.transaction-field.bin" >/dev/null
python3 "$ROOT/tools/ml_dsa_spki.py" wrap "$ML/public-key.bin" "$ML/public-key.der"
"$OPENSSL" pkeyutl -verify -rawin -pubin -keyform DER \
  -inkey "$ML/public-key.der" -in "$ML/message.bin" \
  -sigfile "$ML/signature.bin" >/dev/null
java_bc verify-mldsa "$ML/public-key.bin" "$ML/message.bin" "$ML/signature.bin" >/dev/null
xor_byte_file "$ML/signature.bin" "$ML/tampered-signature.bin" 1
expect_rejection "$OPENSSL" pkeyutl -verify -rawin -pubin -keyform DER \
  -inkey "$ML/public-key.der" -in "$ML/message.bin" \
  -sigfile "$ML/tampered-signature.bin"
expect_rejection java_bc verify-mldsa "$ML/public-key.bin" "$ML/message.bin" \
  "$ML/tampered-signature.bin"

FN="$EXTRACTED/fn-dsa-512"
java_proto verify 1 "$FN/public-key.bin" "$FN/signature.bin" \
  "$FIXTURES/fn-dsa-512.pq-auth-sig.bin" \
  "$FIXTURES/fn-dsa-512.transaction-field.bin" >/dev/null
"$BUILD/bin/falcon-ref-cli" verify "$FN/public-key.bin" "$FN/message.bin" \
  "$FN/signature.bin" >/dev/null
java_bc verify-falcon "$FN/public-key.bin" "$FN/message.bin" "$FN/signature.bin" >/dev/null
xor_byte_file "$FN/signature.bin" "$FN/tampered-signature.bin" 1
expect_rejection "$BUILD/bin/falcon-ref-cli" verify "$FN/public-key.bin" "$FN/message.bin" \
  "$FN/tampered-signature.bin"
expect_rejection java_bc verify-falcon "$FN/public-key.bin" "$FN/message.bin" \
  "$FN/tampered-signature.bin"

{
  echo "status=PASS"
  echo "protobufSemanticAndWireCheck=PASS"
  echo "javaProtocWireCheck=PASS"
  echo "mlDsaOpenSslVerify=PASS"
  echo "mlDsaBouncyCastleVerify=PASS"
  echo "fnDsaFalconReferenceVerify=PASS"
  echo "fnDsaBouncyCastleVerify=PASS"
  echo "tamperedSignaturesRejected=PASS"
} > "$BUILD/reports/fixture-verification.txt"

echo "fixture verification ready: $BUILD/reports/fixture-verification.txt"
node "$ROOT/tools/check_cases.mjs" crypto
node --test "$ROOT/tools/nile.test.mjs"
