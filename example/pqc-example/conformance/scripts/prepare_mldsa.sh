#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

"$ROOT/scripts/bootstrap_common.sh"
require_command "$OPENSSL"
"$OPENSSL" list -signature-algorithms | grep -q 'ML-DSA-44'

VECTOR="$BUILD/vectors/ml-dsa-44-openssl"
BC_VECTOR="$BUILD/vectors/ml-dsa-44-bc"
REPORT="$BUILD/reports/ml-dsa-44.txt"
mkdir -p "$VECTOR" "$BC_VECTOR" "$FIXTURES" "$BUILD/reports"

MESSAGE="$VECTOR/message.bin"
SEED_HEX="$(incrementing_hex 32)"
ZERO_ENTROPY_HEX="$(python3 - <<'PY'
print('00' * 32)
PY
)"
make_incrementing_file "$MESSAGE" 32

"$OPENSSL" genpkey -algorithm ML-DSA-44 \
  -pkeyopt "hexseed:$SEED_HEX" \
  -out "$VECTOR/private-key.pem"
"$OPENSSL" pkey -in "$VECTOR/private-key.pem" -pubout -out "$VECTOR/public-key.pem"
"$OPENSSL" pkey -in "$VECTOR/private-key.pem" -pubout -outform DER \
  -out "$VECTOR/public-key.der"
python3 "$ROOT/tools/ml_dsa_spki.py" extract \
  "$VECTOR/public-key.der" "$VECTOR/public-key.bin"
"$OPENSSL" pkeyutl -sign -rawin \
  -inkey "$VECTOR/private-key.pem" \
  -in "$MESSAGE" \
  -pkeyopt deterministic:1 \
  -out "$VECTOR/signature.bin"
"$OPENSSL" pkeyutl -verify -rawin -pubin \
  -inkey "$VECTOR/public-key.pem" \
  -in "$MESSAGE" \
  -sigfile "$VECTOR/signature.bin" >/dev/null

# OpenSSL-generated signature must verify through the exact BC 1.84 primitive used by java-tron.
java_bc verify-mldsa \
  "$VECTOR/public-key.bin" "$MESSAGE" "$VECTOR/signature.bin" >/dev/null

# Generate the same fixed-seed key and zero-entropy signature through BC.
java_bc generate-mldsa "$SEED_HEX" "$MESSAGE" "$BC_VECTOR" \
  > "$BC_VECTOR/generate.log"
cmp "$VECTOR/public-key.bin" "$BC_VECTOR/public-key.bin"
cmp "$VECTOR/signature.bin" "$BC_VECTOR/signature.bin"
python3 "$ROOT/tools/ml_dsa_spki.py" wrap \
  "$BC_VECTOR/public-key.bin" "$BC_VECTOR/public-key.der"
"$OPENSSL" pkeyutl -verify -rawin -pubin -keyform DER \
  -inkey "$BC_VECTOR/public-key.der" \
  -in "$MESSAGE" \
  -sigfile "$BC_VECTOR/signature.bin" >/dev/null

EXPECTED_PK_SHA256="9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46"
EXPECTED_SK_SHA256="04bf6b9f579166a627961dfc5c3bf9717df868db88863856356c4668c8b56b0b"
[[ "$(sha256_file "$VECTOR/public-key.bin")" == "$EXPECTED_PK_SHA256" ]]
[[ "$(sha256_file "$BC_VECTOR/private-key.bin")" == "$EXPECTED_SK_SHA256" ]]
[[ "$(wc -c < "$VECTOR/signature.bin" | tr -d ' ')" == "2420" ]]

xor_byte_file "$MESSAGE" "$VECTOR/tampered-message.bin" 0
expect_rejection "$OPENSSL" pkeyutl -verify -rawin -pubin \
  -inkey "$VECTOR/public-key.pem" \
  -in "$VECTOR/tampered-message.bin" \
  -sigfile "$VECTOR/signature.bin"
expect_rejection java_bc verify-mldsa \
  "$VECTOR/public-key.bin" "$VECTOR/tampered-message.bin" "$VECTOR/signature.bin"
xor_byte_file "$VECTOR/signature.bin" "$VECTOR/tampered-signature.bin" 1
expect_rejection "$OPENSSL" pkeyutl -verify -rawin -pubin \
  -inkey "$VECTOR/public-key.pem" \
  -in "$MESSAGE" \
  -sigfile "$VECTOR/tampered-signature.bin"
expect_rejection java_bc verify-mldsa \
  "$VECTOR/public-key.bin" "$MESSAGE" "$VECTOR/tampered-signature.bin"
truncate_last_byte_file "$VECTOR/public-key.bin" "$VECTOR/short-public-key.bin"
expect_rejection java_bc verify-mldsa \
  "$VECTOR/short-public-key.bin" "$MESSAGE" "$VECTOR/signature.bin"

node "$ROOT/tools/fixture.mjs" generate ML_DSA_44 \
  "$MESSAGE" "$VECTOR/public-key.bin" "$VECTOR/signature.bin" \
  "$FIXTURES/ml-dsa-44.json" "OpenSSL $("$OPENSSL" version | awk '{print $2}') + BouncyCastle 1.84" \
  "$SEED_HEX" "$ZERO_ENTROPY_HEX" >/dev/null

{
  echo "status=PASS"
  echo "scheme=ML_DSA_44"
  echo "openssl=$("$OPENSSL" version)"
  echo "messageLength=$(wc -c < "$MESSAGE" | tr -d ' ')"
  echo "publicKeyLength=$(wc -c < "$VECTOR/public-key.bin" | tr -d ' ')"
  echo "signatureLength=$(wc -c < "$VECTOR/signature.bin" | tr -d ' ')"
  echo "publicKeySha256=$(sha256_file "$VECTOR/public-key.bin")"
  echo "privateKeySha256Bc=$(sha256_file "$BC_VECTOR/private-key.bin")"
  echo "signatureSha256=$(sha256_file "$VECTOR/signature.bin")"
  echo "opensslToBcVerify=PASS"
  echo "bcToOpenSslVerify=PASS"
  echo "deterministicSignatureByteMatch=PASS"
  echo "tamperedMessageRejectedByBoth=PASS"
  echo "tamperedSignatureRejectedByBoth=PASS"
  echo "wrongPublicKeyLengthRejected=PASS"
} > "$REPORT"

echo "ML-DSA-44 ready: $REPORT"
