#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

"$ROOT/scripts/bootstrap_common.sh"
"$ROOT/scripts/build_falcon.sh"

CLI="$BUILD/bin/falcon-ref-cli"
REF_VECTOR="$BUILD/vectors/fn-dsa-512-reference"
BC_VECTOR="$BUILD/vectors/fn-dsa-512-bc"
REPORT="$BUILD/reports/fn-dsa-512.txt"
mkdir -p "$REF_VECTOR" "$BC_VECTOR" "$FIXTURES" "$BUILD/reports"

MESSAGE="$REF_VECTOR/message.bin"
KEY_SEED_HEX="$(incrementing_hex 48)"
SIGN_SEED_HEX="$(python3 - <<'PY'
print(bytes((0x80 + i) & 0xff for i in range(48)).hex())
PY
)"
make_incrementing_file "$MESSAGE" 32

"$CLI" keygen "$KEY_SEED_HEX" "$REF_VECTOR" > "$REF_VECTOR/keygen.log"
"$CLI" sign "$REF_VECTOR/private-key.bin" "$MESSAGE" "$SIGN_SEED_HEX" \
  "$REF_VECTOR/signature.bin" > "$REF_VECTOR/sign.log"
"$CLI" verify "$REF_VECTOR/public-key.bin" "$MESSAGE" \
  "$REF_VECTOR/signature.bin" >/dev/null
java_bc verify-falcon "$REF_VECTOR/public-key.bin" "$MESSAGE" \
  "$REF_VECTOR/signature.bin" >/dev/null

# BC-generated artifacts must verify with the Falcon reference implementation.
java_bc generate-falcon "$KEY_SEED_HEX" "$MESSAGE" "$BC_VECTOR" \
  > "$BC_VECTOR/generate.log"
"$CLI" verify "$BC_VECTOR/public-key.bin" "$MESSAGE" \
  "$BC_VECTOR/signature.bin" >/dev/null

# Also sign the reference-generated private key through BC, proving raw f||g||F compatibility.
java_bc sign-falcon "$REF_VECTOR/private-key.bin" "$MESSAGE" \
  "$REF_VECTOR/signature-bc.bin" >/dev/null
"$CLI" verify "$REF_VECTOR/public-key.bin" "$MESSAGE" \
  "$REF_VECTOR/signature-bc.bin" >/dev/null

# And sign the BC-generated private key through the C reference implementation.
"$CLI" sign "$BC_VECTOR/private-key.bin" "$MESSAGE" "$SIGN_SEED_HEX" \
  "$BC_VECTOR/signature-reference.bin" >/dev/null
java_bc verify-falcon "$BC_VECTOR/public-key.bin" "$MESSAGE" \
  "$BC_VECTOR/signature-reference.bin" >/dev/null

EXPECTED_PK_SHA256="1cc09837c6931f9c5988e59ad0acd4e8bc5f13e274573d0edb444822cd4afc90"
EXPECTED_SK_SHA256="960a83b03e1a8a075002be97f7a92959a2b60c91184cabac06172d8821c32d6a"
BC_PK_SHA256="$(sha256_file "$BC_VECTOR/public-key.bin")"
BC_SK_SHA256="$(sha256_file "$BC_VECTOR/private-key.bin")"
REF_PK_SHA256="$(sha256_file "$REF_VECTOR/public-key.bin")"
REF_SK_SHA256="$(sha256_file "$REF_VECTOR/private-key.bin")"
BC_KAT_MATCH=false
REF_KAT_MATCH=false
KEYGEN_BYTE_MATCH=false
[[ "$BC_PK_SHA256" == "$EXPECTED_PK_SHA256" && "$BC_SK_SHA256" == "$EXPECTED_SK_SHA256" ]] \
  && BC_KAT_MATCH=true
[[ "$REF_PK_SHA256" == "$EXPECTED_PK_SHA256" && "$REF_SK_SHA256" == "$EXPECTED_SK_SHA256" ]] \
  && REF_KAT_MATCH=true
cmp -s "$REF_VECTOR/public-key.bin" "$BC_VECTOR/public-key.bin" \
  && cmp -s "$REF_VECTOR/private-key.bin" "$BC_VECTOR/private-key.bin" \
  && KEYGEN_BYTE_MATCH=true

[[ "$BC_KAT_MATCH" == true && "$REF_KAT_MATCH" == true && "$KEYGEN_BYTE_MATCH" == true ]]

xor_byte_file "$MESSAGE" "$REF_VECTOR/tampered-message.bin" 0
expect_rejection "$CLI" verify "$REF_VECTOR/public-key.bin" \
  "$REF_VECTOR/tampered-message.bin" "$REF_VECTOR/signature.bin"
expect_rejection java_bc verify-falcon "$REF_VECTOR/public-key.bin" \
  "$REF_VECTOR/tampered-message.bin" "$REF_VECTOR/signature.bin"
xor_byte_file "$REF_VECTOR/signature.bin" "$REF_VECTOR/tampered-signature.bin" 1
expect_rejection "$CLI" verify "$REF_VECTOR/public-key.bin" \
  "$MESSAGE" "$REF_VECTOR/tampered-signature.bin"
expect_rejection java_bc verify-falcon "$REF_VECTOR/public-key.bin" \
  "$MESSAGE" "$REF_VECTOR/tampered-signature.bin"
truncate_last_byte_file "$REF_VECTOR/public-key.bin" "$REF_VECTOR/short-public-key.bin"
expect_rejection "$CLI" verify "$REF_VECTOR/short-public-key.bin" \
  "$MESSAGE" "$REF_VECTOR/signature.bin"
expect_rejection java_bc verify-falcon "$REF_VECTOR/short-public-key.bin" \
  "$MESSAGE" "$REF_VECTOR/signature.bin"

node "$ROOT/tools/fixture.mjs" generate FN_DSA_512 \
  "$MESSAGE" "$REF_VECTOR/public-key.bin" "$REF_VECTOR/signature.bin" \
  "$FIXTURES/fn-dsa-512.json" "Falcon reference 2021-11-01 + BouncyCastle 1.84" \
  "$KEY_SEED_HEX" "$SIGN_SEED_HEX" >/dev/null

{
  echo "status=PASS"
  echo "scheme=FN_DSA_512"
  echo "referenceArchiveSha256=$FALCON_SHA256"
  echo "messageLength=$(wc -c < "$MESSAGE" | tr -d ' ')"
  echo "publicKeyLength=$(wc -c < "$REF_VECTOR/public-key.bin" | tr -d ' ')"
  echo "signatureLength=$(wc -c < "$REF_VECTOR/signature.bin" | tr -d ' ')"
  echo "referencePublicKeySha256=$REF_PK_SHA256"
  echo "referencePrivateKeySha256=$REF_SK_SHA256"
  echo "bcPublicKeySha256=$BC_PK_SHA256"
  echo "bcPrivateKeySha256=$BC_SK_SHA256"
  echo "branchBcKatMatch=$BC_KAT_MATCH"
  echo "referenceKatMatch=$REF_KAT_MATCH"
  echo "referenceAndBcKeygenByteMatch=$KEYGEN_BYTE_MATCH"
  echo "referenceToBcVerify=PASS"
  echo "bcToReferenceVerify=PASS"
  echo "bcSignReferenceKeyToReferenceVerify=PASS"
  echo "referenceSignBcKeyToBcVerify=PASS"
  echo "tamperedMessageRejectedByBoth=PASS"
  echo "tamperedSignatureRejectedByBoth=PASS"
  echo "wrongPublicKeyLengthRejectedByBoth=PASS"
} > "$REPORT"

echo "FN-DSA-512 ready: $REPORT"
