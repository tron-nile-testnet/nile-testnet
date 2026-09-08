#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"

# Only this platform has been validated for fixed-seed Falcon reproduction.
if [[ "$(uname -s)/$(uname -m)" != Darwin/arm64 ]]; then
  echo "supported reproduction platform: macOS arm64; other platforms are unverified" >&2
  exit 2
fi
for command in curl java javac node npm python3 shasum "$OPENSSL"; do
  require_command "$command"
done

mkdir -p "$CACHE" "$BUILD/java" "$BUILD/reports"
download_locked "$BC_URL" "$BC_JAR" "$BC_SHA256"
download_locked "$PROTOBUF_JAR_URL" "$PROTOBUF_JAR" "$PROTOBUF_JAR_SHA256"
download_locked "$PROTOC_URL" "$PROTOC" "$PROTOC_SHA256"
chmod +x "$PROTOC"

(
  cd "$ROOT"
  npm ci --ignore-scripts --no-audit --no-fund
)

mkdir -p "$BUILD/generated/java"
"$PROTOC" -I="$ROOT/proto" --java_out="$BUILD/generated/java" \
  "$ROOT/proto/pq_auth_sig.proto"
javac -encoding UTF-8 -cp "$BC_JAR:$PROTOBUF_JAR" -d "$BUILD/java" \
  "$ROOT/tools/Tip899BcInterop.java" \
  "$ROOT/tools/Tip899ProtoInterop.java" \
  "$BUILD/generated/java/org/tron/tip899/fixture/Tip899FixtureProto.java"

{
  "$OPENSSL" version
  sw_vers
  uname -m
  clang --version | head -1
  python3 --version
  java -version 2>&1 | head -1
  node --version
  npm --version
  echo "BouncyCastle $BC_VERSION sha256=$BC_SHA256"
  echo "protoc $($PROTOC --version) sha256=$PROTOC_SHA256"
  echo "protobuf-java $PROTOBUF_VERSION sha256=$PROTOBUF_JAR_SHA256"
} > "$BUILD/reports/tool-versions.txt"

echo "common tooling ready: $ROOT"
