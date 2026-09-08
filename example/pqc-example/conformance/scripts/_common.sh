#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="$ROOT/.cache"
BUILD="${CONFORMANCE_BUILD_DIR:-$ROOT/build}"
FIXTURES="${CONFORMANCE_FIXTURE_DIR:-$ROOT/fixtures}"
OPENSSL="${OPENSSL:-openssl}"
BC_VERSION="1.84"
BC_JAR="$CACHE/bcprov-jdk18on-$BC_VERSION.jar"
BC_URL="https://repo.maven.apache.org/maven2/org/bouncycastle/bcprov-jdk18on/$BC_VERSION/bcprov-jdk18on-$BC_VERSION.jar"
BC_SHA256="64d6c5a6121fcd927152dd182cbed39afe0fda641a970d9bcc0c9cb1858b2731"
PROTOBUF_VERSION="3.25.8"
PROTOBUF_JAR="$CACHE/protobuf-java-$PROTOBUF_VERSION.jar"
PROTOBUF_JAR_URL="https://repo.maven.apache.org/maven2/com/google/protobuf/protobuf-java/$PROTOBUF_VERSION/protobuf-java-$PROTOBUF_VERSION.jar"
PROTOBUF_JAR_SHA256="72bdb32eb38cafb7dcd288262c29a34d57cba2e19101af9685155ba8c0a56008"
PROTOC="$CACHE/protoc-$PROTOBUF_VERSION-osx-aarch_64"
PROTOC_URL="https://repo.maven.apache.org/maven2/com/google/protobuf/protoc/$PROTOBUF_VERSION/protoc-$PROTOBUF_VERSION-osx-aarch_64.exe"
PROTOC_SHA256="d2300cc09a7a4f347d289b06ac4c0c9d2f99e4eb44fe6467e9f49a2dca66fd81"
FALCON_ARCHIVE="$CACHE/Falcon-impl-20211101.zip"
FALCON_URL="https://falcon-sign.info/Falcon-impl-20211101.zip"
FALCON_SHA256="d9f982bd825b9903b57b686d6d26018dac173a1dff09f224cc39302f9d85a595"
FALCON_REF="$CACHE/falcon-reference/Falcon-impl-20211101"
BC_MAIN="Tip899BcInterop"

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

download_locked() {
  local url="$1"
  local destination="$2"
  local expected="$3"
  local actual=""
  mkdir -p "$(dirname "$destination")"
  if [[ -f "$destination" ]]; then
    actual="$(sha256_file "$destination")"
  fi
  if [[ "$actual" != "$expected" ]]; then
    local temporary="$destination.download"
    curl -fL --retry 3 --retry-delay 1 "$url" -o "$temporary"
    actual="$(sha256_file "$temporary")"
    if [[ "$actual" != "$expected" ]]; then
      rm -f "$temporary"
      echo "checksum mismatch for $url: expected=$expected actual=$actual" >&2
      return 1
    fi
    mv "$temporary" "$destination"
  fi
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command not found: $1" >&2
    return 1
  }
}

java_bc() {
  java -cp "$BC_JAR:$PROTOBUF_JAR:$BUILD/java" "$BC_MAIN" "$@"
}

java_proto() {
  java -cp "$PROTOBUF_JAR:$BUILD/java" Tip899ProtoInterop "$@"
}

make_incrementing_file() {
  local destination="$1"
  local length="$2"
  python3 - "$destination" "$length" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).parent.mkdir(parents=True, exist_ok=True)
Path(sys.argv[1]).write_bytes(bytes(range(int(sys.argv[2]))))
PY
}

incrementing_hex() {
  local length="$1"
  python3 - "$length" <<'PY'
import sys
print(bytes(range(int(sys.argv[1]))).hex())
PY
}

# A process crash, missing executable, or I/O error is NOT a successful negative test.
expect_rejection() {
  local output status=0
  output="$("$@" 2>&1)" || status=$?
  if [[ "$status" != 1 ]] || ! printf '%s\n' "$output" | grep -Eq '^valid=false( |$)|^Signature Verification Failure$'; then
    printf 'expected explicit verification rejection (exit 1), got exit %s:\n%s\n' "$status" "$output" >&2
    return 1
  fi
}

xor_byte_file() {
  local source="$1"
  local destination="$2"
  local offset="$3"
  python3 - "$source" "$destination" "$offset" <<'PY'
from pathlib import Path
import sys
data = bytearray(Path(sys.argv[1]).read_bytes())
offset = int(sys.argv[3])
if offset < 0 or offset >= len(data):
    raise SystemExit(f"mutation offset {offset} outside {len(data)}-byte input")
data[offset] ^= 1
Path(sys.argv[2]).write_bytes(data)
PY
}

truncate_last_byte_file() {
  local source="$1"
  local destination="$2"
  python3 - "$source" "$destination" <<'PY'
from pathlib import Path
import sys
data = Path(sys.argv[1]).read_bytes()
if not data:
    raise SystemExit("cannot truncate an empty file")
Path(sys.argv[2]).write_bytes(data[:-1])
PY
}
