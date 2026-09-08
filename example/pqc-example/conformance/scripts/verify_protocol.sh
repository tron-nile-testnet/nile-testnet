#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"
REPO="$(cd "$ROOT/../../.." && pwd)"
PIN=c164973fffa4a7fa95ecfa9c0fe793f6761aeb78
# Added examples do not change the implementation under test. Reject source drift.
git -C "$REPO" diff --exit-code "$PIN" -- crypto/src protocol/src actuator/src framework/src common/src chainbase/src > /dev/null
"$ROOT/scripts/bootstrap_common.sh"
node "$ROOT/tools/fixture.mjs" check "$FIXTURES"/*.json
node "$ROOT/tools/check_cases.mjs" extract
(
  cd "$REPO"
  ./gradlew -I "$ROOT/tools/protocol.init.gradle" \
    -Dconformance.classpathFile="$BUILD/runtime-classpath.txt" \
    :framework:conformanceClasspath --no-daemon --max-workers=2
)
CLASSPATH="$(cat "$BUILD/runtime-classpath.txt")"
javac -proc:none -encoding UTF-8 -cp "$CLASSPATH" -d "$BUILD/java" "$ROOT/tools/Tip899ProtocolProbe.java"
java -cp "$CLASSPATH:$BUILD/java" Tip899ProtocolProbe \
  "$BUILD/cases/manifest.tsv" "$FIXTURES" > "$BUILD/reports/protocol.txt"
cat "$BUILD/reports/protocol.txt"
