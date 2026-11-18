#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PT Jiji Labs Digital
#
# Runs one fuzz target with Jazzer outside OSS-Fuzz (a laptop, or a Linux box that fuzzes every night).
#   fuzz/run-jazzer.sh <Target> <seconds> [extra libFuzzer flags...]      (CORPUS=<dir> keeps the corpus elsewhere)
# Targets: WireFuzzer CodecFuzzer HandshakeFuzzer RatchetFuzzer SessionRecordFuzzer SignatureFuzzer InviteFuzzer LinkFuzzer.
# Needs JDK 17 or later (JAVA_HOME or java on PATH) and curl. Crash inputs land in fuzz/build/jazzer-artifacts/<Target>/;
# to keep one as a regression, copy it to fuzz/regressions/<Target>/ and run ./gradlew :fuzz:replay (seeds and regressions, no Jazzer).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
target=$1; seconds=$2; shift 2
corpus=${CORPUS:-$here/build/jazzer-corpus/$target}
java=${JAVA_HOME:+$JAVA_HOME/bin/}java

# Jazzer 0.30.0 (Apache-2.0) from Maven Central, checked against these SHA-256 values.
tools=$here/build/jazzer
mkdir -p "$tools"
sha256() { if command -v sha256sum >/dev/null; then sha256sum -c - ; else shasum -a 256 -c - ; fi; }
fetch() {
  local name=$1 sum=$2 url=$3
  if [ ! -f "$tools/$name" ] || ! echo "$sum  $tools/$name" | sha256 >/dev/null 2>&1; then
    curl -fsSL -o "$tools/$name" "$url"
    echo "$sum  $tools/$name" | sha256 >/dev/null
  fi
}
fetch jazzer-0.30.0.jar 8bdeac017bcd3d9473c9772fac62111c4df830188571def1d001a1b743a62b2f \
  https://repo1.maven.org/maven2/com/code-intelligence/jazzer/0.30.0/jazzer-0.30.0.jar
fetch jazzer-api-0.30.0.jar d36a725cfedcb7f3590206866cc2836f84d12afccf7c98912f5c720e4d2208d7 \
  https://repo1.maven.org/maven2/com/code-intelligence/jazzer-api/0.30.0/jazzer-api-0.30.0.jar

(cd "$here/.." && ./gradlew -q :fuzz:fuzzJars :fuzz:seedCorpus)
cp=$tools/jazzer-0.30.0.jar:$tools/jazzer-api-0.30.0.jar
for j in "$here"/build/fuzz-out/*.jar; do cp=$cp:$j; done
artifacts=$here/build/jazzer-artifacts/$target
mkdir -p "$corpus" "$artifacts"
cd "$artifacts"
exec "$java" -Xmx2048m -Xss1024k -cp "$cp" com.code_intelligence.jazzer.Jazzer \
  --target_class=com.jijilabsdigital.swell.protocol.fuzz.$target \
  '--instrumentation_includes=com.jijilabsdigital.swell.protocol.**' \
  '--instrumentation_excludes=com.jijilabsdigital.swell.protocol.fuzz.**' \
  -max_total_time="$seconds" -timeout=30 -rss_limit_mb=4096 -print_final_stats=1 -artifact_prefix="$artifacts/" \
  "$@" "$corpus" "$here/build/seeds/$target"
