#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${ROOT}/dist"
mkdir -p "$OUT/com.croatiasecurity.behavedr.es.systemextension/Contents/MacOS"
cp "$ROOT/Info.plist" "$OUT/com.croatiasecurity.behavedr.es.systemextension/Contents/"

clang -O2 -o "$OUT/com.croatiasecurity.behavedr.es.systemextension/Contents/MacOS/BehavedrES" \
  "$ROOT/main.m" \
  -framework EndpointSecurity -framework Foundation \
  -fobjc-arc

# Optional codesign when identity present
if [[ -n "${MACOS_CODESIGN_IDENTITY:-}" ]]; then
  codesign --force --options runtime --sign "$MACOS_CODESIGN_IDENTITY" \
    --entitlements "$ROOT/entitlements.plist" \
    "$OUT/com.croatiasecurity.behavedr.es.systemextension/Contents/MacOS/BehavedrES"
fi

echo "Built $OUT/com.croatiasecurity.behavedr.es.systemextension"
