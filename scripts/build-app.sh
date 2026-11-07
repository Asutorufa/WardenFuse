#!/bin/bash
# Builds WardenFuse.app (Apple Silicon, release).
#
#   scripts/build-app.sh                 # ad-hoc signed (Keychain fallback mode)
#   SIGN_IDENTITY="Developer ID Application: Name (TEAMID)" TEAM_ID=TEAMID scripts/build-app.sh
#   DMG=1 scripts/build-app.sh           # also create dist/WardenFuse.dmg
#
# Output: dist/WardenFuse.app
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TARGET="${TARGET:-aarch64-apple-darwin}"
VERSION="$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')"
BUILD="${BUILD_NUMBER:-$(git rev-list --count HEAD 2>/dev/null || echo 1)}"
DIST="$ROOT/dist"
APP="$DIST/WardenFuse.app"

echo "==> Rust core + native messaging host ($TARGET)"
export MACOSX_DEPLOYMENT_TARGET=15.0
cargo build --release --locked --target "$TARGET" -p wardenfuse-core -p wardenfuse-nmh

echo "==> SwiftUI app"
swift build -c release --package-path macos --arch arm64 \
  -Xlinker -dead_strip
SWIFT_BIN="$(swift build -c release --package-path macos --arch arm64 --show-bin-path)/WardenFuse"

echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$SWIFT_BIN" "$APP/Contents/MacOS/WardenFuse"
cp "target/$TARGET/release/wardenfuse-nmh" "$APP/Contents/MacOS/wardenfuse-nmh"
sed -e "s/__VERSION__/$VERSION/" -e "s/__BUILD__/$BUILD/" \
  macos/WardenFuse/Resources/Info.plist > "$APP/Contents/Info.plist"
if [ -f macos/WardenFuse/Resources/AppIcon.icns ]; then
  cp macos/WardenFuse/Resources/AppIcon.icns "$APP/Contents/Resources/"
fi
cp LICENSE "$APP/Contents/Resources/LICENSE.txt"
cp NOTICE.md "$APP/Contents/Resources/NOTICE.md"
strip -x "$APP/Contents/MacOS/WardenFuse" "$APP/Contents/MacOS/wardenfuse-nmh" 2>/dev/null || true

echo "==> Signing"
if [ -n "${SIGN_IDENTITY:-}" ]; then
  : "${TEAM_ID:?TEAM_ID is required with SIGN_IDENTITY}"
  ENT="$(mktemp)"
  sed "s/__TEAM_ID__/$TEAM_ID/" macos/WardenFuse/Resources/WardenFuse.entitlements > "$ENT"
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" \
    --identifier io.github.asutorufa.wardenfuse.nmh "$APP/Contents/MacOS/wardenfuse-nmh"
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" \
    --entitlements "$ENT" "$APP"
  rm -f "$ENT"
else
  echo "    (ad-hoc signature; Keychain items use the login keychain fallback)"
  codesign --force --sign - --identifier io.github.asutorufa.wardenfuse.nmh \
    "$APP/Contents/MacOS/wardenfuse-nmh"
  codesign --force --sign - "$APP"
fi
codesign --verify --deep --strict "$APP"

if [ "${DMG:-0}" = "1" ]; then
  echo "==> DMG"
  rm -f "$DIST/WardenFuse.dmg"
  STAGE="$(mktemp -d)"
  cp -R "$APP" "$STAGE/"
  ln -s /Applications "$STAGE/Applications"
  hdiutil create -volname WardenFuse -srcfolder "$STAGE" -ov -format UDZO "$DIST/WardenFuse.dmg" >/dev/null
  rm -rf "$STAGE"
  if [ -n "${SIGN_IDENTITY:-}" ]; then
    codesign --sign "$SIGN_IDENTITY" --timestamp "$DIST/WardenFuse.dmg"
  fi
fi

du -sh "$APP" | awk '{print "==> Done: " $2 " (" $1 ")"}'
