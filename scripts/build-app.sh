#!/bin/bash
# Builds WardenFuse.app (release, universal arm64 + x86_64 by default).
#
#   scripts/build-app.sh                 # ad-hoc signed (Keychain fallback mode)
#   ARCHS="arm64" scripts/build-app.sh   # single architecture (faster local builds)
#   SIGN_IDENTITY="Developer ID Application: Name (TEAMID)" TEAM_ID=TEAMID scripts/build-app.sh
#   DMG=1 scripts/build-app.sh           # also create dist/WardenFuse.dmg
#
# Output: dist/WardenFuse.app
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ARCHS="${ARCHS:-arm64 x86_64}"
VERSION="${APP_VERSION:-$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')}"
BUILD="${BUILD_NUMBER:-$(git rev-list --count HEAD 2>/dev/null || echo 1)}"
DIST="$ROOT/dist"
APP="$DIST/WardenFuse.app"

# Minimum macOS for the Rust objects only. It must NOT be exported to `swift build`: there it
# also ends up as the SDK version recorded in the app binary (LC_BUILD_VERSION sdk 15.0), and
# macOS then draws the app in the pre–Liquid Glass compatibility style.
RUST_MIN_MACOS=15.0
UNI="target/universal-apple-darwin/release"
mkdir -p "$UNI"
LIBS=(); NMHS=(); SWIFT_ARCHS=()
for arch in $ARCHS; do
  case "$arch" in
    arm64) t=aarch64-apple-darwin ;;
    x86_64) t=x86_64-apple-darwin ;;
    *) echo "unknown arch $arch" >&2; exit 1 ;;
  esac
  echo "==> Rust core + native messaging host ($t)"
  MACOSX_DEPLOYMENT_TARGET="$RUST_MIN_MACOS" \
    cargo build --release --locked --target "$t" -p wardenfuse-core -p wardenfuse-nmh
  LIBS+=("target/$t/release/libwardenfuse_core.a")
  NMHS+=("target/$t/release/wardenfuse-nmh")
  SWIFT_ARCHS+=(--arch "$arch")
done
lipo -create "${LIBS[@]}" -output "$UNI/libwardenfuse_core.a"
lipo -create "${NMHS[@]}" -output "$UNI/wardenfuse-nmh"

echo "==> SwiftUI app ($ARCHS)"
swift build -c release --package-path macos "${SWIFT_ARCHS[@]}" -Xlinker -dead_strip
SWIFT_BIN="$(swift build -c release --package-path macos "${SWIFT_ARCHS[@]}" --show-bin-path)/WardenFuse"

echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$SWIFT_BIN" "$APP/Contents/MacOS/WardenFuse"
cp "$UNI/wardenfuse-nmh" "$APP/Contents/MacOS/wardenfuse-nmh"
sed -e "s/__VERSION__/$VERSION/" -e "s/__BUILD__/$BUILD/" \
  macos/WardenFuse/Resources/Info.plist > "$APP/Contents/Info.plist"
if [ -f macos/WardenFuse/Resources/AppIcon.icns ]; then
  cp macos/WardenFuse/Resources/AppIcon.icns "$APP/Contents/Resources/"
fi
cp LICENSE "$APP/Contents/Resources/LICENSE.txt"
cp NOTICE.md "$APP/Contents/Resources/NOTICE.md"
strip -x "$APP/Contents/MacOS/WardenFuse" "$APP/Contents/MacOS/wardenfuse-nmh" 2>/dev/null || true

# SwiftPM's build system links the app with the package's minimum OS as the recorded *SDK*
# version (LC_BUILD_VERSION sdk 15.0) although it compiles against the current SDK. macOS uses
# that value to decide the app's design generation, so an "SDK 15" app is drawn without Liquid
# Glass. Record the SDK the app was actually built with (minimum OS stays 15.0).
SDK_VERSION="$(xcrun --sdk macosx --show-sdk-version)"
for arch in $ARCHS; do
  vtool -arch "$arch" -set-build-version macos "$RUST_MIN_MACOS" "$SDK_VERSION" -replace \
    -output "$APP/Contents/MacOS/WardenFuse" "$APP/Contents/MacOS/WardenFuse"
done

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

lipo -info "$APP/Contents/MacOS/WardenFuse" "$APP/Contents/MacOS/wardenfuse-nmh"
# The app must record the real SDK (macOS 26+) or it is drawn without Liquid Glass.
SDKV="$(vtool -arch arm64 -show-build "$APP/Contents/MacOS/WardenFuse" | awk '/ sdk /{print $2; exit}')"
echo "==> Linked SDK: $SDKV (minimum macOS $(vtool -arch arm64 -show-build "$APP/Contents/MacOS/WardenFuse" | awk '/minos/{print $2; exit}'))"
case "$SDKV" in 1[0-9].*|2[0-5].*) echo "error: app records SDK $SDKV; Liquid Glass needs 26+" >&2; exit 1 ;; esac
du -sh "$APP" | awk '{print "==> Done: " $2 " (" $1 ")"}'
