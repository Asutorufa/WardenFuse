#!/bin/bash
# Notarizes and staples dist/WardenFuse.dmg (or .app zip).
# Requires: a Developer ID signed build (scripts/build-app.sh with SIGN_IDENTITY, DMG=1) and a
# notarytool keychain profile: xcrun notarytool store-credentials wardenfuse --apple-id ... --team-id ...
set -euo pipefail
PROFILE="${NOTARY_PROFILE:-wardenfuse}"
ARTIFACT="${1:-dist/WardenFuse.dmg}"
xcrun notarytool submit "$ARTIFACT" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$ARTIFACT"
