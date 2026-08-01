#!/usr/bin/env bash
set -euo pipefail

FLUTTER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="$(cd "$FLUTTER_DIR/../.." && pwd)"
APP_VERSION="$(awk '/^version:/ { split($2, version, "+"); print version[1]; exit }' "$FLUTTER_DIR/pubspec.yaml")"
ARCH="$(uname -m)"
APP_DIR="$FLUTTER_DIR/build/macos/Build/Products/Release/P2WLAN.app"
DAEMON_PATH="$APP_DIR/Contents/Resources/p2wlan-daemon"
ARTIFACT_DIR="$ROOT_DIR/target/flutter/release"
DMG_PATH="$ARTIFACT_DIR/P2WLAN_${APP_VERSION}_macos_${ARCH}.dmg"

if [[ -z "$APP_VERSION" ]]; then
  echo "Unable to read Flutter app version from pubspec.yaml" >&2
  exit 1
fi

echo "[package-flutter-macos] building p2wlan-daemon $APP_VERSION (release)..."
(cd "$ROOT_DIR" && cargo build -p p2wlan-daemon --release)

echo "[package-flutter-macos] building Flutter macOS app..."
(cd "$FLUTTER_DIR" && flutter build macos --release)

if [[ ! -d "$APP_DIR" ]]; then
  echo "Missing Flutter app bundle: $APP_DIR" >&2
  exit 1
fi
if [[ ! -x "$DAEMON_PATH" ]]; then
  echo "Flutter app does not contain an executable p2wlan-daemon" >&2
  exit 1
fi
if [[ "$($DAEMON_PATH --version)" != "p2wlan-daemon $APP_VERSION" ]]; then
  echo "Bundled daemon version does not match Flutter app version $APP_VERSION" >&2
  exit 1
fi

echo "[package-flutter-macos] signing app after bundling the release daemon..."
codesign \
  --force \
  --sign - \
  --entitlements "$FLUTTER_DIR/macos/Runner/Release.entitlements" \
  "$APP_DIR"
echo "[package-flutter-macos] verifying app signature..."
codesign --verify --deep --strict --verbose=2 "$APP_DIR"

mkdir -p "$ARTIFACT_DIR"
rm -f "$DMG_PATH"
STAGING_DIR="$(mktemp -d "$ROOT_DIR/target/p2wlan-flutter-dmg.XXXXXX")"
trap 'rm -rf "$STAGING_DIR"' EXIT
ditto "$APP_DIR" "$STAGING_DIR/P2WLAN.app"
ln -s /Applications "$STAGING_DIR/Applications"

echo "[package-flutter-macos] creating $DMG_PATH..."
hdiutil create \
  -volname "P2WLAN" \
  -srcfolder "$STAGING_DIR" \
  -ov \
  -format UDZO \
  "$DMG_PATH" >/dev/null

codesign --verify --deep --strict --verbose=2 "$STAGING_DIR/P2WLAN.app"
echo "$DMG_PATH"
