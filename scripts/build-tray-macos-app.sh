#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${P2WLAN_TRAY_PROFILE:-debug}"
APP_NAME="P2WLAN Tray"
APP_DIR="$ROOT_DIR/dist/$APP_NAME.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
EXECUTABLE="$MACOS_DIR/p2wlan-tray"

if [[ "$PROFILE" == "release" ]]; then
  cargo build -p p2wlan-tray --release
  cargo build -p p2wlan-daemon --release
else
  PROFILE="debug"
  cargo build -p p2wlan-tray
  cargo build -p p2wlan-daemon
fi

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"
install -m 0755 "$ROOT_DIR/target/$PROFILE/p2wlan-tray" "$EXECUTABLE"
install -m 0755 "$ROOT_DIR/target/$PROFILE/p2wlan-daemon" "$RESOURCES_DIR/p2wlan-daemon"

cat >"$CONTENTS_DIR/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>p2wlan-tray</string>
  <key>CFBundleIdentifier</key>
  <string>io.p2wlan.tray</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>P2WLAN Tray</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.107</string>
  <key>CFBundleVersion</key>
  <string>107</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
  <key>LSUIElement</key>
  <true/>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
PLIST

echo "$APP_DIR"
