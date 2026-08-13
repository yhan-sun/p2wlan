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

# Derive the bundle version from the workspace so the App, the built-in daemon
# and `/status.version` can never drift apart again.
VERSION="$(grep -m1 -E '^version[[:space:]]*=[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+"' "$ROOT_DIR/Cargo.toml" | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)"/\1/')"
if [[ -z "$VERSION" ]]; then
  echo "[build-tray] could not derive workspace version from Cargo.toml" >&2
  exit 1
fi
# CFBundleVersion must be numeric (dot-separated ok): strip the dots.
BUILD_NUMBER="${VERSION//./}"

cat >"$CONTENTS_DIR/Info.plist" <<PLIST
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
  <string>$VERSION</string>
  <key>CFBundleVersion</key>
  <string>$BUILD_NUMBER</string>
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

# Build identity is checked by the shared fail-closed verifier below.
GIT_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || true)"
if [[ -z "$GIT_COMMIT" ]]; then
  echo "[build-tray] FATAL: git commit unavailable" >&2
  exit 1
fi
TRAY_SHA="$(shasum -a 256 "$EXECUTABLE" | awk '{print $1}')"
DAEMON_SHA="$(shasum -a 256 "$RESOURCES_DIR/p2wlan-daemon" | awk '{print $1}')"
python3 - "$VERSION" "$GIT_COMMIT" "$TRAY_SHA" "$DAEMON_SHA" "$RESOURCES_DIR/p2wlan-daemon" "$CONTENTS_DIR/Resources/build-manifest.json" <<'PY'
import json, subprocess, sys
version, commit, tray_sha, daemon_sha, daemon, manifest = sys.argv[1:]
info = json.loads(subprocess.check_output([daemon, "--build-info"], text=True))
if not info:
    raise SystemExit("embedded daemon returned empty build-info")
with open(manifest, "w", encoding="utf-8") as handle:
    json.dump({
        "app_version": version,
        "git_commit": commit,
        "build_id": info.get("build_id", ""),
        "tray_sha256": tray_sha,
        "daemon_sha256": daemon_sha,
        "daemon_build_info": info,
    }, handle, indent=2)
PY
if [[ "$PROFILE" == "release" ]]; then
  python3 "$ROOT_DIR/scripts/release/verify_release_identity.py" \
    --daemon "$RESOURCES_DIR/p2wlan-daemon" \
    --manifest "$CONTENTS_DIR/Resources/build-manifest.json" \
    --app-info "$CONTENTS_DIR/Info.plist" \
    --expected-commit "$GIT_COMMIT" \
    --release
else
  python3 "$ROOT_DIR/scripts/release/verify_release_identity.py" \
    --daemon "$RESOURCES_DIR/p2wlan-daemon" \
    --manifest "$CONTENTS_DIR/Resources/build-manifest.json" \
    --app-info "$CONTENTS_DIR/Info.plist" \
    --expected-commit "$GIT_COMMIT"
fi
echo "[build-tray] app_version=$VERSION git_commit=$GIT_COMMIT daemon_sha256=$DAEMON_SHA tray_sha256=$TRAY_SHA"

echo "$APP_DIR"
