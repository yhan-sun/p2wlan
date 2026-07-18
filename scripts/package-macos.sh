#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

TARGET=""
TAURI_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET=${2:-}
      if [[ -z "$TARGET" ]]; then
        echo "--target requires a Rust target triple" >&2
        exit 2
      fi
      shift 2
      ;;
    --debug)
      TAURI_ARGS+=(--debug)
      shift
      ;;
    *)
      TAURI_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  TARGET=$(rustc -vV | awk -F': ' '/host/ { print $2 }')
fi
APP_VERSION=$(python3 -c 'import json; print(json.load(open("src-tauri/tauri.conf.json"))["version"])')

echo "[package-macos] target: $TARGET"
DAEMON_RESOURCE="$ROOT_DIR/src-tauri/resources/p2pnet-daemon"

if [[ "$TARGET" == "universal-apple-darwin" ]]; then
  echo "[package-macos] building universal p2pnet-daemon release binary..."
  rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
  cargo build -p p2pnet-daemon --release --target aarch64-apple-darwin
  cargo build -p p2pnet-daemon --release --target x86_64-apple-darwin
  mkdir -p "$(dirname "$DAEMON_RESOURCE")"
  lipo -create \
    "$ROOT_DIR/target/aarch64-apple-darwin/release/p2pnet-daemon" \
    "$ROOT_DIR/target/x86_64-apple-darwin/release/p2pnet-daemon" \
    -output "$DAEMON_RESOURCE"
else
  rustup target add "$TARGET" >/dev/null
  echo "[package-macos] building p2pnet-daemon release binary..."
  cargo build -p p2pnet-daemon --release --target "$TARGET"
  DAEMON_SRC="$ROOT_DIR/target/$TARGET/release/p2pnet-daemon"
  if [[ ! -x "$DAEMON_SRC" ]]; then
    echo "missing daemon binary: $DAEMON_SRC" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$DAEMON_RESOURCE")"
  cp "$DAEMON_SRC" "$DAEMON_RESOURCE"
fi
chmod 755 "$DAEMON_RESOURCE"

echo "[package-macos] building Tauri app/dmg..."
if [[ ${#TAURI_ARGS[@]} -gt 0 ]]; then
  pnpm tauri build --target "$TARGET" "${TAURI_ARGS[@]}"
else
  pnpm tauri build --target "$TARGET"
fi

APP_DIR="$ROOT_DIR/target/$TARGET/release/bundle/macos/p2wlan.app"
DMG_DIR="$ROOT_DIR/target/$TARGET/release/bundle/dmg"
if [[ ! -d "$APP_DIR" && "$TARGET" == "$(rustc -vV | awk -F': ' '/host/ { print $2 }')" ]]; then
  APP_DIR="$ROOT_DIR/target/release/bundle/macos/p2wlan.app"
  DMG_DIR="$ROOT_DIR/target/release/bundle/dmg"
fi

BUNDLED_DAEMON="$APP_DIR/Contents/Resources/p2pnet-daemon"
if [[ ! -x "$BUNDLED_DAEMON" ]]; then
  echo "packaged app is missing executable daemon resource: $BUNDLED_DAEMON" >&2
  exit 1
fi

echo "[package-macos] verified bundled daemon: $BUNDLED_DAEMON"
echo "[package-macos] applying ad-hoc code signature..."
codesign --force --deep --sign - "$APP_DIR"
codesign --verify --deep --strict --verbose=2 "$APP_DIR"

if [[ -d "$DMG_DIR" ]]; then
  STAGING_DIR="$ROOT_DIR/target/p2wlan-dmg-staging"
  rm -rf "$STAGING_DIR"
  mkdir -p "$STAGING_DIR"
  ditto "$APP_DIR" "$STAGING_DIR/p2wlan.app"
  ln -s /Applications "$STAGING_DIR/Applications"
  DMG_PATH="$DMG_DIR/p2wlan_${APP_VERSION}_${TARGET}.dmg"
  if [[ "$TARGET" == "aarch64-apple-darwin" ]]; then
    DMG_PATH="$DMG_DIR/p2wlan_${APP_VERSION}_aarch64.dmg"
  elif [[ "$TARGET" == "x86_64-apple-darwin" ]]; then
    DMG_PATH="$DMG_DIR/p2wlan_${APP_VERSION}_x64.dmg"
  elif [[ "$TARGET" == "universal-apple-darwin" ]]; then
    DMG_PATH="$DMG_DIR/p2wlan_${APP_VERSION}_universal.dmg"
  fi
  find "$DMG_DIR" -maxdepth 1 -name 'p2wlan_*.dmg' -delete
  hdiutil create -volname "p2wlan" -srcfolder "$STAGING_DIR" -ov -format UDZO "$DMG_PATH" >/dev/null
  rm -rf "$STAGING_DIR"
fi

echo "[package-macos] dmg artifacts:"
find "$ROOT_DIR/target" -path "*/release/bundle/dmg/*.dmg" -type f -print
