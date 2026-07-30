#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CONFIGURATION="${CONFIGURATION:-Debug}"
BUILT_PRODUCTS_DIR="${BUILT_PRODUCTS_DIR:-}"
CONTENTS_FOLDER_PATH="${CONTENTS_FOLDER_PATH:-}"

if [[ -z "$BUILT_PRODUCTS_DIR" || -z "$CONTENTS_FOLDER_PATH" ]]; then
  echo "[bundle-daemon] Xcode build variables are missing; skipping."
  exit 0
fi

if [[ "$CONFIGURATION" == "Release" ]]; then
  PROFILE="release"
  CARGO_ARGS=(--release)
else
  PROFILE="debug"
  CARGO_ARGS=()
fi

DAEMON_SRC="$ROOT_DIR/target/$PROFILE/p2wlan-daemon"
if [[ ! -x "$DAEMON_SRC" ]]; then
  echo "[bundle-daemon] building p2wlan-daemon ($PROFILE)..."
  (cd "$ROOT_DIR" && cargo build -p p2wlan-daemon "${CARGO_ARGS[@]}")
fi

if [[ ! -x "$DAEMON_SRC" ]]; then
  echo "[bundle-daemon] missing daemon binary at $DAEMON_SRC" >&2
  exit 1
fi

RESOURCES_DIR="$BUILT_PRODUCTS_DIR/$CONTENTS_FOLDER_PATH/Resources"
mkdir -p "$RESOURCES_DIR"
install -m 0755 "$DAEMON_SRC" "$RESOURCES_DIR/p2wlan-daemon"
echo "[bundle-daemon] bundled $DAEMON_SRC -> $RESOURCES_DIR/p2wlan-daemon"
