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
else
  PROFILE="debug"
fi

DAEMON_SRC="$ROOT_DIR/target/$PROFILE/p2wlan-daemon"
echo "[bundle-daemon] building p2wlan-daemon ($PROFILE) to refresh the embedded daemon..."
if [[ "$PROFILE" == "release" ]]; then
  (cd "$ROOT_DIR" && cargo build -p p2wlan-daemon --release)
else
  (cd "$ROOT_DIR" && cargo build -p p2wlan-daemon)
fi

if [[ ! -x "$DAEMON_SRC" ]]; then
  echo "[bundle-daemon] missing daemon binary at $DAEMON_SRC" >&2
  exit 1
fi

# The Flutter shell and the daemon are released together. Keep an explicit
# identity check here because an old daemon can otherwise remain in target/
# and get silently copied into a newer App bundle.
EXPECTED_VERSION="$(awk -F'"' '/^version = / { print $2; exit }' "$ROOT_DIR/Cargo.toml")"
EXPECTED_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)"
BUILD_INFO="$("$DAEMON_SRC" --build-info)"
if ! grep -Fq "\"app_version\": \"$EXPECTED_VERSION\"" <<< "$BUILD_INFO" \
  || ! grep -Fq "\"daemon_version\": \"$EXPECTED_VERSION\"" <<< "$BUILD_INFO" \
  || ! grep -Fq "\"git_commit\": \"$EXPECTED_COMMIT\"" <<< "$BUILD_INFO"; then
  echo "[bundle-daemon] daemon identity does not match the checkout" >&2
  echo "[bundle-daemon] expected version=$EXPECTED_VERSION commit=$EXPECTED_COMMIT" >&2
  echo "[bundle-daemon] actual: $BUILD_INFO" >&2
  exit 1
fi

RESOURCES_DIR="$BUILT_PRODUCTS_DIR/$CONTENTS_FOLDER_PATH/Resources"
mkdir -p "$RESOURCES_DIR"
install -m 0755 "$DAEMON_SRC" "$RESOURCES_DIR/p2wlan-daemon"
echo "[bundle-daemon] bundled $DAEMON_SRC -> $RESOURCES_DIR/p2wlan-daemon (version=$EXPECTED_VERSION commit=$EXPECTED_COMMIT)"
