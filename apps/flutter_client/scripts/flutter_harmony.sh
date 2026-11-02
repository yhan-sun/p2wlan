#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${FLUTTER_OH_ROOT:-}" || ! -x "$FLUTTER_OH_ROOT/bin/flutter" ]]; then
  echo "Set FLUTTER_OH_ROOT to a Flutter-OH SDK compatible with pubspec.yaml." >&2
  exit 2
fi
FLUTTER_BIN="$(cd "$FLUTTER_OH_ROOT" && pwd)/bin/flutter"
if [[ $# -eq 0 ]]; then
  echo "Usage: FLUTTER_OH_ROOT=/path/to/flutter-oh bash scripts/flutter_harmony.sh <flutter arguments>" >&2
  exit 2
fi
if [[ ! -f "$APP_DIR/harmony/build-profile.json5" ]]; then
  echo "Harmony platform project is missing." >&2
  exit 1
fi

# Serialize Flutter commands. Studio uses the same persistent compatibility
# alias; leaving it in place keeps its configuration and builds valid.
mkdir -p "$APP_DIR/build"
LOCK_DIR="$APP_DIR/build/harmony-flutter.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "Another Harmony command owns the mapping; inspect the lock before retrying." >&2
  exit 1
fi
cleanup() {
  rmdir "$LOCK_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
NODE_BIN="${NODE_HOME:+$NODE_HOME/bin/}node"
"$NODE_BIN" "$APP_DIR/scripts/harmony_paths.cjs"
cd "$APP_DIR"
"$FLUTTER_BIN" "$@"
