#!/usr/bin/env bash
set -euo pipefail

FLUTTER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="$(cd "$FLUTTER_DIR/../.." && pwd)"
DAEMON_BIN="$ROOT_DIR/target/debug/p2wlan-daemon"
AUTO_START=1
SKIP_DAEMON_BUILD=0
DRY_RUN=0
FLUTTER_ARGS=()

usage() {
  cat <<'USAGE'
Usage:
  apps/flutter_client/scripts/run_test_app_macos.sh [options] [-- flutter-run-args]

Build the matching Rust daemon and launch the macOS Flutter test app. For an
already configured client, the app automatically starts the daemon when local
diagnostics are offline.

Options:
  --no-auto-start       Launch the Flutter UI without starting the daemon.
  --skip-daemon-build   Reuse target/debug/p2wlan-daemon after identity checks.
  --dry-run             Build and validate, but only print the launch command.
  -h, --help            Show this help.

Examples:
  ./apps/flutter_client/scripts/run_test_app_macos.sh
  ./apps/flutter_client/scripts/run_test_app_macos.sh --no-auto-start
  ./apps/flutter_client/scripts/run_test_app_macos.sh -- --verbose
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-auto-start)
      AUTO_START=0
      shift
      ;;
    --skip-daemon-build)
      SKIP_DAEMON_BUILD=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      FLUTTER_ARGS=("$@")
      break
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Run with --help for usage." >&2
      exit 2
      ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This launcher currently supports macOS only." >&2
  exit 1
fi

for command_name in cargo flutter git; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name" >&2
    exit 1
  fi
done

if [[ "$SKIP_DAEMON_BUILD" -eq 0 ]]; then
  echo "[run-test-app] Building p2wlan-daemon from the current checkout..."
  (cd "$ROOT_DIR" && cargo build -p p2wlan-daemon)
fi

if [[ ! -x "$DAEMON_BIN" ]]; then
  echo "Missing executable daemon: $DAEMON_BIN" >&2
  echo "Run without --skip-daemon-build to create it." >&2
  exit 1
fi

CURRENT_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)"
BUILD_INFO="$("$DAEMON_BIN" --build-info)"
if ! grep -Fq "\"git_commit\": \"$CURRENT_COMMIT\"" <<< "$BUILD_INFO"; then
  echo "The daemon binary does not match the current checkout." >&2
  echo "Re-run without --skip-daemon-build." >&2
  exit 1
fi

echo "[run-test-app] Daemon identity matches commit ${CURRENT_COMMIT:0:12}."
if [[ "$AUTO_START" -eq 1 ]]; then
  echo "[run-test-app] Automatic daemon start enabled. macOS may request administrator authorization."
else
  echo "[run-test-app] Automatic daemon start disabled; launching UI shell only."
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  printf '[run-test-app] cd %q\n' "$FLUTTER_DIR"
  printf '[run-test-app] P2WLAN_DAEMON_BIN=%q P2WLAN_AUTO_START_DAEMON=%q flutter run -d macos' \
    "$DAEMON_BIN" "$AUTO_START"
  if [[ "${#FLUTTER_ARGS[@]}" -gt 0 ]]; then
    printf ' %q' "${FLUTTER_ARGS[@]}"
  fi
  printf '\n'
  exit 0
fi

cd "$FLUTTER_DIR"
export P2WLAN_DAEMON_BIN="$DAEMON_BIN"
export P2WLAN_AUTO_START_DAEMON="$AUTO_START"
exec flutter run -d macos "${FLUTTER_ARGS[@]}"
