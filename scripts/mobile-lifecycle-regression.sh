#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
APP_DIR="$ROOT_DIR/apps/flutter_client"
ROUNDS=${P2WLAN_MOBILE_LIFECYCLE_ROUNDS:-3}
ARTIFACT_DIR=${P2WLAN_MOBILE_LIFECYCLE_ARTIFACT_DIR:-"${RUNNER_TEMP:-/tmp}/p2wlan-mobile-lifecycle"}

if ! [[ "$ROUNDS" =~ ^[1-9][0-9]*$ ]]; then
  echo "P2WLAN_MOBILE_LIFECYCLE_ROUNDS must be a positive integer" >&2
  exit 2
fi

TESTS=(
  test/mobile_lifecycle_contract_test.dart
  test/mobile_daemon_client_test.dart
  test/android_runtime_contract_test.dart
  test/android_network_handoff_test.dart
  test/android_network_refresh_test.dart
  test/android_background_heartbeat_test.dart
  test/android_connectivity_lock_test.dart
  test/android_active_path_contract_test.dart
  test/android_overlay_tail_latency_test.dart
)

for test_file in "${TESTS[@]}"; do
  if [[ ! -f "$APP_DIR/$test_file" ]]; then
    echo "required mobile lifecycle regression is missing: $test_file" >&2
    exit 1
  fi
done

mkdir -p "$ARTIFACT_DIR"
printf '%s\n' "${TESTS[@]}" > "$ARTIFACT_DIR/test-manifest.txt"

cd "$APP_DIR"
for round in $(seq 1 "$ROUNDS"); do
  log="$ARTIFACT_DIR/round-${round}.log"
  echo "mobile lifecycle regression round $round/$ROUNDS" | tee "$log"
  flutter test \
    --concurrency=1 \
    --reporter=expanded \
    "${TESTS[@]}" 2>&1 | tee -a "$log"
done

cat > "$ARTIFACT_DIR/summary.json" <<EOF
{
  "schema_version": 1,
  "rounds": $ROUNDS,
  "test_count": ${#TESTS[@]},
  "result": "pass"
}
EOF
