#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
APP_DIR="$ROOT_DIR/apps/flutter_client"
ROUNDS=${P2WLAN_MOBILE_LIFECYCLE_ROUNDS:-3}
ARTIFACT_DIR=${P2WLAN_MOBILE_LIFECYCLE_ARTIFACT_DIR:-"${RUNNER_TEMP:-/tmp}/p2wlan-mobile-lifecycle"}

mkdir -p "$ARTIFACT_DIR"

if ! [[ "$ROUNDS" =~ ^[1-9][0-9]*$ ]]; then
  echo "P2WLAN_MOBILE_LIFECYCLE_ROUNDS must be a positive integer" | tee "$ARTIFACT_DIR/configuration-error.log" >&2
  exit 2
fi

# These checked-in suites contain the authoritative lifecycle generation fence,
# diagnostics process-replacement, platform capability and client API contracts.
# Keeping the list limited to files that exist in the repository makes the gate
# self-contained rather than depending on uncommitted device-lab experiments.
TESTS=(
  test/status_store_test.dart
  test/platform_capabilities_test.dart
  test/diagnostics_api_test.dart
  test/contract_test.dart
)

printf '%s\n' "${TESTS[@]}" > "$ARTIFACT_DIR/test-manifest.txt"
missing=0
for test_file in "${TESTS[@]}"; do
  if [[ ! -f "$APP_DIR/$test_file" ]]; then
    echo "required mobile lifecycle regression is missing: $test_file" | tee -a "$ARTIFACT_DIR/missing-tests.log" >&2
    missing=1
  fi
done
if [[ "$missing" -ne 0 ]]; then
  cat > "$ARTIFACT_DIR/summary.json" <<EOF
{
  "schema_version": 1,
  "rounds": 0,
  "test_count": ${#TESTS[@]},
  "result": "missing_test"
}
EOF
  exit 1
fi

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
