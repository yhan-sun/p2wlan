#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
APP_DIR="$ROOT_DIR/apps/flutter_client"
ROUNDS=${P2WLAN_MOBILE_LIFECYCLE_ROUNDS:-3}
ARTIFACT_DIR=${P2WLAN_MOBILE_LIFECYCLE_ARTIFACT_DIR:-"${RUNNER_TEMP:-/tmp}/p2wlan-mobile-lifecycle-flutter"}
SOURCE_HEAD_SHA=${P2WLAN_EXACT_HEAD:-$(git -C "$ROOT_DIR" rev-parse HEAD)}
WORKFLOW_SHA=${P2WLAN_WORKFLOW_SHA:-$SOURCE_HEAD_SHA}
EVIDENCE_TEST="test/mobile_lifecycle_evidence_test.dart"
EVIDENCE_RECORDS="$ARTIFACT_DIR/execution-records.json"

mkdir -p "$ARTIFACT_DIR"

if ! [[ "$ROUNDS" =~ ^[1-9][0-9]*$ ]]; then
  echo "P2WLAN_MOBILE_LIFECYCLE_ROUNDS must be a positive integer" \
    | tee "$ARTIFACT_DIR/configuration-error.log" >&2
  exit 2
fi
if ! [[ "$SOURCE_HEAD_SHA" =~ ^[0-9a-f]{40}$ && "$WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "P2WLAN_EXACT_HEAD and P2WLAN_WORKFLOW_SHA must be 40-character SHA values" >&2
  exit 2
fi
if [[ "$(git -C "$ROOT_DIR" rev-parse HEAD)" != "$SOURCE_HEAD_SHA" ]]; then
  echo "the checked out source does not match P2WLAN_EXACT_HEAD" >&2
  exit 2
fi

# These suites contain the authoritative Flutter generation fence, process
# replacement, Android transport boundary, platform contract and the
# canonical lifecycle vocabulary. They run on every required PR invocation;
# device-only experiments are documented separately and never enter this gate.
TESTS=(
  test/status_store_test.dart
  test/platform_capabilities_test.dart
  test/diagnostics_api_test.dart
  test/contract_test.dart
  test/mobile_lifecycle_coordinator_test.dart
)

printf '%s\n' "${TESTS[@]}" > "$ARTIFACT_DIR/test-manifest.txt"
overall_status=0
missing=0
for test_file in "${TESTS[@]}" "$EVIDENCE_TEST"; do
  if [[ ! -f "$APP_DIR/$test_file" ]]; then
    echo "required mobile lifecycle regression is missing: $test_file" \
      | tee -a "$ARTIFACT_DIR/missing-tests.log" >&2
    missing=1
  fi
done

if [[ "$missing" -ne 0 ]]; then
  overall_status=1
else
  cd "$APP_DIR"
  for round in $(seq 1 "$ROUNDS"); do
    log="$ARTIFACT_DIR/round-${round}.log"
    echo "mobile lifecycle regression round $round/$ROUNDS" | tee "$log"
    set +e
    flutter test \
      --concurrency=1 \
      --reporter=expanded \
      "${TESTS[@]}" 2>&1 | tee -a "$log"
    pipeline_status=("${PIPESTATUS[@]}")
    test_status=${pipeline_status[0]}
    tee_status=${pipeline_status[1]}
    set -e
    if [[ "$test_status" -ne 0 || "$tee_status" -ne 0 ]]; then
      overall_status=1
    fi
  done
fi

# This is the only Flutter evidence run. The component report is built from
# its machine output and per-test records, never from the status of the larger
# suite or from a manifest-wide result fan-out.
evidence_status=1
if [[ "$missing" -eq 0 ]]; then
  cd "$APP_DIR"
  set +e
  flutter test --concurrency=1 --machine "$EVIDENCE_TEST" \
    > "$ARTIFACT_DIR/flutter-machine.json" \
    2> "$ARTIFACT_DIR/flutter-machine.stderr"
  evidence_status=$?
  set -e
fi

records_status=1
if [[ "$evidence_status" -eq 0 ]]; then
  set +e
  python3 "$ROOT_DIR/scripts/mobile_lifecycle/flutter_machine_records.py" \
    --machine-output "$ARTIFACT_DIR/flutter-machine.json" \
    --manifest "$ROOT_DIR/scripts/mobile_lifecycle/manifests/flutter.json" \
    --output "$EVIDENCE_RECORDS"
  records_status=$?
  set -e
fi
if [[ "$records_status" -ne 0 ]]; then
  # Preserve the actual failure as an empty record set. component_report then
  # fails closed on missing execution evidence and still writes an artifact.
  python3 - "$EVIDENCE_RECORDS" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({"schema_version": 1, "records": []}) + "\n", encoding="utf-8")
PY
  overall_status=1
fi
if [[ "$evidence_status" -ne 0 ]]; then
  overall_status=1
fi

toolchain=$(python3 - "$ROUNDS" "${#TESTS[@]}" "$overall_status" "$evidence_status" "$records_status" <<'PY'
import json
import sys

print(json.dumps({
    "runner": "flutter",
    "command": "flutter test --concurrency=1 --reporter=expanded",
    "evidence_command": "flutter test --concurrency=1 --machine test/mobile_lifecycle_evidence_test.dart",
    "evidence_parser": "scripts/mobile_lifecycle/flutter_machine_records.py",
    "rounds": int(sys.argv[1]),
    "test_file_count": int(sys.argv[2]),
    "exit_status": int(sys.argv[3]),
    "evidence_exit_status": int(sys.argv[4]),
    "record_parser_exit_status": int(sys.argv[5]),
}, separators=(",", ":")))
PY
)

set +e
python3 "$ROOT_DIR/scripts/mobile_lifecycle/component_report.py" \
  --root "$ROOT_DIR" \
  --component flutter \
  --manifest "$ROOT_DIR/scripts/mobile_lifecycle/manifests/flutter.json" \
  --source-head-sha "$SOURCE_HEAD_SHA" \
  --workflow-sha "$WORKFLOW_SHA" \
  --execution-records "$EVIDENCE_RECORDS" \
  --toolchain "$toolchain" \
  --output "$ARTIFACT_DIR/flutter.json"
report_status=$?
set -e
if [[ "$report_status" -ne 0 ]]; then
  overall_status=1
fi

python3 - "$ARTIFACT_DIR/summary.json" "$ROUNDS" "${#TESTS[@]}" "$overall_status" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "schema_version": 2,
    "component": "flutter",
    "rounds": int(sys.argv[2]),
    "test_file_count": int(sys.argv[3]),
    "result": "pass" if int(sys.argv[4]) == 0 else "fail",
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

exit "$overall_status"
