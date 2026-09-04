#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ANDROID_DIR="$ROOT_DIR/apps/flutter_client/android"
XML_ROOT="$ANDROID_DIR/../build/app/test-results"
MANIFEST="$ROOT_DIR/scripts/mobile_lifecycle/manifests/android_jvm.json"
ARTIFACT_DIR=${P2WLAN_MOBILE_LIFECYCLE_ARTIFACT_DIR:-"${RUNNER_TEMP:-/tmp}/p2wlan-mobile-lifecycle-android"}
RECORDS="$ARTIFACT_DIR/android-execution-records.json"
mkdir -p "$ARTIFACT_DIR"

write_empty_records() {
  python3 - "$RECORDS" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({"schema_version": 1, "records": []}) + "\n", encoding="utf-8")
PY
}

cd "$ANDROID_DIR"
if [[ -x ./gradlew ]]; then
  command=(./gradlew --no-daemon :app:testDebugUnitTest)
elif command -v gradle >/dev/null 2>&1; then
  command=(gradle --no-daemon :app:testDebugUnitTest)
else
  echo "Android JVM lifecycle tests require ./gradlew or gradle on PATH" >&2
  write_empty_records
  exit 127
fi

printf 'running Android JVM task:'
printf ' %q' "${command[@]}"
printf '\n'

set +e
"${command[@]}"
test_status=$?
set -e

set +e
python3 - "$XML_ROOT" "$ARTIFACT_DIR/android-jvm-test-summary.json" "$test_status" <<'PY'
import json
import pathlib
import sys
import xml.etree.ElementTree as ET

xml_root = pathlib.Path(sys.argv[1])
summary_path = pathlib.Path(sys.argv[2])
command_status = int(sys.argv[3])
test_count = 0
failures = 0
errors = 0
skipped = 0
files = []

if xml_root.is_dir():
    for path in sorted(xml_root.rglob("TEST-*.xml")):
        files.append(path.as_posix())
        try:
            root = ET.parse(path).getroot()
        except (OSError, ET.ParseError):
            continue

        def number(name: str) -> int:
            try:
                return int(root.attrib.get(name, "0"))
            except ValueError:
                return 0

        test_count += number("tests")
        failures += number("failures")
        errors += number("errors")
        skipped += number("skipped")

summary = {
    "task": ":app:testDebugUnitTest",
    "command_status": command_status,
    "test_count": test_count,
    "failures": failures,
    "errors": errors,
    "skipped": skipped,
    "xml_files": files,
}
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if command_status == 0 and (test_count == 0 or failures or errors or skipped):
    raise SystemExit("Android JVM task did not produce a non-skipped, passing test set")
PY
summary_status=$?
set -e

records_status=1
if [[ "$test_status" -eq 0 && -d "$XML_ROOT" ]]; then
  set +e
  python3 "$ROOT_DIR/scripts/mobile_lifecycle/android_junit_records.py" \
    --xml-root "$XML_ROOT" \
    --manifest "$MANIFEST" \
    --output "$RECORDS"
  records_status=$?
  set -e
fi
if [[ "$records_status" -ne 0 ]]; then
  write_empty_records
fi

if [[ "$test_status" -ne 0 ]]; then
  exit "$test_status"
fi
if [[ "$summary_status" -ne 0 ]]; then
  exit 1
fi
exit "$records_status"
