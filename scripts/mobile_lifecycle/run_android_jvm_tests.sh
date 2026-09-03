#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ANDROID_DIR="$ROOT_DIR/apps/flutter_client/android"
ARTIFACT_DIR=${P2WLAN_MOBILE_LIFECYCLE_ARTIFACT_DIR:-"${RUNNER_TEMP:-/tmp}/p2wlan-mobile-lifecycle-android"}
mkdir -p "$ARTIFACT_DIR"

cd "$ANDROID_DIR"
if [[ -x ./gradlew ]]; then
  command=(./gradlew --no-daemon :app:testDebugUnitTest)
elif command -v gradle >/dev/null 2>&1; then
  command=(gradle --no-daemon :app:testDebugUnitTest)
else
  echo "Android JVM lifecycle tests require ./gradlew or gradle on PATH" >&2
  exit 127
fi

printf 'running Android JVM task:'
printf ' %q' "${command[@]}"
printf '\n'

set +e
"${command[@]}"
test_status=$?
set -e

python3 - "$ANDROID_DIR/../build/app/test-results" "$ARTIFACT_DIR/android-jvm-test-summary.json" "$test_status" <<'PY'
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

exit "$test_status"
