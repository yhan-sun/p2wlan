#!/usr/bin/env bash
set -euo pipefail
HELPER="${1:?usage: test_hermetic_build.sh <repo-root>/scripts/release/hermetic_build.sh}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
git init -q
git config user.email t@t; git config user.name t
mkdir -p apps/flutter_client/macos/Runner.xcodeproj
echo v1 > apps/flutter_client/pubspec.lock
echo analysis > apps/flutter_client/analysis_options.yaml
echo meta > apps/flutter_client/.metadata
echo podfile-v1 > apps/flutter_client/macos/Podfile
echo podlock-v1 > apps/flutter_client/macos/Podfile.lock
echo pbx-v1 > apps/flutter_client/macos/Runner.xcodeproj/project.pbxproj
git add -A && git commit -qm init

"$HELPER" check >/dev/null && echo "check-clean-PASS"

printf 'v2\n' > apps/flutter_client/pubspec.lock
if "$HELPER" check >/dev/null 2>&1; then echo "ERROR: dirty check should fail"; exit 1; fi
echo "check-dirty-FAILS-PASS"

"$HELPER" restore >/dev/null
[ "$(cat apps/flutter_client/pubspec.lock)" = "v1" ] || { echo "ERROR: restore failed"; exit 1; }
"$HELPER" check >/dev/null && echo "restore-AND-check-clean-PASS"

printf 'podfile-v2\n' > apps/flutter_client/macos/Podfile
printf 'podlock-v2\n' > apps/flutter_client/macos/Podfile.lock
printf 'pbx-v2\n' > apps/flutter_client/macos/Runner.xcodeproj/project.pbxproj
"$HELPER" restore --macos >/dev/null
[ "$(cat apps/flutter_client/macos/Podfile)" = "podfile-v1" ] || { echo "ERROR: macOS Podfile restore failed"; exit 1; }
[ "$(cat apps/flutter_client/macos/Podfile.lock)" = "podlock-v1" ] || { echo "ERROR: macOS Podfile.lock restore failed"; exit 1; }
[ "$(cat apps/flutter_client/macos/Runner.xcodeproj/project.pbxproj)" = "pbx-v1" ] || { echo "ERROR: macOS project restore failed"; exit 1; }
"$HELPER" check >/dev/null && echo "macos-restore-AND-check-clean-PASS"

touch scratch.json
"$HELPER" check >/dev/null
if "$HELPER" check --release >/dev/null 2>&1; then echo "ERROR: release check should fail on untracked"; exit 1; fi
echo "release-untracked-gate-PASS"

echo "ALL HERMETIC TESTS PASS"
