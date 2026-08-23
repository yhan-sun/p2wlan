#!/usr/bin/env bash
# Hermetic-build helper for the release pipeline (audit §20 / ENG-1).
#
# Flutter `pub get` / `flutter build` re-resolves SDK-pinned transitive files
# (apps/flutter_client/pubspec.lock, analysis_options.yaml, .metadata and, on
# macOS, the CocoaPods/Xcode project files), stamping the source checkout dirty
# AFTER each release build.  The release workflow historically compensated
# with repeated `git checkout --` blocks (9 sites).  This helper centralizes
# that compensation and — more usefully — lets a job assert the invariant the
# whole exercise is protecting: the source workspace is NOT dirty after the
# build.  Long-term this should be replaced by building in a clean per-target
# worktree; until then, one helper beats nine duplicate blocks.
#
# Usage:
#   hermetic_build.sh restore [--macos]   # revert Flutter-managed files
#   hermetic_build.sh check [--release]   # fail if source workspace is dirty
#
# `check --release` is the strict gate: a release must not leave the checkout
# dirty (a non-dirty tree proves the build did not mutate sources).  Without
# --release, `check` tolerates untracked files (dev scratch) but still fails on
# tracked modifications.
set -euo pipefail

# Operate on the git worktree the caller is in (the build workspace), not the
# script's own location: the validation/restore must observe the SAME checkout
# the release build just touched.  Override with P2WLAN_ROOT_DIR for tooling
# that runs in a detached build worktree.
ROOT=${P2WLAN_ROOT_DIR:-$PWD}
[ -d "$ROOT/.git" ] || [ -f "$ROOT/.git" ] || {
  echo "not a git worktree: $ROOT (set P2WLAN_ROOT_DIR)" >&2
  exit 2
}

FLUTTER_MANAGED=(
  "apps/flutter_client/pubspec.lock"
  "apps/flutter_client/analysis_options.yaml"
  "apps/flutter_client/.metadata"
  "apps/flutter_client/linux/flutter/generated_plugin_registrant.cc"
  "apps/flutter_client/linux/flutter/generated_plugin_registrant.h"
  "apps/flutter_client/linux/flutter/generated_plugins.cmake"
  "apps/flutter_client/macos/Flutter/GeneratedPluginRegistrant.swift"
  "apps/flutter_client/windows/flutter/generated_plugin_registrant.cc"
  "apps/flutter_client/windows/flutter/generated_plugin_registrant.h"
  "apps/flutter_client/windows/flutter/generated_plugins.cmake"
)

do_restore() {
  local macos=0
  local arg
  for arg in "$@"; do
    case "$arg" in
      --macos) macos=1 ;;
      *) echo "restore: unknown argument: $arg" >&2; exit 2 ;;
    esac
  done
  cd "$ROOT"
  local files=()
  for f in "${FLUTTER_MANAGED[@]}"; do
    if [ -e "$f" ]; then
      files+=("$f")
    fi
  done
  if [ "$macos" -eq 1 ]; then
    # `flutter build macos` may run pod install and update both the Podfile
    # inputs and the generated lockfile in addition to the Xcode project.
    # Restore every tracked macOS integration file that Flutter/CocoaPods can
    # migrate so the release identity gate sees the original checkout.
    local macos_file
    for macos_file in \
      "apps/flutter_client/macos/Podfile" \
      "apps/flutter_client/macos/Podfile.lock" \
      "apps/flutter_client/macos/Runner.xcodeproj/project.pbxproj"; do
      if [ -e "$macos_file" ]; then
        files+=("$macos_file")
      fi
    done
  fi
  if [ "${#files[@]}" -gt 0 ]; then
    git checkout -- "${files[@]}"
    echo "restored: ${files[*]}"
  else
    echo "restore: nothing to restore"
  fi
}

do_check() {
  local release=0
  local arg
  for arg in "$@"; do
    case "$arg" in
      --release) release=1 ;;
      *) echo "check: unknown argument: $arg" >&2; exit 2 ;;
    esac
  done
  cd "$ROOT"
  # Tracked modifications are always a failure: the build mutated sources.
  local tracked
  tracked=$(git status --porcelain=v1 --untracked-files=no)
  if [ -n "$tracked" ]; then
    echo "hermetic check FAIL: tracked files dirty after build:" >&2
    echo "$tracked" >&2
    exit 1
  fi
  # A release additionally forbids untracked scratch files in the workspace.
  if [ "$release" -eq 1 ]; then
    local untracked
    untracked=$(git status --porcelain=v1 --untracked-files=all)
    if [ -n "$untracked" ]; then
      echo "hermetic check FAIL(--release): untracked files present:" >&2
      echo "$untracked" >&2
      exit 1
    fi
  fi
  echo "hermetic check: source workspace clean"
}

cmd="${1:-}"
case "$cmd" in
  restore) shift; do_restore "$@" ;;
  check) shift; do_check "$@" ;;
  ""|help|-h|--help)
    sed -n '1,30p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    echo "unknown command: $cmd (want restore|check)" >&2
    exit 2
    ;;
esac
