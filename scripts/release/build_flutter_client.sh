#!/usr/bin/env bash
set -euo pipefail

# Build Flutter through the identity stamper so the client and daemon can be
# compared at Windows startup.  Usage: build_flutter_client.sh windows --release
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Do not use process substitution here.  Bash reports the status of the
# while-loop, not the process substitution, so a helper that prints partial
# output and then fails could otherwise be mistaken for a successful stamp.
if ! identity_output="$(python3 "$ROOT_DIR/scripts/release/flutter_client_build_identity.py" "$@")"; then
  echo "Flutter client identity helper failed" >&2
  exit 1
fi

DEFINES=()
while IFS= read -r define; do
  # Python on Windows may write CRLF to stdout; normalize the record before
  # validating fields so the same wrapper works under Git Bash and POSIX bash.
  define="${define%$'\r'}"
  DEFINES+=("$define")
done <<< "$identity_output"

# Freeze the identity before Flutter can migrate SDK-managed files.  The
# snapshot lives under Cargo's ignored target directory so Gradle can read it
# even when it reuses a daemon whose environment predates this invocation.
source_commit=""
source_build_id=""
source_dirty=""
source_diff_hash=""
source_commit_seen=0
source_build_id_seen=0
source_dirty_seen=0
source_diff_hash_seen=0
for define in "${DEFINES[@]}"; do
  if [[ "$define" != --dart-define=* ]]; then
    echo "identity helper emitted malformed output: $define" >&2
    exit 1
  fi
  key_value="${define#--dart-define=}"
  if [[ "$key_value" != *=* ]]; then
    echo "identity helper emitted malformed define: $define" >&2
    exit 1
  fi
  key="${key_value%%=*}"
  value="${key_value#*=}"
  case "$key" in
    P2WLAN_CLIENT_APP_VERSION|P2WLAN_CLIENT_PROFILE) ;;
    P2WLAN_CLIENT_GIT_COMMIT)
      if [[ "$source_commit_seen" -ne 0 ]]; then
        echo "identity helper emitted duplicate P2WLAN_CLIENT_GIT_COMMIT" >&2
        exit 1
      fi
      source_commit="$value"
      source_commit_seen=1
      ;;
    P2WLAN_CLIENT_BUILD_ID)
      if [[ "$source_build_id_seen" -ne 0 ]]; then
        echo "identity helper emitted duplicate P2WLAN_CLIENT_BUILD_ID" >&2
        exit 1
      fi
      source_build_id="$value"
      source_build_id_seen=1
      ;;
    P2WLAN_CLIENT_DIRTY)
      if [[ "$source_dirty_seen" -ne 0 ]]; then
        echo "identity helper emitted duplicate P2WLAN_CLIENT_DIRTY" >&2
        exit 1
      fi
      source_dirty="$value"
      source_dirty_seen=1
      ;;
    P2WLAN_CLIENT_DIFF_HASH)
      if [[ "$source_diff_hash_seen" -ne 0 ]]; then
        echo "identity helper emitted duplicate P2WLAN_CLIENT_DIFF_HASH" >&2
        exit 1
      fi
      source_diff_hash="$value"
      source_diff_hash_seen=1
      ;;
    *)
      echo "identity helper emitted unexpected define: $define" >&2
      exit 1
      ;;
  esac
done
if [[ "$source_commit_seen" -ne 1 || "$source_build_id_seen" -ne 1 || \
  "$source_dirty_seen" -ne 1 || "$source_diff_hash_seen" -ne 1 ]]; then
  echo "identity helper did not emit the complete source identity" >&2
  exit 1
fi
if [[ ! "$source_commit" =~ ^[0-9a-fA-F]{40}$ || "$source_dirty" != true && "$source_dirty" != false ]]; then
  echo "identity helper emitted invalid source identity fields" >&2
  exit 1
fi
if [[ "$source_dirty" == true && ! "$source_diff_hash" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "identity helper emitted an invalid dirty diff hash" >&2
  exit 1
fi
if [[ "$source_dirty" == false && -n "$source_diff_hash" ]]; then
  echo "identity helper emitted a clean identity with a diff hash" >&2
  exit 1
fi
expected_build_id="${source_commit:0:12}"
if [[ "$source_dirty" == true ]]; then
  expected_build_id="${source_commit:0:12}-dirty-${source_diff_hash:0:12}"
fi
if [[ "$source_build_id" != "$expected_build_id" ]]; then
  echo "identity helper emitted an inconsistent build ID" >&2
  exit 1
fi

umask 077
source_identity_dir=""
source_identity_file=""
cleanup() {
  if [[ -n "$source_identity_file" ]]; then
    rm -f -- "$source_identity_file"
  fi
  if [[ -n "$source_identity_dir" ]]; then
    rmdir "$source_identity_dir" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

mkdir -p "$ROOT_DIR/target"
source_identity_dir="$(mktemp -d "$ROOT_DIR/target/p2wlan-source-identity.XXXXXXXX")"
source_identity_file="$source_identity_dir/source.env"
identity_nonce="$(od -An -N16 -tx1 /dev/urandom | tr -d '[:space:]')"
if [[ ! "$identity_nonce" =~ ^[0-9a-f]{32}$ ]]; then
  echo "failed to generate a valid source identity nonce" >&2
  exit 1
fi
{
  printf 'P2WLAN_SOURCE_GIT_COMMIT=%s\n' "$source_commit"
  printf 'P2WLAN_SOURCE_BUILD_ID=%s\n' "$source_build_id"
  printf 'P2WLAN_SOURCE_DIRTY=%s\n' "$source_dirty"
  printf 'P2WLAN_SOURCE_DIFF_HASH=%s\n' "$source_diff_hash"
  printf 'P2WLAN_SOURCE_IDENTITY_NONCE=%s\n' "$identity_nonce"
} > "$source_identity_file"
chmod 600 "$source_identity_file"

# Gradle project properties are carried with each build request, including
# requests handled by an already-running daemon.  The wrapper never exposes a
# default path: a direct Gradle/Flutter build has no identity snapshot.
export ORG_GRADLE_PROJECT_p2wlanSourceIdentityFile="$source_identity_file"
export ORG_GRADLE_PROJECT_p2wlanSourceIdentityNonce="$identity_nonce"

cd "$ROOT_DIR/apps/flutter_client"
if [[ "${1:-}" == windows ]]; then
  # tray_manager 0.5.3 has two Windows native crash paths: an uninitialized
  # HICON on the first setIcon call and an absent separator label in menu
  # construction. Patch the exact resolved pub-cache source before compiling
  # the packaged Windows client; the patch script refuses unknown source.
  python3 "$ROOT_DIR/scripts/release/patch_tray_manager_windows.py" "$PWD"
fi
flutter build "$@" "${DEFINES[@]}"
