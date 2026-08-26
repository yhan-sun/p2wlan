#!/usr/bin/env bash
set -euo pipefail

# Build Flutter through the identity stamper so the client and daemon can be
# compared at Windows startup.  Usage: build_flutter_client.sh windows --release
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEFINES=()
while IFS= read -r define; do
  DEFINES+=("$define")
done < <(python3 "$ROOT_DIR/scripts/release/flutter_client_build_identity.py" "$@")

# Freeze the identity before Flutter can migrate SDK-managed files.  The
# snapshot lives under Cargo's ignored target directory so Gradle can read it
# even when it reuses a daemon whose environment predates this invocation.
source_commit=""
source_build_id=""
source_dirty=""
source_diff_hash=""
source_diff_hash_seen=0
for define in "${DEFINES[@]}"; do
  key_value="${define#--dart-define=}"
  key="${key_value%%=*}"
  value="${key_value#*=}"
  case "$key" in
    P2WLAN_CLIENT_GIT_COMMIT) source_commit="$value" ;;
    P2WLAN_CLIENT_BUILD_ID) source_build_id="$value" ;;
    P2WLAN_CLIENT_DIRTY) source_dirty="$value" ;;
    P2WLAN_CLIENT_DIFF_HASH)
      source_diff_hash="$value"
      source_diff_hash_seen=1
      ;;
  esac
done
if [[ -z "$source_commit" || -z "$source_build_id" || -z "$source_dirty" || "$source_diff_hash_seen" -ne 1 ]]; then
  echo "identity helper did not emit the complete source identity" >&2
  exit 1
fi

source_identity_file="$ROOT_DIR/target/p2wlan-source-identity.env"
mkdir -p "$(dirname "$source_identity_file")"
rm -f -- "$source_identity_file"
umask 077
{
  printf 'P2WLAN_SOURCE_GIT_COMMIT=%s\n' "$source_commit"
  printf 'P2WLAN_SOURCE_BUILD_ID=%s\n' "$source_build_id"
  printf 'P2WLAN_SOURCE_DIRTY=%s\n' "$source_dirty"
  printf 'P2WLAN_SOURCE_DIFF_HASH=%s\n' "$source_diff_hash"
} > "$source_identity_file"
cleanup() {
  rm -f -- "$source_identity_file"
}
trap cleanup EXIT

cd "$ROOT_DIR/apps/flutter_client"
flutter build "$@" "${DEFINES[@]}"
