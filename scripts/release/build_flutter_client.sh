#!/usr/bin/env bash
set -euo pipefail

# Build Flutter through the identity stamper so the client and daemon can be
# compared at Windows startup.  Usage: build_flutter_client.sh windows --release
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mapfile -t DEFINES < <(python3 "$ROOT_DIR/scripts/release/flutter_client_build_identity.py" "$@")
cd "$ROOT_DIR/apps/flutter_client"
exec flutter build "$@" "${DEFINES[@]}"
