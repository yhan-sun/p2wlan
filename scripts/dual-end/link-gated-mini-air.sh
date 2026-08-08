#!/usr/bin/env bash
# Run the Mini-Air cold-start harness only when the lab link is healthy.
#
# Polls scripts/dual-end/link-health-check.sh; on HEALTHY it launches one
# mini-air-smoke.sh run (ROUNDS rounds).  Degraded checks are logged and the
# poll continues until MAX_ATTEMPTS, then exits 1 with the last evidence path.
#
# Env:
#   LINK_INTERVAL_S   seconds between health checks (default 300)
#   MAX_ATTEMPTS      health checks before giving up (default 120)
#   ROUNDS            rounds passed through to mini-air-smoke.sh (default 5)
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LINK_INTERVAL_S=${LINK_INTERVAL_S:-300}
MAX_ATTEMPTS=${MAX_ATTEMPTS:-120}
ROUNDS=${ROUNDS:-5}

HEALTH="$ROOT_DIR/scripts/dual-end/link-health-check.sh"
SMOKE="$ROOT_DIR/scripts/dual-end/mini-air-smoke.sh"

echo "[link-gated] watching for a healthy Mini-Air link (interval=${LINK_INTERVAL_S}s, attempts=${MAX_ATTEMPTS})"
attempt=0
while true; do
  attempt=$((attempt + 1))
  echo "[link-gated] health check ${attempt}/${MAX_ATTEMPTS} @ $(date '+%H:%M:%S')"
  set +e
  "$HEALTH"
  health_rc=$?
  set -e
  if [[ "$health_rc" -eq 0 ]]; then
    echo "[link-gated] link HEALTHY; starting Mini-Air (ROUNDS=$ROUNDS)"
    ROUNDS="$ROUNDS" "$SMOKE"
    exit 0
  fi
  if [[ "$health_rc" -eq 2 ]]; then
    echo "[link-gated] Air unreachable; aborting" >&2
    exit 2
  fi
  if [[ "$attempt" -ge "$MAX_ATTEMPTS" ]]; then
    echo "[link-gated] gave up after ${MAX_ATTEMPTS} degraded health checks" >&2
    exit 1
  fi
  echo "[link-gated] link degraded; next check in ${LINK_INTERVAL_S}s"
  sleep "$LINK_INTERVAL_S"
done
