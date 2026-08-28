#!/usr/bin/env bash
# Stable CI entry point for the deterministic NAT simulator.
#
# The simulator and acceptance logic live in nat-sim-smoke.sh.  This wrapper
# deliberately keeps the required PR profiles conservative and reproducible:
# one cold-start round, deterministic seeds, no injected loss/reordering, and
# bounded but generous convergence windows.  More aggressive fault profiles
# remain available through the smoke harness and scheduled/manual runs.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SMOKE="$ROOT_DIR/scripts/nat-sim/nat-sim-smoke.sh"
PROFILE=${1:-unit}
RUN_ID=${GITHUB_RUN_ID:-local-$$}
RUN_ATTEMPT=${GITHUB_RUN_ATTEMPT:-1}
ARTIFACT_PARENT=${NAT_TOPOLOGY_ARTIFACT_ROOT:-${RUNNER_TEMP:-/tmp}}
ARTIFACT_DIR="$ARTIFACT_PARENT/p2wlan-nat-topology-${RUN_ID}-${RUN_ATTEMPT}-${PROFILE}"
LOG_FILE="${ARTIFACT_DIR}.log"
RUN_NAME="nat-ci-${PROFILE}-${RUN_ID}-${RUN_ATTEMPT}"

mkdir -p "$ARTIFACT_PARENT"
if [[ -e "$ARTIFACT_DIR" || -e "$LOG_FILE" ]]; then
  echo "[nat-ci] refusing to reuse artifact path: $ARTIFACT_DIR" >&2
  exit 2
fi

run_smoke() {
  local expected=$1
  shift
  local status

  set +e
  timeout --signal=TERM --kill-after=30s 20m \
    env \
      NETWORK_ID=default \
      ROUNDS=1 \
      NAT_SEED_BASE=20260828 \
      NAT_SIM_RUN_ID="$RUN_NAME" \
      NAT_SIM_ARTIFACT_DIR="$ARTIFACT_DIR" \
      NAT_SIM_RUST_LOG=info \
      "$@" \
      bash "$SMOKE" 2>&1 | tee "$LOG_FILE"
  status=${PIPESTATUS[0]}
  set -e

  if [[ "$expected" == success ]]; then
    if [[ "$status" -ne 0 ]]; then
      echo "[nat-ci] profile=$PROFILE failed status=$status log=$LOG_FILE artifacts=$ARTIFACT_DIR" >&2
      return "$status"
    fi
    echo "[nat-ci] profile=$PROFILE PASS log=$LOG_FILE artifacts=$ARTIFACT_DIR"
    return 0
  fi

  if [[ "$status" -eq 0 ]]; then
    echo "[nat-ci] profile=$PROFILE unexpectedly succeeded" >&2
    return 1
  fi
  if ! grep -Eq 'reason_code=status_(http_500_injected|unavailable|schema_invalid)' "$LOG_FILE"; then
    echo "[nat-ci] profile=$PROFILE failed without the expected fail-closed reason" >&2
    return 1
  fi
  echo "[nat-ci] profile=$PROFILE PASS expected_failure_status=$status"
}

case "$PROFILE" in
  unit)
    bash -n "$SMOKE"
    python3 -m unittest discover \
      -s "$ROOT_DIR/scripts/nat-sim" \
      -p 'test_nat_sim.py' \
      -v 2>&1 | tee "$LOG_FILE"
    ;;
  direct)
    run_smoke success \
      MODE=direct \
      STEP_A=1 STEP_B=1 \
      CONSUME_A=0 CONSUME_B=0 \
      LOSS=0 REORDER=0 STRICT_FILTERING=0 \
      DIRECT_TIMEOUT_S=90 \
      OVERLAY_TIMEOUT_S=60 \
      OVERLAY_BURST=32
    ;;
  relay)
    run_smoke success \
      MODE=relay-only \
      STEP_A=1 STEP_B=1 \
      CONSUME_A=0 CONSUME_B=0 \
      LOSS=0 REORDER=0 STRICT_FILTERING=0 \
      DIRECT_TIMEOUT_S=60 \
      OVERLAY_TIMEOUT_S=90 \
      OVERLAY_BURST=64 \
      RELAY_COUNT=1
    ;;
  fail-closed)
    run_smoke failure \
      MODE=relay-only \
      STEP_A=1 STEP_B=1 \
      CONSUME_A=0 CONSUME_B=0 \
      LOSS=0 REORDER=0 STRICT_FILTERING=0 \
      DIRECT_TIMEOUT_S=60 \
      OVERLAY_TIMEOUT_S=90 \
      OVERLAY_BURST=16 \
      RELAY_COUNT=1 \
      STATUS_FAILURE_INJECTION=1
    ;;
  *)
    echo "usage: $0 {unit|direct|relay|fail-closed}" >&2
    exit 2
    ;;
esac
