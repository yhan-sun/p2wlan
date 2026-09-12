#!/usr/bin/env bash
# Stable CI entry point for the deterministic NAT simulator.
#
# Success profiles run with a BOUNDED retry for environment transients only:
# attempt 1 runs the full strict gate; if it fails, scripts/nat-sim/transient.py
# classifies the failure from the retained attempt log/evidence.  Only
# whitelisted transient signatures (startup readiness races, data-plane stalls
# with a fully healthy control plane) get exactly one fresh attempt, and that
# attempt must pass the same strict gate with its own genuine evidence — the
# retry can never skip a check or manufacture a pass.  Any hard signature
# (replay/invalid, schema misses, task health, daemon exit, blackhole
# violation, SLO miss) or an unrecognized failure fails the job immediately.
# Attempt-1 evidence is retained under the uploaded artifact (its
# nat-evidence.json is renamed to *.attempt-N-failed.json so the aggregator
# only ever consumes the passing attempt's record).
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SMOKE="$ROOT_DIR/scripts/nat-sim/nat-sim-smoke.sh"
PROFILE=${1:-unit}
RUN_ID=${GITHUB_RUN_ID:-local-$$}
RUN_ATTEMPT=${GITHUB_RUN_ATTEMPT:-1}
REPLICA=${NAT_TOPOLOGY_REPLICA:-1}
EXPECTED_HEAD_SHA=${NAT_TOPOLOGY_HEAD_SHA:-}
ARTIFACT_PARENT=${NAT_TOPOLOGY_ARTIFACT_ROOT:-${RUNNER_TEMP:-/tmp}}
ARTIFACT_DIR="$ARTIFACT_PARENT/p2wlan-nat-topology-${RUN_ID}-${RUN_ATTEMPT}-${PROFILE}-${REPLICA}"
MAX_ATTEMPTS=2
# A retry is only started when this much wall clock remains; a first attempt
# that burned its whole hang-guard budget is not followed by a second one.
RETRY_BUDGET_S=${NAT_CI_RETRY_BUDGET_S:-900}
RUN_NAME="nat-ci-${PROFILE}-${RUN_ID}-${RUN_ATTEMPT}-${REPLICA}"

if ! [[ "$REPLICA" =~ ^[1-9][0-9]*$ ]]; then
  echo "[nat-ci] NAT_TOPOLOGY_REPLICA must be a positive integer" >&2
  exit 2
fi
if [[ -n "$EXPECTED_HEAD_SHA" ]]; then
  ACTUAL_HEAD_SHA=$(git -C "$ROOT_DIR" rev-parse HEAD)
  if [[ "$ACTUAL_HEAD_SHA" != "$EXPECTED_HEAD_SHA" ]]; then
    echo "[nat-ci] exact Head mismatch expected=$EXPECTED_HEAD_SHA actual=$ACTUAL_HEAD_SHA replica=$REPLICA" >&2
    exit 2
  fi
else
  ACTUAL_HEAD_SHA=$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)
fi
WORKFLOW_SHA=$(git -C "$ROOT_DIR" rev-parse "$ACTUAL_HEAD_SHA:.github/workflows/nat-topology-gate.yml")

mkdir -p "$ARTIFACT_PARENT"

TIMEOUT_BIN=$(command -v timeout || command -v gtimeout || true)
if [[ -z "$TIMEOUT_BIN" ]]; then
  # CI runners always provide GNU timeout; this fallback only covers local
  # development hosts (e.g. macOS without coreutils) and is announced loudly.
  echo "[nat-ci] WARNING: GNU timeout not found; running without the 20m hang guard (local development only)" >&2
fi

run_smoke() {
  local expected=$1 attempt_dir=$2 attempt_log=$3
  shift 3
  local status

  if [[ -e "$attempt_dir" || -e "$attempt_log" ]]; then
    echo "[nat-ci] refusing to reuse artifact path: $attempt_dir" >&2
    exit 2
  fi

  set +e
  if [[ -n "$TIMEOUT_BIN" ]]; then
    "$TIMEOUT_BIN" --signal=TERM --kill-after=30s 20m \
      env \
        NETWORK_ID=default \
        ROUNDS=1 \
        NAT_SEED_BASE=20260828 \
        NAT_SIM_RUN_ID="$RUN_NAME" \
        NAT_TOPOLOGY_HEAD_SHA="$ACTUAL_HEAD_SHA" \
        NAT_TOPOLOGY_WORKFLOW_SHA="$WORKFLOW_SHA" \
        NAT_TOPOLOGY_REPLICA="$REPLICA" \
        NAT_SIM_ARTIFACT_DIR="$attempt_dir" \
        "$@" \
        bash "$SMOKE" 2>&1 | tee "$attempt_log"
  else
    env \
      NETWORK_ID=default \
      ROUNDS=1 \
      NAT_SEED_BASE=20260828 \
      NAT_SIM_RUN_ID="$RUN_NAME" \
      NAT_TOPOLOGY_HEAD_SHA="$ACTUAL_HEAD_SHA" \
      NAT_TOPOLOGY_WORKFLOW_SHA="$WORKFLOW_SHA" \
      NAT_TOPOLOGY_REPLICA="$REPLICA" \
      NAT_SIM_ARTIFACT_DIR="$attempt_dir" \
      "$@" \
      bash "$SMOKE" 2>&1 | tee "$attempt_log"
  fi
  status=${PIPESTATUS[0]}
  set -e

  if [[ "$expected" == success ]]; then
    if [[ "$status" -ne 0 ]]; then
      echo "[nat-ci] profile=$PROFILE failed status=$status log=$attempt_log artifacts=$attempt_dir" >&2
      return "$status"
    fi
    echo "[nat-ci] profile=$PROFILE PASS log=$attempt_log artifacts=$attempt_dir"
    return 0
  fi

  if [[ "$status" -eq 0 ]]; then
    echo "[nat-ci] profile=$PROFILE unexpectedly succeeded" >&2
    return 1
  fi
  if ! grep -Eq 'reason_code=status_(http_500_injected|unavailable|schema_invalid|auth_token_missing)' "$attempt_log"; then
    echo "[nat-ci] profile=$PROFILE failed without the expected fail-closed reason" >&2
    return 1
  fi
  echo "[nat-ci] profile=$PROFILE PASS expected_failure_status=$status"
}

# Preserve a failed attempt's evidence before retrying.  The record JSON is
# renamed so aggregate_evidence.py (which walks for nat-evidence.json and
# rejects duplicate scenario records) only consumes the passing attempt,
# while every log, counter and timeline of the failed attempt stays in the
# uploaded artifact.
preserve_failed_attempt_evidence() {
  local attempt_dir=$1 attempt=$2
  local evidence
  for evidence in "$attempt_dir"/round-*/nat-evidence.json; do
    [[ -f "$evidence" ]] || continue
    mv "$evidence" "${evidence%.json}.attempt-${attempt}-failed.json"
  done
}

# Success profiles: bounded retry for whitelisted environment transients.
run_with_bounded_retry() {
  local attempt attempt_dir attempt_log rc classification
  for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
    attempt_dir="${ARTIFACT_DIR}-attempt-${attempt}"
    attempt_log="${attempt_dir}.log"
    rc=0
    run_smoke success "$attempt_dir" "$attempt_log" "$@" || rc=$?
    if [[ "$rc" -eq 0 ]]; then
      if [[ "$attempt" -gt 1 ]]; then
        echo "[nat-ci] profile=$PROFILE PASS after bounded retry attempt=${attempt}/${MAX_ATTEMPTS} (first-attempt evidence retained under ${ARTIFACT_DIR}-attempt-1)"
      fi
      return 0
    fi
    if [[ "$attempt" -ge "$MAX_ATTEMPTS" ]]; then
      return "$rc"
    fi
    if [[ "$SECONDS" -ge "$RETRY_BUDGET_S" ]]; then
      echo "[nat-ci] profile=$PROFILE retry skipped: retry budget ${RETRY_BUDGET_S}s exhausted after ${SECONDS}s" >&2
      return "$rc"
    fi
    classification=$(python3 "$ROOT_DIR/scripts/nat-sim/transient.py" classify \
      --log "$attempt_log" \
      --evidence "$attempt_dir/round-1/nat-evidence.json" \
      --attempt "$attempt" \
      --output "$attempt_dir/retry-classification.json") || true
    if ! python3 - "$attempt_dir/retry-classification.json" <<'PY'
import json, sys
sys.exit(0 if json.load(open(sys.argv[1], encoding="utf-8")).get("retryable") is True else 1)
PY
    then
      echo "[nat-ci] profile=$PROFILE failure is not retryable: $classification" >&2
      return "$rc"
    fi
    echo "[nat-ci] profile=$PROFILE attempt=${attempt} failed with a whitelisted environment transient; starting bounded retry (attempt=$((attempt + 1))/${MAX_ATTEMPTS}): $classification" >&2
    preserve_failed_attempt_evidence "$attempt_dir" "$attempt"
  done
  return 1
}

case "$PROFILE" in
  unit)
    bash -n "$SMOKE"
    bash -n "$0"
    python3 -m unittest discover \
      -s "$ROOT_DIR/scripts/nat-sim" \
      -p 'test_nat_sim.py' \
      -v 2>&1 | tee "${ARTIFACT_DIR}-attempt-1.log"
    ;;
  direct)
    run_with_bounded_retry \
      MODE=direct \
      STEP_A=1 STEP_B=1 \
      CONSUME_A=0 CONSUME_B=0 \
      LOSS=0 REORDER=0 STRICT_FILTERING=0 \
      DIRECT_TIMEOUT_S=90 \
      OVERLAY_TIMEOUT_S=60 \
      OVERLAY_BURST=32
    ;;
  relay)
    run_with_bounded_retry \
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
    # Expected-failure profile: never retried, its verdict is the failure.
    run_smoke failure \
      "${ARTIFACT_DIR}-attempt-1" \
      "${ARTIFACT_DIR}-attempt-1.log" \
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
