#!/usr/bin/env bash

# Harness readiness only; this never owns daemon/network connection state.
reset_baseline_pair() {
  BASELINE_PAIR_READY=0
  BASELINE_PAIR_ROUND_DIR=""
  BASELINE_PAIR_A_OUTPUT=""
  BASELINE_PAIR_B_OUTPUT=""
}

# Call both per-daemon baseline captures as one gate. STATUS_READY is emitted
# only after both captures have returned success; callers must branch on this
# function's status before entering business verification.
capture_baseline_pair() {
  reset_baseline_pair
  if [[ "$#" -ne 10 ]]; then
    echo "[nat-sim] baseline gate requires two five-argument captures" >&2
    return 2
  fi

  local status
  if capture_baseline_status "$1" "$2" "$3" "$4" "$5"; then
    :
  else
    status=$?
    echo "[nat-sim] FAIL reason_code=baseline_status_not_available side=$4 file=$2" >&2
    return "$status"
  fi

  if capture_baseline_status "$6" "$7" "$8" "$9" "${10}"; then
    :
  else
    status=$?
    echo "[nat-sim] FAIL reason_code=baseline_status_not_available side=$9 file=$7" >&2
    return "$status"
  fi

  BASELINE_PAIR_ROUND_DIR="${ROUND_DIR:-}"
  BASELINE_PAIR_A_OUTPUT="$2"
  BASELINE_PAIR_B_OUTPUT="$7"
  BASELINE_PAIR_READY=1
  echo "[nat-sim] node-a ready state=STATUS_READY" >&2
  echo "[nat-sim] node-b ready state=STATUS_READY" >&2
}

# Release only this round's existing daemon business gate after the original
# authenticated baseline callbacks and Relay confirmation barrier succeeded.
release_hard_hard_business_gate() {
  local gate=${1:-}
  if [[ "${BASELINE_PAIR_READY:-0}" != 1 || -z "${ROUND_DIR:-}" \
    || "${BASELINE_PAIR_ROUND_DIR:-}" != "$ROUND_DIR" \
    || "${BASELINE_PAIR_A_OUTPUT:-}" != "$ROUND_DIR/node-a.baseline.status.json" \
    || "${BASELINE_PAIR_B_OUTPUT:-}" != "$ROUND_DIR/node-b.baseline.status.json" \
    || "$gate" != "$ROUND_DIR/business-validation.start-gate" \
    || ! -s "${BASELINE_PAIR_A_OUTPUT:-}" || ! -s "${BASELINE_PAIR_B_OUTPUT:-}" \
    || "${BARRIER_RESULT:-}" != ready \
    || "${BARRIER_A_CONFIRMED:-}" != true || "${BARRIER_B_CONFIRMED:-}" != true \
    || "${BARRIER_A_HTTP:-}" != 200 || "${BARRIER_B_HTTP:-}" != 200 ]]; then
    echo "[nat-sim] FAIL reason_code=hard_hard_business_gate_not_ready" >&2
    return 1
  fi
  if ! (umask 077; set -o noclobber; : >"$gate"); then
    echo "[nat-sim] FAIL reason_code=hard_hard_business_gate_write_failed" >&2
    return 1
  fi
  echo "[nat-sim] Hard<->Hard business gate released after baseline pair and Relay barrier" >&2
}
