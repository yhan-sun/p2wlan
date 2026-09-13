#!/usr/bin/env bash

# Call both per-daemon baseline captures as one gate. STATUS_READY is emitted
# only after both captures have returned success; callers must branch on this
# function's status before entering business verification.
capture_baseline_pair() {
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

  echo "[nat-sim] node-a ready state=STATUS_READY" >&2
  echo "[nat-sim] node-b ready state=STATUS_READY" >&2
}
